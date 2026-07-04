#!/usr/bin/env python3
"""
PwnBroker Endpoint Agent
Supports: Windows (Service), macOS, Linux

Windows service management (run as Administrator):
  python agent.py install   — register as Windows Service
  python agent.py remove    — remove service
  python agent.py start     — start service
  python agent.py stop      — stop service
  python agent.py debug     — run in console (Ctrl-C to quit)

Linux / macOS:
  python agent.py [--no-verify-ssl]
"""

# ── embedded configuration (substituted by PwnBroker at download time) ────────
_DEFAULT_SERVER    = "__PWNBROKER_SERVER__"
_DEFAULT_REG_TOKEN = "__REG_TOKEN__"
# ─────────────────────────────────────────────────────────────────────────────

import os
import sys
import json
import time
import socket
import platform
import logging

_PLAT = sys.platform  # win32 | darwin | linux

logging.basicConfig(
    level=logging.INFO,
    format="[PwnBroker] %(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("pwnbroker")


def _ensure_deps():
    missing = []
    for pkg in ("requests", "psutil"):
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    if missing:
        import subprocess
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--quiet"] + missing
        )


_ensure_deps()

import requests  # noqa: E402
import psutil    # noqa: E402


# ── config ────────────────────────────────────────────────────────────────────

def _config_path():
    if _PLAT == "win32":
        # C:\ProgramData\PwnBroker\ — readable by SYSTEM and all users
        base = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
        return os.path.join(base, "PwnBroker", "config.json")
    if _PLAT == "darwin":
        return "/Library/Application Support/PwnBroker/config.json"
    return "/etc/pwnbroker/config.json"


def _load_config():
    path = _config_path()
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return {}


def _save_config(cfg):
    path = _config_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(cfg, f, indent=2)
    if _PLAT != "win32":
        os.chmod(path, 0o600)


# ── telemetry ─────────────────────────────────────────────────────────────────

def _local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _collect():
    procs = []
    for p in psutil.process_iter(["pid", "name"]):
        try:
            procs.append({"pid": p.info["pid"], "name": p.info["name"]})
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    conns = []
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.raddr and c.status == "ESTABLISHED":
                conns.append({
                    "remote_ip":   c.raddr.ip,
                    "remote_port": c.raddr.port,
                    "local_port":  c.laddr.port if c.laddr else None,
                    "pid":         c.pid,
                })
    except (psutil.AccessDenied, PermissionError):
        pass

    return {
        "hostname":       socket.gethostname(),
        "ip_address":     _local_ip(),
        "os":             _PLAT,
        "os_version":     platform.version(),
        "cpu_percent":    psutil.cpu_percent(interval=0.5),
        "memory_percent": psutil.virtual_memory().percent,
        "processes":      procs[:100],
        "connections":    conns[:50],
    }


# ── server comms ──────────────────────────────────────────────────────────────

def _normalise_server(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    return url.rstrip("/")


def register(server, reg_token, verify_ssl):
    data = _collect()
    data["reg_token"] = reg_token
    try:
        r = requests.post(
            f"{server}/threat/api/register",
            json=data, timeout=20, verify=verify_ssl,
        )
        r.raise_for_status()
        result = r.json()
    except requests.exceptions.SSLError:
        log.error("SSL error — use --no-verify-ssl for self-signed certificates")
        sys.exit(1)
    except Exception as e:
        log.error("Registration failed: %s", e)
        sys.exit(1)

    cfg = {
        "server_url": server,
        "agent_id":   result["agent_id"],
        "token":      result["token"],
        "verify_ssl": verify_ssl,
    }
    _save_config(cfg)
    log.info("Registered as agent %s", result["agent_id"])
    return cfg


def heartbeat(cfg):
    headers = {
        "X-Agent-ID":    cfg["agent_id"],
        "X-Agent-Token": cfg["token"],
    }
    try:
        r = requests.post(
            f"{cfg['server_url']}/threat/api/heartbeat",
            json=_collect(), headers=headers,
            timeout=20, verify=cfg.get("verify_ssl", True),
        )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        log.warning("Heartbeat failed: %s", e)
        return None


def _run_loop(cfg, interval=60, stop_event=None):
    log.info("Heartbeating every %ds to %s", interval, cfg["server_url"])
    while True:
        result = heartbeat(cfg)
        if result:
            for alert in result.get("alerts", []):
                log.warning("ALERT [%s] %s", alert["severity"].upper(), alert["title"])
        # If a threading.Event is provided (service mode), use it for interruptible sleep
        if stop_event is not None:
            stop_event.wait(timeout=interval)
            if stop_event.is_set():
                break
        else:
            time.sleep(interval)


# ── Windows Service (pywin32) ─────────────────────────────────────────────────

_SVC_NAME    = "PwnBrokerAgent"
_SVC_DISPLAY = "PwnBroker Endpoint Agent"
_SVC_DESC    = "PwnBroker security monitoring agent — heartbeats telemetry and receives alerts."

if _PLAT == "win32":
    try:
        import threading
        import win32event
        import win32service
        import win32serviceutil
        import servicemanager

        class _PwnBrokerSvc(win32serviceutil.ServiceFramework):
            _svc_name_         = _SVC_NAME
            _svc_display_name_ = _SVC_DISPLAY
            _svc_description_  = _SVC_DESC

            def __init__(self, args):
                win32serviceutil.ServiceFramework.__init__(self, args)
                self._stop_event = threading.Event()

            def SvcStop(self):
                self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
                self._stop_event.set()

            def SvcDoRun(self):
                servicemanager.LogMsg(
                    servicemanager.EVENTLOG_INFORMATION_TYPE,
                    servicemanager.PYS_SERVICE_STARTED,
                    (self._svc_name_, ""),
                )
                cfg = _load_config()
                if not cfg.get("agent_id"):
                    servicemanager.LogErrorMsg("PwnBroker Agent: no config found — run installer first.")
                    return
                _run_loop(cfg, interval=60, stop_event=self._stop_event)

        _SVC_CLASS_AVAILABLE = True
    except ImportError:
        _SVC_CLASS_AVAILABLE = False
else:
    _SVC_CLASS_AVAILABLE = False

# ── CLI entry point ───────────────────────────────────────────────────────────

_WIN_SVC_CMDS = {"install", "remove", "start", "stop", "restart", "debug", "status", "update"}


def main():
    # On Windows, intercept service management commands before argparse
    if _PLAT == "win32" and len(sys.argv) > 1 and sys.argv[1].lower() in _WIN_SVC_CMDS:
        if not _SVC_CLASS_AVAILABLE:
            print("ERROR: pywin32 is required for service management.")
            print("       pip install pywin32")
            sys.exit(1)
        win32serviceutil.HandleCommandLine(_PwnBrokerSvc)
        return

    import argparse
    parser = argparse.ArgumentParser(description="PwnBroker Endpoint Agent")
    parser.add_argument("--server",        default=_DEFAULT_SERVER)
    parser.add_argument("--reg-token",     default=_DEFAULT_REG_TOKEN)
    parser.add_argument("--no-verify-ssl", action="store_true")
    parser.add_argument("--register",      action="store_true")
    parser.add_argument("--interval",      type=int, default=60)
    args = parser.parse_args()

    verify_ssl = not args.no_verify_ssl
    if not verify_ssl:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    cfg = _load_config()

    if args.register or not cfg.get("agent_id"):
        server = _normalise_server(args.server or "")
        if not server or "://" not in server:
            parser.error("--server <URL> required for first-time registration")
        reg_token = args.reg_token or input("Registration token: ").strip()
        _save_config({})
        cfg = register(server, reg_token, verify_ssl)

    if not cfg.get("agent_id"):
        log.error("Not registered. Run with --register first.")
        sys.exit(1)

    _run_loop(cfg, interval=args.interval)


if __name__ == "__main__":
    # When Windows SCM launches the service it calls this with no useful args;
    # servicemanager.StartServiceCtrlDispatcher handles the dispatch.
    if _PLAT == "win32" and _SVC_CLASS_AVAILABLE and len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(_PwnBrokerSvc)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        main()
