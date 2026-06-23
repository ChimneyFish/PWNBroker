#!/usr/bin/env python3
"""
PwnBroker Endpoint Agent
Supports: Windows, macOS, Linux
Requires: pip install requests psutil

Usage:
  python pwnbroker_agent.py --register [--no-verify-ssl]   # first-time setup
  python pwnbroker_agent.py [--no-verify-ssl]              # normal operation
"""

import os
import sys
import json
import time
import socket
import platform
import argparse
import logging

# ── embedded configuration (set by PwnBroker download endpoint) ──────────────
_DEFAULT_SERVER = "__PWNBROKER_SERVER__"
_DEFAULT_REG_TOKEN = "__REG_TOKEN__"
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="[PwnBroker Agent] %(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("pwnbroker")

_PLAT = sys.platform   # win32 | darwin | linux


def _ensure_deps():
    missing = []
    try:
        import requests  # noqa: F401
    except ImportError:
        missing.append("requests")
    try:
        import psutil  # noqa: F401
    except ImportError:
        missing.append("psutil")
    if missing:
        log.info("Installing missing dependencies: %s", " ".join(missing))
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet"] + missing)


_ensure_deps()

import requests  # noqa: E402
import psutil    # noqa: E402


# ── config file ──────────────────────────────────────────────────────────────

def _config_path():
    if _PLAT == "win32":
        base = os.environ.get("APPDATA", os.path.expanduser("~"))
        return os.path.join(base, "pwnbroker_agent.json")
    if _PLAT == "darwin":
        return os.path.expanduser("~/Library/PwnBroker/config.json")
    # /etc for root, home dir for regular users
    if os.geteuid() == 0:
        return "/etc/pwnbroker_agent.json"
    return os.path.expanduser("~/.pwnbroker_agent.json")


def _load_config():
    path = _config_path()
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return {}


def _save_config(cfg):
    path = _config_path()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        json.dump(cfg, f, indent=2)
    if _PLAT != "win32":
        os.chmod(path, 0o600)


# ── system info ──────────────────────────────────────────────────────────────

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
                    "status":      c.status,
                    "pid":         c.pid,
                })
    except (psutil.AccessDenied, PermissionError):
        log.warning("Cannot read network connections (run as root/admin for full visibility)")

    cpu_pct = psutil.cpu_percent(interval=0.5)
    mem_pct = psutil.virtual_memory().percent

    return {
        "hostname":       socket.gethostname(),
        "ip_address":     _local_ip(),
        "os":             _PLAT,
        "os_version":     platform.version(),
        "cpu_percent":    cpu_pct,
        "memory_percent": mem_pct,
        "processes":      procs[:100],
        "connections":    conns[:50],
    }


# ── registration ─────────────────────────────────────────────────────────────

def _normalise_server(url):
    """Ensure the server URL has a scheme."""
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    return url.rstrip("/")


def register(server, reg_token, verify_ssl):
    data = _collect()
    data["reg_token"] = reg_token
    try:
        r = requests.post(f"{server}/threat/api/register",
                          json=data, timeout=20, verify=verify_ssl)
        r.raise_for_status()
        result = r.json()
    except requests.exceptions.SSLError:
        log.error("SSL error — use --no-verify-ssl if using a self-signed certificate")
        sys.exit(1)
    except Exception as e:
        log.error("Registration failed: %s", e)
        sys.exit(1)

    cfg = {
        "server_url":  server,
        "agent_id":    result["agent_id"],
        "token":       result["token"],
        "verify_ssl":  verify_ssl,
    }
    _save_config(cfg)
    log.info("Registered as agent %s", result["agent_id"])
    return cfg


# ── heartbeat ────────────────────────────────────────────────────────────────

def heartbeat(cfg):
    data    = _collect()
    headers = {
        "X-Agent-ID":    cfg["agent_id"],
        "X-Agent-Token": cfg["token"],
    }
    try:
        r = requests.post(
            f"{cfg['server_url']}/threat/api/heartbeat",
            json=data, headers=headers,
            timeout=20, verify=cfg.get("verify_ssl", True),
        )
        r.raise_for_status()
        return r.json()
    except requests.exceptions.SSLError:
        log.error("SSL error — use --no-verify-ssl if using a self-signed certificate")
        return None
    except Exception as e:
        log.warning("Heartbeat failed: %s", e)
        return None


# ── main loop ────────────────────────────────────────────────────────────────

def run_loop(cfg, interval):
    log.info("Running. Heartbeating every %ds to %s  (Ctrl-C to stop)",
             interval, cfg["server_url"])
    while True:
        result = heartbeat(cfg)
        if result:
            alerts = result.get("alerts", [])
            new    = result.get("new_alerts", 0)
            if new:
                log.warning("%d new alert(s) from server!", new)
            for a in alerts:
                log.warning("ALERT [%s] %s (IOC: %s)", a["severity"].upper(), a["title"], a.get("ioc", ""))
        time.sleep(interval)


def main():
    parser = argparse.ArgumentParser(description="PwnBroker Endpoint Agent")
    parser.add_argument("--server",         default=_DEFAULT_SERVER,
                        help="PwnBroker server URL")
    parser.add_argument("--reg-token",      default=_DEFAULT_REG_TOKEN,
                        help="Registration token (from Settings → Threat Intel)")
    parser.add_argument("--no-verify-ssl",  action="store_true",
                        help="Skip TLS verification (use for self-signed certs)")
    parser.add_argument("--register",       action="store_true",
                        help="Force re-registration")
    parser.add_argument("--interval",       type=int, default=60,
                        help="Heartbeat interval in seconds (default: 60)")
    args = parser.parse_args()

    verify_ssl = not args.no_verify_ssl
    if not verify_ssl:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    cfg = _load_config()

    if args.register or not cfg.get("agent_id"):
        server = _normalise_server(args.server or "")
        if not server or "://" not in server:
            parser.error("--server <URL> is required for first-time registration  e.g. --server https://pwnbroker.local:5000")
        reg_token = args.reg_token or ""
        if not reg_token:
            reg_token = input("Registration token: ").strip()
        # Wipe old config so we get a fresh agent_id
        _save_config({})
        cfg = register(server, reg_token, verify_ssl)

    if not cfg.get("agent_id"):
        log.error("Not registered. Run with --register first.")
        sys.exit(1)

    run_loop(cfg, args.interval)


if __name__ == "__main__":
    main()
