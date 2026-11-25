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
import re
import sys
import gzip
import json
import time
import shutil
import socket
import platform
import logging
import subprocess
from datetime import datetime, timezone

AGENT_VERSION = "2.1.0"

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
        "agent_version":  AGENT_VERSION,
        "hostname":       socket.gethostname(),
        "ip_address":     _local_ip(),
        "os":             _PLAT,
        "os_version":     platform.version(),
        "cpu_percent":    psutil.cpu_percent(interval=0.5),
        "memory_percent": psutil.virtual_memory().percent,
        "processes":      procs[:100],
        "connections":    conns[:50],
    }


# ── host inventory (for verifying PwnBroker scan findings) ────────────────────
#
# Read-only. Only fixed commands are run (package queries, `apachectl -M`,
# `nginx -V`), never anything the server sends. The server can only ask "send
# an inventory" and name packages whose changelogs it wants; names are checked
# against a strict pattern before use.

_CVE_RE      = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
_DEB_HEADER  = re.compile(r"^[a-z0-9][a-z0-9.+-]* \([^)]+\) ")
_TRIMMED_RE  = re.compile(r"older changelog entries|changelog has been trimmed", re.I)
_PKG_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_-]{0,199}$")
_MAX_READ    = 4 * 1024 * 1024


def _run(argv, timeout=30):
    """Run a fixed read-only command (no shell) → stdout+stderr text, or ''."""
    if not shutil.which(argv[0]):
        return ""
    try:
        extra = {"creationflags": 0x08000000} if _PLAT == "win32" else {}   # CREATE_NO_WINDOW
        p = subprocess.run(argv, capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL,
                           env={**os.environ, "LC_ALL": "C"}, **extra)
        return (p.stdout + p.stderr)[:_MAX_READ].decode("utf-8", "replace")
    except Exception:
        return ""


def _os_release():
    info = {}
    try:
        with open("/etc/os-release") as f:
            for line in f:
                k, _, v = line.strip().partition("=")
                info[k] = v.strip().strip('"')
    except OSError:
        pass
    return info


def _package_manager():
    if _PLAT != "linux":
        return None
    if shutil.which("dpkg-query"):
        return "deb"
    if shutil.which("rpm"):
        return "rpm"
    return None


def _all_ips():
    ips = []
    for addrs in psutil.net_if_addrs().values():
        for a in addrs:
            if a.family in (socket.AF_INET, socket.AF_INET6):
                ips.append(a.address.split("%", 1)[0])
    return ips


def _listeners():
    out, seen = [], set()
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        return out
    for c in conns:
        tcp = c.type == socket.SOCK_STREAM
        if not c.laddr or (tcp and c.status != psutil.CONN_LISTEN) or (not tcp and c.raddr):
            continue
        key = (c.laddr.port, "tcp" if tcp else "udp")
        if key in seen:
            continue
        seen.add(key)
        exe = None
        if c.pid:
            try:
                exe = psutil.Process(c.pid).exe() or None
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                pass
        out.append({"port": key[0], "proto": key[1], "exe": exe})
    return out


def _owning_package(pm, path):
    for p in dict.fromkeys([path, path[4:] if path.startswith("/usr/") else path]):
        if pm == "deb":
            out = _run(["dpkg", "-S", p], timeout=15)
            if ":" in out and "no path found" not in out:
                return out.split(":", 1)[0].split(",")[0].strip()
        elif pm == "rpm":
            out = _run(["rpm", "-qf", "--qf", "%{NAME}\n", p], timeout=15).strip()
            if out and "not owned" not in out and "No such file" not in out:
                return out.split()[0]
    return None


def _packages(pm):
    pkgs = {}
    if pm == "deb":
        out = _run(["dpkg-query", "-W", "-f",
                    "${db:Status-Status}\t${Package}\t${Version}\t${source:Package}\n"], timeout=60)
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) == 4 and parts[0] == "installed":
                pkgs[parts[1]] = [parts[2], parts[3] or parts[1]]
    elif pm == "rpm":
        out = _run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{SOURCERPM}\n"], timeout=60)
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) == 3:
                src = re.sub(r"-[^-]+-[^-]+\.src\.rpm$", "", parts[2]) or parts[0]
                pkgs[parts[0]] = [parts[1], src]
    return pkgs


def _changelog(pm, pkg, source):
    """CVE-mentioning changelog lines with their version header."""
    text = ""
    if pm == "deb":
        for d in dict.fromkeys([pkg, source]):
            for name in ("changelog.Debian.gz", "changelog.Debian"):
                path = os.path.join("/usr/share/doc", d, name)
                try:
                    opener = gzip.open if name.endswith(".gz") else open
                    with opener(path, "rb") as f:
                        text = f.read(_MAX_READ).decode("utf-8", "replace")
                    break
                except OSError:
                    continue
            if text:
                break
    elif pm == "rpm":
        text = _run(["rpm", "-q", "--changelog", pkg], timeout=30)
    entries, header = [], ""
    for line in text.splitlines():
        if _DEB_HEADER.match(line) or line.startswith("* "):
            header = line.strip()[:200]
        if _CVE_RE.search(line):
            entries.append([header, line.strip()[:300]])
    return {"found": bool(text.strip()), "trimmed": bool(_TRIMMED_RE.search(text)),
            "entries": entries[:5000]}


def _apache_modules():
    for cmd in ("apache2ctl", "apachectl", "httpd"):
        if shutil.which(cmd):
            out = _run([cmd, "-M"], timeout=20)
            mods = sorted(set(re.findall(r"^\s*([a-z0-9_]+)_module\b", out, re.M)))
            return mods or None
    return None


def _nginx_build():
    if not shutil.which("nginx"):
        return None
    out = _run(["nginx", "-V"], timeout=20)
    for root, _, files in os.walk("/etc/nginx"):
        for fn in files:
            try:
                with open(os.path.join(root, fn), errors="replace") as f:
                    out += "".join(l for l in f if l.lstrip().startswith("load_module"))
            except OSError:
                pass
    return out if "configure arguments" in out else None


# ── Windows: build number, updates, installed programs, file versions ────────
#
# Read from the registry and the executables' version resources — nothing is
# changed. The only command run is Get-HotFix (fixed text, no input).

_KB_RE = re.compile(r"^KB\d{4,9}$", re.I)


def _reg_values(parent, subkey, names, access=None):
    import winreg
    out = {}
    try:
        with winreg.OpenKey(parent, subkey, 0, access or winreg.KEY_READ) as k:
            for n in names:
                try:
                    out[n] = winreg.QueryValueEx(k, n)[0]
                except OSError:
                    pass
    except OSError:
        pass
    return out


def _file_info(path):
    """Version resource of an executable → {product, company, description,
    product_version, file_version}, or {}."""
    try:
        import ctypes
        from ctypes import wintypes
        ver = ctypes.WinDLL("version")
        ver.GetFileVersionInfoSizeW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
        ver.GetFileVersionInfoSizeW.restype = wintypes.DWORD
        ver.GetFileVersionInfoW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                            ctypes.c_void_p]
        ver.GetFileVersionInfoW.restype = wintypes.BOOL
        ver.VerQueryValueW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR,
                                       ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.UINT)]
        ver.VerQueryValueW.restype = wintypes.BOOL

        size = ver.GetFileVersionInfoSizeW(path, None)
        if not size:
            return {}
        buf = ctypes.create_string_buffer(size)
        if not ver.GetFileVersionInfoW(path, 0, size, buf):
            return {}
        ptr, n = ctypes.c_void_p(), wintypes.UINT()
        info = {}

        class _Fixed(ctypes.Structure):
            _fields_ = [(f, wintypes.DWORD) for f in (
                "sig", "struc", "file_ms", "file_ls", "prod_ms", "prod_ls", "mask", "flags",
                "os", "type", "subtype", "date_ms", "date_ls")]

        if ver.VerQueryValueW(buf, "\\", ctypes.byref(ptr), ctypes.byref(n)) and n.value:
            f = ctypes.cast(ptr, ctypes.POINTER(_Fixed)).contents
            if f.sig == 0xFEEF04BD:
                info["file_version"] = (f"{f.file_ms >> 16}.{f.file_ms & 0xFFFF}."
                                        f"{f.file_ls >> 16}.{f.file_ls & 0xFFFF}")
                info["product_version"] = (f"{f.prod_ms >> 16}.{f.prod_ms & 0xFFFF}."
                                           f"{f.prod_ls >> 16}.{f.prod_ls & 0xFFFF}")
        langs = []
        if (ver.VerQueryValueW(buf, "\\VarFileInfo\\Translation", ctypes.byref(ptr), ctypes.byref(n))
                and n.value >= 4):
            words = ctypes.cast(ptr, ctypes.POINTER(wintypes.WORD * (n.value // 2))).contents
            langs = [(words[i], words[i + 1]) for i in range(0, len(words) - 1, 2)][:4]
        langs += [(0x0409, 0x04B0), (0x0409, 0x04E4), (0x0000, 0x04B0)]
        keys = {"ProductName": "product", "CompanyName": "company", "FileDescription": "description",
                "ProductVersion": "product_version", "FileVersion": "file_version"}
        found = set()
        for lang, cp in langs:
            for key, out_key in keys.items():
                if key in found:
                    continue
                sub = f"\\StringFileInfo\\{lang:04x}{cp:04x}\\{key}"
                if ver.VerQueryValueW(buf, sub, ctypes.byref(ptr), ctypes.byref(n)) and n.value:
                    val = ctypes.wstring_at(ptr.value, n.value).split("\0", 1)[0].strip()
                    if val:
                        info[out_key] = val[:160]     # strings beat the numeric versions
                        found.add(key)
        return info
    except Exception:
        return {}


def _hotfixes():
    out = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                "Get-HotFix | ForEach-Object { $_.HotFixID }"], timeout=120)
    return sorted({l.strip().upper() for l in out.splitlines() if _KB_RE.match(l.strip())})


def _windows_info():
    import winreg
    cv = _reg_values(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                     ("ProductName", "DisplayVersion", "ReleaseId", "EditionID", "InstallationType",
                      "CurrentMajorVersionNumber", "CurrentMinorVersionNumber", "CurrentVersion",
                      "CurrentBuildNumber", "CurrentBuild", "UBR"))
    major, minor = cv.get("CurrentMajorVersionNumber"), cv.get("CurrentMinorVersionNumber")
    if major is None and cv.get("CurrentVersion"):
        major, _, minor = str(cv["CurrentVersion"]).partition(".")
    buildno = cv.get("CurrentBuildNumber") or cv.get("CurrentBuild")
    ubr = cv.get("UBR")
    build = ""
    if None not in (major, minor, buildno, ubr) and "" not in (major, minor):
        build = f"{major}.{minor}.{buildno}.{ubr}"
    else:
        # Older Windows has no UBR value: the kernel's file version carries it.
        root = os.environ.get("SystemRoot", r"C:\Windows")
        fv = _file_info(os.path.join(root, "System32", "ntoskrnl.exe")).get("file_version", "")
        m = re.match(r"^(\d+\.\d+\.\d+\.\d+)", fv)
        build = m.group(1) if m else ""
    product = str(cv.get("ProductName") or "")
    try:
        if int(buildno) >= 22000 and product.startswith("Windows 10"):
            product = "Windows 11" + product[len("Windows 10"):]   # registry still says 10
    except (TypeError, ValueError):
        pass
    return {"build": build, "product": product,
            "display_version": str(cv.get("DisplayVersion") or cv.get("ReleaseId") or ""),
            "edition": str(cv.get("EditionID") or ""),
            "installation_type": str(cv.get("InstallationType") or ""),
            "hotfixes": _hotfixes()}


def _programs():
    """Apps & Features: name, version, publisher, install folder (64- and 32-bit)."""
    import winreg
    out, seen = [], set()
    path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
        access = winreg.KEY_READ | view
        try:
            root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, access)
        except OSError:
            continue
        with root:
            i = 0
            while i < 20000:
                try:
                    sub = winreg.EnumKey(root, i)
                except OSError:
                    break
                i += 1
                v = _reg_values(root, sub, ("DisplayName", "DisplayVersion", "Publisher",
                                            "InstallLocation", "ParentKeyName"), access)
                name = str(v.get("DisplayName") or "").strip()
                if not name or v.get("ParentKeyName"):        # skip updates of other programs
                    continue
                item = {"name": name[:200], "version": str(v.get("DisplayVersion") or "")[:64],
                        "publisher": str(v.get("Publisher") or "")[:120],
                        "location": str(v.get("InstallLocation") or "").strip().strip('"')[:400]}
                key = (item["name"], item["version"], item["location"])
                if key not in seen:
                    seen.add(key)
                    out.append(item)
    return out[:5000]


def collect_inventory(changelog_packages=()):
    errors = []
    osr = _os_release()
    kernel = {"win32": "Windows", "darwin": "Darwin"}.get(_PLAT, platform.system())
    pm = _package_manager()
    listeners = _listeners()
    if not listeners:
        errors.append("couldn't list listening ports (agent not running as root/Administrator?)")
    elif any(not l["exe"] for l in listeners):
        n = sum(1 for l in listeners if not l["exe"])
        errors.append(f"{n} listening port(s) owned by processes this agent can't inspect "
                      f"(run it as root/Administrator to check them)")
    packages = _packages(pm) if pm else {}
    windows = programs = None
    if _PLAT == "win32":
        files = {}
        for l in listeners:
            if l["exe"]:
                if l["exe"] not in files:
                    files[l["exe"]] = _file_info(l["exe"])
                if files[l["exe"]]:
                    l["file"] = files[l["exe"]]
        try:
            windows = _windows_info()
        except Exception as e:
            errors.append(f"couldn't read the Windows version: {e}")
        try:
            programs = _programs()
        except Exception as e:
            errors.append(f"couldn't list installed programs: {e}")
        if windows and not windows.get("hotfixes"):
            errors.append("couldn't list installed updates (Get-HotFix)")
    owner = {}
    for l in listeners:
        if l["exe"] and pm:
            if l["exe"] not in owner:
                owner[l["exe"]] = _owning_package(pm, l["exe"])
            l["package"] = owner[l["exe"]]
    want = {l.get("package") for l in listeners if l.get("package")}
    want |= {p for p in changelog_packages if isinstance(p, str) and _PKG_NAME_RE.match(p)}
    changelogs = {}
    for p in sorted(want):
        if p in packages:
            changelogs[p] = _changelog(pm, p, packages[p][1])
    return {
        "schema": 1,
        "agent_version": AGENT_VERSION,
        "collected_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "os": {"kernel": kernel,
               "id": "windows" if _PLAT == "win32" else osr.get("ID", _PLAT),
               "pretty": ((windows or {}).get("product") and " ".join(filter(None, (
                              windows["product"], windows.get("display_version")))))
                         or osr.get("PRETTY_NAME") or f"{platform.system()} {platform.release()}"},
        "package_manager": pm,
        "ips": _all_ips(),
        "listeners": listeners,
        "packages": packages,
        "changelogs": changelogs,
        "apache_modules": _apache_modules() if _PLAT == "linux" else None,
        "nginx_build": _nginx_build() if _PLAT == "linux" else None,
        "windows": windows,
        "programs": programs or [],
        "errors": errors,
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


def send_inventory(cfg, changelog_packages=()):
    headers = {
        "X-Agent-ID":    cfg["agent_id"],
        "X-Agent-Token": cfg["token"],
    }
    try:
        inv = collect_inventory(changelog_packages)
        r = requests.post(
            f"{cfg['server_url']}/threat/api/inventory",
            json=inv, headers=headers,
            timeout=120, verify=cfg.get("verify_ssl", True),
        )
        r.raise_for_status()
        log.info("Sent host inventory (%d packages, %d programs, %d listening ports)",
                 len(inv["packages"]), len(inv["programs"]), len(inv["listeners"]))
    except Exception as e:
        log.warning("Inventory upload failed: %s", e)


def _run_loop(cfg, interval=60, stop_event=None):
    log.info("Heartbeating every %ds to %s", interval, cfg["server_url"])
    while True:
        result = heartbeat(cfg)
        if result:
            for alert in result.get("alerts", []):
                log.warning("ALERT [%s] %s", alert["severity"].upper(), alert["title"])
            if result.get("send_inventory"):
                send_inventory(cfg, result.get("changelog_packages") or ())
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
    parser.add_argument("--print-inventory", action="store_true",
                        help="print the host inventory this agent would send, then exit")
    args = parser.parse_args()

    verify_ssl = not args.no_verify_ssl
    if not verify_ssl:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if args.print_inventory:
        print(json.dumps(collect_inventory(), indent=2))
        return

    cfg = _load_config()

    if args.register or not cfg.get("agent_id"):
        server = _normalise_server(args.server or "")
        if not server or "://" not in server:
            parser.error("--server <URL> required for first-time registration")
        reg_token = args.reg_token or input("Registration token: ").strip()
        _save_config({})
        cfg = register(server, reg_token, verify_ssl)
        if args.register:
            # --register is the one-shot enrollment step every install script
            # (systemd/launchd/Windows Service) runs before separately setting
            # up the persistent process — which then invokes agent.py *without*
            # --register, relying on the config just written here. Falling
            # through into the heartbeat loop below instead of returning meant
            # this "one-shot" step never actually returned: it just became the
            # agent, in the foreground, forever — so every installer hung here
            # indefinitely and never got to the "create the service" step.
            return

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
