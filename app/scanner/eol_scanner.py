"""
End-of-Life (EOL) detection scanner.

SSHes into a Linux/Unix target, reads /etc/os-release, and queries the
endoflife.date public API to determine if the OS is EOL or approaching it.
No API key required.
"""
import io
import json
from datetime import date, timedelta

import requests

EOL_API   = "https://endoflife.date/api"
WARN_DAYS = 180  # flag "high" if EOL within 6 months

# Ordered list of (/etc/os-release NAME substrings) → endoflife.date product slug.
# Longer / more specific patterns first to avoid false matches.
_OS_MAP = [
    ("almalinux",    "almalinux"),
    ("rocky",        "rocky-linux"),
    ("amazon linux", "amazon-linux"),
    ("red hat",      "rhel"),
    ("oracle",       "oracle-linux"),
    ("ubuntu",       "ubuntu"),
    ("debian",       "debian"),
    ("centos",       "centos"),
    ("fedora",       "fedora"),
    ("opensuse",     "opensuse"),
    ("suse",         "sles"),
    ("alpine",       "alpine"),
]


def _ssh_exec(target, commands: dict) -> dict:
    """SSH into target and run each command. Returns {name: stdout_text}."""
    import paramiko

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kw = {
        "hostname":       target.host,
        "port":           target.ssh_port or 22,
        "username":       target.ssh_username,
        "timeout":        15,
        "banner_timeout": 15,
    }

    if target.ssh_auth_type == "key" and target.ssh_private_key:
        key_file = io.StringIO(target.ssh_private_key)
        passphrase = target.ssh_key_passphrase or None
        # Try RSA first, then Ed25519
        try:
            kw["pkey"] = paramiko.RSAKey.from_private_key(key_file, password=passphrase)
        except Exception:
            key_file.seek(0)
            kw["pkey"] = paramiko.Ed25519Key.from_private_key(key_file, password=passphrase)
    else:
        kw["password"] = target.ssh_password

    client.connect(**kw)
    try:
        out = {}
        for name, cmd in commands.items():
            _, stdout, _ = client.exec_command(cmd, timeout=10)
            out[name] = stdout.read().decode("utf-8", errors="replace").strip()
        return out
    finally:
        client.close()


def _parse_os_release(text: str) -> dict:
    data: dict = {}
    for line in text.splitlines():
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            k, _, v = line.partition("=")
            data[k.strip()] = v.strip().strip('"')
    return data


def _identify(os_info: dict):
    """Map parsed /etc/os-release fields to (eol_slug, version_string)."""
    name   = os_info.get("NAME", "").lower()
    ver_id = os_info.get("VERSION_ID", "").strip()

    for pattern, slug in _OS_MAP:
        if pattern in name:
            ver = ver_id
            # RHEL and its clones: use major version only (e.g. "8" not "8.6")
            if slug in ("rhel", "almalinux", "rocky-linux", "oracle-linux") and "." in ver:
                ver = ver.split(".")[0]
            return slug, ver
    return None, None


def _eol_lookup(product: str, version: str):
    """Query endoflife.date for a specific product + version. Returns dict or None."""
    try:
        r = requests.get(
            f"{EOL_API}/{product}/{version}.json",
            timeout=10,
            headers={"Accept": "application/json"},
        )
        return r.json() if r.ok else None
    except Exception:
        return None


def _build_result(product: str, version: str, eol_data: dict, host: str) -> dict:
    eol_raw = eol_data.get("eol")
    latest  = eol_data.get("latest", "")
    lts     = eol_data.get("lts", False)
    today   = date.today()

    def _parse_date(d):
        if isinstance(d, bool) or d is None:
            return None
        try:
            return date.fromisoformat(str(d))
        except Exception:
            return None

    eol_date = _parse_date(eol_raw)
    is_eol   = eol_raw is True or (eol_date and eol_date <= today)
    near_eol = eol_date and not is_eol and eol_date <= today + timedelta(days=WARN_DAYS)

    if is_eol:
        severity = "critical"
        eol_str  = str(eol_date) if eol_date else "unknown date"
        title    = f"{product.title()} {version} — End of Life"
        desc     = (
            f"{product.title()} {version} has reached end of life ({eol_str}) "
            f"and no longer receives security patches.\n"
            f"Latest supported release: {latest}\n"
            "Upgrade immediately to a supported release."
        )
        remediation = f"Upgrade to {product} {latest} or a newer LTS release immediately."
    elif near_eol:
        days_left   = (eol_date - today).days
        severity    = "high"
        title       = f"{product.title()} {version} — EOL in {days_left} days ({eol_date})"
        desc        = (
            f"{product.title()} {version} reaches end of life on {eol_date} "
            f"({days_left} days remaining). Security patches will stop after that date.\n"
            f"Latest available: {latest}\nPlan and schedule an upgrade."
        )
        remediation = f"Plan upgrade to {product} {latest} before {eol_date}."
    else:
        severity = "info"
        eol_str  = str(eol_date) if eol_date else "unknown"
        title    = f"{product.title()} {version} — Supported (EOL: {eol_str})"
        desc     = (
            f"{product.title()} {version} is currently supported.\n"
            f"EOL date: {eol_str} | LTS: {'Yes' if lts else 'No'} | Latest: {latest}"
        )
        remediation = ""

    return {
        "result_type": "vulnerability" if severity in ("critical", "high") else "info",
        "host":        host,
        "severity":    severity,
        "title":       title,
        "description": desc,
        "remediation": remediation,
        "raw_data": json.dumps({
            "source":  "eol",
            "product": product,
            "version": version,
            "eol":     str(eol_raw),
            "latest":  latest,
            "lts":     lts,
        }),
    }


def run_eol_scan(scan, target) -> list:
    """
    SSH into target, detect OS version, query endoflife.date.
    Returns list of ScanResult-ready dicts.
    """
    host = target.host if target else "unknown"

    if not target or not target.ssh_username:
        return [{
            "result_type": "info", "host": host, "severity": "info",
            "title": "No SSH Credentials",
            "description": "EOL scanning requires SSH credentials configured on the target.",
        }]

    try:
        raw = _ssh_exec(target, {
            "os_release": "cat /etc/os-release 2>/dev/null || true",
            "uname":      "uname -sr",
        })
    except Exception as e:
        return [{
            "result_type": "info", "host": host, "severity": "info",
            "title": "SSH Connection Failed",
            "description": f"Could not connect to {host}: {e}",
        }]

    os_release_text = raw.get("os_release", "")
    uname_text      = raw.get("uname", "")
    os_info         = _parse_os_release(os_release_text)
    pretty          = (
        os_info.get("PRETTY_NAME")
        or os_info.get("NAME")
        or uname_text
        or "Unknown OS"
    )

    results = [{
        "result_type": "info",
        "host":        host,
        "severity":    "info",
        "title":       f"OS Detected: {pretty}",
        "description": f"uname: {uname_text}\n\n/etc/os-release:\n{os_release_text[:800]}",
        "raw_data": json.dumps({
            "source": "eol_detect",
            "pretty": pretty,
            "uname":  uname_text,
        }),
    }]

    product, version = _identify(os_info)

    if not product or not version:
        results.append({
            "result_type": "info",
            "host":        host,
            "severity":    "info",
            "title":       "OS Not Recognized for EOL Check",
            "description": (
                f"'{pretty}' could not be mapped to an endoflife.date product.\n"
                "Supported distributions: Ubuntu, Debian, CentOS, RHEL, AlmaLinux, "
                "Rocky Linux, Fedora, Amazon Linux, openSUSE, SLES, Alpine Linux, "
                "Oracle Linux."
            ),
        })
        return results

    eol_data = _eol_lookup(product, version)
    if not eol_data:
        results.append({
            "result_type": "info",
            "host":        host,
            "severity":    "info",
            "title":       "EOL Data Unavailable",
            "description": (
                f"No endoflife.date entry for {product} {version}. "
                "The version may be very new, or the product slug may need updating."
            ),
        })
        return results

    results.append(_build_result(product, version, eol_data, host))
    return results
