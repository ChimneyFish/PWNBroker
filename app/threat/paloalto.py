"""
PAN-OS (Palo Alto) threat log ingestion — pulls firewall Threat log entries
(spyware/vulnerability/virus/WildFire detections) via the PAN-OS XML API,
including entries seen on TAP-mode (passive/mirror) interfaces.

Follows the same contract as the other app/threat/ modules: a normalized
dict on success, or {"error": "..."} on failure — never raises into callers.
Secrets (api_key/password) are never included in returned or logged text.
"""
import re
import time
from datetime import datetime
import xml.etree.ElementTree as ET
import requests

_SECRET_RE = re.compile(r"(key|password)=[^&\s'\"]+", re.IGNORECASE)


def _scrub(text):
    """Strip API keys/passwords out of exception text before it's returned or logged —
    PAN-OS puts them directly in the request query string."""
    return _SECRET_RE.sub(r"\1=***", str(text))


def _base_url(hostname):
    hostname = (hostname or "").strip().rstrip("/")
    if not hostname.startswith(("http://", "https://")):
        hostname = f"https://{hostname}"
    return f"{hostname}/api/"


def _parse_error(xml_text):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return "PAN-OS returned an unparseable response"
    msg = root.find(".//msg")
    if msg is not None and msg.text:
        return msg.text.strip()
    line = root.find(".//line")
    if line is not None and line.text:
        return line.text.strip()
    return f"PAN-OS API error (status={root.get('status', 'unknown')})"


def _request(hostname, params, verify_ssl, timeout):
    """GET the PAN-OS XML API. Returns (root_element, error_string)."""
    try:
        r = requests.get(_base_url(hostname), params=params, verify=verify_ssl, timeout=timeout)
    except requests.exceptions.SSLError:
        return None, ("TLS certificate verification failed — check the firewall's certificate "
                       "or disable verify_ssl for this firewall")
    except requests.exceptions.RequestException as e:
        return None, _scrub(str(e))

    try:
        root = ET.fromstring(r.text)
    except ET.ParseError:
        return None, "PAN-OS returned an unparseable response"

    if root.get("status") == "error":
        return None, _parse_error(r.text)
    return root, None


def generate_api_key(hostname, username, password, verify_ssl=True, timeout=12):
    """Exchange firewall admin credentials for a long-lived API key (type=keygen)."""
    root, err = _request(hostname, {"type": "keygen", "user": username, "password": password},
                          verify_ssl, timeout)
    if err:
        return {"error": err}
    key_el = root.find(".//key")
    if key_el is None or not key_el.text:
        return {"error": "PAN-OS did not return an API key"}
    return {"api_key": key_el.text.strip()}


def test_connection(hostname, api_key, verify_ssl=True, timeout=12):
    """Lightweight reachability/auth check via a harmless op command."""
    root, err = _request(
        hostname,
        {"type": "op", "cmd": "<show><system><info></info></system></show>", "key": api_key},
        verify_ssl, timeout,
    )
    if err:
        return {"error": err}

    info = root.find(".//system")
    if info is None:
        return {"error": "Unexpected response from firewall"}

    def _t(tag):
        el = info.find(tag)
        return el.text.strip() if el is not None and el.text else ""

    return {
        "ok":         True,
        "hostname":   _t("hostname"),
        "sw_version": _t("sw-version"),
        "model":      _t("model"),
    }


def _text(entry, tag):
    el = entry.find(tag)
    return el.text.strip() if el is not None and el.text else None


def _int(entry, tag):
    val = _text(entry, tag)
    try:
        return int(val) if val is not None else None
    except ValueError:
        return None


def _parse_time(value):
    if not value:
        return None
    for fmt in ("%Y/%m/%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def _parse_entry(entry):
    """Normalize a single PAN-OS threat-log <entry> into PaloAltoThreatLog fields.
    Field names (inbound interface especially) are best-effort — see paloalto
    integration plan's Open Questions for what needs verifying against a real device."""
    seqno = entry.get("seqno") or _text(entry, "seqno")
    try:
        seqno = int(seqno)
    except (TypeError, ValueError):
        return None  # no usable cursor/dedupe key — skip defensively

    return {
        "seqno":          seqno,
        "time_generated": _parse_time(_text(entry, "time_generated") or _text(entry, "receive_time")),
        "src_ip":         _text(entry, "src"),
        "src_port":       _int(entry, "sport"),
        "dst_ip":         _text(entry, "dst"),
        "dst_port":       _int(entry, "dport"),
        "nat_src_ip":     _text(entry, "natsrc"),
        "nat_dst_ip":     _text(entry, "natdst"),
        "rule_name":      _text(entry, "rule"),
        "application":    _text(entry, "app"),
        "threat_name":    _text(entry, "threatid"),
        "threat_id":      _text(entry, "threat-id") or _text(entry, "threatid"),
        "category":       _text(entry, "category"),
        "subtype":        _text(entry, "subtype"),
        "severity":       _text(entry, "severity"),
        "action":         _text(entry, "action"),
        "from_zone":      _text(entry, "from"),
        "to_zone":        _text(entry, "to"),
        "inbound_if":     _text(entry, "inbound_if") or _text(entry, "interface"),
        "outbound_if":    _text(entry, "outbound_if"),
        "direction":      _text(entry, "direction"),
        "raw_xml":        ET.tostring(entry, encoding="unicode"),
    }


def query_threat_logs(hostname, api_key, verify_ssl=True, since_seqno=None, since_time=None,
                       limit=1000, max_wait_seconds=60, poll_interval_seconds=2, timeout=12):
    """Fetch new PAN-OS threat log entries since the given cursor.

    PAN-OS log queries are asynchronous: submit a query to get a job id, then
    poll for completion. This function owns its own wall-clock retry budget
    since it runs inside a scheduler job thread, not a request handler.
    """
    if since_seqno:
        query = f"(seqno gt '{int(since_seqno)}')"
    elif since_time:
        query = f"(receive_time geq '{since_time.strftime('%Y/%m/%d %H:%M:%S')}')"
    else:
        query = None

    params = {"type": "log", "log-type": "threat", "key": api_key, "nlogs": str(limit)}
    if query:
        params["query"] = query

    root, err = _request(hostname, params, verify_ssl, timeout)
    if err:
        return {"error": err}

    job_el = root.find(".//job")
    if job_el is None or not job_el.text:
        return {"error": "PAN-OS did not return a log query job id"}
    job_id = job_el.text.strip()

    deadline = time.monotonic() + max_wait_seconds
    while True:
        root, err = _request(
            hostname, {"type": "log", "action": "get", "job-id": job_id, "key": api_key},
            verify_ssl, timeout,
        )
        if err:
            return {"error": err}

        status_el = root.find(".//job/status")
        status = status_el.text.strip() if status_el is not None and status_el.text else ""

        if status == "FIN":
            break
        if status in ("FAIL", "ERR"):
            return {"error": f"PAN-OS log query job failed (job-id={job_id})"}
        if time.monotonic() >= deadline:
            return {"error": f"PAN-OS log query timed out waiting for job-id={job_id}"}
        time.sleep(poll_interval_seconds)

    logs = []
    for entry in root.findall(".//log/logs/entry"):
        parsed = _parse_entry(entry)
        if parsed:
            logs.append(parsed)
    return {"logs": logs, "count": len(logs)}
