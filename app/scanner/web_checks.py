import requests
import ssl
import socket
import urllib3
from datetime import datetime, timezone
from typing import List, Dict
from urllib.parse import urlparse

SECURITY_HEADERS = [
    ("Strict-Transport-Security", "HSTS missing — site vulnerable to downgrade attacks"),
    ("Content-Security-Policy", "CSP missing — XSS risk elevated"),
    ("X-Frame-Options", "Clickjacking protection missing"),
    ("X-Content-Type-Options", "MIME sniffing protection missing"),
    ("Referrer-Policy", "Referrer-Policy header missing"),
    ("Permissions-Policy", "Permissions-Policy header missing"),
]


def run_web_checks(host: str) -> List[Dict]:
    findings = []
    targets = _build_urls(host)

    for url in targets:
        findings.extend(_check_headers(url))
        findings.extend(_check_ssl(url))

    return findings


def _build_urls(host: str) -> List[str]:
    if host.startswith("http://") or host.startswith("https://"):
        return [host]
    return [f"https://{host}", f"http://{host}"]


def _check_headers(url: str) -> List[Dict]:
    findings = []
    try:
        with urllib3.warnings.catch_warnings():
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            resp = requests.get(url, timeout=10, verify=False, allow_redirects=True)
    except Exception as e:
        return [_finding("web_check", url, "low", "Connection Failed",
                         f"Could not connect to {url}: {e}")]

    for header, message in SECURITY_HEADERS:
        if header not in resp.headers:
            findings.append(_finding("web_check", url, "medium", f"Missing Header: {header}", message))

    server = resp.headers.get("Server", "")
    if server:
        findings.append(_finding("web_check", url, "low", "Server Header Exposed",
                                 f"Server header reveals: {server}. Consider removing to reduce fingerprinting."))

    x_powered = resp.headers.get("X-Powered-By", "")
    if x_powered:
        findings.append(_finding("web_check", url, "low", "X-Powered-By Header Exposed",
                                 f"X-Powered-By reveals: {x_powered}."))

    if resp.status_code in (401, 403) and url.endswith("/"):
        pass
    elif resp.status_code >= 500:
        findings.append(_finding("web_check", url, "low", f"HTTP {resp.status_code} Response",
                                 "Server returned a 5xx error — possible instability or misconfiguration."))

    return findings


def _check_ssl(url: str) -> List[Dict]:
    if not url.startswith("https://"):
        return []

    findings = []
    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or 443

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()

        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (not_after - datetime.now(timezone.utc)).days

        if days_left < 0:
            findings.append(_finding("web_check", url, "critical", "SSL Certificate Expired",
                                     f"Certificate expired {abs(days_left)} days ago."))
        elif days_left < 14:
            findings.append(_finding("web_check", url, "high", "SSL Certificate Expiring Soon",
                                     f"Certificate expires in {days_left} days."))
        elif days_left < 30:
            findings.append(_finding("web_check", url, "medium", "SSL Certificate Expiring",
                                     f"Certificate expires in {days_left} days."))

        if protocol in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
            findings.append(_finding("web_check", url, "high", f"Weak TLS Protocol: {protocol}",
                                     "Use TLS 1.2 or 1.3 only."))

    except ssl.SSLCertVerificationError as e:
        findings.append(_finding("web_check", url, "high", "SSL Certificate Invalid", str(e)))
    except Exception:
        pass

    return findings


def _finding(result_type, host, severity, title, description, remediation="") -> Dict:
    return {
        "result_type": result_type,
        "host": host,
        "severity": severity,
        "title": title,
        "description": description,
        "remediation": remediation,
    }
