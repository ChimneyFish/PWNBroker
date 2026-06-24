import re
import nmap
from typing import List, Dict, Tuple

_CIDR_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$')

# Common web/service ports used when doing a fast secondary scan of subdomains
WEB_PORTS = "21,22,25,53,80,443,8080,8443,8000,3000,3306,5432,6379,9000,9200"


def _parse_hosts(nm) -> Tuple[List[Dict], Dict]:
    """Extract port results and host metadata from a completed nmap scan."""
    port_results = []
    host_metadata = {}

    for scanned_host in nm.all_hosts():
        info = nm[scanned_host]

        hostname = info.hostname() or None

        os_name = None
        osmatch = info.get("osmatch", [])
        if osmatch:
            os_name = osmatch[0].get("name")

        host_metadata[scanned_host] = {"hostname": hostname, "os_name": os_name}

        for proto in info.all_protocols():
            for port in info[proto].keys():
                port_data = info[proto][port]
                if port_data["state"] != "open":
                    continue
                port_results.append({
                    "host":      scanned_host,
                    "port":      port,
                    "protocol":  proto,
                    "state":     port_data["state"],
                    "service":   port_data.get("name", "unknown"),
                    "version":   port_data.get("version", ""),
                    "product":   port_data.get("product", ""),
                    "extrainfo": port_data.get("extrainfo", ""),
                    "cpe":       port_data.get("cpe", ""),
                    "scripts":   port_data.get("script", {}),
                })

    return port_results, host_metadata


def run_port_scan(host: str, port_range: str = "1-1024") -> Tuple[List[Dict], Dict]:
    """
    Full port + service + OS scan for a single host.
    For CIDR ranges, uses a faster mode (skips OS detection and NSE scripts).
    Returns (port_results, host_metadata).
    """
    nm = nmap.PortScanner()
    is_subnet = bool(_CIDR_RE.match(host.strip()))

    # Subnet scans skip OS detection and heavy NSE scripts — far too slow across many hosts
    if is_subnet:
        args = "-sV --open -T4"
    else:
        args = "-sV -sC -O --osscan-guess --open -T4"

    try:
        nm.scan(hosts=host, ports=port_range, arguments=args)
    except Exception as e:
        return [{"error": str(e)}], {}

    return _parse_hosts(nm)


def run_web_port_scan(host: str) -> Tuple[List[Dict], Dict]:
    """
    Fast scan of common web/service ports for subdomain secondary scans.
    No OS detection or scripting — just banner-grab the open ports quickly.
    """
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=host, ports=WEB_PORTS, arguments="-sV --open -T4")
    except Exception as e:
        return [{"error": str(e)}], {}

    return _parse_hosts(nm)


def run_os_detection(host: str) -> Dict:
    """Kept for backward compatibility; prefer run_port_scan which includes OS."""
    _, meta = run_port_scan(host, port_range="22-443")
    return next(iter(meta.values()), {})
