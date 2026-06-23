import nmap
from typing import List, Dict, Tuple


def run_port_scan(host: str, port_range: str = "1-1024") -> Tuple[List[Dict], Dict]:
    """
    Returns (port_results, host_metadata).
    host_metadata is keyed by IP: {hostname, os_name, os_accuracy}
    Combined port scan + OS detection + hostname resolution in one nmap call.
    """
    nm = nmap.PortScanner()
    port_results = []
    host_metadata = {}
    try:
        nm.scan(hosts=host, ports=port_range,
                arguments="-sV -sC -O --osscan-guess --open -T4")
    except Exception as e:
        return [{"error": str(e)}], {}

    for scanned_host in nm.all_hosts():
        info = nm[scanned_host]

        # Hostname from reverse DNS
        hostname = info.hostname() or None

        # OS detection
        os_name = None
        osmatch = info.get("osmatch", [])
        if osmatch:
            best    = osmatch[0]
            os_name = best.get("name")

        host_metadata[scanned_host] = {
            "hostname": hostname,
            "os_name":  os_name,
        }

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


def run_os_detection(host: str) -> Dict:
    """Kept for backward compatibility; prefer run_port_scan which includes OS."""
    _, meta = run_port_scan(host, port_range="22-443")
    return next(iter(meta.values()), {})
