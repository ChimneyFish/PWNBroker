import requests

_BASE = "https://internetdb.shodan.io"


def lookup(ip):
    """
    Query Shodan InternetDB — free, no API key required.

    Returns open ports, hostnames, CPEs, known CVEs, and tags for an IP.
    404 means Shodan has no data for this IP (private/unscanned).
    """
    try:
        r = requests.get(f"{_BASE}/{ip}", timeout=12)
        if r.status_code == 404:
            return {"no_data": True, "ports": [], "hostnames": [],
                    "cpes": [], "vulns": [], "tags": []}
        r.raise_for_status()
        d = r.json()
    except requests.exceptions.HTTPError as e:
        return {"error": f"InternetDB HTTP {e.response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

    return {
        "no_data":   False,
        "ports":     sorted(d.get("ports", [])),
        "hostnames": d.get("hostnames", []),
        "cpes":      d.get("cpes", []),
        "vulns":     sorted(d.get("vulns", [])),
        "tags":      d.get("tags", []),
    }
