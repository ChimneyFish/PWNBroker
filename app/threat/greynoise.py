import requests

_COMMUNITY = "https://api.greynoise.io/v3/community"


def lookup(ip, api_key):
    """
    Query GreyNoise Community API for an IP.

    Key fields returned:
      noise       - bool: IP is actively scanning the internet
      riot        - bool: IP belongs to a well-known benign service (Google, AWS, etc.)
      classification - 'malicious' | 'benign' | 'unknown'
      name        - human-readable entity name when riot=True
      last_seen   - ISO date string
    """
    headers = {"key": api_key}
    try:
        r = requests.get(f"{_COMMUNITY}/{ip}", headers=headers, timeout=12)
        if r.status_code == 404:
            # IP not seen by GreyNoise at all
            return {"noise": False, "riot": False, "classification": "unknown",
                    "name": "", "last_seen": "", "not_seen": True}
        if r.status_code == 401:
            return {"error": "GreyNoise: invalid API key"}
        if r.status_code == 429:
            return {"error": "GreyNoise: rate limit exceeded"}
        r.raise_for_status()
        d = r.json()
    except requests.exceptions.HTTPError as e:
        return {"error": f"GreyNoise HTTP {e.response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

    return {
        "noise":          d.get("noise", False),
        "riot":           d.get("riot", False),
        "classification": d.get("classification", "unknown"),
        "name":           d.get("name", ""),
        "last_seen":      d.get("last_seen", ""),
        "message":        d.get("message", ""),
        "link":           d.get("link", ""),
        "not_seen":       False,
    }
