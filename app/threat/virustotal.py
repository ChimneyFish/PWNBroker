import base64
import requests

_BASE = "https://www.virustotal.com/api/v3"


def lookup(indicator, ioc_type, api_key):
    """Query VirusTotal. ioc_type: ip | domain | url | hash"""
    headers = {"x-apikey": api_key}

    if ioc_type == "ip":
        url = f"{_BASE}/ip_addresses/{indicator}"
    elif ioc_type == "domain":
        url = f"{_BASE}/domains/{indicator}"
    elif ioc_type == "url":
        url_id = base64.urlsafe_b64encode(indicator.encode()).decode().rstrip("=")
        url = f"{_BASE}/urls/{url_id}"
    elif ioc_type == "hash":
        url = f"{_BASE}/files/{indicator}"
    else:
        return {"error": f"Unsupported IOC type: {ioc_type}"}

    try:
        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code == 404:
            return {"verdict": "unknown", "threat_score": 0, "not_found": True,
                    "malicious": 0, "suspicious": 0, "total_engines": 0}
        r.raise_for_status()
        data = r.json()
    except requests.exceptions.HTTPError as e:
        return {"error": f"HTTP {e.response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)
    harmless   = stats.get("harmless", 0)
    total = malicious + suspicious + undetected + harmless

    if total:
        threat_score = int((malicious + suspicious * 0.5) / total * 100)
    else:
        threat_score = 0

    if malicious >= 5:
        verdict = "malicious"
    elif malicious > 0 or suspicious > 0:
        verdict = "suspicious"
    else:
        verdict = "clean"

    # Top detections for display
    engines = attrs.get("last_analysis_results", {})
    detections = [
        {"engine": name, "result": info.get("result", ""), "category": info.get("category", "")}
        for name, info in engines.items()
        if info.get("category") in ("malicious", "suspicious")
    ][:10]

    return {
        "malicious": malicious,
        "suspicious": suspicious,
        "undetected": undetected,
        "harmless": harmless,
        "total_engines": total,
        "threat_score": threat_score,
        "verdict": verdict,
        "reputation": attrs.get("reputation", 0),
        "country": attrs.get("country", ""),
        "tags": attrs.get("tags", [])[:10],
        "detections": detections,
        "not_found": False,
    }
