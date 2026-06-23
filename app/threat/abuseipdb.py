import requests

_BASE = "https://api.abuseipdb.com/api/v2"


def check_ip(ip, api_key, max_age_days=90):
    """Check an IP against AbuseIPDB."""
    headers = {"Key": api_key, "Accept": "application/json"}
    params  = {"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": True}
    try:
        r = requests.get(f"{_BASE}/check", headers=headers, params=params, timeout=12)
        r.raise_for_status()
        d = r.json().get("data", {})
    except requests.exceptions.HTTPError as e:
        return {"error": f"HTTP {e.response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

    confidence = d.get("abuseConfidenceScore", 0)
    reports    = d.get("totalReports", 0)

    if confidence >= 50:
        verdict = "malicious"
    elif confidence >= 20:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return {
        "confidence_score": confidence,
        "total_reports": reports,
        "country_code": d.get("countryCode", ""),
        "isp": d.get("isp", ""),
        "usage_type": d.get("usageType", ""),
        "domain": d.get("domain", ""),
        "is_tor": d.get("isTor", False),
        "is_whitelisted": d.get("isWhitelisted", False),
        "last_reported": d.get("lastReportedAt", ""),
        "verdict": verdict,
        "threat_score": confidence,
    }


def report_ip(ip, categories, comment, api_key):
    """Report an abusive IP."""
    headers = {"Key": api_key, "Accept": "application/json"}
    payload = {"ip": ip, "categories": ",".join(str(c) for c in categories), "comment": comment}
    try:
        r = requests.post(f"{_BASE}/report", headers=headers, data=payload, timeout=12)
        r.raise_for_status()
        return {"success": True, "data": r.json().get("data", {})}
    except Exception as e:
        return {"success": False, "error": str(e)}
