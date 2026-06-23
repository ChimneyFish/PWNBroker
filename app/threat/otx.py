import requests

_BASE = "https://otx.alienvault.com/api/v1"


def lookup(indicator, ioc_type, api_key):
    """Query OTX for an indicator. ioc_type: ip | domain | url | hash"""
    endpoint_map = {
        "ip":     f"{_BASE}/indicators/IPv4/{indicator}/general",
        "domain": f"{_BASE}/indicators/domain/{indicator}/general",
        "url":    f"{_BASE}/indicators/url/{indicator}/general",
        "hash":   f"{_BASE}/indicators/file/{indicator}/general",
    }
    url = endpoint_map.get(ioc_type)
    if not url:
        return {"error": f"Unsupported IOC type: {ioc_type}"}

    headers = {"X-OTX-API-KEY": api_key}
    try:
        r = requests.get(url, headers=headers, timeout=12)
        r.raise_for_status()
        data = r.json()
    except requests.exceptions.HTTPError as e:
        return {"error": f"HTTP {e.response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

    pulse_info = data.get("pulse_info", {})
    pulse_count = pulse_info.get("count", 0)

    tags, malware_families = [], []
    pulses_detail = []
    for pulse in pulse_info.get("pulses", [])[:25]:
        for t in pulse.get("tags", []):
            if isinstance(t, str):
                tags.append(t)
        for mf in pulse.get("malware_families", []):
            name = mf.get("display_name") or mf.get("id") if isinstance(mf, dict) else str(mf)
            if name:
                malware_families.append(name)

        mf_names = []
        for mf in pulse.get("malware_families", []):
            n = mf.get("display_name") or mf.get("id") if isinstance(mf, dict) else str(mf)
            if n:
                mf_names.append(n)

        pulses_detail.append({
            "id":          pulse.get("id", ""),
            "name":        pulse.get("name", ""),
            "description": (pulse.get("description") or "")[:300],
            "author":      pulse.get("author_name", ""),
            "created":     (pulse.get("created") or "")[:10],
            "tags":        [t for t in pulse.get("tags", []) if isinstance(t, str)][:10],
            "malware":     mf_names[:5],
            "references":  [r for r in pulse.get("references", []) if isinstance(r, str)][:5],
        })

    tags = list(dict.fromkeys(tags))[:15]
    malware_families = list(dict.fromkeys(malware_families))[:8]

    threat_score = min(pulse_count * 10, 100)
    if pulse_count >= 5:
        verdict = "malicious"
    elif pulse_count > 0:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return {
        "pulse_count": pulse_count,
        "threat_score": threat_score,
        "tags": tags,
        "malware_families": malware_families,
        "pulses": pulses_detail,
        "verdict": verdict,
        "country": data.get("country_name", ""),
        "asn": data.get("asn", ""),
        "reputation": data.get("reputation", 0),
    }


def get_pulses(api_key, limit=30):
    """Fetch recent subscribed OTX pulses."""
    headers = {"X-OTX-API-KEY": api_key}
    try:
        r = requests.get(f"{_BASE}/pulses/subscribed",
                         headers=headers, params={"limit": limit}, timeout=15)
        r.raise_for_status()
        data = r.json()
        return data.get("results", [])
    except Exception as e:
        raise RuntimeError(f"OTX feed error: {e}")
