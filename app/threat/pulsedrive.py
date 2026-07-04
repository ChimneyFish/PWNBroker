"""
pulseDrive — consolidated threat-intel API layer.

Replaces GreyNoise as the home for lightweight IP/domain/hash/CVE
enrichment sources. Each *_lookup() function follows the same contract as
the other app/threat/ modules: a normalized dict on success, or
{"error": "..."} on failure — never raises into callers.
"""
import requests

_THREATMINER_BASE = "https://api.threatminer.org/v2"
_URLHAUS_BASE      = "https://urlhaus-api.abuse.ch/v1"
_CRIMINALIP_BASE   = "https://api.criminalip.io/v1"
_VULNERS_BASE      = "https://vulners.com/api/v3"
_CIRCL_BASE        = "https://cve.circl.lu/api"
_HYBRID_BASE       = "https://hybrid-analysis.com/api/v2"
_PHISHTANK_URL     = "http://checkurl.phishtank.com/checkurl/"


# ── ThreatMiner (keyless, IP/domain/hash) ──────────────────────────────────

def threatminer_lookup(indicator, ioc_type):
    """Query ThreatMiner. ioc_type: ip | domain | hash. No API key required."""
    endpoint_map = {
        "ip":     f"{_THREATMINER_BASE}/host.php",
        "domain": f"{_THREATMINER_BASE}/domain.php",
        "hash":   f"{_THREATMINER_BASE}/sample.php",
    }
    url = endpoint_map.get(ioc_type)
    if not url:
        return {"error": f"ThreatMiner does not support IOC type: {ioc_type}"}

    def _rt(report_type):
        try:
            r = requests.get(url, params={"q": indicator, "rt": report_type}, timeout=12)
            r.raise_for_status()
            d = r.json()
            return d.get("results", []) if d.get("status_code") == "200" else []
        except Exception:
            return []

    # rt=2 is passive DNS for host/domain, AV detections (rt=6) for hash
    if ioc_type == "hash":
        detections = _rt(6)
        tags       = _rt(7)
        return {
            "av_detections": detections[:15],
            "tags":          [t.get("name", "") for t in tags if isinstance(t, dict)][:10],
            "verdict":       "suspicious" if detections else "unknown",
        }

    passive_dns = _rt(2)
    tags        = _rt(6)
    return {
        "passive_dns": [
            {"ip": p.get("ip", ""), "domain": p.get("domain", ""),
             "first_seen": p.get("first_seen", ""), "last_seen": p.get("last_seen", "")}
            for p in passive_dns[:10]
        ],
        "tags":    [t.get("name", "") for t in tags if isinstance(t, dict)][:10],
        "verdict": "suspicious" if tags else "unknown",
    }


# ── PhishTank (free, optional key for higher rate limit) ──────────────────

def phishtank_lookup(url, api_key=None):
    """Check a URL against PhishTank's phishing database."""
    data = {"url": url, "format": "json"}
    if api_key:
        data["app_key"] = api_key
    headers = {"User-Agent": "PwnBroker/pulseDrive"}
    try:
        r = requests.post(_PHISHTANK_URL, data=data, headers=headers, timeout=12)
        r.raise_for_status()
        results = r.json().get("results", {})
    except Exception as e:
        return {"error": str(e)}

    in_db    = results.get("in_database", False)
    verified = results.get("verified", False)
    valid    = results.get("valid", False)

    if in_db and verified and valid:
        verdict = "malicious"
    elif in_db:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return {
        "in_database":       in_db,
        "verified":          verified,
        "valid":             valid,
        "phish_id":          results.get("phish_id", ""),
        "phish_detail_page": results.get("phish_detail_page", ""),
        "verdict":           verdict,
    }


# ── URLhaus (abuse.ch, requires free Auth-Key) ─────────────────────────────

def urlhaus_lookup(indicator, ioc_type, api_key):
    """Query URLhaus. ioc_type: url | domain | ip (domain/ip use the host endpoint)."""
    if not api_key:
        return {"error": "URLhaus: API key not configured"}
    headers = {"Auth-Key": api_key}
    if ioc_type == "url":
        endpoint, param = f"{_URLHAUS_BASE}/url/", "url"
    elif ioc_type in ("domain", "ip"):
        endpoint, param = f"{_URLHAUS_BASE}/host/", "host"
    else:
        return {"error": f"URLhaus does not support IOC type: {ioc_type}"}

    try:
        r = requests.post(endpoint, headers=headers, data={param: indicator}, timeout=12)
        r.raise_for_status()
        d = r.json()
    except requests.exceptions.HTTPError as e:
        return {"error": f"HTTP {e.response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

    status = d.get("query_status", "")
    if status == "no_results":
        return {"found": False, "verdict": "clean", "url_count": 0}
    if status != "ok":
        return {"error": f"URLhaus: {status}"}

    urls = d.get("urls", [])
    url_count = d.get("url_count", len(urls))
    return {
        "found":      True,
        "verdict":    "malicious" if (url_count or d.get("url_status")) else "clean",
        "url_status": d.get("url_status", ""),
        "url_count":  url_count,
        "threat":     d.get("threat", ""),
        "date_added": d.get("date_added", d.get("firstseen", "")),
        "tags":       d.get("tags", []) or [],
        "urls":       [
            {"url": u.get("url", ""), "url_status": u.get("url_status", ""),
             "date_added": u.get("date_added", "")}
            for u in urls[:10]
        ],
    }


# ── Criminal IP (requires free-tier x-api-key) ─────────────────────────────

def criminalip_lookup(ip, api_key):
    """Query Criminal IP for IP reputation/risk data."""
    if not api_key:
        return {"error": "Criminal IP: API key not configured"}
    headers = {"x-api-key": api_key}
    try:
        r = requests.get(f"{_CRIMINALIP_BASE}/ip/data",
                         headers=headers, params={"ip": ip, "full": "true"}, timeout=12)
        if r.status_code == 401:
            return {"error": "Criminal IP: invalid API key"}
        r.raise_for_status()
        d = r.json()
    except requests.exceptions.HTTPError as e:
        return {"error": f"HTTP {e.response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

    score   = (d.get("score") or {})
    is_vpn  = bool(d.get("is_vpn", False))
    is_scan = bool(d.get("is_scanner", False))
    inbound = (score.get("inbound") or "").lower()

    if inbound in ("critical", "dangerous"):
        verdict = "malicious"
    elif inbound in ("moderate",) or is_scan:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return {
        "verdict":     verdict,
        "risk_score":  inbound or "unknown",
        "is_vpn":      is_vpn,
        "is_scanner":  is_scan,
        "is_tor":      bool(d.get("is_tor", False)),
        "open_ports":  [p.get("port") for p in (d.get("port") or {}).get("data", [])][:20],
        "country":     d.get("country", ""),
    }


# ── Vulners (CVE search, requires free-tier X-Api-Key) ─────────────────────

def vulners_lookup(cve_id, api_key):
    """Fetch a CVE record from Vulners."""
    if not api_key:
        return {"error": "Vulners: API key not configured"}
    headers = {"X-Api-Key": api_key, "Content-Type": "application/json"}
    try:
        r = requests.post(f"{_VULNERS_BASE}/search/id",
                          headers=headers, json={"id": cve_id}, timeout=12)
        if r.status_code == 401:
            return {"error": "Vulners: invalid API key"}
        r.raise_for_status()
        d = r.json()
    except requests.exceptions.HTTPError as e:
        return {"error": f"HTTP {e.response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

    doc = ((d.get("data") or {}).get("documents") or {}).get(cve_id, {})
    if not doc:
        return {"found": False, "verdict": "unknown"}

    cvss   = doc.get("cvss", {}) or {}
    score  = cvss.get("score", 0)
    return {
        "found":       True,
        "title":       doc.get("title", ""),
        "description": (doc.get("description") or "")[:500],
        "cvss_score":  score,
        "verdict":     "malicious" if score >= 7 else ("suspicious" if score >= 4 else "clean"),
        "published":   doc.get("published", ""),
        "references":  (doc.get("references") or [])[:8],
    }


# ── CVE-Search (CIRCL, keyless) ─────────────────────────────────────────────

def _extract_cvss(metrics_lists):
    """Search CVE Record v5.1 metrics arrays for the highest CVSS baseScore found."""
    best = 0.0
    for metrics in metrics_lists:
        for m in metrics or []:
            for key in ("cvssV3_1", "cvssV3_0", "cvssV2_0"):
                score = (m.get(key) or {}).get("baseScore")
                if isinstance(score, (int, float)):
                    best = max(best, float(score))
    return best


def cve_search_lookup(cve_id):
    """Fetch a CVE record from CIRCL's public cve-search / Vulnerability-Lookup API.

    CIRCL now serves the raw CVE Record v5.1 JSON schema rather than the old
    flattened cve-search format, so this parses containers.cna/adp directly.
    """
    try:
        r = requests.get(f"{_CIRCL_BASE}/cve/{cve_id}", timeout=12)
        if r.status_code == 404:
            return {"found": False, "verdict": "unknown"}
        r.raise_for_status()
        d = r.json()
    except requests.exceptions.HTTPError as e:
        return {"error": f"HTTP {e.response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

    if not d:
        return {"found": False, "verdict": "unknown"}

    containers = d.get("containers", {}) or {}
    cna        = containers.get("cna", {}) or {}
    adp        = containers.get("adp", []) or []

    descriptions = cna.get("descriptions", []) or []
    summary = next((desc.get("value", "") for desc in descriptions if desc.get("lang", "").startswith("en")),
                    descriptions[0].get("value", "") if descriptions else "")

    cvss = _extract_cvss([cna.get("metrics", [])] + [a.get("metrics", []) for a in adp])

    references = [ref.get("url", "") for ref in cna.get("references", []) if ref.get("url")]

    return {
        "found":       True,
        "summary":     summary[:500],
        "cvss_score":  cvss,
        "verdict":     "malicious" if cvss >= 7 else ("suspicious" if cvss >= 4 else "clean"),
        "published":   (d.get("cveMetadata", {}) or {}).get("datePublished", ""),
        "references":  references[:8],
    }


# ── Hybrid Analysis (hash lookup only — submission/detonation is async) ────

def hybridanalysis_lookup(file_hash, api_key):
    """Search Hybrid Analysis's Falcon Sandbox reports for a file hash."""
    if not api_key:
        return {"error": "Hybrid Analysis: API key not configured"}
    headers = {"api-key": api_key, "User-Agent": "Falcon Sandbox",
               "Accept": "application/json"}
    try:
        r = requests.get(f"{_HYBRID_BASE}/search/hash",
                         headers=headers, params={"hash": file_hash}, timeout=15)
        if r.status_code == 401:
            return {"error": "Hybrid Analysis: invalid API key"}
        r.raise_for_status()
        results = r.json()
    except requests.exceptions.HTTPError as e:
        return {"error": f"HTTP {e.response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

    if not results:
        return {"found": False, "verdict": "unknown"}

    top = results[0]
    verdict_raw = (top.get("verdict") or "").lower()
    verdict = {"malicious": "malicious", "suspicious": "suspicious"}.get(verdict_raw, "clean")

    return {
        "found":         True,
        "verdict":       verdict,
        "threat_score":  top.get("threat_score", 0),
        "av_detect":     top.get("av_detect", 0),
        "environment":   top.get("environment_description", ""),
        "submit_name":   top.get("submit_name", ""),
        "report_url":    f"https://hybrid-analysis.com/sample/{top.get('sha256', '')}"
                          if top.get("sha256") else "",
    }


# ── SOCRadar — not wired up: no publicly documented endpoint ──────────────

def socradar_lookup(*args, **kwargs):
    """SOCRadar's IOC/reputation API is customer-portal-only — no public,
    self-serve endpoint exists to build against. The settings key field is
    ready; this returns a clear error until a real endpoint URL is supplied."""
    return {"error": "SOCRadar lookup not implemented — no public API endpoint documented. "
                      "Provide the endpoint URL from your SOCRadar account portal to enable this."}


# ── Dispatchers ─────────────────────────────────────────────────────────────

def enrich_ip(ip, cfg):
    """Aggregate pulseDrive IP signals — replaces GreyNoise's role in triage."""
    out = {}
    out["threatminer"] = threatminer_lookup(ip, "ip")
    if getattr(cfg, "urlhaus_api_key", None):
        out["urlhaus"] = urlhaus_lookup(ip, "ip", cfg.urlhaus_api_key)
    if getattr(cfg, "criminalip_api_key", None):
        out["criminalip"] = criminalip_lookup(ip, cfg.criminalip_api_key)
    return out


def enrich_cve(cve_id, cfg):
    """Aggregate pulseDrive CVE-enrichment signals."""
    out = {"cve_search": cve_search_lookup(cve_id)}
    if getattr(cfg, "vulners_api_key", None):
        out["vulners"] = vulners_lookup(cve_id, cfg.vulners_api_key)
    return out
