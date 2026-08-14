from . import pulsedrive, internetdb as idb_mod


def run(ip, cfg=None):
    """Query pulseDrive (ThreatMiner/URLhaus/Criminal IP) + Shodan InternetDB
    for an IP and return a unified triage dict."""
    pd  = pulsedrive.enrich_ip(ip, cfg) if cfg else {}
    idb = idb_mod.lookup(ip)
    v   = verdict(pd)
    return {"ip": ip, "pd": pd, "idb": idb, "verdict": v}


def verdict(pd):
    """
    Returns dict with keys: label, level, reason.
    Labels: NOISE | INVESTIGATE | ESCALATE
    """
    pd   = pd or {}
    crim = pd.get("criminalip") or {}
    urlh = pd.get("urlhaus") or {}
    tm   = pd.get("threatminer") or {}

    if crim and not crim.get("error") and crim.get("risk_score") in ("critical", "dangerous"):
        return {"label": "ESCALATE",   "level": "danger",
                "reason": f"Criminal IP: {crim.get('risk_score')} risk score"}

    if urlh and not urlh.get("error") and urlh.get("found") and urlh.get("url_count", 0) > 0:
        return {"label": "ESCALATE",   "level": "danger",
                "reason": f"URLhaus: {urlh.get('url_count')} malicious URL(s) hosted on this IP"}

    if crim and not crim.get("error") and (crim.get("is_scanner") or crim.get("is_vpn")):
        return {"label": "NOISE",      "level": "info",
                "reason": "Criminal IP: known scanner/VPN infrastructure"}

    if tm and not tm.get("error") and tm.get("tags"):
        return {"label": "INVESTIGATE", "level": "warning",
                "reason": f"ThreatMiner: tagged ({', '.join(tm['tags'][:3])})"}

    return {"label": "INVESTIGATE", "level": "warning",
            "reason": "No definitive signal — manual review recommended"}


# Severity mapping for ScanResult storage
_VERDICT_SEVERITY = {
    "ESCALATE":   "high",
    "INVESTIGATE": "medium",
    "NOISE":      "low",
    "DISMISS":    "info",
}


def severity_for(verdict_label):
    return _VERDICT_SEVERITY.get(verdict_label, "info")
