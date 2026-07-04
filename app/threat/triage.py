from . import pulsedrive, internetdb as idb_mod, virustotal as vt_mod


def run(ip, cfg=None, vt_key=None):
    """Query pulseDrive (ThreatMiner/URLhaus/Criminal IP) + InternetDB + VirusTotal
    for an IP and return a unified triage dict."""
    pd  = pulsedrive.enrich_ip(ip, cfg) if cfg else {}
    idb = idb_mod.lookup(ip)
    vt  = vt_mod.lookup(ip, "ip", vt_key) if vt_key else None
    v   = verdict(pd, vt)
    return {"ip": ip, "pd": pd, "idb": idb, "vt": vt, "verdict": v}


def verdict(pd, vt):
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

    if vt and not vt.get("error") and not vt.get("not_found"):
        malicious = vt.get("malicious", 0)
        if malicious >= 5:
            return {"label": "ESCALATE",   "level": "danger",
                    "reason": f"VirusTotal: {malicious} engine(s) flagged as malicious"}
        if malicious > 0:
            return {"label": "INVESTIGATE", "level": "warning",
                    "reason": f"VirusTotal: {malicious} engine(s) detected — low confidence"}

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
