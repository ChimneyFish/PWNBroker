from . import greynoise as gn_mod, internetdb as idb_mod, virustotal as vt_mod


def run(ip, greynoise_key=None, vt_key=None):
    """Query GreyNoise + InternetDB + VirusTotal for an IP and return a unified triage dict."""
    gn  = gn_mod.lookup(ip, greynoise_key) if greynoise_key else None
    idb = idb_mod.lookup(ip)
    vt  = vt_mod.lookup(ip, "ip", vt_key)  if vt_key        else None
    v   = verdict(gn, vt)
    return {"ip": ip, "gn": gn, "idb": idb, "vt": vt, "verdict": v}


def verdict(gn, vt):
    """
    Returns dict with keys: label, level, reason.
    Labels: DISMISS | NOISE | INVESTIGATE | ESCALATE
    """
    if gn and not gn.get("error") and gn.get("riot"):
        return {"label": "DISMISS",    "level": "success",
                "reason": f"RIOT: known benign infrastructure ({gn.get('name', 'known service')})"}

    if gn and not gn.get("error") and gn.get("noise") and gn.get("classification") == "malicious":
        return {"label": "ESCALATE",   "level": "danger",
                "reason": "GreyNoise: known malicious internet scanner"}

    if vt and not vt.get("error") and not vt.get("not_found"):
        malicious = vt.get("malicious", 0)
        if malicious >= 5:
            return {"label": "ESCALATE",   "level": "danger",
                    "reason": f"VirusTotal: {malicious} engine(s) flagged as malicious"}
        if malicious > 0:
            return {"label": "INVESTIGATE", "level": "warning",
                    "reason": f"VirusTotal: {malicious} engine(s) detected — low confidence"}

    if gn and not gn.get("error") and gn.get("noise") and gn.get("classification") == "benign":
        return {"label": "NOISE",      "level": "info",
                "reason": "GreyNoise: benign internet scanner (research/crawler)"}

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
