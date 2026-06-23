import json
import re
import ipaddress
from datetime import datetime, timezone, timedelta
from ..extensions import db

_IP_RE     = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
_HASH_RE   = re.compile(r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$')
_DOMAIN_RE = re.compile(r'^(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}$')


def detect_type(indicator):
    s = indicator.strip()
    if _IP_RE.match(s):
        return "ip"
    if _HASH_RE.match(s):
        return "hash"
    if s.startswith("http://") or s.startswith("https://"):
        return "url"
    if _DOMAIN_RE.match(s):
        return "domain"
    return None


def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return True


def lookup(indicator, cfg, user_id=None, force=False):
    from ..models import IOCRecord
    from . import otx, virustotal, abuseipdb

    indicator = indicator.strip()
    ioc_type  = detect_type(indicator)
    if not ioc_type:
        return {"error": "Cannot determine IOC type. Provide an IP, domain, URL, or file hash."}

    now = datetime.now(timezone.utc)

    if not force:
        cached = IOCRecord.query.filter_by(indicator=indicator).first()
        if cached and cached.expires_at:
            exp = cached.expires_at
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if exp > now:
                return _format_record(cached)

    scores, verdicts = [], []

    otx_result = None
    if cfg.otx_api_key:
        otx_result = otx.lookup(indicator, ioc_type, cfg.otx_api_key)
        if otx_result and "error" not in otx_result:
            scores.append(otx_result.get("threat_score", 0))
            verdicts.append(otx_result.get("verdict", "clean"))

    vt_result = None
    if cfg.virustotal_api_key:
        vt_result = virustotal.lookup(indicator, ioc_type, cfg.virustotal_api_key)
        if vt_result and "error" not in vt_result:
            scores.append(vt_result.get("threat_score", 0))
            verdicts.append(vt_result.get("verdict", "clean"))

    abuse_result = None
    if ioc_type == "ip" and cfg.abuseipdb_api_key:
        abuse_result = abuseipdb.check_ip(indicator, cfg.abuseipdb_api_key)
        if abuse_result and "error" not in abuse_result:
            scores.append(abuse_result.get("threat_score", 0))
            verdicts.append(abuse_result.get("verdict", "clean"))

    overall_score = int(sum(scores) / len(scores)) if scores else 0
    if "malicious" in verdicts:
        overall_verdict = "malicious"
    elif "suspicious" in verdicts:
        overall_verdict = "suspicious"
    else:
        overall_verdict = "clean" if scores else "unknown"

    record = IOCRecord.query.filter_by(indicator=indicator).first() or IOCRecord()
    record.indicator        = indicator
    record.ioc_type         = ioc_type
    record.threat_score     = overall_score
    record.verdict          = overall_verdict
    record.otx_result       = json.dumps(otx_result)    if otx_result    else None
    record.vt_result        = json.dumps(vt_result)     if vt_result     else None
    record.abuseipdb_result = json.dumps(abuse_result)  if abuse_result  else None
    record.looked_up_by     = user_id
    record.created_at       = now
    record.expires_at       = now + timedelta(hours=24)
    db.session.add(record)
    db.session.commit()

    _maybe_queue_triage(record)

    return _format_record(record)


def _maybe_queue_triage(record):
    """If ≥2 sources flag this IOC as suspicious/malicious, queue it for SOC Triage."""
    from ..models import SocCase
    flagging = []
    for field, source in [
        (record.vt_result,        "VirusTotal"),
        (record.otx_result,       "OTX"),
        (record.abuseipdb_result, "AbuseIPDB"),
    ]:
        if field:
            try:
                if json.loads(field).get("verdict") in ("suspicious", "malicious"):
                    flagging.append(source)
            except Exception:
                pass

    if len(flagging) < 2:
        return

    existing = SocCase.query.filter_by(ioc=record.indicator, status="pending").first()
    if existing:
        existing.threat_score     = record.threat_score
        existing.verdict          = record.verdict
        existing.flagging_sources = json.dumps(flagging)
        existing.source_count     = len(flagging)
        existing.otx_result       = record.otx_result
        existing.vt_result        = record.vt_result
        existing.abuseipdb_result = record.abuseipdb_result
        db.session.commit()
        return

    db.session.add(SocCase(
        ioc              = record.indicator,
        ioc_type         = record.ioc_type,
        threat_score     = record.threat_score,
        verdict          = record.verdict,
        flagging_sources = json.dumps(flagging),
        source_count     = len(flagging),
        otx_result       = record.otx_result,
        vt_result        = record.vt_result,
        abuseipdb_result = record.abuseipdb_result,
        ioc_record_id    = record.id,
    ))
    db.session.commit()


def _format_record(record):
    return {
        "id":          record.id,
        "indicator":   record.indicator,
        "ioc_type":    record.ioc_type,
        "threat_score": record.threat_score,
        "verdict":     record.verdict,
        "otx":    json.loads(record.otx_result)       if record.otx_result       else None,
        "vt":     json.loads(record.vt_result)        if record.vt_result        else None,
        "abuse":  json.loads(record.abuseipdb_result) if record.abuseipdb_result else None,
        "created_at":  record.created_at,
        "expires_at":  record.expires_at,
    }
