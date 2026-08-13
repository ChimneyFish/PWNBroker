"""Correlates vulnerability management with threat intelligence.

Vuln management (VulnTicket/CVEEnrichment) and threat intel (SocCase,
PaloAltoThreatLog, AgentAlert, IOCRecord) track completely separate data
today — a VulnTicket's host_ip is just a string with nothing pointing at
whatever network activity has been observed for that same host. The
functions here answer one question: "has this host also shown up in
threat intel as something other than clean?" — by matching on IP across
the existing tables, without introducing a new asset-identity system.
"""
import json
import logging
from datetime import datetime, timezone, timedelta

from ..extensions import db

log = logging.getLogger(__name__)

_BAD_VERDICTS = ("malicious", "suspicious")

# A vuln with this EPSS probability (0-1 scale) of exploitation in the next 30
# days is treated as "actively at-risk" even if it isn't (yet) in CISA's KEV
# catalog. 0.5 is a commonly-cited EPSS triage cutoff — well above the median
# CVE (most sit under 0.01) but below requiring near-certainty.
EPSS_ESCALATION_THRESHOLD = 0.5


def _aware(dt):
    """Normalize to a tz-aware UTC datetime — PaloAltoThreatLog.time_generated
    is stored naive (parsed straight off the PAN-OS log), while everything
    else here defaults to tz-aware, so cutoff comparisons are done in Python
    rather than relying on SQLite's naive string comparison of mixed formats."""
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def find_host_activity(host_ip: str, since: datetime | None = None) -> list[dict]:
    """Return every piece of non-clean threat-intel activity seen for host_ip.

    Each item is {"source", "detail", "verdict", "occurred_at"}. Matching is a
    plain string/IP equality check against whatever's already stored in
    SocCase.ioc, PaloAltoThreatLog.src_ip/dst_ip, AgentAlert (via the
    endpoint's own IP), and IOCRecord.indicator — no new identity table.
    """
    from ..models import SocCase, PaloAltoThreatLog, AgentAlert, EndpointAgent, IOCRecord

    if not host_ip:
        return []
    since = _aware(since) or (datetime.now(timezone.utc) - timedelta(days=3))
    activity = []

    for case in (SocCase.query.filter_by(ioc=host_ip)
                 .filter(SocCase.verdict.in_(_BAD_VERDICTS)).all()):
        if _aware(case.created_at) and _aware(case.created_at) < since:
            continue
        sources = json.loads(case.flagging_sources) if case.flagging_sources else []
        activity.append({
            "source":      "SocCase",
            "detail":      f"SOC case #{case.id}: flagged by {', '.join(sources) or 'unknown'} "
                           f"(score {case.threat_score}/100)",
            "verdict":     case.verdict,
            "occurred_at": case.created_at,
        })

    logs = (PaloAltoThreatLog.query
            .filter(PaloAltoThreatLog.severity.in_(("critical", "high")))
            .filter((PaloAltoThreatLog.src_ip == host_ip) | (PaloAltoThreatLog.dst_ip == host_ip))
            .order_by(PaloAltoThreatLog.time_generated.desc())
            .limit(50).all())
    for entry in logs:
        if _aware(entry.time_generated) and _aware(entry.time_generated) < since:
            continue
        activity.append({
            "source":      "PaloAlto",
            "detail":      f"{entry.threat_name or entry.category or 'threat signature'} "
                           f"({entry.severity}, action={entry.action})",
            "verdict":     "malicious" if entry.severity == "critical" else "suspicious",
            "occurred_at": entry.time_generated,
        })

    agent_ids = [a.id for a in EndpointAgent.query.filter_by(ip_address=host_ip).all()]
    if agent_ids:
        alerts = (AgentAlert.query
                  .filter(AgentAlert.agent_db_id.in_(agent_ids))
                  .order_by(AgentAlert.created_at.desc())
                  .limit(50).all())
        for a in alerts:
            if _aware(a.created_at) and _aware(a.created_at) < since:
                continue
            activity.append({
                "source":      "EndpointAgent",
                "detail":      f"{a.title} (severity={a.severity})",
                "verdict":     "malicious" if a.severity in ("critical", "high") else "suspicious",
                "occurred_at": a.created_at,
            })

    if not any(x["source"] == "SocCase" for x in activity):
        ioc = (IOCRecord.query.filter_by(indicator=host_ip)
               .filter(IOCRecord.verdict.in_(_BAD_VERDICTS))
               .order_by(IOCRecord.created_at.desc()).first())
        if ioc and _aware(ioc.created_at) and _aware(ioc.created_at) >= since:
            activity.append({
                "source":      "IOCLookup",
                "detail":      f"IOC lookup: score {ioc.threat_score}/100",
                "verdict":     ioc.verdict,
                "occurred_at": ioc.created_at,
            })

    return activity


def has_corroborated_activity(host_ip: str, since: datetime | None = None) -> tuple[bool, list[dict]]:
    """True if find_host_activity() returns anything beyond a single weak
    IOCLookup hit — i.e. there's a SOC case, a firewall signature match, or an
    endpoint agent alert, any of which already represent corroborated signal
    on their own (see ioc_lookup._maybe_queue_triage / jobs._queue_paloalto_soc_case)."""
    activity = find_host_activity(host_ip, since)
    strong = [a for a in activity if a["source"] != "IOCLookup"]
    return bool(strong), activity


def run_correlation() -> int:
    """The actual automation: an exploitable vuln sitting on a host is routine
    backlog; an exploitable vuln on a host that's *also* showing corroborated
    malicious network activity is a real incident. Only the latter raises an
    alert — surfaced into the existing SOC triage queue rather than a second
    inbox. Must be called inside an app/db context. Returns cases touched.

    Caller must already be inside an app/db context — used by both the
    scheduler job and (optionally) a manual trigger.
    """
    from ..models import VulnTicket, CVEEnrichment

    candidates = (VulnTicket.query
                  .filter(VulnTicket.cve_id.isnot(None))
                  .filter(VulnTicket.host_ip.isnot(None), VulnTicket.host_ip != "")
                  .filter(VulnTicket.status.in_(("open", "in_progress")))
                  .all())
    if not candidates:
        return 0

    cve_ids = {t.cve_id for t in candidates}
    enrichments = {e.cve_id: e for e in
                   CVEEnrichment.query.filter(CVEEnrichment.cve_id.in_(cve_ids)).all()}

    touched = set()
    for ticket in candidates:
        enrichment = enrichments.get(ticket.cve_id)
        if not enrichment:
            continue
        is_kev  = bool(enrichment.kev_listed)
        is_epss = (enrichment.epss_score or 0) >= EPSS_ESCALATION_THRESHOLD
        if not (is_kev or is_epss):
            continue

        corroborated, activity = has_corroborated_activity(ticket.host_ip)
        if not corroborated:
            continue

        _escalate(ticket, enrichment, is_kev, activity)
        touched.add(ticket.host_ip)

    if touched:
        db.session.commit()
        log.info("Vuln/threat-intel correlation escalated %d host(s): %s",
                  len(touched), sorted(touched))
    return len(touched)


def _escalate(ticket, enrichment, is_kev, activity):
    """Create or update the pending SocCase for ticket.host_ip, folding in the
    vuln side of the corroboration alongside whatever threat-intel activity
    already exists for that host."""
    from ..models import SocCase

    vuln_source = f"VulnMgmt:{'KEV' if is_kev else 'EPSS'}:{ticket.cve_id}"
    verdicts = {a["verdict"] for a in activity}
    verdict  = "malicious" if "malicious" in verdicts else "suspicious"
    vuln_score = 95 if is_kev else int(70 + 25 * (enrichment.epss_score or 0))
    intel_score = max((90 if v == "malicious" else 60 for v in verdicts), default=0)

    case = SocCase.query.filter_by(ioc=ticket.host_ip, status="pending").first()
    if not case:
        case = SocCase(ioc=ticket.host_ip, ioc_type="ip", status="pending")
        db.session.add(case)

    existing_sources = set(json.loads(case.flagging_sources)) if case.flagging_sources else set()
    activity_sources  = {a["source"] for a in activity}
    all_sources = existing_sources | activity_sources | {vuln_source}

    case.flagging_sources = json.dumps(sorted(all_sources))
    case.source_count     = len(all_sources)
    case.threat_score      = max(case.threat_score or 0, vuln_score, intel_score)
    case.verdict           = "malicious" if verdict == "malicious" else (case.verdict or verdict)
    case.vuln_ticket_id    = ticket.id
