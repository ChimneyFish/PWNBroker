"""Orchestrates the O365 email-security pipeline: keep the tenant's mailbox
list current, delta-fetch new mail per mailbox, run it through the analyzer,
and persist only the messages that actually got flagged.

Both entry points are safe to call repeatedly (idempotent) and expect to
already be inside an app/db context, matching every other poller in
app/scheduler/jobs.py.
"""
import json
import logging
from datetime import datetime, timezone

from ..extensions import db
from . import graph_client, analyzer

log = logging.getLogger(__name__)


def _parse_iso(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def _make_reputation_fn(threat_cfg):
    """Wraps the existing multi-source IOC lookup (OTX/AbuseIPDB/pulseDrive,
    with its own 24h cache and ≥2-source corroboration) as a plain
    domain -> verdict function for the analyzer's phishing check."""
    from ..threat.ioc_lookup import lookup as ioc_lookup

    def _fn(domain):
        if not domain:
            return None
        result = ioc_lookup(domain, threat_cfg)
        if result.get("error"):
            return None
        return result.get("verdict")
    return _fn


def sync_mailboxes() -> int:
    """Refresh MonitoredMailbox from the tenant's current user list. Mailboxes
    that disappear (disabled/departed users) are marked disabled rather than
    deleted, so their scan history and delta cursors survive. Returns the
    number of mailboxes seen this run, or -1 if not configured/enabled."""
    from ..models import O365Config, MonitoredMailbox

    cfg = O365Config.query.first()
    if not cfg or not cfg.enabled or not (cfg.tenant_id and cfg.client_id and cfg.client_secret):
        return -1

    token, err = graph_client.get_app_token(cfg.tenant_id, cfg.client_id, cfg.client_secret)
    if err:
        cfg.status, cfg.last_error = "error", err
        db.session.commit()
        return -1

    mailboxes, err = graph_client.list_mailboxes(token)
    if err:
        cfg.status, cfg.last_error = "error", err
        db.session.commit()
        return -1

    seen_ids = set()
    for mb in mailboxes:
        seen_ids.add(mb["user_id"])
        existing = MonitoredMailbox.query.filter_by(user_id=mb["user_id"]).first()
        if existing:
            existing.upn = mb["upn"]
            existing.display_name = mb["display_name"]
            existing.enabled = True
        else:
            db.session.add(MonitoredMailbox(user_id=mb["user_id"], upn=mb["upn"],
                                            display_name=mb["display_name"]))

    for existing in MonitoredMailbox.query.filter_by(enabled=True).all():
        if existing.user_id not in seen_ids:
            existing.enabled = False

    cfg.status = "ok"
    cfg.last_error = None
    cfg.last_mailbox_sync_at = datetime.now(timezone.utc)
    db.session.commit()
    log.info("O365 mailbox sync: %d mailbox(es)", len(mailboxes))
    return len(mailboxes)


def poll_mail() -> int:
    """Delta-fetch inbox (phishing/shadow-IT) and sent items (DLP lookalike)
    for every enabled mailbox, classify each new message, and persist only
    the ones the analyzer actually flagged. Returns the number flagged, or
    -1 if not configured/enabled."""
    from ..models import O365Config, MonitoredMailbox, EmailScanResult, ThreatConfig

    cfg = O365Config.query.first()
    if not cfg or not cfg.enabled or not (cfg.tenant_id and cfg.client_id and cfg.client_secret):
        return -1

    token, err = graph_client.get_app_token(cfg.tenant_id, cfg.client_id, cfg.client_secret)
    if err:
        cfg.status, cfg.last_error = "error", err
        db.session.commit()
        return -1

    threat_cfg = ThreatConfig.query.first()
    reputation_fn = _make_reputation_fn(threat_cfg) if threat_cfg else None

    mailboxes = MonitoredMailbox.query.filter_by(enabled=True).all()
    internal_domains = {mb.upn.split("@", 1)[1].lower() for mb in mailboxes if mb.upn and "@" in mb.upn}

    now = datetime.now(timezone.utc)
    flagged = 0
    for mb in mailboxes:
        for folder, attr, direction in (
            ("inbox", "inbox_delta_link", "inbound"),
            ("sentitems", "sentitems_delta_link", "outbound"),
        ):
            result = graph_client.delta_messages(token, mb.user_id, folder, getattr(mb, attr))
            if result.get("error") and result.get("error") != "delta_gone":
                mb.last_error = result["error"][:2000]

            for raw in result.get("messages", []):
                msg = graph_client.normalize_message(raw)
                if not msg["id"]:
                    continue
                if EmailScanResult.query.filter_by(mailbox_id=mb.id, message_id=msg["id"]).first():
                    continue

                classification = analyzer.classify_message(
                    msg, mailbox_upn=mb.upn, direction=direction,
                    internal_domains=internal_domains, cfg=cfg, reputation_fn=reputation_fn,
                )
                if not classification:
                    continue

                db.session.add(EmailScanResult(
                    mailbox_id=mb.id, message_id=msg["id"], direction=direction,
                    sender=msg["sender_email"], recipients=json.dumps(msg["recipients"]),
                    subject=(msg["subject"] or "")[:500], received_at=_parse_iso(msg["received_at"]),
                    snippet=msg["snippet"],
                    is_phishing_risk=classification["is_phishing_risk"],
                    phishing_detail=json.dumps(classification["phishing_detail"]) if classification["phishing_detail"] else None,
                    is_dlp_risk=classification["is_dlp_risk"],
                    dlp_detail=json.dumps(classification["dlp_detail"]) if classification["dlp_detail"] else None,
                    is_shadow_it=classification["is_shadow_it"],
                    shadow_it_detail=json.dumps(classification["shadow_it_detail"]) if classification["shadow_it_detail"] else None,
                    severity=classification["severity"],
                ))
                flagged += 1

            if result.get("delta_link") is not None or result.get("error") == "delta_gone":
                setattr(mb, attr, result.get("delta_link"))

        mb.last_synced_at = now

    cfg.status = "ok"
    cfg.last_error = None
    cfg.last_mail_poll_at = now
    db.session.commit()
    if flagged:
        log.info("O365 mail poll flagged %d message(s)", flagged)
    return flagged
