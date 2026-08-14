"""Tests for the vuln-management <-> threat-intel correlation pipeline
(app/threat/correlation.py). Uses the real sqlite-backed `app` fixture from
conftest.py rather than mocks, since the whole point is exercising actual
cross-table joins (VulnTicket x CVEEnrichment x SocCase/PaloAltoThreatLog).
"""
import json
from datetime import datetime, timedelta, timezone

from app.extensions import db
from app.models import (Target, VulnTicket, CVEEnrichment, SocCase,
                        PaloAltoFirewall, PaloAltoThreatLog)
from app.threat import correlation


def _make_target():
    t = Target(name="host-1", host="203.0.113.5")
    db.session.add(t)
    db.session.flush()
    return t


def _make_vuln_ticket(target, cve_id, host_ip, status="open"):
    t = VulnTicket(target_id=target.id, title=cve_id, vuln_name=cve_id,
                    host_ip=host_ip, severity="critical", cve_id=cve_id,
                    status=status)
    db.session.add(t)
    db.session.flush()
    return t


def _make_enrichment(cve_id, kev_listed=False, epss_score=None):
    e = CVEEnrichment(cve_id=cve_id, kev_listed=kev_listed, epss_score=epss_score)
    db.session.add(e)
    db.session.flush()
    return e


def _make_soc_case(ioc, verdict="malicious", sources=("OTX", "AbuseIPDB")):
    c = SocCase(ioc=ioc, ioc_type="ip", verdict=verdict, threat_score=80,
                flagging_sources=json.dumps(list(sources)), source_count=len(sources),
                status="pending")
    db.session.add(c)
    db.session.flush()
    return c


def _make_paloalto_log(ip, severity="high", naive_time=None):
    fw = PaloAltoFirewall(name="fw1", hostname="fw1.internal")
    db.session.add(fw)
    db.session.flush()
    log = PaloAltoThreatLog(
        firewall_id=fw.id, seqno=1, severity=severity, action="alert",
        category="command-and-control", threat_name="Test C2 Signature",
        src_ip=ip, dst_ip="198.51.100.1",
        time_generated=naive_time or datetime.now(timezone.utc).replace(tzinfo=None),  # deliberately naive
    )
    db.session.add(log)
    db.session.flush()
    return log


# ── find_host_activity / has_corroborated_activity ──────────────────────────

def test_find_host_activity_matches_soc_case(app):
    with app.app_context():
        _make_soc_case("203.0.113.5")
        db.session.commit()

        activity = correlation.find_host_activity("203.0.113.5")
        assert any(a["source"] == "SocCase" for a in activity)


def test_find_host_activity_matches_paloalto_despite_naive_timestamp(app):
    """Regression guard: PaloAltoThreatLog.time_generated is stored naive
    (parsed straight off the PAN-OS log) while the `since` cutoff is
    tz-aware — the lookup must not silently drop real matches over that
    mismatch."""
    with app.app_context():
        _make_paloalto_log("203.0.113.5", severity="critical")
        db.session.commit()

        since = datetime.now(timezone.utc) - timedelta(days=3)
        activity = correlation.find_host_activity("203.0.113.5", since=since)
        assert any(a["source"] == "PaloAlto" for a in activity)


def test_find_host_activity_ignores_clean_and_old_records(app):
    with app.app_context():
        _make_soc_case("203.0.113.5", verdict="malicious")
        # Old activity, outside the lookback window
        old_case = SocCase.query.filter_by(ioc="203.0.113.5").first()
        old_case.created_at = datetime.now(timezone.utc) - timedelta(days=30)
        db.session.commit()

        activity = correlation.find_host_activity(
            "203.0.113.5", since=datetime.now(timezone.utc) - timedelta(days=3))
        assert activity == []


def test_has_corroborated_activity_treats_lone_ioc_lookup_as_weak(app):
    from app.models import IOCRecord
    with app.app_context():
        db.session.add(IOCRecord(indicator="203.0.113.5", ioc_type="ip",
                                 verdict="suspicious", threat_score=40))
        db.session.commit()

        corroborated, activity = correlation.has_corroborated_activity("203.0.113.5")
        assert corroborated is False
        assert len(activity) == 1


# ── run_correlation / escalation ────────────────────────────────────────────

def test_run_correlation_escalates_kev_vuln_with_corroborated_activity(app):
    with app.app_context():
        target = _make_target()
        ticket = _make_vuln_ticket(target, "CVE-2024-9999", "203.0.113.5")
        _make_enrichment("CVE-2024-9999", kev_listed=True)
        _make_soc_case("203.0.113.5", verdict="malicious")
        db.session.commit()

        touched = correlation.run_correlation()

        assert touched == 1
        case = SocCase.query.filter_by(ioc="203.0.113.5").first()
        assert case.vuln_ticket_id == ticket.id
        sources = json.loads(case.flagging_sources)
        assert "VulnMgmt:KEV:CVE-2024-9999" in sources
        assert case.verdict == "malicious"
        assert case.threat_score >= 90


def test_run_correlation_does_not_alert_on_kev_vuln_alone(app):
    """The core "don't alert unless it's real" behavior: a KEV-listed vuln
    with no observed malicious activity on the host must not raise a case."""
    with app.app_context():
        target = _make_target()
        _make_vuln_ticket(target, "CVE-2024-9999", "203.0.113.5")
        _make_enrichment("CVE-2024-9999", kev_listed=True)
        db.session.commit()

        touched = correlation.run_correlation()

        assert touched == 0
        assert SocCase.query.count() == 0


def test_run_correlation_uses_epss_threshold_with_paloalto_corroboration(app):
    with app.app_context():
        target = _make_target()
        _make_vuln_ticket(target, "CVE-2024-2222", "203.0.113.5")
        _make_enrichment("CVE-2024-2222", kev_listed=False, epss_score=0.6)
        _make_paloalto_log("203.0.113.5", severity="high")
        db.session.commit()

        touched = correlation.run_correlation()

        assert touched == 1
        case = SocCase.query.filter_by(ioc="203.0.113.5").first()
        assert "VulnMgmt:EPSS:CVE-2024-2222" in json.loads(case.flagging_sources)


def test_run_correlation_skips_low_epss_without_kev(app):
    with app.app_context():
        target = _make_target()
        _make_vuln_ticket(target, "CVE-2024-3333", "203.0.113.5")
        _make_enrichment("CVE-2024-3333", kev_listed=False, epss_score=0.1)
        _make_soc_case("203.0.113.5", verdict="malicious")
        db.session.commit()

        touched = correlation.run_correlation()

        assert touched == 0
        assert SocCase.query.count() == 1  # the pre-existing case is untouched
        untouched = SocCase.query.first()
        assert untouched.vuln_ticket_id is None


def test_run_correlation_ignores_resolved_tickets(app):
    with app.app_context():
        target = _make_target()
        _make_vuln_ticket(target, "CVE-2024-9999", "203.0.113.5", status="patched")
        _make_enrichment("CVE-2024-9999", kev_listed=True)
        _make_soc_case("203.0.113.5", verdict="malicious")
        db.session.commit()

        touched = correlation.run_correlation()

        assert touched == 0


def test_run_correlation_merges_into_existing_pending_case(app):
    """Two open, corroborated vulns on the same host should accumulate into
    one triage entry, not create duplicate cases."""
    with app.app_context():
        target = _make_target()
        _make_vuln_ticket(target, "CVE-2024-9999", "203.0.113.5")
        _make_vuln_ticket(target, "CVE-2024-8888", "203.0.113.5")
        _make_enrichment("CVE-2024-9999", kev_listed=True)
        _make_enrichment("CVE-2024-8888", kev_listed=True)
        _make_soc_case("203.0.113.5", verdict="malicious")
        db.session.commit()

        correlation.run_correlation()

        assert SocCase.query.filter_by(ioc="203.0.113.5").count() == 1
        case = SocCase.query.filter_by(ioc="203.0.113.5").first()
        sources = json.loads(case.flagging_sources)
        assert "VulnMgmt:KEV:CVE-2024-9999" in sources
        assert "VulnMgmt:KEV:CVE-2024-8888" in sources
