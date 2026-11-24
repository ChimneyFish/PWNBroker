"""Palo Alto threat-log retention: admins choose how long ingested logs are
kept; blank means forever (the old behaviour)."""
from datetime import datetime, timedelta, timezone

from app.extensions import db


def _seed(app):
    from app.models import PaloAltoFirewall, PaloAltoThreatLog
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    with app.app_context():
        fw = PaloAltoFirewall(name="FW", hostname="192.0.2.1", api_key="k")
        db.session.add(fw)
        db.session.flush()
        for seq, age in [(1, 200), (2, 40), (3, 1)]:
            db.session.add(PaloAltoThreatLog(firewall_id=fw.id, seqno=seq,
                                             time_generated=now - timedelta(days=age)))
        # no firewall timestamp — falls back to when it was received
        db.session.add(PaloAltoThreatLog(firewall_id=fw.id, seqno=4, time_generated=None,
                                         created_at=now - timedelta(days=100)))
        db.session.commit()


def _seqnos(app):
    from app.models import PaloAltoThreatLog
    with app.app_context():
        return sorted(l.seqno for l in PaloAltoThreatLog.query.all())


def test_default_keeps_logs_forever(app, admin_client):
    _seed(app)
    from app.scheduler.jobs import _run_paloalto_retention
    _run_paloalto_retention(app)
    assert _seqnos(app) == [1, 2, 3, 4]
    html = admin_client.get("/threat/paloalto").get_data(as_text=True)
    assert "kept forever" in html and 'id="retention_days"' in html


def test_setting_retention_purges_old_logs_now_and_daily(app, admin_client):
    _seed(app)
    r = admin_client.post("/threat/paloalto/retention", data={"retention_days": "90"},
                          follow_redirects=True)
    assert r.status_code == 200
    assert "2 older logs deleted" in r.get_data(as_text=True)
    assert _seqnos(app) == [2, 3]

    from app.models import ThreatConfig
    with app.app_context():
        assert ThreatConfig.query.first().paloalto_retention_days == 90
        ThreatConfig.query.first().paloalto_retention_days = 30
        db.session.commit()
    from app.scheduler.jobs import _run_paloalto_retention
    _run_paloalto_retention(app)
    assert _seqnos(app) == [3]


def test_blank_restores_forever_and_bad_values_rejected(app, admin_client):
    from app.models import ThreatConfig
    admin_client.post("/threat/paloalto/retention", data={"retention_days": "30"})
    for bad in ("0", "-5", "abc", "99999"):
        r = admin_client.post("/threat/paloalto/retention", data={"retention_days": bad},
                              follow_redirects=True)
        assert "whole number of days" in r.get_data(as_text=True)
    with app.app_context():
        assert ThreatConfig.query.first().paloalto_retention_days == 30
    admin_client.post("/threat/paloalto/retention", data={"retention_days": ""})
    with app.app_context():
        assert ThreatConfig.query.first().paloalto_retention_days is None

