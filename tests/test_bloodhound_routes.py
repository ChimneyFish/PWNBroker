"""Route and engine-dispatch tests for the BloodHound (Attack Paths) section."""
import re
from unittest.mock import patch


def _csrf_token(client, path="/bloodhound/new"):
    r = client.get(path)
    return re.search(r'name="csrf-token" content="([^"]+)"', r.data.decode()).group(1)


def _make_ad_domain_target(app, name="bh-test-domain", host="corp.local"):
    from app.extensions import db
    from app.models import Target
    with app.app_context():
        t = Target(name=name, host=host, target_type="ad_domain",
                   ad_dc_host="10.0.0.1", ad_username="svc_bh",
                   ad_auth_type="password", ad_password="hunter2")
        db.session.add(t)
        db.session.commit()
        return t.id


def test_bloodhound_new_requires_ad_domain_target(app, admin_client):
    from app.extensions import db
    from app.models import Target

    with app.app_context():
        t = Target(name="not-ad", host="example.com", target_type="domain")
        db.session.add(t)
        db.session.commit()
        target_id = t.id

    token = _csrf_token(admin_client)
    with patch("threading.Thread.start"):
        r = admin_client.post("/bloodhound/new", data={
            "name": "Bad Target Scan", "target_id": str(target_id), "csrf_token": token,
        }, follow_redirects=True)
    assert r.status_code == 200
    assert b"only analyzes AD Domain targets" in r.data

    with app.app_context():
        from app.models import Scan
        assert Scan.query.filter_by(name="Bad Target Scan").first() is None


def test_creating_bloodhound_scan_dispatches_correctly(app, admin_client):
    target_id = _make_ad_domain_target(app)
    token = _csrf_token(admin_client)

    with patch("threading.Thread.start"):
        r = admin_client.post("/bloodhound/new", data={
            "name": "My BloodHound Scan", "target_id": str(target_id), "csrf_token": token,
        }, follow_redirects=True)
    assert r.status_code == 200

    with app.app_context():
        from app.models import Scan
        scan = Scan.query.filter_by(name="My BloodHound Scan").first()
        assert scan is not None
        assert scan.scan_type == "bloodhound"
        assert scan.target_id == target_id


def test_bloodhound_index_only_lists_bloodhound_scans(app, admin_client):
    from app.extensions import db
    from app.models import Scan

    target_id = _make_ad_domain_target(app, name="idx-domain-target")
    with app.app_context():
        db.session.add(Scan(name="A BloodHound Scan", target_id=target_id, scan_type="bloodhound", status="done"))
        db.session.add(Scan(name="An OSV Scan", target_id=target_id, scan_type="osv", status="done"))
        db.session.commit()

    r = admin_client.get("/bloodhound/")
    assert b"A BloodHound Scan" in r.data
    assert b"An OSV Scan" not in r.data


def test_bloodhound_index_warns_when_not_configured(app, admin_client):
    r = admin_client.get("/bloodhound/")
    assert b"BloodHound CE isn" in r.data


def test_bloodhound_index_no_warning_when_enabled(app, admin_client):
    from app.extensions import db
    from app.models import BloodHoundConfig
    with app.app_context():
        db.session.add(BloodHoundConfig(enabled=True, token_id="t", token_key="k"))
        db.session.commit()
    r = admin_client.get("/bloodhound/")
    assert b"BloodHound CE isn" not in r.data


def test_engine_dispatches_bloodhound_scan_type(app):
    from app.extensions import db
    from app.models import Target, Scan
    from app.scanner.engine import run_scan

    with app.app_context():
        t = Target(name="engine-bh-target", host="corp.local", target_type="ad_domain")
        db.session.add(t)
        db.session.commit()
        scan = Scan(name="Engine BloodHound Scan", target_id=t.id, scan_type="bloodhound", status="pending")
        db.session.add(scan)
        db.session.commit()
        scan_id = scan.id

    fake_findings = [{
        "result_type": "vulnerability", "host": "corp.local", "severity": "critical",
        "title": "Kerberoastable account: SVC_SQL@CORP.LOCAL", "description": "desc",
        "verification_status": "confirmed",
    }]
    with patch("app.scanner.bloodhound_scanner.run_bloodhound_scan", return_value=fake_findings) as mock_run:
        run_scan(scan_id, app)

    mock_run.assert_called_once()

    with app.app_context():
        scan = db.session.get(Scan, scan_id)
        assert scan.status == "done"
        results = scan.results.all()
        assert any(r.title.startswith("Kerberoastable account") and r.severity == "critical"
                  and r.verification_status == "confirmed" for r in results)


def test_engine_skips_bloodhound_scan_for_non_ad_domain_target(app):
    from app.extensions import db
    from app.models import Target, Scan
    from app.scanner.engine import run_scan

    with app.app_context():
        t = Target(name="not-ad-domain", host="example.com", target_type="domain")
        db.session.add(t)
        db.session.commit()
        scan = Scan(name="Non-AD BloodHound Scan", target_id=t.id, scan_type="bloodhound", status="pending")
        db.session.add(scan)
        db.session.commit()
        scan_id = scan.id

    with patch("app.scanner.bloodhound_scanner.run_collection") as mock_run:
        run_scan(scan_id, app)

    mock_run.assert_not_called()
    with app.app_context():
        scan = db.session.get(Scan, scan_id)
        assert scan.status == "done"
        assert any("requires an AD Domain target" in (r.title or "") for r in scan.results.all())
