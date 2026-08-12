"""Route and engine-dispatch tests for the Backdoor Scan section."""
import re
from unittest.mock import patch


def _csrf_token(client, path="/backdoor/new"):
    r = client.get(path)
    return re.search(r'name="csrf-token" content="([^"]+)"', r.data.decode()).group(1)


def _make_local_path_target(app, name="backdoor-test-path", host="/opt/some-project"):
    from app.extensions import db
    from app.models import Target
    with app.app_context():
        t = Target(name=name, host=host, target_type="local_path")
        db.session.add(t)
        db.session.commit()
        return t.id


def test_backdoor_new_requires_local_path_target(app, admin_client):
    from app.extensions import db
    from app.models import Target

    with app.app_context():
        t = Target(name="not-a-path", host="example.com", target_type="domain")
        db.session.add(t)
        db.session.commit()
        target_id = t.id

    token = _csrf_token(admin_client)
    with patch("threading.Thread.start"):
        r = admin_client.post("/backdoor/new", data={
            "name": "Bad Target Scan", "target_id": str(target_id), "csrf_token": token,
        }, follow_redirects=True)
    assert r.status_code == 200
    assert b"only scans Local Path targets" in r.data

    with app.app_context():
        from app.models import Scan
        assert Scan.query.filter_by(name="Bad Target Scan").first() is None


def test_creating_backdoor_scan_dispatches_correctly(app, admin_client):
    target_id = _make_local_path_target(app)
    token = _csrf_token(admin_client)

    with patch("threading.Thread.start"):
        r = admin_client.post("/backdoor/new", data={
            "name": "My Backdoor Scan", "target_id": str(target_id), "csrf_token": token,
        }, follow_redirects=True)
    assert r.status_code == 200

    with app.app_context():
        from app.models import Scan
        scan = Scan.query.filter_by(name="My Backdoor Scan").first()
        assert scan is not None
        assert scan.scan_type == "backdoor"
        assert scan.target_id == target_id


def test_backdoor_index_only_lists_backdoor_scans(app, admin_client):
    from app.extensions import db
    from app.models import Scan

    target_id = _make_local_path_target(app, name="idx-path-target")
    with app.app_context():
        db.session.add(Scan(name="A Backdoor Scan", target_id=target_id, scan_type="backdoor", status="done"))
        db.session.add(Scan(name="An OSV Scan", target_id=target_id, scan_type="osv", status="done"))
        db.session.commit()

    r = admin_client.get("/backdoor/")
    assert b"A Backdoor Scan" in r.data
    assert b"An OSV Scan" not in r.data


def test_engine_dispatches_backdoor_scan_type(app):
    from app.extensions import db
    from app.models import Target, Scan
    from app.scanner.engine import run_scan

    with app.app_context():
        t = Target(name="engine-backdoor-target", host="/opt/vendor-drop", target_type="local_path")
        db.session.add(t)
        db.session.commit()
        scan = Scan(name="Engine Backdoor Scan", target_id=t.id, scan_type="backdoor", status="pending")
        db.session.add(scan)
        db.session.commit()
        scan_id = scan.id

    fake_findings = [{
        "result_type": "vulnerability", "host": "/opt/vendor-drop", "severity": "high",
        "title": "hardcoded_secret: AWS key found", "description": "config.py:3 — AWS key found",
    }]
    with patch("app.scanner.backdoor_scanner.run_backdoor_scan", return_value=fake_findings) as mock_run:
        run_scan(scan_id, app)

    mock_run.assert_called_once_with("/opt/vendor-drop")

    with app.app_context():
        scan = db.session.get(Scan, scan_id)
        assert scan.status == "done"
        results = scan.results.all()
        assert any(r.title == "hardcoded_secret: AWS key found" and r.severity == "high" for r in results)


def test_engine_skips_backdoor_scan_for_non_local_path_target(app):
    from app.extensions import db
    from app.models import Target, Scan
    from app.scanner.engine import run_scan

    with app.app_context():
        t = Target(name="not-local-path", host="example.com", target_type="domain")
        db.session.add(t)
        db.session.commit()
        scan = Scan(name="Non-Local-Path Backdoor Scan", target_id=t.id, scan_type="backdoor", status="pending")
        db.session.add(scan)
        db.session.commit()
        scan_id = scan.id

    with patch("app.scanner.backdoor_scanner.run_backdoor_scan") as mock_run:
        run_scan(scan_id, app)

    mock_run.assert_not_called()
    with app.app_context():
        scan = db.session.get(Scan, scan_id)
        assert scan.status == "done"
        assert any("requires a local-path target" in (r.title or "") for r in scan.results.all())
