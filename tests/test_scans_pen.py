"""Scan-creation and engine-dispatch tests for the "pen" scan type."""
import re
from unittest.mock import patch


def _csrf_token(client, path="/scans/new"):
    r = client.get(path)
    return re.search(r'name="csrf-token" content="([^"]+)"', r.data.decode()).group(1)


def _make_target(app):
    from app.extensions import db
    from app.models import Target
    with app.app_context():
        t = Target(name="pen-test-target", host="example.com", target_type="domain")
        db.session.add(t)
        db.session.commit()
        return t.id


def test_creating_pen_scan_stores_token_encrypted(app, admin_client):
    from sqlalchemy import text
    from app.extensions import db

    target_id = _make_target(app)
    token = _csrf_token(admin_client)

    with patch("threading.Thread.start"):  # don't actually launch the background scan
        r = admin_client.post("/scans/new", data={
            "name": "PEN Test Scan", "target_id": str(target_id), "scan_type": "pen",
            "port_range": "1-1024", "pen_token": "super-secret-bearer-token",
            "csrf_token": token,
        }, follow_redirects=True)
    assert r.status_code == 200

    with app.app_context():
        from app.models import Scan
        scan = Scan.query.filter_by(name="PEN Test Scan").first()
        assert scan is not None
        assert scan.scan_type == "pen"
        # ORM access transparently decrypts.
        assert scan.pen_token == "super-secret-bearer-token"

        raw = db.session.execute(
            text("SELECT pen_token FROM scans WHERE id=:id"), {"id": scan.id}
        ).scalar()
        assert raw.startswith("enc:v1:")


def test_creating_pen_scan_without_token_leaves_it_null(app, admin_client):
    target_id = _make_target(app)
    token = _csrf_token(admin_client)

    with patch("threading.Thread.start"):
        admin_client.post("/scans/new", data={
            "name": "PEN No-Token Scan", "target_id": str(target_id), "scan_type": "pen",
            "port_range": "1-1024", "pen_token": "",
            "csrf_token": token,
        }, follow_redirects=True)

    with app.app_context():
        from app.models import Scan
        scan = Scan.query.filter_by(name="PEN No-Token Scan").first()
        assert scan is not None
        assert scan.pen_token is None


def test_engine_dispatches_pen_scan_type(app):
    from app.extensions import db
    from app.models import Target, Scan
    from app.scanner.engine import run_scan

    with app.app_context():
        t = Target(name="pen-engine-target", host="example.org", target_type="domain")
        db.session.add(t)
        db.session.commit()
        scan = Scan(name="Engine PEN Scan", target_id=t.id, scan_type="pen",
                    pen_token="tok", status="pending")
        db.session.add(scan)
        db.session.commit()
        scan_id = scan.id

    fake_findings = [{
        "result_type": "vulnerability", "host": "example.org", "severity": "high",
        "title": "fake finding", "description": "fake",
    }]
    with patch("app.scanner.pen_scanner.run_pen_scan", return_value=fake_findings) as mock_run:
        run_scan(scan_id, app)

    mock_run.assert_called_once()
    call_args = mock_run.call_args
    assert call_args.args[0] == "https://example.org"  # scheme defaulted
    assert call_args.args[1] == "example.org"
    assert call_args.kwargs.get("token") == "tok"

    with app.app_context():
        scan = db.session.get(Scan, scan_id)
        assert scan.status == "done"
        results = scan.results.all()
        assert any(r.title == "fake finding" and r.severity == "high" for r in results)


def test_engine_skips_pen_scan_for_cidr_target(app):
    from app.extensions import db
    from app.models import Target, Scan
    from app.scanner.engine import run_scan

    with app.app_context():
        t = Target(name="pen-cidr-target", host="203.0.113.0/28", target_type="host")
        db.session.add(t)
        db.session.commit()
        scan = Scan(name="Engine PEN CIDR Scan", target_id=t.id, scan_type="pen", status="pending")
        db.session.add(scan)
        db.session.commit()
        scan_id = scan.id

    with patch("app.scanner.pen_scanner.run_pen_scan") as mock_run:
        run_scan(scan_id, app)

    mock_run.assert_not_called()
