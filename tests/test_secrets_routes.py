"""Route and engine-dispatch tests for the Secrets section (REAPER scans)."""
import re
from unittest.mock import patch


def _csrf_token(client, path="/secrets/new"):
    r = client.get(path)
    return re.search(r'name="csrf-token" content="([^"]+)"', r.data.decode()).group(1)


def _make_github_target(app, name="secrets-test-repo", host="octocat/Hello-World"):
    from app.extensions import db
    from app.models import Target
    with app.app_context():
        t = Target(name=name, host=host, target_type="github_repo")
        db.session.add(t)
        db.session.commit()
        return t.id


def test_secrets_new_requires_github_repo_target(app, admin_client):
    from app.extensions import db
    from app.models import Target

    with app.app_context():
        t = Target(name="not-a-repo", host="example.com", target_type="domain")
        db.session.add(t)
        db.session.commit()
        target_id = t.id

    token = _csrf_token(admin_client)
    with patch("threading.Thread.start"):
        r = admin_client.post("/secrets/new", data={
            "name": "Bad Target Scan", "target_id": str(target_id), "csrf_token": token,
        }, follow_redirects=True)
    assert r.status_code == 200
    assert b"only scans GitHub repository targets" in r.data

    with app.app_context():
        from app.models import Scan
        assert Scan.query.filter_by(name="Bad Target Scan").first() is None


def test_creating_secrets_scan_dispatches_to_reaper(app, admin_client):
    target_id = _make_github_target(app)
    token = _csrf_token(admin_client)

    with patch("threading.Thread.start"):
        r = admin_client.post("/secrets/new", data={
            "name": "My Secret Scan", "target_id": str(target_id), "csrf_token": token,
        }, follow_redirects=True)
    assert r.status_code == 200

    with app.app_context():
        from app.models import Scan
        scan = Scan.query.filter_by(name="My Secret Scan").first()
        assert scan is not None
        assert scan.scan_type == "reaper"
        assert scan.target_id == target_id


def test_secrets_index_only_lists_reaper_scans(app, admin_client):
    from app.extensions import db
    from app.models import Scan

    target_id = _make_github_target(app, name="idx-target")
    with app.app_context():
        db.session.add(Scan(name="A REAPER Scan", target_id=target_id, scan_type="reaper", status="done"))
        db.session.add(Scan(name="An OSV Scan", target_id=target_id, scan_type="osv", status="done"))
        db.session.commit()

    r = admin_client.get("/secrets/")
    assert b"A REAPER Scan" in r.data
    assert b"An OSV Scan" not in r.data


def test_engine_dispatches_reaper_scan_type(app):
    from app.extensions import db
    from app.models import Target, Scan, ThreatConfig
    from app.scanner.engine import run_scan

    with app.app_context():
        t = Target(name="engine-reaper-target", host="https://github.com/owner/repo",
                   target_type="github_repo")
        db.session.add(t)
        tc = ThreatConfig(github_advisory_token="shared-gh-token")
        db.session.add(tc)
        db.session.commit()
        scan = Scan(name="Engine REAPER Scan", target_id=t.id, scan_type="reaper", status="pending")
        db.session.add(scan)
        db.session.commit()
        scan_id = scan.id

    fake_findings = [{
        "result_type": "vulnerability", "host": "owner/repo", "severity": "critical",
        "title": "AWS Access Key", "description": "found in config.py",
    }]
    with patch("app.scanner.reaper_scanner.run_reaper_scan", return_value=fake_findings) as mock_run:
        run_scan(scan_id, app)

    mock_run.assert_called_once_with("owner", "repo", "shared-gh-token")

    with app.app_context():
        scan = db.session.get(Scan, scan_id)
        assert scan.status == "done"
        results = scan.results.all()
        assert any(r.title == "AWS Access Key" and r.severity == "critical" for r in results)


def test_engine_skips_reaper_scan_for_non_github_target(app):
    from app.extensions import db
    from app.models import Target, Scan
    from app.scanner.engine import run_scan

    with app.app_context():
        t = Target(name="not-github", host="example.com", target_type="domain")
        db.session.add(t)
        db.session.commit()
        scan = Scan(name="Non-GitHub Reaper Scan", target_id=t.id, scan_type="reaper", status="pending")
        db.session.add(scan)
        db.session.commit()
        scan_id = scan.id

    with patch("app.scanner.reaper_scanner.run_reaper_scan") as mock_run:
        run_scan(scan_id, app)

    mock_run.assert_not_called()
    with app.app_context():
        scan = db.session.get(Scan, scan_id)
        assert scan.status == "done"
        assert any("requires a GitHub repository target" in (r.title or "") for r in scan.results.all())
