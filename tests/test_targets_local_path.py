"""Tests for target creation via the actual /targets/new route, covering:

- the local_path target type added for Backdoor Detector
- a regression test for a pre-existing bug found while adding local_path:
  is_valid_host() was being called unconditionally for every target_type,
  which meant github_repo targets (format "owner/repo") could never
  actually be created through the real web form — is_valid_host rejects the
  "/" in that format. Fixed in app/routes/targets.py by branching validation
  on target_type. Every github_repo target used elsewhere in this suite was
  previously inserted directly via the ORM, which is how this went unnoticed.
"""
import re


def _csrf_token(client, path="/targets/new"):
    r = client.get(path)
    return re.search(r'name="csrf-token" content="([^"]+)"', r.data.decode()).group(1)


def test_creating_github_repo_target_via_route_succeeds(app, admin_client):
    token = _csrf_token(admin_client)
    r = admin_client.post("/targets/new", data={
        "name": "octocat-repo", "host": "octocat/Hello-World",
        "target_type": "github_repo", "csrf_token": token,
    }, follow_redirects=True)
    assert r.status_code == 200
    assert b"created" in r.data.lower()

    with app.app_context():
        from app.models import Target
        t = Target.query.filter_by(name="octocat-repo").first()
        assert t is not None
        assert t.target_type == "github_repo"
        assert t.host == "octocat/Hello-World"


def test_creating_local_path_target_via_route_succeeds(app, admin_client):
    token = _csrf_token(admin_client)
    r = admin_client.post("/targets/new", data={
        "name": "server-project", "host": "/opt/some-project",
        "target_type": "local_path", "csrf_token": token,
    }, follow_redirects=True)
    assert r.status_code == 200
    assert b"created" in r.data.lower()

    with app.app_context():
        from app.models import Target
        t = Target.query.filter_by(name="server-project").first()
        assert t is not None
        assert t.target_type == "local_path"
        assert t.host == "/opt/some-project"


def test_local_path_rejects_relative_path(app, admin_client):
    token = _csrf_token(admin_client)
    r = admin_client.post("/targets/new", data={
        "name": "bad-path", "host": "relative/path",
        "target_type": "local_path", "csrf_token": token,
    }, follow_redirects=True)
    assert r.status_code == 200
    assert b"valid absolute path" in r.data

    with app.app_context():
        from app.models import Target
        assert Target.query.filter_by(name="bad-path").first() is None


def test_github_repo_rejects_malformed_value(app, admin_client):
    token = _csrf_token(admin_client)
    r = admin_client.post("/targets/new", data={
        "name": "bad-repo", "host": "not a repo at all",
        "target_type": "github_repo", "csrf_token": token,
    }, follow_redirects=True)
    assert r.status_code == 200
    assert b"valid GitHub repository" in r.data

    with app.app_context():
        from app.models import Target
        assert Target.query.filter_by(name="bad-repo").first() is None


def test_host_target_type_still_validated_as_before(app, admin_client):
    token = _csrf_token(admin_client)
    r = admin_client.post("/targets/new", data={
        "name": "bad-host", "host": "not_a_valid_host!!",
        "target_type": "host", "csrf_token": token,
    }, follow_redirects=True)
    assert r.status_code == 200
    assert b"valid IP address, CIDR range, or hostname" in r.data

    with app.app_context():
        from app.models import Target
        assert Target.query.filter_by(name="bad-host").first() is None
