import re
from config import Config
from app import create_app


class _CSRFEnabledConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = True
    RATELIMIT_ENABLED = False
    SESSION_COOKIE_SECURE = False


def _make_app(tmp_path, name):
    _CSRFEnabledConfig.SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / name}"
    return create_app(_CSRFEnabledConfig)


def test_post_without_csrf_token_is_rejected(tmp_path):
    app = _make_app(tmp_path, "csrf1.db")
    client = app.test_client()
    client.get("/login")  # establishes the session
    r = client.post("/login", data={"username": "admin", "password": "admin"})
    assert r.status_code == 400


def test_post_with_valid_csrf_token_is_accepted(tmp_path):
    app = _make_app(tmp_path, "csrf2.db")
    client = app.test_client()
    r = client.get("/login")
    token = re.search(r'name="csrf-token" content="([^"]+)"', r.data.decode()).group(1)
    r = client.post("/login", data={
        "username": "admin", "password": "admin", "csrf_token": token,
    })
    assert r.status_code in (302, 303)


def test_agent_api_is_exempt_from_csrf(tmp_path):
    """The standalone endpoint-agent script has no browser session/CSRF token
    to present — its two API routes must stay reachable without one."""
    app = _make_app(tmp_path, "csrf3.db")
    client = app.test_client()
    r = client.post("/threat/api/register", json={"hostname": "test-host"})
    assert r.status_code != 400
