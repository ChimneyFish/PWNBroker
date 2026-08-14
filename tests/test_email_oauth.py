"""Tests for the O365 one-click admin-consent flow
(email_security.oauth_authorize / oauth_callback)."""
from urllib.parse import urlparse, parse_qs


def _save_cfg(app, **kwargs):
    with app.app_context():
        from app.models import O365Config
        from app.extensions import db
        cfg = O365Config.query.first() or O365Config()
        for k, v in kwargs.items():
            setattr(cfg, k, v)
        db.session.add(cfg)
        db.session.commit()


def test_authorize_without_config_redirects_to_settings(app, admin_client):
    r = admin_client.get("/email-security/oauth/authorize", follow_redirects=False)
    assert r.status_code == 302
    assert "/settings/" in r.headers["Location"]


def test_authorize_redirects_to_microsoft_with_state_and_correct_params(app, admin_client):
    _save_cfg(app, tenant_id="tenant-123", client_id="client-abc")
    r = admin_client.get("/email-security/oauth/authorize", follow_redirects=False)
    assert r.status_code == 302

    parsed = urlparse(r.headers["Location"])
    assert parsed.netloc == "login.microsoftonline.com"
    assert parsed.path == "/tenant-123/adminconsent"
    qs = parse_qs(parsed.query)
    assert qs["client_id"] == ["client-abc"]
    assert "state" in qs
    assert qs["redirect_uri"] == ["http://localhost/email-security/oauth/callback"]


def test_callback_success_marks_config_ok(app, admin_client):
    _save_cfg(app, tenant_id="tenant-123", client_id="client-abc", status="unknown")
    r = admin_client.get("/email-security/oauth/authorize", follow_redirects=False)
    state = parse_qs(urlparse(r.headers["Location"]).query)["state"][0]

    r2 = admin_client.get(
        f"/email-security/oauth/callback?admin_consent=True&tenant=tenant-123&state={state}",
        follow_redirects=True,
    )
    assert r2.status_code == 200
    assert b"admin consent granted" in r2.data.lower()

    with app.app_context():
        from app.models import O365Config
        cfg = O365Config.query.first()
        assert cfg.status == "ok"


def test_callback_rejects_state_mismatch(app, admin_client):
    _save_cfg(app, tenant_id="tenant-123", client_id="client-abc")
    admin_client.get("/email-security/oauth/authorize", follow_redirects=False)

    r = admin_client.get(
        "/email-security/oauth/callback?admin_consent=True&tenant=tenant-123&state=forged-state",
        follow_redirects=True,
    )
    assert b"could not be verified" in r.data.lower()


def test_callback_rejects_missing_state(app, admin_client):
    r = admin_client.get(
        "/email-security/oauth/callback?admin_consent=True&tenant=tenant-123",
        follow_redirects=True,
    )
    assert b"could not be verified" in r.data.lower()


def test_callback_state_is_single_use(app, admin_client):
    """The stored state is popped on first use — replaying the same callback
    URL a second time must not succeed."""
    _save_cfg(app, tenant_id="tenant-123", client_id="client-abc")
    r = admin_client.get("/email-security/oauth/authorize", follow_redirects=False)
    state = parse_qs(urlparse(r.headers["Location"]).query)["state"][0]
    callback_url = f"/email-security/oauth/callback?admin_consent=True&tenant=tenant-123&state={state}"

    first = admin_client.get(callback_url, follow_redirects=True)
    assert b"admin consent granted" in first.data.lower()

    second = admin_client.get(callback_url, follow_redirects=True)
    assert b"could not be verified" in second.data.lower()


def test_callback_surfaces_microsoft_error(app, admin_client):
    r = admin_client.get(
        "/email-security/oauth/callback?error=access_denied&error_description=User+declined",
        follow_redirects=True,
    )
    assert b"consent failed" in r.data.lower()
    assert b"user declined" in r.data.lower() or b"User declined" in r.data


def test_callback_declined_consent_shows_warning(app, admin_client):
    _save_cfg(app, tenant_id="tenant-123", client_id="client-abc")
    r = admin_client.get("/email-security/oauth/authorize", follow_redirects=False)
    state = parse_qs(urlparse(r.headers["Location"]).query)["state"][0]

    r2 = admin_client.get(
        f"/email-security/oauth/callback?admin_consent=False&tenant=tenant-123&state={state}",
        follow_redirects=True,
    )
    assert b"not granted" in r2.data.lower()
