"""SSO tests mock Authlib's token exchange — there's no real Google/Microsoft
credentials available in this environment, so these verify the app's own
domain-gating and provisioning logic, not the OAuth handshake itself."""
from unittest.mock import patch, MagicMock


def _configure_sso(app, allowed_domains="example.com", auto_provision=True):
    from app.extensions import db
    from app.models import SSOConfig
    with app.app_context():
        cfg = SSOConfig(
            google_enabled=True, google_client_id="fake-id", google_client_secret="fake-secret",
            allowed_domains=allowed_domains, auto_provision=auto_provision,
        )
        db.session.add(cfg)
        db.session.commit()


def _mock_client(email, email_verified=True):
    client = MagicMock()
    client.authorize_access_token.return_value = {"userinfo": None}
    client.userinfo.return_value = {"email": email, "email_verified": email_verified}
    return client


def test_domain_not_allowed_is_rejected(app, client):
    _configure_sso(app, allowed_domains="example.com")
    with patch("app.routes.auth.oauth.create_client", return_value=_mock_client("someone@evil.com")):
        r = client.get("/login/sso/google/callback", follow_redirects=True)
    assert "/login" in r.request.path
    with app.app_context():
        from app.models import User
        assert User.query.filter_by(email="someone@evil.com").first() is None


def test_allowed_domain_auto_provisions_new_user(app, client):
    _configure_sso(app, allowed_domains="example.com", auto_provision=True)
    with patch("app.routes.auth.oauth.create_client", return_value=_mock_client("newhire@example.com")):
        r = client.get("/login/sso/google/callback", follow_redirects=True)
    assert r.status_code == 200
    with app.app_context():
        from app.models import User
        u = User.query.filter_by(email="newhire@example.com").first()
        assert u is not None
        assert u.role == "user"


def test_auto_provision_disabled_requires_existing_account(app, client):
    _configure_sso(app, allowed_domains="example.com", auto_provision=False)
    with patch("app.routes.auth.oauth.create_client", return_value=_mock_client("nosuchuser@example.com")):
        r = client.get("/login/sso/google/callback", follow_redirects=True)
    assert "/login" in r.request.path
    with app.app_context():
        from app.models import User
        assert User.query.filter_by(email="nosuchuser@example.com").first() is None


def test_existing_account_logs_in_via_sso_without_provisioning(app, client):
    from app.extensions import db
    from app.models import User
    with app.app_context():
        u = User(username="existing", email="existing@example.com", role="user")
        u.set_password("whatever")
        db.session.add(u)
        db.session.commit()

    _configure_sso(app, allowed_domains="example.com", auto_provision=False)
    with patch("app.routes.auth.oauth.create_client", return_value=_mock_client("existing@example.com")):
        r = client.get("/login/sso/google/callback", follow_redirects=True)
    assert r.status_code == 200
    assert "/login" not in r.request.path


def test_unverified_email_is_rejected(app, client):
    _configure_sso(app, allowed_domains="example.com")
    with patch("app.routes.auth.oauth.create_client",
               return_value=_mock_client("someone@example.com", email_verified=False)):
        r = client.get("/login/sso/google/callback", follow_redirects=True)
    assert "/login" in r.request.path
    with app.app_context():
        from app.models import User
        assert User.query.filter_by(email="someone@example.com").first() is None


def test_empty_allowed_domains_never_auto_provisions(app, client):
    """An empty allowlist must never silently mean 'allow everyone' —
    regardless of the auto_provision flag."""
    _configure_sso(app, allowed_domains="", auto_provision=True)
    with patch("app.routes.auth.oauth.create_client", return_value=_mock_client("anyone@anywhere.com")):
        r = client.get("/login/sso/google/callback", follow_redirects=True)
    assert "/login" in r.request.path
    with app.app_context():
        from app.models import User
        assert User.query.filter_by(email="anyone@anywhere.com").first() is None


def test_disabled_provider_redirects_to_login(client):
    r = client.get("/login/sso/google", follow_redirects=True)
    assert "/login" in r.request.path
