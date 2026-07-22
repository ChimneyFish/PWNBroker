import re
import pyotp


def _csrf(client, path):
    r = client.get(path)
    return re.search(r'name="csrf_token" value="([^"]+)"', r.data.decode()).group(1)


def _enroll_mfa(app, client):
    """Log in as admin (password-change already satisfied by admin_client),
    enroll MFA, and return (secret, backup_codes).

    Both the secret and CSRF token must come from the SAME GET response —
    every GET to /users/mfa/setup mints a fresh secret into the session, so a
    second request here would silently invalidate the one just extracted.
    """
    r = client.get("/users/mfa/setup")
    body = r.data.decode()
    secret = re.search(r"<div[^>]*>([A-Z2-7]{16,})</div>", body).group(1)
    token  = re.search(r'name="csrf_token" value="([^"]+)"', body).group(1)

    code = pyotp.TOTP(secret).now()
    r = client.post("/users/mfa/setup", data={"code": code, "csrf_token": token})
    assert r.status_code == 200
    codes = re.findall(r'<div class="mb-1">([0-9a-f]{8})</div>', r.data.decode())
    assert len(codes) == 10
    return secret, codes


def test_enroll_requires_valid_code(app, admin_client):
    r = admin_client.get("/users/mfa/setup")
    assert r.status_code == 200
    body = r.data.decode()
    token = re.search(r'name="csrf_token" value="([^"]+)"', body).group(1)

    # wrong code rejected
    r = admin_client.post("/users/mfa/setup", data={"code": "000000", "csrf_token": token})
    assert r.status_code == 200
    with app.app_context():
        from app.models import User
        admin = User.query.filter_by(username="admin").first()
        assert admin.mfa_enabled is False


def test_enroll_then_login_requires_mfa_step(app, admin_client):
    secret, _ = _enroll_mfa(app, admin_client)

    with app.app_context():
        from app.models import User
        admin = User.query.filter_by(username="admin").first()
        assert admin.mfa_enabled is True

    # log out, log back in — should now require the MFA step
    admin_client.get("/logout")
    token = _csrf(admin_client, "/login")
    r = admin_client.post("/login", data={"username": "admin", "password": "admin", "csrf_token": token},
                          follow_redirects=True)
    assert "/login/mfa" in r.request.path

    # wrong code stays on the MFA page
    token2 = _csrf(admin_client, "/login/mfa")
    r = admin_client.post("/login/mfa", data={"code": "000000", "csrf_token": token2}, follow_redirects=True)
    assert "/login/mfa" in r.request.path

    # correct TOTP code completes login
    code = pyotp.TOTP(secret).now()
    r = admin_client.post("/login/mfa", data={"code": code, "csrf_token": token2}, follow_redirects=True)
    assert r.status_code == 200
    assert "/login" not in r.request.path


def test_backup_code_is_single_use(app, admin_client):
    _, backup_codes = _enroll_mfa(app, admin_client)
    admin_client.get("/logout")

    token = _csrf(admin_client, "/login")
    admin_client.post("/login", data={"username": "admin", "password": "admin", "csrf_token": token})
    token2 = _csrf(admin_client, "/login/mfa")

    code = backup_codes[0]
    r = admin_client.post("/login/mfa", data={"code": code, "csrf_token": token2}, follow_redirects=True)
    assert "/login" not in r.request.path

    # reusing the same backup code must fail
    admin_client.get("/logout")
    token3 = _csrf(admin_client, "/login")
    admin_client.post("/login", data={"username": "admin", "password": "admin", "csrf_token": token3})
    token4 = _csrf(admin_client, "/login/mfa")
    r = admin_client.post("/login/mfa", data={"code": code, "csrf_token": token4}, follow_redirects=True)
    assert "/login/mfa" in r.request.path


def test_admin_can_reset_mfa(app, admin_client):
    with app.app_context():
        from app.extensions import db
        from app.models import User
        other = User(username="analyst", email="analyst@example.com", role="user")
        other.set_password("analystpw")
        db.session.add(other)
        db.session.commit()
        other_id = other.id
        other.mfa_secret = pyotp.random_base32()
        other.mfa_enabled = True
        db.session.commit()

    token = _csrf(admin_client, "/users/")
    r = admin_client.post(f"/users/{other_id}/mfa/reset", data={"csrf_token": token}, follow_redirects=True)
    assert r.status_code == 200

    with app.app_context():
        from app.models import User
        other = User.query.get(other_id)
        assert other.mfa_enabled is False
        assert other.mfa_secret is None


def test_admin_can_require_mfa_and_it_forces_setup(app, admin_client):
    with app.app_context():
        from app.extensions import db
        from app.models import User
        other = User(username="mustmfa", email="mustmfa@example.com", role="user")
        other.set_password("mustmfapw")
        db.session.add(other)
        db.session.commit()
        other_id = other.id

    token = _csrf(admin_client, "/users/")
    admin_client.post(f"/users/{other_id}/mfa/require", data={"csrf_token": token}, follow_redirects=True)
    admin_client.get("/logout")

    token2 = _csrf(admin_client, "/login")
    r = admin_client.post("/login", data={"username": "mustmfa", "password": "mustmfapw", "csrf_token": token2},
                          follow_redirects=True)
    assert "/users/mfa/setup" in r.request.path

    # blocked from navigating elsewhere until enrolled
    r = admin_client.get("/targets/", follow_redirects=True)
    assert "/users/mfa/setup" in r.request.path
