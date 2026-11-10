import json
import os
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app import licensing
from license_helpers import make_license

HTML = {"Accept": "text/html"}


def _install(app, text):
    with open(os.path.join(app.config["LICENSE_DIR"], "license.key"), "w") as f:
        f.write(text)


def _remove(app):
    os.remove(os.path.join(app.config["LICENSE_DIR"], "license.key"))


# ── status states ────────────────────────────────────────────────────────────

def test_valid_license(app):
    st = licensing.status(app)
    assert st.state == "valid" and st.full_access and st.customer == "Test Co"


def test_expiring_within_30_days(app):
    _install(app, make_license(days=10))
    st = licensing.status(app)
    assert st.state == "expiring" and st.full_access and st.days_left == 10


def test_expiry_day_itself_is_still_valid(app):
    _install(app, make_license(days=0))
    assert licensing.status(app).full_access


def test_grace_period_is_read_only(app):
    _install(app, make_license(days=-3))
    st = licensing.status(app)
    assert st.state == "grace" and st.read_only and not st.full_access


def test_locked_after_grace(app):
    _install(app, make_license(days=-15))
    assert licensing.status(app).locked


def test_missing_license_locks(app):
    _remove(app)
    st = licensing.status(app)
    assert st.locked and "No license" in st.message


def test_tampered_expiry_rejected(app):
    text = make_license(days=-100)
    body = text.splitlines()[1]
    p, s = body.split(".")
    import base64
    payload = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    payload["expires"] = "2099-01-01"
    forged = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    _install(app, text.replace(p, forged))
    st = licensing.status(app)
    assert st.locked and "signature" in st.message


def test_license_signed_by_other_key_rejected(app):
    _install(app, make_license(key=Ed25519PrivateKey.generate()))
    assert licensing.status(app).locked


def test_install_binding(app):
    _install(app, make_license(install_id="WRONG-ID"))
    assert licensing.status(app).locked
    _install(app, make_license(install_id=licensing.install_id(app)))
    assert licensing.status(app).full_access


def test_clock_rollback_detected(app):
    now = datetime.now(timezone.utc)
    assert licensing.status(app, now=now).full_access
    assert licensing.status(app, now=now - timedelta(hours=1)).full_access   # small drift ok
    assert licensing.status(app, now=now - timedelta(days=5)).locked


# ── enforcement ──────────────────────────────────────────────────────────────

def test_locked_redirects_pages_to_license(app, admin_client):
    _remove(app)
    r = admin_client.get("/vulns/", headers=HTML)
    assert r.status_code == 302 and r.headers["Location"].endswith("/license/")
    assert admin_client.get("/license/", headers=HTML).status_code == 200


def test_locked_api_returns_402_json(app, admin_client):
    _remove(app)
    r = admin_client.get("/api/dashboard/stats")
    assert r.status_code == 402 and r.get_json()["ok"] is False


def test_login_and_health_reachable_when_locked(app, client):
    _remove(app)
    assert client.get("/login").status_code == 200
    assert client.get("/healthz").status_code == 200


def test_grace_allows_reads_blocks_writes(app, admin_client):
    _install(app, make_license(days=-2))
    assert admin_client.get("/vulns/", headers=HTML).status_code == 200
    r = admin_client.post("/vulns/tickets/1/update", data={"status": "patched"})
    assert r.status_code == 402 and "read-only" in r.get_json()["error"]


def test_grace_lets_agents_report(app, client):
    _install(app, make_license(days=-2))
    r = client.post("/threat/api/heartbeat", json={})
    assert r.status_code != 402   # reaches the agent auth check instead


def test_locked_blocks_agents(app, client):
    _remove(app)
    assert client.post("/threat/api/heartbeat", json={}).status_code == 402


def test_upload_valid_license_unlocks(app, admin_client):
    _remove(app)
    r = admin_client.post("/license/", data={"license_text": make_license(days=365, customer="Acme")})
    assert r.status_code == 302
    st = licensing.status(app)
    assert st.full_access and st.customer == "Acme"
    assert admin_client.get("/vulns/", headers=HTML).status_code == 200


def test_upload_invalid_license_keeps_old_one(app, admin_client):
    admin_client.post("/license/", data={"license_text": make_license(key=Ed25519PrivateKey.generate())})
    assert licensing.status(app).customer == "Test Co"


def test_non_admin_cannot_install(app, client):
    with app.app_context():
        from app.extensions import db
        from app.models import User
        u = User(username="viewer", email="v@example.com", role="user")
        u.set_password("pw-123456789")
        db.session.add(u); db.session.commit()
    client.post("/login", data={"username": "viewer", "password": "pw-123456789"})
    client.post("/license/", data={"license_text": make_license(customer="Evil")})
    assert licensing.status(app).customer == "Test Co"


def test_expiring_banner_shown_to_admin(app, admin_client):
    _install(app, make_license(days=5))
    html = admin_client.get("/vulns/", headers=HTML).get_data(as_text=True)
    assert "License expires in 5 day(s)" in html


def test_scheduled_jobs_skip_without_license(app):
    calls = []
    def job(): calls.append(1)
    wrapped = licensing.licensed_job(app, job)
    wrapped(); assert calls == [1]
    _install(app, make_license(days=-2))
    wrapped(); assert calls == [1]
