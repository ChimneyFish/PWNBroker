"""Tests for the ad_domain target type (BloodHound CE integration) via the
real /targets/new route, mirroring tests/test_targets_local_path.py."""
import re


def _csrf_token(client, path="/targets/new"):
    r = client.get(path)
    return re.search(r'name="csrf-token" content="([^"]+)"', r.data.decode()).group(1)


def test_creating_ad_domain_target_via_route_succeeds(app, admin_client):
    token = _csrf_token(admin_client)
    r = admin_client.post("/targets/new", data={
        "name": "corp-ad", "host": "corp.local",
        "target_type": "ad_domain", "ad_dc_host": "10.0.0.1",
        "ad_username": "svc_bloodhound", "ad_auth_type": "password",
        "ad_password": "hunter2", "csrf_token": token,
    }, follow_redirects=True)
    assert r.status_code == 200
    assert b"created" in r.data.lower()

    with app.app_context():
        from app.models import Target
        t = Target.query.filter_by(name="corp-ad").first()
        assert t is not None
        assert t.target_type == "ad_domain"
        assert t.host == "corp.local"
        assert t.ad_dc_host == "10.0.0.1"
        assert t.ad_username == "svc_bloodhound"
        assert t.ad_password == "hunter2"  # transparently decrypted via EncryptedString


def test_ad_domain_rejects_invalid_domain_host(app, admin_client):
    token = _csrf_token(admin_client)
    r = admin_client.post("/targets/new", data={
        "name": "bad-ad", "host": "not a valid domain!!",
        "target_type": "ad_domain", "ad_dc_host": "10.0.0.1",
        "ad_username": "svc_bloodhound", "csrf_token": token,
    }, follow_redirects=True)
    assert r.status_code == 200
    assert b"valid domain name" in r.data

    with app.app_context():
        from app.models import Target
        assert Target.query.filter_by(name="bad-ad").first() is None


def test_ad_domain_requires_dc_host(app, admin_client):
    token = _csrf_token(admin_client)
    r = admin_client.post("/targets/new", data={
        "name": "no-dc", "host": "corp.local",
        "target_type": "ad_domain", "ad_dc_host": "",
        "ad_username": "svc_bloodhound", "csrf_token": token,
    }, follow_redirects=True)
    assert r.status_code == 200
    assert b"domain controller" in r.data

    with app.app_context():
        from app.models import Target
        assert Target.query.filter_by(name="no-dc").first() is None


def test_ad_domain_rejects_invalid_dc_host(app, admin_client):
    token = _csrf_token(admin_client)
    r = admin_client.post("/targets/new", data={
        "name": "bad-dc", "host": "corp.local",
        "target_type": "ad_domain", "ad_dc_host": "not a valid host!!",
        "ad_username": "svc_bloodhound", "csrf_token": token,
    }, follow_redirects=True)
    assert r.status_code == 200
    assert b"domain controller" in r.data

    with app.app_context():
        from app.models import Target
        assert Target.query.filter_by(name="bad-dc").first() is None


def test_ad_password_is_encrypted_at_rest(app, admin_client):
    token = _csrf_token(admin_client)
    admin_client.post("/targets/new", data={
        "name": "encrypted-ad", "host": "corp.local",
        "target_type": "ad_domain", "ad_dc_host": "10.0.0.1",
        "ad_username": "svc_bloodhound", "ad_auth_type": "password",
        "ad_password": "supersecretpassword", "csrf_token": token,
    }, follow_redirects=True)

    with app.app_context():
        from sqlalchemy import text
        from app.extensions import db
        from app.models import Target

        t = Target.query.filter_by(name="encrypted-ad").first()
        raw = db.session.execute(
            text("SELECT ad_password FROM targets WHERE id = :id"), {"id": t.id}
        ).scalar()
        assert raw.startswith("enc:v1:")
        assert t.ad_password == "supersecretpassword"  # ORM transparently decrypts


def test_hash_auth_stores_nt_hash_not_password(app, admin_client):
    token = _csrf_token(admin_client)
    admin_client.post("/targets/new", data={
        "name": "hash-ad", "host": "corp.local",
        "target_type": "ad_domain", "ad_dc_host": "10.0.0.1",
        "ad_username": "svc_bloodhound", "ad_auth_type": "hash",
        "ad_nt_hash": "aabbccddeeff00112233445566778899", "csrf_token": token,
    }, follow_redirects=True)

    with app.app_context():
        from app.models import Target
        t = Target.query.filter_by(name="hash-ad").first()
        assert t.ad_auth_type == "hash"
        assert t.ad_nt_hash == "aabbccddeeff00112233445566778899"
        assert t.ad_password is None
