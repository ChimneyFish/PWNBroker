import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "update_server"))
import server as upd  # noqa: E402

from license_helpers import TEST_PUBLIC_PEM, make_license


def publish(root, version, channel="stable", signed=True):
    d = os.path.join(root, "releases", version)
    os.makedirs(d, exist_ok=True)
    m = {"product": "pwnbroker", "version": version, "channel": channel, "changelog": f"v{version}"}
    open(os.path.join(d, "manifest.json"), "w").write(json.dumps(m))
    open(os.path.join(d, f"pwnbroker-{version}.tar.gz"), "wb").write(b"TARBALL" + version.encode())
    if signed:
        open(os.path.join(d, "manifest.sig"), "w").write("SIG")


@pytest.fixture
def srv(tmp_path):
    root = str(tmp_path)
    app = upd.create_app(root=root, license_public_key_pem=TEST_PUBLIC_PEM)
    return app.test_client(), root


def check(c, version="1.0.0", channel="stable", lic=None, install_id=""):
    return c.post("/v1/check", json={"license": lic or make_license(days=100), "version": version,
                                     "channel": channel, "install_id": install_id})


def test_offers_newest_stable_and_download_works(srv):
    c, root = srv
    publish(root, "1.1.0"); publish(root, "1.2.0"); publish(root, "1.3.0", channel="beta")
    r = check(c)
    j = r.get_json()
    assert r.status_code == 200 and j["update"] and j["version"] == "1.2.0"
    assert j["signature"] == "SIG" and json.loads(j["manifest"])["version"] == "1.2.0"
    d = c.get(j["download"])
    assert d.status_code == 200 and d.data == b"TARBALL1.2.0"


def test_beta_channel_sees_beta(srv):
    c, root = srv
    publish(root, "1.2.0"); publish(root, "1.3.0", channel="beta")
    assert check(c, channel="beta").get_json()["version"] == "1.3.0"


def test_up_to_date(srv):
    c, root = srv
    publish(root, "1.2.0")
    j = check(c, version="1.2.0").get_json()
    assert j == {"update": False, "latest": "1.2.0"}


def test_unsigned_partial_upload_not_offered(srv):
    c, root = srv
    publish(root, "1.1.0"); publish(root, "2.0.0", signed=False)
    assert check(c).get_json()["version"] == "1.1.0"


def test_yanked_release_skipped(srv):
    c, root = srv
    publish(root, "1.1.0"); publish(root, "1.2.0")
    open(os.path.join(root, "yanked.txt"), "w").write("1.2.0\n")
    assert check(c).get_json()["version"] == "1.1.0"


def test_expired_license_gets_402(srv):
    c, root = srv
    publish(root, "1.1.0")
    r = check(c, lic=make_license(days=-1))
    assert r.status_code == 402 and "renew" in r.get_json()["error"]


def test_forged_license_rejected(srv):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    c, root = srv
    assert check(c, lic=make_license(key=Ed25519PrivateKey.generate())).status_code == 403


def test_revoked_license(srv):
    c, root = srv
    publish(root, "1.1.0")
    lic = make_license(license_id="L-123")
    open(os.path.join(root, "revoked.txt"), "w").write("L-123\n")
    assert check(c, lic=lic).status_code == 403


def test_install_binding(srv):
    c, root = srv
    publish(root, "1.1.0")
    lic = make_license(install_id="AAAA-BBBB")
    assert check(c, lic=lic, install_id="OTHER").status_code == 403
    assert check(c, lic=lic, install_id="AAAA-BBBB").status_code == 200


def test_download_token_tamper_and_cross_version(srv):
    c, root = srv
    publish(root, "1.1.0"); publish(root, "1.2.0")
    url = check(c).get_json()["download"]
    assert c.get(url[:-1] + ("0" if url[-1] != "0" else "1")).status_code == 403
    assert c.get(url.replace("1.2.0", "1.1.0")).status_code == 403


def test_checkins_recorded(srv):
    import sqlite3
    c, root = srv
    check(c, lic=make_license(customer="Acme", license_id="L-9"), version="1.0.0", install_id="ID1")
    row = sqlite3.connect(os.path.join(root, "checkins.db")).execute(
        "SELECT customer, version, install_id FROM checkins").fetchone()
    assert row == ("Acme", "1.0.0", "ID1")


def test_routes_served_under_url_prefix(tmp_path):
    c = upd.create_app(root=str(tmp_path), license_public_key_pem=TEST_PUBLIC_PEM,
                       prefix="/updates").test_client()
    assert c.get("/updates/v1/health").get_json() == {"ok": True}
    assert c.get("/v1/health").get_json() == {"ok": True}
    assert c.get("/updatesX/v1/health").status_code == 404
