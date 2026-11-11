import io
import json
import os
import tarfile

import pytest


@pytest.fixture
def data_dir(app, tmp_path):
    d = tmp_path / "upd"
    d.mkdir()
    app.config["UPDATE_DATA_DIR"] = str(d)
    return d


def test_page_renders_with_version(admin_client, data_dir):
    from app.version import __version__
    r = admin_client.get("/updates/")
    assert r.status_code == 200 and __version__ in r.get_data(as_text=True)


def test_page_shows_available_update(admin_client, data_dir):
    (data_dir / "update_status.json").write_text(json.dumps({
        "state": "available", "message": "Version 1.2.0 is available.",
        "available": {"version": "1.2.0", "changelog": "Faster scans"}}))
    html = admin_client.get("/updates/").get_data(as_text=True)
    assert "Install 1.2.0 now" in html and "Faster scans" in html


def test_save_settings(admin_client, data_dir):
    admin_client.post("/updates/settings", data={"channel": "beta", "window_start": "1", "window_end": "4"})
    s = json.loads((data_dir / "update_settings.json").read_text())
    assert s == {"auto_update": False, "channel": "beta", "window_start": 1, "window_end": 4}


def test_settings_reject_bad_values(admin_client, data_dir):
    admin_client.post("/updates/settings", data={"auto_update": "on", "channel": "nightly",
                                                 "window_start": "99", "window_end": "x"})
    s = json.loads((data_dir / "update_settings.json").read_text())
    assert s == {"auto_update": True, "channel": "stable", "window_start": 23, "window_end": 5}


def test_check_and_install_write_request(admin_client, data_dir):
    admin_client.post("/updates/check")
    assert json.loads((data_dir / "update_request.json").read_text()) == {"action": "check"}
    admin_client.post("/updates/install")
    assert json.loads((data_dir / "update_request.json").read_text()) == {"action": "install"}


def test_offline_upload_rejects_non_bundle(admin_client, data_dir):
    admin_client.post("/updates/offline", data={"bundle": (io.BytesIO(b"nope"), "x.pwnupdate")},
                      content_type="multipart/form-data")
    assert not (data_dir / "update_offline.pwnupdate").exists()
    assert not (data_dir / "update_request.json").exists()


def test_offline_upload_queues_bundle(admin_client, data_dir):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for n in ("manifest.json", "manifest.sig"):
            ti = tarfile.TarInfo(n); ti.size = 2; t.addfile(ti, io.BytesIO(b"{}"))
    buf.seek(0)
    admin_client.post("/updates/offline", data={"bundle": (buf, "r.pwnupdate")},
                      content_type="multipart/form-data")
    assert (data_dir / "update_offline.pwnupdate").exists()
    assert json.loads((data_dir / "update_request.json").read_text()) == {"action": "install_offline"}


def test_non_admin_blocked(app, client, data_dir):
    with app.app_context():
        from app.extensions import db
        from app.models import User
        u = User(username="u1", email="u1@example.com", role="user")
        u.set_password("pw-123456789")
        db.session.add(u); db.session.commit()
    client.post("/login", data={"username": "u1", "password": "pw-123456789"})
    client.post("/updates/install")
    assert not (data_dir / "update_request.json").exists()
