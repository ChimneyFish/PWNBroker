"""Updater: signed-release verification, install, rollback, scheduling."""
import base64
import hashlib
import io
import json
import os
import sqlite3
import sys
import tarfile
from datetime import datetime

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "updater"))
import pwnbroker_updater as pu  # noqa: E402

KEY = Ed25519PrivateKey.generate()
PUB = KEY.public_key().public_bytes(serialization.Encoding.PEM,
                                    serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def make_release(tmp, version, files, key=KEY, channel="stable", tamper=False):
    """Build (manifest_bytes, sig_b64, archive_path) like build_release.py does."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for name, content in files.items():
            data = content.encode()
            ti = tarfile.TarInfo(name); ti.size = len(data); ti.mode = 0o644
            t.addfile(ti, io.BytesIO(data))
    blob = buf.getvalue()
    archive = os.path.join(tmp, f"rel-{version}.tar.gz")
    open(archive, "wb").write(blob + (b"x" if tamper else b""))
    manifest = {"product": "pwnbroker", "version": version, "channel": channel,
                "file": f"pwnbroker-{version}.tar.gz", "sha256": hashlib.sha256(blob).hexdigest(),
                "files": sorted(files), "changelog": f"notes for {version}"}
    raw = json.dumps(manifest, indent=2, sort_keys=True).encode()
    return raw, base64.b64encode(key.sign(raw)).decode(), archive


def version_py(v):
    return f'__version__ = "{v}"\n'


class FakeUpdater(pu.Updater):
    healthy = True
    pip_calls = 0

    def systemctl(self, *a):
        self.calls = getattr(self, "calls", []) + [a[0]]

    def wait_healthy(self, timeout=0):
        return self.healthy

    def pip_install(self):
        self.pip_calls += 1


@pytest.fixture
def install(tmp_path):
    d = tmp_path / "PWNBroker"
    (d / "app").mkdir(parents=True)
    (d / "data").mkdir()
    (d / "venv").mkdir()
    (d / "app" / "version.py").write_text(version_py("1.0.0"))
    (d / "app" / "old_module.py").write_text("old = True\n")
    (d / "app" / "main.py").write_text("v1\n")
    (d / "requirements.txt").write_text("Flask==3.1.3\n")
    (d / "venv" / "marker").write_text("keep me")
    (d / ".env").write_text(f"DATABASE_URL=sqlite:///{d}/data/scanner.db\n")
    (d / "data" / "license.key").write_text("LICENSE")
    con = sqlite3.connect(d / "data" / "scanner.db")
    con.execute("CREATE TABLE scans (id INTEGER, status TEXT)")
    con.execute("CREATE TABLE marker (v TEXT)"); con.execute("INSERT INTO marker VALUES ('before')")
    con.commit(); con.close()
    (d / ".release_files").write_text(json.dumps(["app/main.py", "app/old_module.py", "app/version.py",
                                                  "requirements.txt"]))
    u = FakeUpdater(str(d), backup_dir=str(tmp_path / "backups"), public_key_pem=PUB)
    return u, d, tmp_path


NEW_FILES = {"app/version.py": version_py("1.1.0"), "app/main.py": "v2\n",
             "requirements.txt": "Flask==3.1.3\n", "app/new_module.py": "new = True\n"}


def test_successful_install(install):
    u, d, tmp = install
    raw, sig, arc = make_release(str(tmp), "1.1.0", NEW_FILES)
    u.install(raw, sig, arc)
    assert u.current_version() == "1.1.0"
    assert (d / "app" / "main.py").read_text() == "v2\n"
    assert (d / "app" / "new_module.py").exists()
    assert not (d / "app" / "old_module.py").exists()        # dropped from the release
    assert (d / "venv" / "marker").read_text() == "keep me"   # runtime state untouched
    assert (d / "data" / "license.key").exists()
    assert u.pip_calls == 0                                   # requirements unchanged
    assert u.calls == ["stop", "start"]
    st = u.status()
    assert st["state"] == "installed" and "1.0.0 → 1.1.0" in st["message"]
    assert len(os.listdir(tmp / "backups")) == 1


def test_requirements_change_runs_pip(install):
    u, d, tmp = install
    raw, sig, arc = make_release(str(tmp), "1.1.0", {**NEW_FILES, "requirements.txt": "Flask==9.9.9\n"})
    u.install(raw, sig, arc)
    assert u.pip_calls == 1


def test_bad_signature_refused_before_touching_anything(install):
    u, d, tmp = install
    raw, sig, arc = make_release(str(tmp), "1.1.0", NEW_FILES, key=Ed25519PrivateKey.generate())
    with pytest.raises(pu.UpdateError, match="signature"):
        u.install(raw, sig, arc)
    assert u.current_version() == "1.0.0" and not hasattr(u, "calls")


def test_edited_manifest_refused(install):
    u, d, tmp = install
    raw, sig, arc = make_release(str(tmp), "1.1.0", NEW_FILES)
    with pytest.raises(pu.UpdateError, match="signature"):
        u.install(raw.replace(b"1.1.0", b"9.9.9"), sig, arc)


def test_tampered_archive_refused(install):
    u, d, tmp = install
    raw, sig, arc = make_release(str(tmp), "1.1.0", NEW_FILES, tamper=True)
    with pytest.raises(pu.UpdateError, match="checksum"):
        u.install(raw, sig, arc)
    assert u.current_version() == "1.0.0"


def test_downgrade_refused(install):
    u, d, tmp = install
    raw, sig, arc = make_release(str(tmp), "0.9.0", {"app/version.py": version_py("0.9.0")})
    with pytest.raises(pu.UpdateError, match="not newer"):
        u.install(raw, sig, arc)


def test_unhealthy_update_rolls_back_code_and_database(install):
    u, d, tmp = install
    u.healthy = False

    orig_apply = u.apply
    def apply_and_migrate(archive, manifest):
        orig_apply(archive, manifest)
        con = sqlite3.connect(d / "data" / "scanner.db")   # the "new version" migrates the DB
        con.execute("UPDATE marker SET v = 'after'"); con.commit(); con.close()
    u.apply = apply_and_migrate

    raw, sig, arc = make_release(str(tmp), "1.1.0", NEW_FILES)
    with pytest.raises(pu.UpdateError):
        u.install(raw, sig, arc)

    assert u.current_version() == "1.0.0"
    assert (d / "app" / "main.py").read_text() == "v1\n"
    assert (d / "app" / "old_module.py").exists()
    assert not (d / "app" / "new_module.py").exists()
    con = sqlite3.connect(d / "data" / "scanner.db")
    assert con.execute("SELECT v FROM marker").fetchone()[0] == "before"
    assert u.status()["state"] == "rolled_back"
    assert u.calls[-1] == "start"


def test_offline_bundle(install):
    u, d, tmp = install
    raw, sig, arc = make_release(str(tmp), "1.1.0", NEW_FILES)
    bundle = tmp / "x.pwnupdate"
    with tarfile.open(bundle, "w") as t:
        for name, data in (("manifest.json", raw), ("manifest.sig", sig.encode()),
                           ("pwnbroker-1.1.0.tar.gz", open(arc, "rb").read())):
            ti = tarfile.TarInfo(name); ti.size = len(data); t.addfile(ti, io.BytesIO(data))
    u.install_offline(str(bundle))
    assert u.current_version() == "1.1.0"


def test_path_traversal_member_not_written_outside(install):
    u, d, tmp = install
    raw, sig, arc = make_release(str(tmp), "1.1.0", {**NEW_FILES, "../escape.txt": "x"})
    try:
        u.install(raw, sig, arc)
    except pu.UpdateError:
        pass
    assert not (tmp / "escape.txt").exists()


def test_maintenance_window():
    u = pu.Updater.__new__(pu.Updater)
    s = {"window_start": 2, "window_end": 5}
    assert u.in_window(s, datetime(2026, 1, 1, 3))
    assert not u.in_window(s, datetime(2026, 1, 1, 6))
    wrap = {"window_start": 23, "window_end": 3}
    assert u.in_window(wrap, datetime(2026, 1, 1, 1)) and not u.in_window(wrap, datetime(2026, 1, 1, 12))


def _server_info(tmp, version="1.1.0"):
    raw, sig, arc = make_release(str(tmp), version, NEW_FILES)
    return {"update": True, "version": version, "changelog": "c", "manifest": raw.decode(),
            "signature": sig, "download": "/dl"}, arc


def test_run_respects_auto_update_off(install):
    u, d, tmp = install
    info, arc = _server_info(tmp)
    u.check = lambda ch: info
    (d / "data" / "update_settings.json").write_text(json.dumps({"auto_update": False}))
    u.run()
    assert u.current_version() == "1.0.0" and u.status()["state"] == "available"


def test_run_manual_request_installs_outside_window(install):
    u, d, tmp = install
    info, arc = _server_info(tmp)
    u.check = lambda ch: info
    u.download = lambda path, dest: open(dest, "wb").write(open(arc, "rb").read())
    (d / "data" / "update_settings.json").write_text(json.dumps({"auto_update": False}))
    (d / "data" / "update_request.json").write_text(json.dumps({"action": "install"}))
    u.run()
    assert u.current_version() == "1.1.0"
    assert not (d / "data" / "update_request.json").exists()


def test_run_auto_waits_for_running_scans(install):
    u, d, tmp = install
    info, arc = _server_info(tmp)
    u.check = lambda ch: info
    con = sqlite3.connect(d / "data" / "scanner.db")
    con.execute("INSERT INTO scans VALUES (1, 'running')"); con.commit(); con.close()
    h = datetime.now().hour
    (d / "data" / "update_settings.json").write_text(json.dumps(
        {"auto_update": True, "window_start": h, "window_end": (h + 1) % 24}))
    u.run()
    assert u.current_version() == "1.0.0" and "running scans" in u.status()["message"]


def test_run_rejects_garbage_version_from_server(install):
    u, d, tmp = install
    u.check = lambda ch: {"update": True, "version": "<script>", "manifest": "", "signature": ""}
    u.run()
    assert u.status()["state"] == "error"


def test_settings_validation(install):
    u, d, tmp = install
    (d / "data" / "update_settings.json").write_text(json.dumps(
        {"auto_update": "yes", "channel": "evil", "window_start": 99}))
    assert u.settings() == {"auto_update": True, "channel": "stable", "window_start": 2, "window_end": 5}


def test_health_url_from_unit(tmp_path):
    unit = tmp_path / "u.service"
    unit.write_text("ExecStart=/x/gunicorn \\\n    --bind 0.0.0.0:8443 \\\n    --certfile c.pem\n")
    u = pu.Updater.__new__(pu.Updater); u.unit_file = str(unit)
    assert u.health_url() == "https://127.0.0.1:8443/healthz"
