"""Single-file installer: tools/release/build_release.py make_installer +
the self-checks in installer_header.sh + the update server's /v1/installer."""
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools", "release"))
sys.path.insert(0, os.path.join(ROOT, "update_server"))
import build_release as br  # noqa: E402
import server as upd  # noqa: E402

from license_helpers import TEST_PUBLIC_PEM, make_license

VERSION = "9.8.7"
needs_tools = pytest.mark.skipif(
    not all(shutil.which(t) for t in ("bash", "openssl", "sha256sum", "tar")) or
    b"OpenSSL 3" not in subprocess.run(["openssl", "version"], capture_output=True).stdout,
    reason="needs bash, OpenSSL 3, coreutils")


def _release(tmp_path, key):
    """A minimal signed release dir, shaped like `build_release.py build` output."""
    import io
    import tarfile
    d = tmp_path / VERSION
    d.mkdir()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for name, data in (("setup.sh", b"#!/bin/bash\necho setup-ran\n"),
                           ("app/version.py", f'__version__ = "{VERSION}"\n'.encode())):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    tar = buf.getvalue()
    (d / f"pwnbroker-{VERSION}.tar.gz").write_bytes(tar)
    manifest = {"product": "pwnbroker", "version": VERSION, "channel": "stable",
                "file": f"pwnbroker-{VERSION}.tar.gz", "sha256": hashlib.sha256(tar).hexdigest(),
                "requirements_sha256": "0" * 64}
    raw, sig = br.sign_manifest(key, manifest)
    (d / "manifest.json").write_bytes(raw)
    (d / "manifest.sig").write_bytes(sig)
    return d


@pytest.fixture
def built(tmp_path):
    key = Ed25519PrivateKey.generate()
    d = _release(tmp_path, key)
    path, digest = br.make_installer(str(d), VERSION, key.public_key())
    return d, path, digest


def _run(path, *args):
    return subprocess.run(["bash", path, *args], capture_output=True, text=True, timeout=60)


def test_installer_is_one_executable_file_with_checksum(built):
    d, path, digest = built
    assert os.path.basename(path) == f"pwnbroker-{VERSION}-install.run"
    assert os.access(path, os.X_OK)
    data = open(path, "rb").read()
    assert data.startswith(b"#!/usr/bin/env bash")
    assert hashlib.sha256(data).hexdigest() == digest
    assert open(path + ".sha256").read() == f"{digest}  {os.path.basename(path)}\n"
    head = data.split(b"__PWNBROKER_PAYLOAD_BELOW__\n")[0].decode()
    assert "@" + "VERSION@" not in head and f'VERSION="{VERSION}"' in head


@needs_tools
def test_check_passes_on_genuine_file(built):
    _, path, _ = built
    r = _run(path, "--check")
    assert r.returncode == 0, r.stderr
    assert "Signature valid" in r.stdout


@needs_tools
def test_extract_unpacks_release(built, tmp_path):
    _, path, _ = built
    out = tmp_path / "x"
    r = _run(path, "--extract", str(out))
    assert r.returncode == 0, r.stderr
    assert (out / "setup.sh").exists() and (out / "app" / "version.py").exists()


@needs_tools
def test_truncated_download_is_rejected(built, tmp_path):
    _, path, _ = built
    bad = tmp_path / "bad.run"
    bad.write_bytes(open(path, "rb").read()[:-100])
    r = _run(str(bad), "--check")
    assert r.returncode != 0 and "checksum mismatch" in r.stderr


@needs_tools
def test_release_signed_by_another_key_is_rejected(tmp_path):
    good, evil = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    d = _release(tmp_path, evil)                       # signed by someone else…
    path, _ = br.make_installer(str(d), VERSION, good.public_key())  # …but trusts the real key
    r = _run(path, "--check")
    assert r.returncode != 0 and "signature is INVALID" in r.stderr


@needs_tools
def test_archive_swapped_after_signing_is_rejected(tmp_path):
    key = Ed25519PrivateKey.generate()
    d = _release(tmp_path, key)
    (d / f"pwnbroker-{VERSION}.tar.gz").write_bytes(b"not the signed archive")
    path, _ = br.make_installer(str(d), VERSION, key.public_key())
    r = _run(path, "--check")
    assert r.returncode != 0 and "doesn't match its signed manifest" in r.stderr


@needs_tools
def test_bad_options_rejected_before_any_work(built):
    _, path, _ = built
    assert "--port must be" in _run(path, "--check", "--port", "0").stderr
    assert "absolute path" in _run(path, "--check", "--dir", "relative/dir").stderr
    assert "Can't read license" in _run(path, "--check", "--license", "/nonexistent").stderr


def test_help(built):
    _, path, _ = built
    r = _run(path, "--help")
    assert r.returncode == 0 and "--license FILE" in r.stdout and "#" not in r.stdout.splitlines()[0]


# ── update server download ───────────────────────────────────────────────────

@pytest.fixture
def srv(tmp_path):
    root = tmp_path / "srv"
    for v, ch, inst in (("1.0.0", "stable", True), ("1.1.0", "stable", False), ("1.2.0", "beta", True)):
        d = root / "releases" / v
        d.mkdir(parents=True)
        (d / "manifest.json").write_text(json.dumps({"version": v, "channel": ch}))
        (d / "manifest.sig").write_text("SIG")
        (d / f"pwnbroker-{v}.tar.gz").write_bytes(b"T")
        if inst:
            (d / f"pwnbroker-{v}-install.run").write_bytes(f"INSTALLER {v}".encode())
    app = upd.create_app(root=str(root), license_public_key_pem=TEST_PUBLIC_PEM)
    return app.test_client()


def test_licensed_download_gets_newest_stable_installer(srv):
    r = srv.post("/v1/installer", data=make_license(days=30))
    assert r.status_code == 200 and r.data == b"INSTALLER 1.0.0"   # 1.1.0 has no installer
    assert "pwnbroker-1.0.0-install.run" in r.headers["Content-Disposition"]


def test_beta_channel_and_json_body(srv):
    r = srv.post("/v1/installer?channel=beta", json={"license": make_license(days=30)})
    assert r.data == b"INSTALLER 1.2.0"


def test_no_or_expired_license_refused(srv):
    assert srv.post("/v1/installer", data="nope").status_code == 403
    assert srv.post("/v1/installer", data=make_license(days=-1)).status_code == 402
