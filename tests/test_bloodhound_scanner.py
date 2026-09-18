"""Tests for app/scanner/bloodhound_scanner.py (Phase 1: collector only —
the ingest/hunting-query pipeline is Phase 2, see the project plan).

No real bloodhound-ce-python binary is used — subprocess.run is mocked.
A real run against an actual AD lab domain was done manually during
development; that can't be part of the automated suite since it needs live
AD infrastructure CI shouldn't depend on, same reasoning as
test_reaper_scanner.py's own docstring.
"""
import os
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from app.scanner import bloodhound_scanner as bh


def _make_target(**overrides):
    defaults = dict(
        host="corp.local", target_type="ad_domain",
        ad_dc_host="10.0.0.1", ad_username="svc_bloodhound",
        ad_auth_type="password", ad_password="hunter2", ad_nt_hash=None,
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


# ── _find_collector_binary ────────────────────────────────────────────────

def test_find_collector_binary_uses_env_override(tmp_path, monkeypatch):
    fake_bin = tmp_path / "bloodhound-ce-python"
    fake_bin.write_text("#!/bin/sh\necho hi\n")
    os.chmod(fake_bin, 0o755)
    monkeypatch.setenv("BLOODHOUND_COLLECTOR_BINARY", str(fake_bin))
    assert bh._find_collector_binary() == str(fake_bin)


def test_find_collector_binary_falls_back_to_path(monkeypatch):
    monkeypatch.delenv("BLOODHOUND_COLLECTOR_BINARY", raising=False)
    with patch.object(bh.shutil, "which", return_value="/usr/bin/bloodhound-ce-python"):
        assert bh._find_collector_binary() == "/usr/bin/bloodhound-ce-python"


def test_find_collector_binary_returns_none_when_nothing_found(monkeypatch):
    monkeypatch.delenv("BLOODHOUND_COLLECTOR_BINARY", raising=False)
    with patch.object(bh.shutil, "which", return_value=None):
        assert bh._find_collector_binary() is None


# ── run_collection: validation ────────────────────────────────────────────

class TestRunCollectionValidation:
    def test_requires_dc_host(self):
        result = bh.run_collection(_make_target(ad_dc_host=""))
        assert "error" in result

    def test_requires_username(self):
        result = bh.run_collection(_make_target(ad_username=""))
        assert "error" in result

    def test_password_auth_requires_password(self):
        result = bh.run_collection(_make_target(ad_auth_type="password", ad_password=""))
        assert "error" in result
        assert "password" in result["error"].lower()

    def test_hash_auth_requires_hash(self):
        result = bh.run_collection(_make_target(ad_auth_type="hash", ad_nt_hash=""))
        assert "error" in result
        assert "hash" in result["error"].lower()

    def test_missing_binary_reports_error(self):
        with patch.object(bh, "_find_collector_binary", return_value=None):
            result = bh.run_collection(_make_target())
        assert "error" in result
        assert "bloodhound-ce-python" in result["error"]


# ── run_collection: subprocess driving ────────────────────────────────────

class TestRunCollectionSubprocess:
    def test_success_finds_produced_zip(self):
        def fake_run(args, cwd, capture_output, text, timeout):
            with open(os.path.join(cwd, "collection_20260101.zip"), "wb") as f:
                f.write(b"PK\x03\x04fakezipcontent")
            result = MagicMock()
            result.stderr = ""
            result.stdout = ""
            return result

        with patch.object(bh, "_find_collector_binary", return_value="/fake/bloodhound-ce-python"):
            with patch.object(bh.subprocess, "run", side_effect=fake_run):
                result = bh.run_collection(_make_target())

        assert "zip_path" in result
        assert result["zip_path"].endswith(".zip")
        assert os.path.isfile(result["zip_path"])
        bh.shutil.rmtree(result["work_dir"], ignore_errors=True)

    def test_password_auth_passes_password_flag(self):
        captured = {}

        def fake_run(args, cwd, capture_output, text, timeout):
            captured["args"] = args
            result = MagicMock()
            result.stderr = ""
            result.stdout = ""
            return result

        with patch.object(bh, "_find_collector_binary", return_value="/fake/bloodhound-ce-python"):
            with patch.object(bh.subprocess, "run", side_effect=fake_run):
                bh.run_collection(_make_target(ad_password="hunter2"))

        assert "-p" in captured["args"]
        assert "hunter2" in captured["args"]
        assert "--hashes" not in captured["args"]

    def test_hash_auth_passes_hashes_flag_not_password(self):
        captured = {}

        def fake_run(args, cwd, capture_output, text, timeout):
            captured["args"] = args
            result = MagicMock()
            result.stderr = ""
            result.stdout = ""
            return result

        with patch.object(bh, "_find_collector_binary", return_value="/fake/bloodhound-ce-python"):
            with patch.object(bh.subprocess, "run", side_effect=fake_run):
                bh.run_collection(_make_target(ad_auth_type="hash", ad_nt_hash="aabbccddeeff00112233445566778899"))

        assert "--hashes" in captured["args"]
        assert ":aabbccddeeff00112233445566778899" in captured["args"]
        assert "-p" not in captured["args"]

    def test_no_zip_produced_is_reported_as_error(self):
        def fake_run(args, cwd, capture_output, text, timeout):
            result = MagicMock()
            result.stderr = "LDAP bind failed: invalid credentials"
            result.stdout = ""
            return result

        with patch.object(bh, "_find_collector_binary", return_value="/fake/bloodhound-ce-python"):
            with patch.object(bh.subprocess, "run", side_effect=fake_run):
                result = bh.run_collection(_make_target())

        assert "error" in result
        assert "invalid credentials" in result["error"]

    def test_timeout_is_reported_as_error(self):
        import subprocess as sp

        def fake_run(args, cwd, capture_output, text, timeout):
            raise sp.TimeoutExpired(cmd=args, timeout=timeout)

        with patch.object(bh, "_find_collector_binary", return_value="/fake/bloodhound-ce-python"):
            with patch.object(bh.subprocess, "run", side_effect=fake_run):
                result = bh.run_collection(_make_target())

        assert "error" in result
        assert "minute budget" in result["error"]


# ── run_bloodhound_scan ────────────────────────────────────────────────────

class TestRunBloodhoundScan:
    def test_rejects_non_ad_domain_target(self):
        target = _make_target(target_type="host")
        findings = bh.run_bloodhound_scan(scan=None, target=target)
        assert len(findings) == 1
        assert "requires an AD Domain target" in findings[0]["title"]

    def test_rejects_none_target(self):
        findings = bh.run_bloodhound_scan(scan=None, target=None)
        assert len(findings) == 1
        assert findings[0]["result_type"] == "info"

    def test_collection_failure_surfaces_as_info_result(self):
        with patch.object(bh, "run_collection", return_value={"error": "bad creds"}):
            findings = bh.run_bloodhound_scan(scan=None, target=_make_target())
        assert len(findings) == 1
        assert findings[0]["severity"] == "info"
        assert "bad creds" in findings[0]["description"]

    def test_collection_success_reports_collected_data(self, tmp_path):
        # A dedicated subdirectory, not tmp_path itself — run_bloodhound_scan
        # rmtree()s work_dir when it's done with it.
        work_dir = tmp_path / "collected"
        work_dir.mkdir()
        zip_path = work_dir / "collection.zip"
        zip_path.write_bytes(b"x" * 1234)
        with patch.object(bh, "run_collection", return_value={
            "zip_path": str(zip_path), "work_dir": str(work_dir),
        }):
            findings = bh.run_bloodhound_scan(scan=None, target=_make_target())
        assert len(findings) == 1
        assert "1234" in findings[0]["description"]
        assert findings[0]["result_type"] == "info"  # Phase 2 will make this a real analysis
