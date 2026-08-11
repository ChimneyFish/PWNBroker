"""Tests for the REAPER GitHub secret-scan integration (app/scanner/reaper_scanner.py).

No real REAPER binary or GitHub API access is used here — the JSONL parser
is tested directly against fixture files, and the subprocess-driving path is
tested with subprocess.run mocked out. A real build + a live run against the
actual REAPER binary (with a real GITHUB_TOKEN) was done manually during
development; that can't be part of the automated suite since it needs a real
GitHub token and network access CI shouldn't depend on.
"""
import json
import os
import stat
from unittest.mock import patch, MagicMock

from app.scanner import reaper_scanner


# ── _parse_findings ──────────────────────────────────────────────────────

def _write_jsonl(path, lines):
    with open(path, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")


def test_parse_findings_maps_fields_correctly(tmp_path):
    jsonl = tmp_path / "reaper_findings.jsonl"
    _write_jsonl(jsonl, [
        json.dumps({
            "id": "1", "repository": "owner/repo", "file_path": "config.py",
            "line_number": 12, "secret_type": "AWS Access Key",
            "secret_value": "AKIA12...XYZ890", "context": "key = AKIA...",
            "url": "https://github.com/owner/repo/blob/main/config.py",
            "branch": "main", "timestamp": "2026-01-01T00:00:00Z", "severity": "CRITICAL",
        }),
    ])
    findings = reaper_scanner._parse_findings(str(jsonl), host="owner/repo")
    assert len(findings) == 1
    f = findings[0]
    assert f["result_type"] == "vulnerability"
    assert f["severity"] == "critical"  # lowercased
    assert f["title"] == "AWS Access Key"
    assert f["host"] == "owner/repo"
    assert json.loads(f["raw_data"])["file_path"] == "config.py"


def test_parse_findings_skips_malformed_lines(tmp_path):
    jsonl = tmp_path / "reaper_findings.jsonl"
    _write_jsonl(jsonl, [
        json.dumps({"secret_type": "Slack Token", "context": "x", "severity": "HIGH"}),
        "not valid json {{{",
        "",
        json.dumps({"secret_type": "JWT Token", "context": "y", "severity": "HIGH"}),
    ])
    findings = reaper_scanner._parse_findings(str(jsonl), host="owner/repo")
    assert len(findings) == 2
    assert {f["title"] for f in findings} == {"Slack Token", "JWT Token"}


def test_parse_findings_missing_file_returns_empty(tmp_path):
    assert reaper_scanner._parse_findings(str(tmp_path / "nope.jsonl"), host="h") == []


def test_parse_findings_defaults_severity_when_absent(tmp_path):
    jsonl = tmp_path / "reaper_findings.jsonl"
    _write_jsonl(jsonl, [json.dumps({"secret_type": "Generic API Key"})])
    findings = reaper_scanner._parse_findings(str(jsonl), host="h")
    assert findings[0]["severity"] == "high"


# ── _find_reaper_binary ──────────────────────────────────────────────────

def test_find_reaper_binary_uses_env_override(tmp_path, monkeypatch):
    fake_bin = tmp_path / "reaper"
    fake_bin.write_text("#!/bin/sh\necho hi\n")
    fake_bin.chmod(fake_bin.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("REAPER_BINARY", str(fake_bin))
    assert reaper_scanner._find_reaper_binary() == str(fake_bin)


def test_find_reaper_binary_returns_none_when_nothing_found(monkeypatch):
    monkeypatch.delenv("REAPER_BINARY", raising=False)
    monkeypatch.setattr(reaper_scanner, "_DEFAULT_BINARY", reaper_scanner.Path("/nonexistent/reaper"))
    assert reaper_scanner._find_reaper_binary() is None


# ── run_reaper_scan ───────────────────────────────────────────────────────

def test_run_reaper_scan_requires_token():
    findings = reaper_scanner.run_reaper_scan("owner", "repo", token=None)
    assert len(findings) == 1
    assert findings[0]["title"] == "GitHub Token Required"
    assert findings[0]["severity"] == "info"


def test_run_reaper_scan_graceful_when_binary_missing(monkeypatch):
    monkeypatch.setattr(reaper_scanner, "_find_reaper_binary", lambda: None)
    findings = reaper_scanner.run_reaper_scan("owner", "repo", token="tok")
    assert len(findings) == 1
    assert findings[0]["title"] == "REAPER binary not found"


def test_run_reaper_scan_parses_real_output_written_by_mocked_subprocess(monkeypatch):
    """Simulates a successful run: the mocked subprocess.run 'writes' a
    findings file into the work_dir it was given, same as the real binary
    would via -output."""
    monkeypatch.setattr(reaper_scanner, "_find_reaper_binary", lambda: "/fake/reaper")

    def fake_run(args, cwd, env, capture_output, text, timeout):
        assert env["GITHUB_TOKEN"] == "secret-token"
        assert "-continuous=false" in args
        assert f"https://github.com/owner/repo" in args
        jsonl_path = os.path.join(cwd, "reaper_findings.jsonl")
        _write_jsonl(jsonl_path, [json.dumps({
            "secret_type": "Stripe Secret Key", "context": "sk_live_...",
            "severity": "CRITICAL", "file_path": "billing.py", "line_number": 5,
        })])
        result = MagicMock()
        result.stderr = ""
        return result

    with patch("app.scanner.reaper_scanner.subprocess.run", side_effect=fake_run):
        findings = reaper_scanner.run_reaper_scan("owner", "repo", token="secret-token")

    assert len(findings) == 1
    assert findings[0]["title"] == "Stripe Secret Key"
    assert findings[0]["severity"] == "critical"


def test_run_reaper_scan_surfaces_stderr_as_error_even_with_exit_0():
    """REAPER's own failure mode: auth/parse errors go to stderr but it
    still exits 0 with an empty findings file — must not look like a clean
    scan."""
    with patch("app.scanner.reaper_scanner._find_reaper_binary", return_value="/fake/reaper"):
        def fake_run(args, cwd, env, capture_output, text, timeout):
            result = MagicMock()
            result.stderr = "Failed to parse https://github.com/owner/repo: 401 Bad credentials\n"
            return result

        with patch("app.scanner.reaper_scanner.subprocess.run", side_effect=fake_run):
            findings = reaper_scanner.run_reaper_scan("owner", "repo", token="bad-token")

    assert len(findings) == 1
    assert findings[0]["title"] == "REAPER scan error"
    assert "Bad credentials" in findings[0]["description"]


def test_run_reaper_scan_timeout_still_parses_partial_output():
    import subprocess as sp

    with patch("app.scanner.reaper_scanner._find_reaper_binary", return_value="/fake/reaper"):
        def fake_run(args, cwd, env, capture_output, text, timeout):
            jsonl_path = os.path.join(cwd, "reaper_findings.jsonl")
            _write_jsonl(jsonl_path, [json.dumps({
                "secret_type": "GitHub Token", "context": "ghp_...", "severity": "CRITICAL",
            })])
            raise sp.TimeoutExpired(cmd=args, timeout=timeout)

        with patch("app.scanner.reaper_scanner.subprocess.run", side_effect=fake_run):
            findings = reaper_scanner.run_reaper_scan("owner", "repo", token="tok")

    titles = [f["title"] for f in findings]
    assert "GitHub Token" in titles
    assert "REAPER scan truncated by timeout" in titles
