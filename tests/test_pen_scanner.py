"""Tests for the PEN scan-type integration (app/scanner/pen_scanner.py).

No real PEN binary or network access is used here — the stdout parser is
tested directly against fixture text, and the pexpect-driving path is tested
with pexpect.spawn mocked out. A real end-to-end run against the actual PEN
binary was done manually during development (see docs/deployment.md); that
can't be part of the automated suite since it requires building PEN's Go
binary and isn't something CI should depend on.
"""
import os
import stat
from unittest.mock import patch, MagicMock

import pexpect

from app.scanner import pen_scanner


# ── _parse_output ────────────────────────────────────────────────────────

def test_parse_output_classifies_markers_correctly():
    raw = (
        "\n[+] Starting IDOR enumeration on /api/users/{id}\n"
        "[-] User 1 returned status 404\n"
        "[*] Response status: 404\n"
        "[!] Vulnerability confirmed: Unauthenticated access to user profiles (IDOR).\n"
    )
    findings = pen_scanner._parse_output(raw, host="example.com", truncated=False)

    vuln = [f for f in findings if f["result_type"] == "vulnerability"]
    info = [f for f in findings if f["result_type"] == "info"]

    assert len(vuln) == 1
    assert vuln[0]["severity"] == "high"
    assert "Vulnerability confirmed" in vuln[0]["title"]
    assert vuln[0]["host"] == "example.com"

    # One low-severity info result for the [+] line, plus the always-present
    # full-transcript rollup record.
    assert any(f["severity"] == "low" and "Starting IDOR enumeration" in f["title"] for f in info)
    assert any(f["title"] == "PEN — Full Scan Transcript" for f in info)

    # [-] and [*] lines never become their own individual results.
    assert not any("404" in f.get("title", "") for f in findings if f is not vuln[0])


def test_parse_output_excludes_dash_and_star_lines_from_individual_results():
    raw = "[-] Something failed\n[*] Just a status update\n"
    findings = pen_scanner._parse_output(raw, host="h", truncated=False)
    # Only the rollup transcript record should exist — no per-line results
    # for [-]/[*].
    assert len(findings) == 1
    assert findings[0]["title"] == "PEN — Full Scan Transcript"


def test_parse_output_empty_input_returns_no_findings():
    assert pen_scanner._parse_output("", host="h", truncated=False) == []
    assert pen_scanner._parse_output("   \n  \n", host="h", truncated=False) == []


def test_parse_output_truncated_adds_note_and_marks_transcript():
    raw = "[+] Partial progress\n"
    findings = pen_scanner._parse_output(raw, host="h", truncated=True)
    titles = [f["title"] for f in findings]
    assert "PEN scan truncated by timeout" in titles
    assert any("truncated by timeout" in t for t in titles if "Transcript" in t)


# ── _find_pen_binary ─────────────────────────────────────────────────────

def test_find_pen_binary_uses_env_override(tmp_path, monkeypatch):
    fake_bin = tmp_path / "pen"
    fake_bin.write_text("#!/bin/sh\necho hi\n")
    fake_bin.chmod(fake_bin.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PEN_BINARY", str(fake_bin))
    assert pen_scanner._find_pen_binary() == str(fake_bin)


def test_find_pen_binary_ignores_non_executable_override(tmp_path, monkeypatch):
    fake_bin = tmp_path / "pen"
    fake_bin.write_text("not executable")
    monkeypatch.setenv("PEN_BINARY", str(fake_bin))
    # Falls through to the default path, which won't exist in the test env.
    assert pen_scanner._find_pen_binary() != str(fake_bin)


def test_find_pen_binary_returns_none_when_nothing_found(monkeypatch):
    monkeypatch.delenv("PEN_BINARY", raising=False)
    monkeypatch.setattr(pen_scanner, "_DEFAULT_BINARY", pen_scanner.Path("/nonexistent/pen"))
    assert pen_scanner._find_pen_binary() is None


# ── run_pen_scan ──────────────────────────────────────────────────────────

def test_run_pen_scan_graceful_when_binary_missing(monkeypatch):
    monkeypatch.setattr(pen_scanner, "_find_pen_binary", lambda: None)
    findings = pen_scanner.run_pen_scan("https://example.com", "example.com", token=None)
    assert len(findings) == 1
    assert findings[0]["title"] == "PEN binary not found"
    assert findings[0]["severity"] == "info"


def test_run_pen_scan_timeout_still_parses_partial_output(monkeypatch):
    monkeypatch.setattr(pen_scanner, "_find_pen_binary", lambda: "/fake/pen")

    mock_child = MagicMock()
    mock_child.isalive.return_value = True

    def fake_expect(*args, **kwargs):
        # Simulate PEN having printed some real output before hanging.
        mock_child.logfile_read.write(
            "[+] Starting IDOR enumeration\n[!] Vulnerability confirmed: IDOR.\n"
        )
        raise pexpect.TIMEOUT("simulated hang")

    mock_child.expect.side_effect = fake_expect

    with patch("app.scanner.pen_scanner.pexpect.spawn", return_value=mock_child):
        findings = pen_scanner.run_pen_scan("https://example.com", "example.com", token="tok")

    assert any(f["title"] == "PEN scan truncated by timeout" for f in findings)
    assert any(f["severity"] == "high" for f in findings)
    mock_child.terminate.assert_called_once_with(force=True)


def test_run_pen_scan_full_happy_path_sends_expected_sequence(monkeypatch):
    """Verifies the exact prompt-answer sequence: URL, token, '11' (Run All),
    then '12' (exit) once the menu reappears — without a real PEN process."""
    monkeypatch.setattr(pen_scanner, "_find_pen_binary", lambda: "/fake/pen")

    mock_child = MagicMock()
    mock_child.isalive.return_value = False
    # expect() call sequence: target prompt, token prompt, menu prompt,
    # then the loop's [yesno/menu/EOF] expect — return "menu" (index 1) to
    # simulate Run All Scans finishing immediately, then EOF after exit.
    mock_child.expect.side_effect = [None, None, None, 1, None]

    with patch("app.scanner.pen_scanner.pexpect.spawn", return_value=mock_child):
        pen_scanner.run_pen_scan("https://example.com", "example.com", token="secret-token")

    sent_lines = [call.args[0] for call in mock_child.sendline.call_args_list]
    assert sent_lines == ["https://example.com", "secret-token", "11", "12"]
