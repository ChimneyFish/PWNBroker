"""Tests for the Backdoor Detector integration (app/scanner/backdoor_scanner.py).

No real backdoor_detector.py or third-party dependency scanners (Safety,
Trivy, pip-audit, npm audit) are used here — subprocess.run is mocked out and
fed fixture JSON matching the real shape printed by
_backdoor_detector_runner.py (verified against the runner's actual output
during manual development). A real end-to-end run — real tool clone, real
runner subprocess, real YARA/secret/dependency scan — was done manually via
the actual /backdoor routes; that can't be part of the automated suite since
it needs the vendored tools/backdoor_detector/ checkout this repo doesn't
ship in git.
"""
import json
import subprocess as sp
from unittest.mock import patch, MagicMock

from app.scanner import backdoor_scanner


def _runner_stdout(findings=None, checklist=None):
    return json.dumps({"findings": findings or [], "checklist": checklist or []})


# ── _map_finding ──────────────────────────────────────────────────────────

def test_map_finding_maps_fields_and_lowercases_severity():
    f = {
        "type": "hardcoded_secret", "severity": "HIGH", "file": "config.py",
        "line_number": 12, "description": "AWS Access Key found", "rule": "",
    }
    mapped = backdoor_scanner._map_finding(f, host="/opt/project")
    assert mapped["result_type"] == "vulnerability"
    assert mapped["severity"] == "high"
    assert mapped["host"] == "/opt/project"
    assert mapped["title"] == "hardcoded_secret: AWS Access Key found"
    assert "config.py:12" in mapped["description"]
    assert json.loads(mapped["raw_data"]) == f


def test_map_finding_prefers_rule_over_type_for_title():
    f = {"type": "yara_match", "rule": "backdoor_indicator", "severity": "critical",
         "description": "matched pattern", "file": "app.py", "line_number": 0}
    mapped = backdoor_scanner._map_finding(f, host="/opt/project")
    assert mapped["title"] == "backdoor_indicator: matched pattern"


def test_map_finding_defaults_unknown_severity_to_info():
    f = {"type": "vuln", "description": "some CVE", "severity": "unexpected-value"}
    mapped = backdoor_scanner._map_finding(f, host="/opt/project")
    assert mapped["severity"] == "info"


# ── _find_tool_dir ────────────────────────────────────────────────────────

def test_find_tool_dir_uses_env_override(tmp_path, monkeypatch):
    fake_dir = tmp_path / "backdoor_detector"
    fake_dir.mkdir()
    (fake_dir / "backdoor_detector.py").write_text("# stub\n")
    monkeypatch.setenv("BACKDOOR_DETECTOR_DIR", str(fake_dir))
    assert backdoor_scanner._find_tool_dir() == fake_dir


def test_find_tool_dir_returns_none_when_missing(monkeypatch):
    monkeypatch.delenv("BACKDOOR_DETECTOR_DIR", raising=False)
    monkeypatch.setattr(backdoor_scanner, "_DEFAULT_TOOL_DIR", backdoor_scanner.Path("/nonexistent/backdoor_detector"))
    assert backdoor_scanner._find_tool_dir() is None


# ── run_backdoor_scan ─────────────────────────────────────────────────────

def test_run_backdoor_scan_requires_existing_directory(tmp_path):
    findings = backdoor_scanner.run_backdoor_scan(str(tmp_path / "nope"))
    assert len(findings) == 1
    assert findings[0]["title"] == "Target path not found"
    assert findings[0]["severity"] == "info"


def test_run_backdoor_scan_rejects_a_file_not_a_directory(tmp_path):
    f = tmp_path / "somefile.txt"
    f.write_text("x")
    findings = backdoor_scanner.run_backdoor_scan(str(f))
    assert findings[0]["title"] == "Target path not found"


def test_run_backdoor_scan_graceful_when_tool_dir_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(backdoor_scanner, "_find_tool_dir", lambda: None)
    findings = backdoor_scanner.run_backdoor_scan(str(tmp_path))
    assert len(findings) == 1
    assert findings[0]["title"] == "Backdoor Detector not found"


def test_run_backdoor_scan_parses_runner_output(tmp_path, monkeypatch):
    monkeypatch.setattr(backdoor_scanner, "_find_tool_dir", lambda: tmp_path)

    stdout = _runner_stdout(
        findings=[
            {"type": "hardcoded_secret", "severity": "HIGH", "file": "config.py",
             "line_number": 3, "description": "Slack token found"},
            {"type": "yara_match", "rule": "backdoor_indicator", "severity": "CRITICAL",
             "file": "shell.py", "line_number": 1, "description": "reverse shell pattern"},
        ],
        checklist=[
            {"category": "Authentication & Authorization", "items": ["Check for hardcoded creds", "Review debug accounts"]},
            {"category": "Network Communication", "items": ["Look for hardcoded C2 addresses"]},
        ],
    )
    fake_proc = MagicMock(returncode=0, stdout=stdout, stderr="")

    with patch("app.scanner.backdoor_scanner.subprocess.run", return_value=fake_proc):
        findings = backdoor_scanner.run_backdoor_scan(str(tmp_path))

    vulns = [f for f in findings if f["result_type"] == "vulnerability"]
    infos = [f for f in findings if f["result_type"] == "info"]
    assert len(vulns) == 2
    assert {f["severity"] for f in vulns} == {"high", "critical"}
    assert len(infos) == 1
    assert infos[0]["title"] == "Manual Review Checklist"
    assert "Authentication & Authorization: Check for hardcoded creds; Review debug accounts" in infos[0]["description"]
    assert "Network Communication: Look for hardcoded C2 addresses" in infos[0]["description"]


def test_run_backdoor_scan_no_checklist_key_means_no_info_result(tmp_path, monkeypatch):
    monkeypatch.setattr(backdoor_scanner, "_find_tool_dir", lambda: tmp_path)
    fake_proc = MagicMock(returncode=0, stdout=_runner_stdout(findings=[]), stderr="")

    with patch("app.scanner.backdoor_scanner.subprocess.run", return_value=fake_proc):
        findings = backdoor_scanner.run_backdoor_scan(str(tmp_path))

    assert findings == []


def test_run_backdoor_scan_surfaces_nonzero_exit_as_error(tmp_path, monkeypatch):
    monkeypatch.setattr(backdoor_scanner, "_find_tool_dir", lambda: tmp_path)
    fake_proc = MagicMock(returncode=1, stdout="", stderr="Traceback: ImportError: no module named yara\n")

    with patch("app.scanner.backdoor_scanner.subprocess.run", return_value=fake_proc):
        findings = backdoor_scanner.run_backdoor_scan(str(tmp_path))

    assert len(findings) == 1
    assert findings[0]["title"] == "Backdoor scan error"
    assert "ImportError" in findings[0]["description"]


def test_run_backdoor_scan_surfaces_unparseable_stdout_as_error(tmp_path, monkeypatch):
    monkeypatch.setattr(backdoor_scanner, "_find_tool_dir", lambda: tmp_path)
    fake_proc = MagicMock(returncode=0, stdout="not valid json {{{", stderr="")

    with patch("app.scanner.backdoor_scanner.subprocess.run", return_value=fake_proc):
        findings = backdoor_scanner.run_backdoor_scan(str(tmp_path))

    assert len(findings) == 1
    assert findings[0]["title"] == "Backdoor scan error"


def test_run_backdoor_scan_timeout_has_no_partial_results(tmp_path, monkeypatch):
    """Unlike PEN/REAPER, the runner only prints its JSON at the very end —
    nothing is written incrementally — so a timeout has genuinely nothing to
    recover, and the result set should say so rather than claim partial
    findings exist."""
    monkeypatch.setattr(backdoor_scanner, "_find_tool_dir", lambda: tmp_path)

    def fake_run(args, capture_output, text, timeout):
        raise sp.TimeoutExpired(cmd=args, timeout=timeout)

    with patch("app.scanner.backdoor_scanner.subprocess.run", side_effect=fake_run):
        findings = backdoor_scanner.run_backdoor_scan(str(tmp_path))

    assert len(findings) == 1
    assert findings[0]["title"] == "Backdoor scan truncated by timeout"
    assert "no partial findings" in findings[0]["description"]


def test_run_backdoor_scan_cleans_up_temp_dirs(tmp_path, monkeypatch):
    monkeypatch.setattr(backdoor_scanner, "_find_tool_dir", lambda: tmp_path)
    captured = {}

    def fake_run(args, capture_output, text, timeout):
        # args: [python, runner, target, yara_dir, tool_dir, output_dir]
        captured["yara_dir"] = args[3]
        captured["output_dir"] = args[5]
        return MagicMock(returncode=0, stdout=_runner_stdout(), stderr="")

    with patch("app.scanner.backdoor_scanner.subprocess.run", side_effect=fake_run):
        backdoor_scanner.run_backdoor_scan(str(tmp_path))

    import os
    assert not os.path.isdir(captured["yara_dir"])
    assert not os.path.isdir(captured["output_dir"])
