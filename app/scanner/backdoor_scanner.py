"""
Backdoor Detector (github.com/ekomsSavior/backdoor_detector) integration — a
static-analysis tool for a *local filesystem directory*: YARA signature
matching, hardcoded-secret patterns, and dependency vulnerability scanning
(Safety/Trivy/pip-audit/npm audit). Wired in as the "backdoor" scan type,
against `local_path`-type Targets (an absolute path already on this server —
not a remote address or a GitHub repo like every other target type).

Unlike PEN or REAPER, this tool has no compiled binary and no CLI worth
shelling out to directly — it's a single importable Python file. But it is
NOT imported into this process: app/scanner/_backdoor_detector_runner.py
does that in a *subprocess*, invoked below via subprocess.run(..., timeout=).
That's deliberate, not incidental — see that file's docstring for why (the
short version: an in-process Python call can't be forcibly killed on
timeout the way a subprocess can, and this tool's file-walking phases have
no size/count cap of their own).

The single most important thing about this tool, found by reading its
source rather than its README: run_full_analysis() — the only entry point
its own CLI mode calls — unconditionally includes a "runtime analysis"
phase that auto-detects an entry point in the target directory (main.py,
package.json -> npm start, a Makefile, any executable file, ...) and
executes it via `subprocess.Popen(cmd, shell=True, ...)` with no
sandboxing, to observe its network behavior. There is no flag to disable
this. This integration NEVER calls run_full_analysis() or
analyze_network_behavior() — see _backdoor_detector_runner.py, which calls
only the specific safe phase methods. Do not "simplify" this by switching
back to the tool's own CLI entry point.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Dict, Optional

# scan_for_vulnerabilities() alone can take up to ~8 minutes in the worst
# case (safety 60s + trivy 300s + npm/pip-audit 120s each, summed across
# sequential sub-scanners), plus unbounded file-walk time for YARA/secret
# scanning on a large directory. Generous but bounded.
BACKDOOR_TIMEOUT_SECONDS = 600  # 10 minutes

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_DEFAULT_TOOL_DIR = _REPO_ROOT / "tools" / "backdoor_detector"
_RUNNER_SCRIPT = Path(__file__).resolve().parent / "_backdoor_detector_runner.py"

_SEVERITY_MAP = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info"}


def _find_tool_dir() -> Optional[Path]:
    override = os.environ.get("BACKDOOR_DETECTOR_DIR")
    candidate = Path(override) if override else _DEFAULT_TOOL_DIR
    if (candidate / "backdoor_detector.py").is_file():
        return candidate
    return None


def _map_finding(f: Dict, host: str) -> Dict:
    rule_or_type = f.get("rule") or f.get("type", "finding")
    description = f.get("description", "")
    title = f"{rule_or_type}: {description}" if rule_or_type != description else description
    file_ref = f.get("file", "")
    line_no = f.get("line_number") or 0
    location = f"{file_ref}:{line_no}" if file_ref and line_no else file_ref
    full_description = f"{location} — {description}" if location else description
    return {
        "result_type": "vulnerability",
        "host": host,
        "severity": _SEVERITY_MAP.get(str(f.get("severity", "info")).lower(), "info"),
        "title": title[:255],
        "description": full_description,
        "raw_data": json.dumps(f),
    }


def run_backdoor_scan(local_path: str) -> List[Dict]:
    """Statically analyze a local directory for backdoor indicators. Never
    raises — failures come back as a single info-severity result."""
    host = local_path

    if not local_path or not os.path.isdir(local_path):
        return [{
            "result_type": "info",
            "host": host,
            "severity": "info",
            "title": "Target path not found",
            "description": f"'{local_path}' does not exist or is not a directory on this server.",
        }]

    tool_dir = _find_tool_dir()
    if not tool_dir:
        return [{
            "result_type": "info",
            "host": host,
            "severity": "info",
            "title": "Backdoor Detector not found",
            "description": (
                "No backdoor_detector.py at tools/backdoor_detector/ and BACKDOOR_DETECTOR_DIR "
                "is not set. See docs/deployment.md for the setup step (git clone, no build needed)."
            ),
        }]

    yara_dir = tempfile.mkdtemp(prefix="backdoor_yara_")
    output_dir = tempfile.mkdtemp(prefix="backdoor_out_")
    truncated = False
    error_note = None
    findings: List[Dict] = []

    try:
        proc = subprocess.run(
            [sys.executable, str(_RUNNER_SCRIPT), local_path, yara_dir, str(tool_dir), output_dir],
            capture_output=True, text=True, timeout=BACKDOOR_TIMEOUT_SECONDS,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            error_note = (proc.stderr or "no output").strip()[-2000:]
        else:
            data = json.loads(proc.stdout.strip().splitlines()[-1])
            for f in data.get("findings", []):
                findings.append(_map_finding(f, host))
            checklist = data.get("checklist", [])
            if checklist:
                items_text = "\n".join(
                    f"{cat.get('category', '')}: " + "; ".join(cat.get("items", []))
                    for cat in checklist
                )
                findings.append({
                    "result_type": "info",
                    "host": host,
                    "severity": "info",
                    "title": "Manual Review Checklist",
                    "description": items_text,
                })
    except subprocess.TimeoutExpired:
        truncated = True
    except (ValueError, TypeError) as e:
        error_note = f"Could not parse scanner output: {e}"
    except Exception as e:
        error_note = str(e)
    finally:
        shutil.rmtree(yara_dir, ignore_errors=True)
        shutil.rmtree(output_dir, ignore_errors=True)

    if truncated:
        # Unlike PEN/REAPER, the runner only prints its JSON at the very
        # end — nothing is written incrementally — so a timeout genuinely
        # has no partial results to recover, unlike those two.
        findings.append({
            "result_type": "info",
            "host": host,
            "severity": "info",
            "title": "Backdoor scan truncated by timeout",
            "description": (
                f"The scan exceeded its {BACKDOOR_TIMEOUT_SECONDS // 60}-minute budget and was "
                "terminated before it finished. Unlike the other scan types, this tool only "
                "reports results at the end of a run, so no partial findings are available — "
                "try again against a smaller directory, or a subdirectory."
            ),
        })
    if error_note:
        findings.append({
            "result_type": "info",
            "host": host,
            "severity": "info",
            "title": "Backdoor scan error",
            "description": f"The scan could not be completed: {error_note}",
        })

    return findings
