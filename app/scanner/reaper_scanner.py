"""
REAPER (github.com/ekomsSavior/REAPER) integration — an external Go CLI that
scans a GitHub repository's code, commit messages, PRs, and issues for
exposed secrets (API keys, tokens, credentials, private keys). Wired in as
the "reaper" scan type, launched from the dedicated Secrets section (not the
generic New Scan form — same precedent as "osv", which also isn't there).

Unlike PEN, REAPER has real CLI flags (confirmed against its actual source,
not just the README) — no interactive stdin driving needed. Two things from
reading reaper.go/detector.go matter for how this driver works:

1. Passing -repo forces one-shot mode regardless of -continuous's
   default-true value (main() checks getTargetRepos() first and returns
   after scanning, never entering the continuous loop). No need to manage
   REAPER's own "run forever" behavior — one subprocess.run() and it exits
   cleanly on its own.

2. REAPER requires a token (log.Fatal if missing), but its GitHub Security
   Advisories GraphQL lookup reads os.Getenv("GITHUB_TOKEN") directly,
   bypassing its own -token flag entirely. The token must always be passed
   via the GITHUB_TOKEN environment variable, not just -token, or that one
   code path silently sends an empty Authorization header.

Output is structured (unlike PEN): reaper_findings.jsonl, one JSON object
per finding, written directly into whatever -output directory is passed
(useExactDirectory := flagWasSet("output") in reaper.go — no extra
timestamped subfolder to account for). REAPER masks secret values itself
before writing them out, so nothing unmasked ends up in PwnBroker's DB.
"""
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Optional

# REAPER's own default API throttle (-api-rps 1) means even a modest repo's
# commit/PR/issue history can take a while to walk. Shorter than PEN's
# timeout since this is rate-limited API calls, not a wordlist crack.
REAPER_TIMEOUT_SECONDS = 1200  # 20 minutes

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_DEFAULT_BINARY = _REPO_ROOT / "tools" / "reaper" / "reaper"


def _find_reaper_binary() -> Optional[str]:
    override = os.environ.get("REAPER_BINARY")
    if override and os.path.isfile(override) and os.access(override, os.X_OK):
        return override
    if _DEFAULT_BINARY.is_file() and os.access(_DEFAULT_BINARY, os.X_OK):
        return str(_DEFAULT_BINARY)
    return None


def _parse_findings(jsonl_path: str, host: str) -> List[Dict]:
    findings: List[Dict] = []
    if not os.path.isfile(jsonl_path):
        return findings
    with open(jsonl_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except (ValueError, TypeError):
                continue  # skip a malformed line rather than aborting the whole parse
            findings.append({
                "result_type": "vulnerability",
                "host": host,
                "severity": str(rec.get("severity", "high")).lower(),
                "title": rec.get("secret_type", "Exposed secret"),
                "description": rec.get("context", ""),
                "raw_data": line,
            })
    return findings


def run_reaper_scan(owner: str, repo: str, token: Optional[str]) -> List[Dict]:
    """Scan one GitHub repository for exposed secrets. Never raises —
    failures come back as a single info-severity result."""
    host = f"{owner}/{repo}"

    if not token:
        return [{
            "result_type": "info",
            "host": host,
            "severity": "info",
            "title": "GitHub Token Required",
            "description": "Configure a GitHub token in Settings → Threat Intel APIs "
                            "(needs repo and public_repo scopes for REAPER to read commit/PR/issue history).",
        }]

    binary = _find_reaper_binary()
    if not binary:
        return [{
            "result_type": "info",
            "host": host,
            "severity": "info",
            "title": "REAPER binary not found",
            "description": (
                "No REAPER binary at tools/reaper/reaper and REAPER_BINARY is not set. "
                "See docs/deployment.md for the build steps (git clone + go build)."
            ),
        }]

    work_dir = tempfile.mkdtemp(prefix="reaper_scan_")
    truncated = False
    error_note = None

    try:
        env = dict(os.environ)
        env["GITHUB_TOKEN"] = token  # some REAPER code paths read this directly, not -token
        args = [
            binary,
            "-repo", f"https://github.com/{owner}/{repo}",
            "-continuous=false",
            "-output", work_dir,
            "-verbose=false",
        ]
        proc = subprocess.run(
            args, cwd=work_dir, env=env,
            capture_output=True, text=True, timeout=REAPER_TIMEOUT_SECONDS,
        )
        # REAPER's own log.Printf/log.Fatal (auth failures, unreadable repo,
        # etc.) go to stderr and exit 0 with an empty findings file — from
        # here that's indistinguishable from "scanned fine, nothing found"
        # unless stderr is checked. REAPER never writes normal progress to
        # stderr (that's stdout), so any stderr content here is a real error.
        if proc.stderr and proc.stderr.strip():
            error_note = proc.stderr.strip()
    except subprocess.TimeoutExpired:
        truncated = True  # reaper_findings.jsonl is append-written incrementally,
                            # so whatever was flushed before the kill still parses.
    except Exception as e:
        error_note = str(e)
    finally:
        jsonl_path = os.path.join(work_dir, "reaper_findings.jsonl")
        findings = _parse_findings(jsonl_path, host)
        shutil.rmtree(work_dir, ignore_errors=True)

    if truncated:
        findings.append({
            "result_type": "info",
            "host": host,
            "severity": "info",
            "title": "REAPER scan truncated by timeout",
            "description": (
                f"The scan exceeded its {REAPER_TIMEOUT_SECONDS // 60}-minute budget "
                "and was terminated. Findings above reflect whatever completed before "
                "the cutoff — a large repository's full history may not have been covered."
            ),
        })
    if error_note:
        findings.append({
            "result_type": "info",
            "host": host,
            "severity": "info",
            "title": "REAPER scan error",
            "description": f"The REAPER process could not be run: {error_note}",
        })

    return findings
