"""
PEN (github.com/ekomsSavior/PEN) integration — an external Go CLI that runs
operational web/API pentest checks. Wired in as the "pen" scan type.

PEN has no CLI flags (confirmed against its actual main.go, not just the
README) — it's interactive-only: on launch it prompts on stdin for a target
URL and optional Bearer token, shows a numbered menu, and waits for a
selection. There is no structured output; everything is printed to stdout
with [+]/[-]/[*]/[!] prefixes.

Two things about PEN's own source matter for how this driver works:

1. promptString() builds a brand-new bufio.Reader on *every* prompt call.
   If all stdin were written upfront in one shot, Go's first read can pull
   several lines into that reader's internal buffer, consume only the first
   line via ReadString, then discard the rest when the reader goes out of
   scope — starving every later prompt. Driving it correctly means sending
   exactly one line only after the corresponding prompt has actually been
   printed, which is what pexpect's expect()/sendline() cycle gives us.

2. Only options 6-10 (GraphQL, WebSocket, git-exposure, fingerprinting,
   misconfig) are generic checks. Options 1-5 (IDOR, upload, SQLi, lateral
   movement, exploitation) probe endpoints hardcoded to PEN's own reference
   vulnerable app (/api/users/{id}, /api/upload/csv, /api/networks, and a
   privilege-escalation attempt hardcoded to PUT /api/users/6) — against an
   arbitrary real target these will simply 404 and produce nothing. "Run
   All Scans" still runs all 11, matching what the tool itself does; this
   just means real signal on generic targets mostly comes from 6-10.
"""
import io
import os
import re
import shutil
import tempfile
import time
from pathlib import Path
from typing import List, Dict, Optional

import pexpect

# Overall wall-clock budget for one PEN run (covers "Run All Scans", including
# exploitation's optional hash-cracking against /usr/share/wordlists/rockyou.txt,
# which has no natural end). Killed and partial output is still parsed/kept.
PEN_TIMEOUT_SECONDS = 2400  # 40 minutes

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_DEFAULT_BINARY = _REPO_ROOT / "tools" / "pen" / "pen"

# promptString()/promptYesNo() print "<prompt><suffix>" with no trailing
# newline, so these patterns match up to the ": " with no anchor at start —
# pexpect scans the growing output buffer, not individual lines.
_RE_TARGET_PROMPT = re.compile(r"Enter target base URL[^\n]*:\s*")
_RE_TOKEN_PROMPT  = re.compile(r"Enter Bearer token[^\n]*:\s*")
_RE_MENU_PROMPT   = re.compile(r"Select option[^\n]*:\s*")
_RE_YESNO_PROMPT  = re.compile(r"\[\?\][^\n]*\(y/N\):\s*")

_MENU_RUN_ALL = "11"
_MENU_EXIT    = "12"


def _find_pen_binary() -> Optional[str]:
    override = os.environ.get("PEN_BINARY")
    if override and os.path.isfile(override) and os.access(override, os.X_OK):
        return override
    if _DEFAULT_BINARY.is_file() and os.access(_DEFAULT_BINARY, os.X_OK):
        return str(_DEFAULT_BINARY)
    return None


def _parse_output(raw: str, host: str, truncated: bool) -> List[Dict]:
    """Turn PEN's marker-prefixed stdout into ScanResult-shaped dicts.

    This is necessarily heuristic — PEN has no structured output format.
    [!] is the tool's own signal for a confirmed vulnerability/exploit and
    becomes a "vulnerability" result. [+] covers both real positive findings
    and routine "starting module X" banners with no reliable way to tell
    them apart from the prefix alone, so it's kept as low-severity "info"
    rather than counted as a vulnerability. [-]/[*] lines are dropped from
    individual results (errors and routine status noise) but nothing is
    lost: the full unfiltered transcript is preserved in one rollup record.
    """
    findings: List[Dict] = []

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("[!]"):
            text = line[3:].strip()
            findings.append({
                "result_type": "vulnerability",
                "host": host,
                "severity": "high",
                "title": text[:200],
                "description": text,
                "raw_data": line,
            })
        elif line.startswith("[+]"):
            text = line[3:].strip()
            findings.append({
                "result_type": "info",
                "host": host,
                "severity": "low",
                "title": text[:200],
                "description": text,
                "raw_data": line,
            })
        # [-] and [*] lines: intentionally not turned into individual
        # results — see module docstring.

    if raw.strip():
        findings.append({
            "result_type": "info",
            "host": host,
            "severity": "info",
            "title": "PEN — Full Scan Transcript" + (" (truncated by timeout)" if truncated else ""),
            "description": raw.strip(),
            "raw_data": raw,
        })

    if truncated:
        findings.append({
            "result_type": "info",
            "host": host,
            "severity": "info",
            "title": "PEN scan truncated by timeout",
            "description": (
                f"The scan exceeded its {PEN_TIMEOUT_SECONDS // 60}-minute budget "
                "and was terminated. Results above reflect whatever completed "
                "before the cutoff — later menu options (e.g. hash cracking) "
                "may not have finished."
            ),
        })

    return findings


def run_pen_scan(target_url: str, host: str, token: Optional[str] = None) -> List[Dict]:
    """Drive PEN's "Run All Scans" (option 11) against target_url and return
    ScanResult-shaped finding dicts. Never raises — failures come back as a
    single info-severity result so a missing binary or a hung process
    doesn't take the whole scan down."""
    binary = _find_pen_binary()
    if not binary:
        return [{
            "result_type": "info",
            "host": host,
            "severity": "info",
            "title": "PEN binary not found",
            "description": (
                "No PEN binary at tools/pen/pen and PEN_BINARY is not set. "
                "See docs/deployment.md for the build steps (git clone + go build)."
            ),
        }]

    work_dir = tempfile.mkdtemp(prefix="pen_scan_")
    truncated = False
    error_note = None
    # pexpect's .before/.after only reflect the most recent expect() call —
    # logfile_read instead captures every byte read from the child across
    # the whole session, which is what we actually want to parse afterward.
    log_capture = io.StringIO()
    child = None
    deadline = time.monotonic() + PEN_TIMEOUT_SECONDS

    try:
        env = dict(os.environ)
        env["HOME"] = work_dir  # isolates ~/.pen_config.json per run — no
                                  # cross-scan collisions, and no config
                                  # file exists yet so PEN skips straight to
                                  # the URL/token prompts (no y/N re-use step)

        child = pexpect.spawn(
            binary, cwd=work_dir, env=env,
            timeout=min(300, PEN_TIMEOUT_SECONDS), encoding="utf-8",
            codec_errors="replace",
        )
        child.logfile_read = log_capture

        def remaining():
            return max(1, int(deadline - time.monotonic()))

        child.expect(_RE_TARGET_PROMPT, timeout=remaining())
        child.sendline(target_url)

        child.expect(_RE_TOKEN_PROMPT, timeout=remaining())
        child.sendline(token or "")

        child.expect(_RE_MENU_PROMPT, timeout=remaining())
        child.sendline(_MENU_RUN_ALL)

        # Run All Scans walks through every module; two of them (hash
        # cracking, privilege escalation) each pop a conditional y/N prompt
        # only if there's something to act on. Answer yes to both — the
        # user explicitly opted into full exploitation for this scan type.
        # Seeing the main-menu prompt again means runAllScans() returned.
        while time.monotonic() < deadline:
            idx = child.expect(
                [_RE_YESNO_PROMPT, _RE_MENU_PROMPT, pexpect.EOF],
                timeout=remaining(),
            )
            if idx == 0:
                child.sendline("y")
            elif idx == 1:
                child.sendline(_MENU_EXIT)
                child.expect(pexpect.EOF, timeout=remaining())
                break
            else:  # EOF — process exited on its own
                break
        else:
            truncated = True
    except pexpect.TIMEOUT:
        truncated = True
    except Exception as e:
        error_note = str(e)
    finally:
        if child is not None:
            try:
                if child.isalive():
                    child.terminate(force=True)
            except Exception:
                pass
        shutil.rmtree(work_dir, ignore_errors=True)

    output = log_capture.getvalue()
    findings = _parse_output(output, host, truncated)
    if error_note:
        findings.append({
            "result_type": "info",
            "host": host,
            "severity": "info",
            "title": "PEN scan error",
            "description": f"The PEN process could not be driven to completion: {error_note}",
        })
    return findings
