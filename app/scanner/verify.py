"""Active exploitability verification for version-matched CVEs.

A CVE matched from a service banner (CPE / keyword correlation in
cve_lookup.py) only says "this product+version *can* be vulnerable". Whether
this host actually is depends on configuration: Apache 2.4.49 is only
exploitable via CVE-2021-41773 if `Require all denied` was removed, a Struts
CVE only matters if the vulnerable plugin is loaded, and so on. This module
re-tests each such finding against the live service with a check written for
that specific CVE, and records one of three outcomes:

    confirmed        the check reproduced the vulnerable behaviour
                     (evidence = the request that worked + response excerpt)
    not_exploitable  a check for this CVE ran cleanly and the vulnerable
                     behaviour was NOT present (feature disabled, backported
                     patch, not actually that product, ...)
    unconfirmed      no safe check exists for this CVE, or the check couldn't
                     complete (port closed, timeout) — stays unverified

Checks are nuclei templates (MIT-licensed, ~4,500 CVE-specific checks). Only
"safe" templates are used: never ones tagged dos/intrusive/fuzz, never ones
needing credentials, and never ones that rely on an out-of-band callback
server (interactsh is disabled so no scan data leaves the network — and a
template that can only succeed via a callback can't produce a trustworthy
negative without it).
"""
import json
import logging
import os
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
from datetime import datetime, timezone

log = logging.getLogger(__name__)

CONFIRMED, NOT_EXPLOITABLE, UNCONFIRMED = "confirmed", "not_exploitable", "unconfirmed"

# Version-correlated / heuristic findings — the ones that need proof before
# they count. (ScanResult.match_confidence values.)
INFERRED_CONFIDENCE = ("cpe", "keyword", "heuristic")

_UNSAFE_TAGS = {"dos", "intrusive", "fuzz", "fuzzing", "authenticated", "bruteforce", "brute-force"}
_SAFE_DIRS = ("http/", "network/", "javascript/")
_TAGS_RE = re.compile(r"^\s+tags:\s*(.+)$", re.M)
_HTTPISH = re.compile(r"http|www|ssl|https|web", re.I)

_MAX_PROOF_CHARS = 1500
_TOTAL_BUDGET_SECONDS = 20 * 60  # per scan, across all checks


def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def evidence(method, check, result, detail, **extra):
    d = {"method": method, "check": check, "result": result, "detail": detail,
         "checked_at": _now_iso()}
    d.update({k: v for k, v in extra.items() if v})
    return json.dumps(d)


# ── configuration ────────────────────────────────────────────────────────────

def _root():
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _cfg(key, default=None):
    try:
        from flask import current_app
        return current_app.config.get(key, default)
    except RuntimeError:
        return os.environ.get(key, default)


def nuclei_bin():
    configured = _cfg("NUCLEI_BIN")
    if configured:
        return configured if os.path.exists(configured) else None
    bundled = os.path.join(_root(), "tools", "nuclei", "nuclei")
    if os.access(bundled, os.X_OK):
        return bundled
    return shutil.which("nuclei")


def templates_dir():
    return _cfg("NUCLEI_TEMPLATES_DIR") or os.path.join(_root(), "data", "nuclei-templates")


def nuclei_home():
    # nuclei writes config/cache under $HOME; the service user has no home and
    # the systemd sandbox only allows writes under data/.
    return _cfg("NUCLEI_HOME") or os.path.join(_root(), "data", "nuclei-home")


def enabled():
    return str(_cfg("VULN_VERIFY", "1")).lower() not in ("0", "false", "no", "off")


# ── template index ───────────────────────────────────────────────────────────

class TemplateIndex:
    """CVE id → safe nuclei template path, built from the templates repo's
    cves.json and filtered by reading each candidate template's tags."""

    _cache = {}

    def __init__(self, tdir):
        self.tdir = tdir
        self.by_cve = {}
        idx = os.path.join(tdir, "cves.json")
        with open(idx) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                cve, rel = (d.get("ID") or "").upper(), d.get("file_path") or ""
                if cve.startswith("CVE-") and rel.startswith(_SAFE_DIRS):
                    self.by_cve.setdefault(cve, rel)
        self._safe = {}

    @classmethod
    def load(cls, tdir):
        idx = os.path.join(tdir, "cves.json")
        try:
            mtime = os.path.getmtime(idx)
        except OSError:
            return None
        hit = cls._cache.get(tdir)
        if hit and hit[0] == mtime:
            return hit[1]
        inst = cls(tdir)
        cls._cache[tdir] = (mtime, inst)
        return inst

    def template_for(self, cve_id):
        """(abs_path, protocol) for a safe template, or (None, reason)."""
        rel = self.by_cve.get((cve_id or "").upper())
        if not rel:
            return None, "no active check exists for this CVE"
        if rel not in self._safe:
            self._safe[rel] = self._check_safe(rel)
        reason = self._safe[rel]
        if reason:
            return None, reason
        return os.path.join(self.tdir, rel), rel.split("/", 1)[0]

    def _check_safe(self, rel):
        try:
            text = open(os.path.join(self.tdir, rel), encoding="utf-8", errors="replace").read()
        except OSError:
            return "check file missing"
        m = _TAGS_RE.search(text)
        tags = {t.strip().lower() for t in (m.group(1) if m else "").split(",")}
        bad = tags & _UNSAFE_TAGS
        if bad:
            return f"the only check for this CVE is {sorted(bad)[0]}, so it isn't run automatically"
        if "interactsh" in text:
            return "the check needs an external callback server, which is disabled for privacy"
        return None


# ── probing ──────────────────────────────────────────────────────────────────

def _speaks_tls(host, port, timeout=4):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host):
                return True
    except (OSError, ssl.SSLError):
        return False


def _fmt_host(host):
    return f"[{host}]" if ":" in host and not host.startswith("[") else host


def run_nuclei(target, template_paths, timeout):
    """Run nuclei with matcher-status output; returns list of result dicts.
    Raises RuntimeError if nuclei itself can't run."""
    binary = nuclei_bin()
    if not binary:
        raise RuntimeError("nuclei is not installed")
    home = nuclei_home()
    os.makedirs(home, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, dir=home) as tl:
        tl.write("\n".join(template_paths))
        tlist = tl.name
    cmd = [binary, "-duc", "-ni", "-nc", "-silent", "-jsonl", "-ms",
           "-t", tlist, "-u", target,
           "-timeout", "8", "-retries", "1", "-rl", "30", "-c", "10"]
    env = {**os.environ, "HOME": home}
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"check timed out after {timeout}s")
    finally:
        try:
            os.unlink(tlist)
        except OSError:
            pass
    out = []
    for line in p.stdout.splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    if not out and p.returncode != 0:
        raise RuntimeError((p.stderr or "nuclei failed").strip().splitlines()[-1][:300])
    return out


def _proof(entry):
    resp = entry.get("response") or ""
    # Keep the part around the match: status line + tail of the body.
    head = resp.split("\r\n", 1)[0] if resp else ""
    tail = resp[-_MAX_PROOF_CHARS:] if len(resp) > _MAX_PROOF_CHARS else resp
    proof = tail if head in tail else f"{head}\n…\n{tail}"
    extracted = entry.get("extracted-results")
    if extracted:
        proof = "Extracted: " + ", ".join(map(str, extracted))[:300] + "\n\n" + proof
    return proof[:_MAX_PROOF_CHARS + 400]


def _summarise(entries):
    """nuclei -ms entries for one template → (status, detail, extra)."""
    hits = [e for e in entries if e.get("matcher-status")]
    if hits:
        e = hits[0]
        name = e.get("matcher-name")
        return CONFIRMED, (
            f"Reproduced against the live service{f' ({name})' if name else ''}."
        ), {"matched_at": e.get("matched-at"), "proof": _proof(e),
            "request": (e.get("request") or "")[:1200]}
    errors = [e.get("error") for e in entries if e.get("error")]
    if entries and not errors:
        return NOT_EXPLOITABLE, (
            "The check for this CVE ran against the live service and the vulnerable "
            "behaviour was not present (feature disabled, patched, or not affected)."
        ), {}
    reason = errors[0] if errors else "the check produced no result"
    return UNCONFIRMED, f"Check inconclusive: {reason}.", {}


# ── public API ───────────────────────────────────────────────────────────────

def classify(r):
    """Set result_type from the verdict. Only proven (or non-inferred)
    findings are stored as "vulnerability" — so every count, report, export
    and integration that looks at vulnerabilities sees real ones only.
    Unproven version matches are "unverified"; ruled-out ones "not_exploitable"."""
    if getattr(r, "result_type", None) not in VULN_TYPES or not r.is_inferred:
        return r
    r.result_type = {CONFIRMED: "vulnerability", NOT_EXPLOITABLE: "not_exploitable"}.get(
        r.verification_status, "unverified")
    return r


VULN_TYPES = ("vulnerability", "unverified", "not_exploitable")


def needs_verification(r):
    return (getattr(r, "result_type", None) in ("vulnerability", "unverified")
            and getattr(r, "cve_id", None)
            and getattr(r, "match_confidence", None) in INFERRED_CONFIDENCE
            and getattr(r, "verification_status", UNCONFIRMED) == UNCONFIRMED
            and not getattr(r, "verification_evidence", None))


def verify_results(results, budget=_TOTAL_BUDGET_SECONDS):
    """Verify every version-matched CVE finding in `results` (ScanResult
    objects, saved or not) in place. Returns a {status: count} summary."""
    todo = [r for r in results if needs_verification(r)]
    summary = {CONFIRMED: 0, NOT_EXPLOITABLE: 0, UNCONFIRMED: 0}
    try:
        _verify(todo, summary, budget)
    finally:
        for r in results:
            classify(r)
    return summary


def _verify(todo, summary, budget):
    if not todo:
        return

    if not enabled():
        for r in todo:
            r.verification_evidence = evidence("none", None, UNCONFIRMED,
                                               "Exploit verification is turned off (VULN_VERIFY=0).")
        summary[UNCONFIRMED] += len(todo)
        return

    idx = TemplateIndex.load(templates_dir()) if nuclei_bin() else None
    if idx is None:
        why = ("nuclei is not installed" if not nuclei_bin()
               else f"nuclei templates are missing ({templates_dir()})")
        for r in todo:
            r.verification_evidence = evidence("none", None, UNCONFIRMED,
                                               f"Not verified: {why}. Re-run setup.sh to install it.")
        summary[UNCONFIRMED] += len(todo)
        return

    # Group by service so each host:port gets one nuclei run.
    groups = {}
    for r in todo:
        tpl, proto_or_reason = idx.template_for(r.cve_id)
        if not tpl or not r.port or not r.host:
            detail = (f"Not verified: {proto_or_reason}." if not tpl
                      else "Not verified: finding has no host/port to test.")
            r.verification_evidence = evidence("none", None, UNCONFIRMED, detail)
            summary[UNCONFIRMED] += 1
            continue
        groups.setdefault((r.host, int(r.port)), []).append((r, tpl, proto_or_reason))

    deadline = time.monotonic() + budget
    for (host, port), items in groups.items():
        by_proto = {}
        for r, tpl, proto in items:
            by_proto.setdefault("http" if proto == "http" else "net", []).append((r, tpl))
        for kind, pairs in by_proto.items():
            remaining = deadline - time.monotonic()
            if remaining < 30:
                for r, _ in pairs:
                    r.verification_evidence = evidence(
                        "nuclei", r.cve_id, UNCONFIRMED,
                        "Not verified: this scan's verification time budget ran out.")
                    summary[UNCONFIRMED] += 1
                continue
            if kind == "http":
                scheme = "https" if _speaks_tls(host, port) else "http"
                target = f"{scheme}://{_fmt_host(host)}:{port}"
            else:
                target = f"{_fmt_host(host)}:{port}"
            tpls = sorted({t for _, t in pairs})
            timeout = int(min(remaining, 120 + 30 * len(tpls), 900))
            try:
                entries = run_nuclei(target, tpls, timeout)
                err = None
            except RuntimeError as e:
                entries, err = [], str(e)
                log.warning("verification of %s failed: %s", target, e)
            by_id = {}
            for e in entries:
                by_id.setdefault((e.get("template-id") or "").upper(), []).append(e)
            for r, tpl in pairs:
                if err:
                    status, detail, extra = UNCONFIRMED, f"Check could not run: {err}.", {}
                else:
                    status, detail, extra = _summarise(by_id.get(r.cve_id.upper(), []))
                r.verification_status = status
                r.verification_evidence = evidence("nuclei", r.cve_id, status, detail,
                                                   target=target, **extra)
                summary[status] += 1


def update_templates():
    """Download/refresh the nuclei templates (scheduled weekly)."""
    binary = nuclei_bin()
    if not binary:
        return False, "nuclei is not installed"
    home = nuclei_home()
    os.makedirs(home, exist_ok=True)
    # No -duc here: it also disables the template download itself.
    p = subprocess.run([binary, "-update-templates", "-update-template-dir", templates_dir(),
                        "-silent", "-nc"], capture_output=True, text=True, timeout=900,
                       env={**os.environ, "HOME": home})
    ok = os.path.exists(os.path.join(templates_dir(), "cves.json"))
    return ok, (p.stderr or p.stdout).strip()[-300:]
