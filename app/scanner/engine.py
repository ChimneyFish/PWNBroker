import json
import re
import threading
from datetime import datetime, timezone
from flask import current_app
from ..extensions import db
from ..models import Scan, ScanResult

_IP_RE   = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
_CIDR_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$')

# Maximum hosts triaged per subnet scan (avoids serial API exhaustion on large /16s)
_MAX_TRIAGE_HOSTS = 10

# Maximum subdomains actively scanned per domain scan
_MAX_SUBDOMAIN_SCAN = 30

# nmap's "vulns" NSE library (shared by most --script vuln modules, e.g.
# ssl-heartbleed, smb-vuln-ms17-010) prints a "State: VULNERABLE" line when a
# script's live probe positively confirms the issue, vs "NOT VULNERABLE" or no
# State line at all otherwise — this is what promotes a hit to "confirmed"
# rather than the version-correlation guess every CVE/CPE match otherwise is.
_NSE_VULNERABLE_RE = re.compile(r'State:\s*(?:LIKELY )?VULNERABLE', re.I)
_NSE_CVE_RE        = re.compile(r'CVE-\d{4}-\d{4,7}')
_NSE_RISK_RE       = re.compile(r'Risk factor:\s*(\w+)', re.I)
_NSE_RISK_TO_SEVERITY = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}


def _parse_nse_vuln_scripts(scripts: dict, host: str, port, protocol: str) -> list:
    """Turn positive nmap NSE vuln-category script output into confirmed
    vulnerability ScanResult dicts. `scripts` is nmap-python's {script_name:
    output_text} dict for one port — everything not from the vulns.lua
    library (most of "default") won't match and is silently skipped."""
    findings = []
    for script_name, output in (scripts or {}).items():
        if not output or not _NSE_VULNERABLE_RE.search(output):
            continue
        cve_ids = _NSE_CVE_RE.findall(output)
        risk_match = _NSE_RISK_RE.search(output)
        severity = _NSE_RISK_TO_SEVERITY.get(
            (risk_match.group(1).lower() if risk_match else ""), "high")
        findings.append({
            "cve_id": cve_ids[0] if cve_ids else None,
            "severity": severity,
            "title": f"{script_name}: confirmed vulnerable — {host}:{port}/{protocol}",
            "description": output.strip(),
        })
    return findings

# Every call site (scheduled tag/manual group scans, the eol/secrets/dependency/
# backdoor routes, manual re-scans) launches run_scan on its own daemon thread
# with no cap of its own — a scheduled scan against a group of N assets starts
# N threads at once. Bounding actual concurrent execution here, in one place,
# keeps that from piling up unboundedly against the single-worker web process's
# shared SQLite connection and the external APIs scans call out to (NVD, etc.);
# excess scans simply wait their turn instead of racing every other request for
# the same DB locks and the same rate-limited endpoints.
_MAX_CONCURRENT_SCANS = 4
_scan_slots = threading.Semaphore(_MAX_CONCURRENT_SCANS)


def _is_cidr(host: str) -> bool:
    return bool(_CIDR_RE.match(host.strip()))


def _parse_github_repo_host(host: str):
    """Split a github_repo Target's host field ('owner/repo', or a full
    https://github.com/owner/repo URL) into (owner, repo)."""
    raw_host = host.strip()
    for prefix in ("https://github.com/", "http://github.com/", "github.com/"):
        if raw_host.startswith(prefix):
            raw_host = raw_host[len(prefix):]
            break
    parts = raw_host.strip("/").split("/", 1)
    owner = parts[0]
    repo = parts[1] if len(parts) > 1 else ""
    return owner, repo


def _is_domain(host: str) -> bool:
    h = host.strip()
    return not _IP_RE.match(h) and not _CIDR_RE.match(h)


def _enrich_assets(target_id, host_meta: dict):
    """Create/update Asset records for every host nmap discovered.

    Previously this only updated hostname/os_name on an Asset that already
    existed for that IP — a subnet scan finding a host nobody had manually
    added as an Asset before left it completely out of the asset inventory.
    (routes/assets.py's _sync_assets() does eventually backfill new Assets
    from ScanResult rows, but only lazily, the next time someone loads the
    Assets page — not as part of "scan a subnet" itself.) Now creates the
    Asset immediately, matching a subnet scan being the actual inventory
    mechanism, not just a vulnerability finder.
    """
    from ..models import Asset
    now = datetime.now(timezone.utc)
    for ip, data in host_meta.items():
        asset = Asset.query.filter_by(ip_address=ip, target_id=target_id).first()
        if not asset:
            asset = Asset(
                ip_address=ip, target_id=target_id,
                hostname=data.get("hostname"), os_name=data.get("os_name"),
                first_seen=now, last_seen=now,
            )
            db.session.add(asset)
            db.session.commit()
            continue
        if data.get("hostname") and not asset.hostname:
            asset.hostname = data["hostname"]
        if data.get("os_name") and not asset.os_name:
            asset.os_name = data["os_name"]
        asset.last_seen = now
        db.session.commit()


def _append_port_results(results, scan_id, ports, do_cve=False):
    """Append port ScanResult rows (and optionally CVE rows) into results list."""
    from .cve_lookup import lookup_cves_for_service
    for p in ports:
        if "error" in p:
            continue
        results.append(ScanResult(
            scan_id=scan_id,
            result_type="port",
            host=p["host"],
            port=p["port"],
            protocol=p["protocol"],
            service=f"{p.get('product','')} {p.get('service','')} {p.get('version','')}".strip(),
            severity="info",
            title=f"Open Port {p['port']}/{p['protocol']}",
            description=f"Service: {p.get('service','unknown')} {p.get('product','')} {p.get('version','')}".strip(),
            cpe=p.get("cpe", ""),
            raw_data=str(p),
        ))

        # NSE vuln-category scripts actively probed this port and reported a
        # real verdict — promote a positive hit ahead of (and independent of)
        # do_cve, since it's a live confirmation rather than a version guess.
        for nse_hit in _parse_nse_vuln_scripts(p.get("scripts"), p["host"], p["port"], p["protocol"]):
            results.append(ScanResult(
                scan_id=scan_id,
                result_type="vulnerability",
                host=p["host"],
                port=p["port"],
                service=p.get("service"),
                severity=nse_hit["severity"],
                title=nse_hit["title"],
                description=nse_hit["description"],
                cve_id=nse_hit["cve_id"],
                verification_status="confirmed",
            ))

        if do_cve:
            cves = lookup_cves_for_service(
                p.get("product", p.get("service", "")),
                p.get("version", ""),
                cpe=p.get("cpe", ""),
            )
            for cve in cves:
                results.append(ScanResult(
                    scan_id=scan_id,
                    result_type="vulnerability",
                    host=p["host"],
                    port=p["port"],
                    service=p.get("service"),
                    severity=cve["severity"],
                    title=cve["cve_id"],
                    description=cve["description"],
                    cve_id=cve["cve_id"],
                    cvss_score=cve["cvss_score"],
                    cpe=cve.get("cpe", ""),
                    match_confidence=cve.get("match_confidence", "none"),
                    # A CPE/keyword-correlated CVE match: NVD says this
                    # product+version *can* be vulnerable, not that this
                    # specific host demonstrably is — the banner could be
                    # stale, backported-patched, or simply wrong. Left as the
                    # column's "unconfirmed" default explicitly, so it reads
                    # clearly here rather than relying on a schema default.
                    verification_status="unconfirmed",
                ))


def run_scan(scan_id: int, app=None):
    _app = app or current_app._get_current_object()
    with _app.app_context():
        scan = db.session.get(Scan, scan_id)
        if not scan:
            return

        _scan_slots.acquire()
        try:
            scan.status = "running"
            scan.started_at = datetime.now(timezone.utc)
            db.session.commit()

            try:
                results = []
                host = scan.target.host
                scan_type = scan.scan_type
                host_meta = {}

                # ── EOL scan ──────────────────────────────────────────────────────
                if scan_type == "eol":
                    from .eol_scanner import run_eol_scan
                    eol_results = run_eol_scan(scan, scan.target)
                    for r in eol_results:
                        results.append(ScanResult(
                            scan_id=scan_id,
                            result_type=r.get("result_type", "info"),
                            host=r.get("host", host),
                            severity=r.get("severity", "info"),
                            title=r.get("title", ""),
                            description=r.get("description", ""),
                            remediation=r.get("remediation", ""),
                            raw_data=r.get("raw_data"),
                        ))

                # ── PEN operational web/API pentest ────────────────────────────────
                # URL-oriented, like web/subdomain scans — not meaningful against a
                # CIDR range, so skip rather than trying to build a bogus URL from it.
                if scan_type == "pen" and not _is_cidr(host):
                    from .pen_scanner import run_pen_scan
                    target_url = host if host.startswith(("http://", "https://")) else f"https://{host}"
                    pen_results = run_pen_scan(target_url, host, token=scan.pen_token)
                    for r in pen_results:
                        results.append(ScanResult(
                            scan_id=scan_id,
                            result_type=r.get("result_type", "info"),
                            host=r.get("host", host),
                            severity=r.get("severity", "info"),
                            title=r.get("title", ""),
                            description=r.get("description", ""),
                            raw_data=r.get("raw_data"),
                            verification_status=r.get("verification_status", "unconfirmed"),
                        ))

                # ── REAPER GitHub secret scan ─────────────────────────────────────
                if scan_type == "reaper":
                    from ..models import ThreatConfig
                    from .reaper_scanner import run_reaper_scan
                    _tc = ThreatConfig.query.first()
                    gh_token = _tc.github_advisory_token if _tc else None

                    if scan.target and scan.target.target_type == "github_repo":
                        owner, repo = _parse_github_repo_host(scan.target.host)
                        reaper_results = run_reaper_scan(owner, repo, gh_token)
                    else:
                        reaper_results = [{
                            "result_type": "info", "host": host, "severity": "info",
                            "title": "REAPER requires a GitHub repository target",
                            "description": "This scan's target isn't a GitHub repository — "
                                            "REAPER only scans GitHub repos for exposed secrets.",
                        }]

                    for r in reaper_results:
                        results.append(ScanResult(
                            scan_id=scan_id,
                            result_type=r.get("result_type", "info"),
                            host=r.get("host", host),
                            severity=r.get("severity", "info"),
                            title=r.get("title", ""),
                            description=r.get("description", ""),
                            raw_data=r.get("raw_data"),
                        ))

                # ── Backdoor Detector static analysis ──────────────────────────────
                if scan_type == "backdoor":
                    from .backdoor_scanner import run_backdoor_scan

                    if scan.target and scan.target.target_type == "local_path":
                        backdoor_results = run_backdoor_scan(scan.target.host)
                    else:
                        backdoor_results = [{
                            "result_type": "info", "host": host, "severity": "info",
                            "title": "Backdoor scan requires a local-path target",
                            "description": "This scan's target isn't a Local Path target — "
                                            "Backdoor Detector only analyzes directories on this server.",
                        }]

                    for r in backdoor_results:
                        results.append(ScanResult(
                            scan_id=scan_id,
                            result_type=r.get("result_type", "info"),
                            host=r.get("host", host),
                            severity=r.get("severity", "info"),
                            title=r.get("title", ""),
                            description=r.get("description", ""),
                            raw_data=r.get("raw_data"),
                        ))

                # ── OSV dependency scan ───────────────────────────────────────────
                if scan_type == "osv":
                    from ..models import ThreatConfig
                    _tc = ThreatConfig.query.first()
                    gh_token = _tc.github_advisory_token if _tc else None

                    if scan.target and scan.target.target_type == "github_repo":
                        from .github_repo_scanner import run_github_dep_scan, create_fix_pr
                        owner, repo = _parse_github_repo_host(scan.target.host)
                        dep_results = run_github_dep_scan(
                            scan, owner, repo, gh_token, subpath=scan.scan_path or ""
                        )

                        if scan.auto_remediate and gh_token:
                            pr_notes = []
                            for r in dep_results:
                                if r.get("result_type") == "vulnerability" and r.get("fixed_version"):
                                    pr = create_fix_pr(owner, repo, r, gh_token)
                                    if pr["ok"]:
                                        pr_notes.append(f"✓ {r['package_name']}: {pr['pr_url']}")
                                    else:
                                        pr_notes.append(f"✗ {r['package_name']}: {pr['error']}")
                            if pr_notes:
                                dep_results.append({
                                    "result_type": "info",
                                    "host": f"github.com/{owner}/{repo}",
                                    "severity": "info",
                                    "title": f"Auto-Remediation — {sum(1 for n in pr_notes if n.startswith('✓'))} PR(s) opened",
                                    "description": "\n".join(pr_notes),
                                })
                    else:
                        from .osv_scanner import run_osv_scan
                        scan_path = scan.scan_path or host
                        dep_results = run_osv_scan(scan, scan_path, target=scan.target,
                                                   github_token=gh_token)

                    for r in dep_results:
                        results.append(ScanResult(
                            scan_id=scan_id,
                            result_type=r.get("result_type", "vulnerability"),
                            host=r.get("host", host),
                            severity=r.get("severity", "info"),
                            title=r.get("title", ""),
                            description=r.get("description", ""),
                            cve_id=r.get("cve_id"),
                            cvss_score=r.get("cvss_score"),
                            remediation=r.get("remediation"),
                            package_name=r.get("package_name"),
                            package_version=r.get("package_version"),
                            ecosystem=r.get("ecosystem"),
                            fixed_version=r.get("fixed_version"),
                            raw_data=r.get("raw_data"),
                        ))

                # ── Port scan (single host or CIDR subnet) ────────────────────────
                if scan_type in ("full", "port"):
                    from .nmap_scanner import run_port_scan
                    ports, host_meta = run_port_scan(host, scan.port_range)
                    _append_port_results(results, scan_id, ports, do_cve=(scan_type == "full"))

                    if host_meta:
                        _enrich_assets(scan.target_id, host_meta)

                        # EOL check on every port/full scan — no credentials needed,
                        # just nmap's OS fingerprint. Flags unsupported OSes as alerts
                        # without requiring a separate, manually-run EOL scan.
                        from .eol_scanner import check_fingerprint_eol
                        for h, meta in host_meta.items():
                            eol_hit = check_fingerprint_eol(meta.get("os_name"), h)
                            if eol_hit:
                                results.append(ScanResult(
                                    scan_id=scan_id,
                                    result_type=eol_hit["result_type"],
                                    host=eol_hit["host"],
                                    severity=eol_hit["severity"],
                                    title=eol_hit["title"],
                                    description=eol_hit["description"],
                                    remediation=eol_hit.get("remediation", ""),
                                    raw_data=eol_hit.get("raw_data"),
                                ))

                    # Deeper, version-precise EOL check via SSH + endoflife.date —
                    # only for full scans against a single credentialed host (skips
                    # subnets/domains, and skips port-only scans to stay fast).
                    if (scan_type == "full" and scan.target and scan.target.ssh_username
                            and not _is_cidr(host) and not _is_domain(host)):
                        from .eol_scanner import run_eol_scan
                        for r in run_eol_scan(scan, scan.target):
                            results.append(ScanResult(
                                scan_id=scan_id,
                                result_type=r.get("result_type", "info"),
                                host=r.get("host", host),
                                severity=r.get("severity", "info"),
                                title=r.get("title", ""),
                                description=r.get("description", ""),
                                remediation=r.get("remediation", ""),
                                raw_data=r.get("raw_data"),
                            ))

                # ── Web checks — single host/IP only, not subnets ────────────────
                if scan_type in ("full", "web") and not _is_cidr(host):
                    from .web_checks import run_web_checks
                    web_findings = run_web_checks(host)
                    for f in web_findings:
                        results.append(ScanResult(
                            scan_id=scan_id,
                            result_type=f["result_type"],
                            host=f["host"],
                            severity=f["severity"],
                            title=f["title"],
                            description=f["description"],
                            remediation=f.get("remediation", ""),
                        ))

                # ── SOC triage ────────────────────────────────────────────────────
                # Domains are excluded (triage is IP-only).
                # For CIDR, triage the first N discovered hosts to avoid exhausting
                # external API rate limits across a large subnet.
                if scan_type not in ("osv", "eol", "subdomain") and not _is_domain(host):
                    from ..threat.triage import run as triage_run, severity_for
                    from ..models import ThreatConfig
                    _tc = ThreatConfig.query.first()
                    if _is_cidr(host):
                        triage_hosts = list(host_meta.keys())[:_MAX_TRIAGE_HOSTS]
                    else:
                        triage_hosts = [host]
                    for triage_host in triage_hosts:
                        t_result = triage_run(triage_host, cfg=_tc)
                        v = t_result["verdict"]
                        results.append(ScanResult(
                            scan_id=scan_id,
                            result_type="triage",
                            host=triage_host,
                            severity=severity_for(v["label"]),
                            title=f"SOC Triage: {v['label']}",
                            description=v["reason"],
                            raw_data=json.dumps(t_result),
                        ))

                # ── Subdomain enumeration + per-subdomain scanning ────────────────
                if scan_type in ("full", "subdomain") and _is_domain(host):
                    from ..threat.subdomain import enumerate as sub_enum
                    from .web_checks import run_web_checks
                    from .nmap_scanner import run_web_port_scan
                    from ..models import ThreatConfig
                    _tc = ThreatConfig.query.first()

                    sub_result = sub_enum(host, dnsdumpster_key=_tc.dnsdumpster_api_key if _tc else None)

                    # Store enumeration records first
                    for sub in sub_result["subdomains"]:
                        results.append(ScanResult(
                            scan_id=scan_id,
                            result_type="subdomain",
                            host=sub["subdomain"],
                            service=sub["ip"] or "",
                            protocol=sub["first_seen"] or "",
                            severity="info",
                            title=sub["subdomain"],
                            description=", ".join(sub["sources"]),
                            raw_data=json.dumps(sub),
                        ))

                    if sub_result["errors"]:
                        results.append(ScanResult(
                            scan_id=scan_id,
                            result_type="info",
                            severity="info",
                            title="Subdomain Enumeration Warnings",
                            description="; ".join(sub_result["errors"]),
                        ))

                    # For full scans: actively scan each subdomain that resolves
                    # Cap to avoid runaway scan time on domains with hundreds of subdomains
                    if scan_type == "full":
                        scannable = [
                            s for s in sub_result["subdomains"]
                            if s.get("ip")  # only those that resolved to an IP
                        ][:_MAX_SUBDOMAIN_SCAN]

                        for sub in scannable:
                            sub_host = sub["subdomain"]

                            # Quick port scan (common web + service ports)
                            sub_ports, _ = run_web_port_scan(sub_host)
                            _append_port_results(results, scan_id, sub_ports, do_cve=True)

                            # Web security header / misconfiguration checks
                            sub_web = run_web_checks(sub_host)
                            for f in sub_web:
                                results.append(ScanResult(
                                    scan_id=scan_id,
                                    result_type=f["result_type"],
                                    host=f["host"],
                                    severity=f["severity"],
                                    title=f["title"],
                                    description=f["description"],
                                    remediation=f.get("remediation", ""),
                                ))

                db.session.bulk_save_objects(results)
                scan.status = "done"

                new_cve_ids = [r.cve_id for r in results if getattr(r, "cve_id", None)]
                if new_cve_ids:
                    try:
                        from ..grc.enrichment import enrich_scan_cves
                        enrich_scan_cves(new_cve_ids, app=_app)
                    except Exception as e:
                        current_app.logger.warning("Post-scan CVE enrichment failed: %s", e)
            except Exception as e:
                # The exception may have come from a failed commit (e.g. a cache
                # table's unique-constraint race), which leaves the session's
                # transaction aborted — touching it further without rolling back
                # first raises PendingRollbackError here, which would propagate
                # out of this thread unhandled and leave `scan` stuck at
                # "running" forever instead of being marked "failed" below.
                db.session.rollback()
                scan.status = "failed"
                db.session.add(ScanResult(
                    scan_id=scan_id,
                    result_type="info",
                    severity="info",
                    title="Scan Error",
                    description=str(e),
                ))

            scan.completed_at = datetime.now(timezone.utc)
            db.session.commit()
        finally:
            _scan_slots.release()
