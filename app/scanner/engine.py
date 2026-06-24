import json
import re
from datetime import datetime, timezone
from flask import current_app
from ..extensions import db
from ..models import Scan, ScanResult

_IP_RE   = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
_CIDR_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$')


def _is_cidr(host: str) -> bool:
    return bool(_CIDR_RE.match(host.strip()))


def _is_domain(host: str) -> bool:
    h = host.strip()
    return not _IP_RE.match(h) and not _CIDR_RE.match(h)


def _enrich_assets(target_id, host_meta: dict):
    """Write hostname and OS name back to Asset records discovered by nmap."""
    from ..models import Asset
    for ip, data in host_meta.items():
        asset = Asset.query.filter_by(ip_address=ip, target_id=target_id).first()
        if not asset:
            continue
        changed = False
        if data.get("hostname") and not asset.hostname:
            asset.hostname = data["hostname"]
            changed = True
        if data.get("os_name") and not asset.os_name:
            asset.os_name = data["os_name"]
            changed = True
        if changed:
            db.session.commit()


def run_scan(scan_id: int, app=None):
    _app = app or current_app._get_current_object()
    with _app.app_context():
        scan = db.session.get(Scan, scan_id)
        if not scan:
            return

        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        db.session.commit()

        try:
            results = []
            host = scan.target.host
            scan_type = scan.scan_type
            host_meta = {}

            if scan_type == "osv":
                from .osv_scanner import run_osv_scan
                scan_path = scan.scan_path or host
                osv_results = run_osv_scan(scan, scan_path, target=scan.target)
                for r in osv_results:
                    results.append(ScanResult(
                        scan_id=scan_id,
                        result_type=r.get("result_type", "vulnerability"),
                        host=r.get("host", scan_path),
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

            if scan_type in ("full", "port"):
                from .nmap_scanner import run_port_scan
                ports, host_meta = run_port_scan(host, scan.port_range)
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
                        raw_data=str(p),
                    ))

                    if scan_type == "full":
                        from .cve_lookup import lookup_cves_for_service
                        cves = lookup_cves_for_service(p.get("product", p.get("service", "")), p.get("version", ""))
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
                            ))

                # Enrich Asset records with hostname + OS from this scan
                if host_meta:
                    _enrich_assets(scan.target_id, host_meta)

            # Web checks only make sense against a single host/IP, not a subnet
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

            if scan_type not in ("osv", "subdomain") and not _is_domain(host):
                from ..threat.triage import run as triage_run, severity_for
                from ..models import ThreatConfig
                _tc = ThreatConfig.query.first()
                # For CIDR targets, triage each discovered host individually
                triage_hosts = list(host_meta.keys()) if _is_cidr(host) and host_meta else [host]
                for triage_host in triage_hosts:
                    t_result = triage_run(
                        triage_host,
                        greynoise_key=_tc.greynoise_api_key if _tc else None,
                        vt_key=_tc.virustotal_api_key       if _tc else None,
                    )
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

            if scan_type in ("full", "subdomain") and _is_domain(host):
                from ..threat.subdomain import enumerate as sub_enum
                from ..models import ThreatConfig
                _tc = ThreatConfig.query.first()
                sub_result = sub_enum(host, dnsdumpster_key=_tc.dnsdumpster_api_key if _tc else None)
                for sub in sub_result["subdomains"]:
                    results.append(ScanResult(
                        scan_id=scan_id,
                        result_type="subdomain",
                        host=sub["subdomain"],
                        service=sub["ip"] or "",
                        protocol=sub["first_seen"] or "",   # reused: not needed for subdomains
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

            db.session.bulk_save_objects(results)
            scan.status = "done"
        except Exception as e:
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
