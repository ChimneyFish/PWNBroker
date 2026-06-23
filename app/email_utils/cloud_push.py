import base64
import requests
from datetime import datetime, timezone
from ..models import CloudConfig


def push_report_to_cloud(scan, report_bytes=None, file_format="pdf") -> dict:
    """
    POST scan findings to the configured cloud API endpoint.
    Returns {"ok": bool, "status_code": int|None, "message": str}
    """
    cfg = CloudConfig.query.first()
    if not cfg or not cfg.enabled or not cfg.endpoint_url:
        return {"ok": False, "status_code": None, "message": "Cloud API not configured or disabled."}

    payload = _build_payload(scan, report_bytes, file_format if cfg.send_file else None)
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    _apply_auth(headers, cfg)

    try:
        resp = requests.post(cfg.endpoint_url, json=payload, headers=headers, timeout=30)
        ok = 200 <= resp.status_code < 300
        return {
            "ok": ok,
            "status_code": resp.status_code,
            "message": resp.text[:500] if not ok else "OK",
        }
    except requests.exceptions.ConnectionError:
        return {"ok": False, "status_code": None, "message": "Connection refused — check endpoint URL."}
    except requests.exceptions.Timeout:
        return {"ok": False, "status_code": None, "message": "Request timed out after 30s."}
    except Exception as e:
        return {"ok": False, "status_code": None, "message": str(e)}


def _build_payload(scan, report_bytes, file_format):
    from ..models import ScanResult
    results = scan.results.all()

    findings = []
    for r in results:
        findings.append({
            "type": r.result_type,
            "severity": r.severity,
            "title": r.title,
            "host": r.host,
            "port": r.port,
            "cve_id": r.cve_id,
            "cvss_score": r.cvss_score,
            "description": r.description,
            "remediation": r.remediation,
        })

    severity_counts = {}
    for r in results:
        if r.result_type == "vulnerability":
            severity_counts[r.severity] = severity_counts.get(r.severity, 0) + 1

    payload = {
        "source": "PwnBroker",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan": {
            "id": scan.id,
            "name": scan.name,
            "target": scan.target.host,
            "scan_type": scan.scan_type,
            "status": scan.status,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "duration_seconds": scan.duration,
        },
        "summary": {
            "total_findings": len(findings),
            "vulnerabilities": sum(1 for r in results if r.result_type == "vulnerability"),
            "severity_breakdown": severity_counts,
        },
        "findings": findings,
    }

    if report_bytes and file_format:
        payload["report_file"] = {
            "format": file_format,
            "encoding": "base64",
            "data": base64.b64encode(report_bytes).decode("utf-8"),
        }

    return payload


def _apply_auth(headers, cfg):
    if cfg.auth_type == "bearer" and cfg.auth_token:
        headers["Authorization"] = f"Bearer {cfg.auth_token}"
    elif cfg.auth_type == "api_key" and cfg.auth_token:
        header_name = cfg.auth_header or "X-API-Key"
        headers[header_name] = cfg.auth_token
