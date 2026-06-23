import base64
import requests
from datetime import datetime, timezone


def _auth_header(email, api_token):
    token = base64.b64encode(f"{email}:{api_token}".encode()).decode()
    return {"Authorization": f"Basic {token}", "Content-Type": "application/json", "Accept": "application/json"}


SEVERITY_PRIORITY = {
    "critical": "Highest",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Lowest",
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _adf_doc(text_blocks: list) -> dict:
    """Build a minimal Atlassian Document Format body."""
    return {
        "type": "doc",
        "version": 1,
        "content": text_blocks,
    }


def _adf_paragraph(text: str) -> dict:
    return {"type": "paragraph", "content": [{"type": "text", "text": text}]}


def _adf_heading(text: str, level: int = 2) -> dict:
    return {"type": "heading", "attrs": {"level": level},
            "content": [{"type": "text", "text": text}]}


def _build_issue_description(result, scan):
    blocks = [
        _adf_heading("Finding Details", 2),
        _adf_paragraph(f"Scan: {scan.name}"),
        _adf_paragraph(f"Target: {scan.target.host}"),
        _adf_paragraph(f"Host: {result.host or 'N/A'}"),
    ]
    if result.port:
        blocks.append(_adf_paragraph(f"Port: {result.port}/{result.protocol}"))
    if result.cve_id:
        blocks.append(_adf_paragraph(f"CVE: {result.cve_id}"))
    if result.cvss_score:
        blocks.append(_adf_paragraph(f"CVSS Score: {result.cvss_score}"))
    if result.description:
        blocks.append(_adf_heading("Description", 3))
        blocks.append(_adf_paragraph(result.description))
    if result.remediation:
        blocks.append(_adf_heading("Remediation", 3))
        blocks.append(_adf_paragraph(result.remediation))
    blocks.append(_adf_paragraph(f"Reported by PwnBroker — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"))
    return _adf_doc(blocks)


def create_ticket_for_finding(result, scan, cfg) -> dict:
    """
    Create a single Jira issue for one ScanResult.
    Returns {"ok": bool, "key": str|None, "url": str|None, "message": str}
    """
    headers = _auth_header(cfg.email, cfg.api_token)
    base = cfg.base_url.rstrip("/")
    url = f"{base}/rest/api/3/issue"

    summary = f"[PwnBroker] {result.severity.upper()}: {result.title}"
    if result.host:
        summary += f" on {result.host}"
    summary = summary[:255]

    payload = {
        "fields": {
            "project": {"key": cfg.jira_project_key},
            "summary": summary,
            "description": _build_issue_description(result, scan),
            "issuetype": {"name": cfg.jira_issue_type or "Bug"},
            "priority": {"name": SEVERITY_PRIORITY.get(result.severity, "Medium")},
            "labels": ["security", "pwnbroker", result.severity],
        }
    }

    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=20)
        if resp.status_code == 201:
            data = resp.json()
            key = data.get("key")
            issue_url = f"{base}/browse/{key}"
            return {"ok": True, "key": key, "url": issue_url, "message": "Created"}
        else:
            return {"ok": False, "key": None, "url": None,
                    "message": f"HTTP {resp.status_code}: {resp.text[:300]}"}
    except requests.exceptions.ConnectionError:
        return {"ok": False, "key": None, "url": None,
                "message": "Connection refused — check Atlassian base URL."}
    except Exception as e:
        return {"ok": False, "key": None, "url": None, "message": str(e)}


def create_tickets_for_scan(scan, cfg) -> dict:
    """
    Create Jira tickets for all unticket vulnerabilities in a scan above threshold.
    Returns {"created": int, "skipped": int, "errors": list}
    """
    from ..models import ScanResult, JiraTicket
    from ..extensions import db

    threshold_idx = SEVERITY_ORDER.index(cfg.jira_severity_threshold) if cfg.jira_severity_threshold in SEVERITY_ORDER else 2
    eligible_sevs = SEVERITY_ORDER[:threshold_idx + 1]

    results = scan.results.filter(
        ScanResult.result_type == "vulnerability",
        ScanResult.severity.in_(eligible_sevs),
    ).all()

    already_ticketed = {t.result_id for t in JiraTicket.query.filter_by(scan_id=scan.id).all()}

    created, skipped, errors = 0, 0, []

    for r in results:
        if r.id in already_ticketed:
            skipped += 1
            continue

        result = create_ticket_for_finding(r, scan, cfg)
        if result["ok"]:
            ticket = JiraTicket(
                result_id=r.id,
                scan_id=scan.id,
                ticket_key=result["key"],
                ticket_url=result["url"],
            )
            db.session.add(ticket)
            created += 1
        else:
            errors.append(f"{r.title}: {result['message']}")

    db.session.commit()
    return {"created": created, "skipped": skipped, "errors": errors}
