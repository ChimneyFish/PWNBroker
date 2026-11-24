"""Reports, exports, Jira and Confluence carry the same Exploitable /
Unverified label the web UI shows on each version-matched CVE."""
import csv
import io
import json
import shutil
import subprocess
from datetime import datetime, timezone

import pytest

from app.extensions import db


def _seed(app):
    from app.models import Scan, ScanResult, Target
    with app.app_context():
        t = Target(name="srv", host="10.0.0.9")
        db.session.add(t); db.session.commit()
        s = Scan(name="Weekly <srv>", target_id=t.id, scan_type="full", status="done",
                 completed_at=datetime.now(timezone.utc))
        db.session.add(s); db.session.commit()
        common = dict(scan_id=s.id, result_type="vulnerability", host="10.0.0.9", port=80,
                      service="http", match_confidence="cpe")
        db.session.add_all([
            ScanResult(title="Apache path traversal", cve_id="CVE-2021-41773", severity="critical",
                       verification_status="confirmed", remediation="Upgrade httpd",
                       verification_evidence=json.dumps({"result": "confirmed",
                                                         "detail": "nuclei CVE-2021-41773 matched"}),
                       **common),
            ScanResult(title="dnsmasq heap overflow", cve_id="CVE-2017-14491", severity="high",
                       verification_status="unconfirmed", remediation="Upgrade dnsmasq", **common),
            ScanResult(title="Missing HSTS", result_type="web_check", severity="low",
                       scan_id=s.id, host="10.0.0.9", match_confidence=None),
        ])
        db.session.commit()
        return s.id


def test_label_property(app):
    from app.models import ScanResult
    _seed(app)
    with app.app_context():
        by_title = {r.title: r for r in ScanResult.query.all()}
        assert by_title["Apache path traversal"].verification_label == "Exploitable"
        assert by_title["Apache path traversal"].verification_note == "nuclei CVE-2021-41773 matched"
        assert by_title["dnsmasq heap overflow"].verification_label == "Unverified"
        assert "version only" in by_title["dnsmasq heap overflow"].verification_note
        assert by_title["Missing HSTS"].verification_label is None


def test_csv_has_verification_columns(app):
    from app.email_utils.report_builder import build_csv_report
    from app.models import Scan
    sid = _seed(app)
    with app.app_context():
        rows = list(csv.DictReader(io.StringIO(
            build_csv_report([db.session.get(Scan, sid)]).decode("utf-8-sig"))))
    got = {r["Title"]: (r["Verification"], r["Verification Detail"]) for r in rows}
    assert got["Apache path traversal"] == ("Exploitable", "nuclei CVE-2021-41773 matched")
    assert got["dnsmasq heap overflow"][0] == "Unverified"
    assert got["Missing HSTS"] == ("", "")


def test_html_report_labels_and_counts(app):
    from app.email_utils.report_builder import build_html_report
    from app.models import Scan
    sid = _seed(app)
    with app.app_context():
        html = build_html_report([db.session.get(Scan, sid)])
    assert 'class="vlabel"' in html
    assert ">Unverified</span>" in html and ">Exploitable</span>" in html
    assert "<b>1</b> was proven exploitable and <b>1</b> is unverified" in html


def _pdf_text(data, tmp_path):
    p = tmp_path / "r.pdf"
    p.write_bytes(data)
    return subprocess.run(["pdftotext", "-layout", str(p), "-"], capture_output=True,
                          text=True, check=True).stdout


@pytest.mark.skipif(not shutil.which("pdftotext"), reason="pdftotext not installed")
def test_pdf_reports_show_labels(app, tmp_path):
    from app.email_utils.report_builder import (build_pdf_report, build_tech_overview_pdf,
                                                build_executive_summary_pdf)
    from app.models import Scan
    sid = _seed(app)
    with app.app_context():
        scan_pdf = _pdf_text(build_pdf_report([db.session.get(Scan, sid)]), tmp_path)
        tech_pdf = _pdf_text(build_tech_overview_pdf(), tmp_path)
        exec_pdf = _pdf_text(build_executive_summary_pdf(), tmp_path)
    for text in (scan_pdf, tech_pdf):
        assert "UNVERIFIED" in text and "EXPLOITABLE" in text
    assert "1 is unverified" in " ".join(exec_pdf.split())


def test_jira_issue_carries_label(app):
    from app.integrations import jira_client
    from app.models import Scan, ScanResult
    sid = _seed(app)

    class Cfg:
        base_url = "https://jira.example"; email = "a@b"; api_token = "t"
        jira_project_key = "SEC"; jira_issue_type = "Bug"

    sent = []

    class Resp:
        status_code = 201
        ok = True
        def json(self): return {"key": "SEC-1"}
        def raise_for_status(self): pass

    def fake_post(url, json=None, **kw):
        sent.append(json)
        return Resp()

    with app.app_context():
        r = ScanResult.query.filter_by(cve_id="CVE-2017-14491").first()
        orig = jira_client.requests.post
        jira_client.requests.post = fake_post
        try:
            jira_client.create_ticket_for_finding(r, db.session.get(Scan, sid), Cfg())
        finally:
            jira_client.requests.post = orig
    fields = sent[0]["fields"]
    assert fields["summary"].startswith("[PwnBroker] HIGH (Unverified): ")
    assert "unverified" in fields["labels"]
    assert "Verification: Unverified" in json.dumps(fields["description"])


def test_confluence_page_labels_and_escapes(app):
    from app.integrations.confluence import _build_page_body
    from app.models import Scan
    sid = _seed(app)
    with app.app_context():
        body = _build_page_body(db.session.get(Scan, sid))
    assert "[UNVERIFIED]" in body and "[EXPLOITABLE]" in body
    assert "Unverified (version match only)</td><td>1</td>" in body
    assert "Weekly &lt;srv&gt;" in body and "Weekly <srv>" not in body
