"""Tests for the NSE vuln-script confirmation path in app/scanner/engine.py.

nmap's --script vuln category (added to single-host scans in nmap_scanner.py)
runs an active probe against the live service and reports a real
VULNERABLE/NOT VULNERABLE verdict via its shared vulns.lua output format —
this is the one source in the scanner that actually demonstrates a
vulnerability against the target, rather than correlating a version banner
against NVD, so a positive hit is promoted to verification_status="confirmed"
independent of (and ahead of) the speculative CPE/keyword CVE match path.
"""
from unittest.mock import patch

from app.scanner.engine import _parse_nse_vuln_scripts, _append_port_results


_VULNERABLE_OUTPUT = """
VULNERABLE:
Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
  State: VULNERABLE
  IDs:  CVE:CVE-2017-0143
  Risk factor: HIGH
    A critical remote code execution vulnerability exists in Microsoft SMBv1
    servers (ms17-010).
"""

_NOT_VULNERABLE_OUTPUT = """
  State: NOT VULNERABLE
"""


class TestParseNseVulnScripts:
    def test_positive_hit_is_confirmed_with_cve_and_severity(self):
        scripts = {"smb-vuln-ms17-010": _VULNERABLE_OUTPUT}
        findings = _parse_nse_vuln_scripts(scripts, "10.0.0.5", 445, "tcp")

        assert len(findings) == 1
        f = findings[0]
        assert f["cve_id"] == "CVE-2017-0143"
        assert f["severity"] == "high"
        assert "smb-vuln-ms17-010" in f["title"]

    def test_not_vulnerable_is_skipped(self):
        scripts = {"smb-vuln-ms17-010": _NOT_VULNERABLE_OUTPUT}
        assert _parse_nse_vuln_scripts(scripts, "10.0.0.5", 445, "tcp") == []

    def test_empty_or_missing_scripts_dict(self):
        assert _parse_nse_vuln_scripts({}, "10.0.0.5", 445, "tcp") == []
        assert _parse_nse_vuln_scripts(None, "10.0.0.5", 445, "tcp") == []

    def test_no_risk_factor_defaults_to_high(self):
        scripts = {"some-vuln-script": "State: VULNERABLE\nno risk line here"}
        findings = _parse_nse_vuln_scripts(scripts, "10.0.0.5", 22, "tcp")
        assert findings[0]["severity"] == "high"

    def test_likely_vulnerable_state_also_counts(self):
        scripts = {"ssl-heartbleed": "State: LIKELY VULNERABLE\nRisk factor: HIGH"}
        findings = _parse_nse_vuln_scripts(scripts, "10.0.0.5", 443, "tcp")
        assert len(findings) == 1


class TestAppendPortResultsNseIntegration:
    def test_confirmed_nse_finding_gets_confirmed_verification_status(self, app):
        with app.app_context():
            from app.extensions import db
            from app.models import Target, Scan

            target = Target(name="t", host="10.0.0.5")
            db.session.add(target)
            db.session.commit()
            scan = Scan(name="s", target_id=target.id, scan_type="port")
            db.session.add(scan)
            db.session.commit()

            ports = [{
                "host": "10.0.0.5", "port": 445, "protocol": "tcp",
                "service": "microsoft-ds", "product": "", "version": "",
                "scripts": {"smb-vuln-ms17-010": _VULNERABLE_OUTPUT},
            }]

            results = []
            with patch("app.scanner.cve_lookup.lookup_cves_for_service", return_value=[]):
                _append_port_results(results, scan.id, ports, do_cve=False)

        vuln_rows = [r for r in results if r.result_type == "vulnerability"]
        assert len(vuln_rows) == 1
        assert vuln_rows[0].verification_status == "confirmed"
        assert vuln_rows[0].cve_id == "CVE-2017-0143"

    def test_cve_lookup_match_is_unconfirmed(self, app):
        with app.app_context():
            from app.extensions import db
            from app.models import Target, Scan

            target = Target(name="t", host="10.0.0.6")
            db.session.add(target)
            db.session.commit()
            scan = Scan(name="s", target_id=target.id, scan_type="full")
            db.session.add(scan)
            db.session.commit()

            fake_cve = {
                "cve_id": "CVE-2021-0001", "description": "desc", "cvss_score": 9.8,
                "severity": "critical", "cpe": "", "match_confidence": "keyword",
            }
            ports = [{
                "host": "10.0.0.6", "port": 80, "protocol": "tcp",
                "service": "http", "product": "SomeServer", "version": "1.0",
            }]

            results = []
            with patch("app.scanner.cve_lookup.lookup_cves_for_service", return_value=[fake_cve]):
                _append_port_results(results, scan.id, ports, do_cve=True)

        vuln_row = next(r for r in results if r.result_type == "vulnerability")
        assert vuln_row.verification_status == "unconfirmed"
