"""Tests for app/scanner/web_checks.py.

Covers the result_type mislabeling bug: every finding used to come back as
result_type="web_check", a value no vuln-tracking query in the app
recognizes (dashboard counts, /vulns, VulnTicket auto-sync all filter on
result_type == "vulnerability"), so a critical finding like an expired SSL
cert was silently invisible to the whole vulnerability-management workflow.
"""
from unittest.mock import MagicMock, patch

from app.scanner import web_checks as wc


def _resp(status_code=200, headers=None):
    m = MagicMock()
    m.status_code = status_code
    m.headers = headers or {}
    return m


class TestFindingResultType:
    def test_critical_high_medium_become_vulnerability(self):
        for severity in ("critical", "high", "medium"):
            f = wc._finding("https://x", severity, "title", "desc")
            assert f["result_type"] == "vulnerability", severity

    def test_low_stays_info(self):
        f = wc._finding("https://x", "low", "title", "desc")
        assert f["result_type"] == "info"


class TestCheckHeaders:
    def test_missing_security_headers_are_vulnerabilities(self):
        with patch.object(wc.requests, "get", return_value=_resp(headers={})):
            findings = wc._check_headers("https://example.test")

        missing = [f for f in findings if f["title"].startswith("Missing Header")]
        assert missing
        assert all(f["result_type"] == "vulnerability" for f in missing)

    def test_server_header_exposure_is_low_info(self):
        with patch.object(wc.requests, "get",
                           return_value=_resp(headers={"Server": "nginx/1.18.0"})):
            findings = wc._check_headers("https://example.test")

        server_finding = next(f for f in findings if f["title"] == "Server Header Exposed")
        assert server_finding["severity"] == "low"
        assert server_finding["result_type"] == "info"

    def test_connection_failure_returns_single_low_info_finding(self):
        with patch.object(wc.requests, "get", side_effect=Exception("boom")):
            findings = wc._check_headers("https://unreachable.test")

        assert len(findings) == 1
        assert findings[0]["title"] == "Connection Failed"
        assert findings[0]["result_type"] == "info"


class TestCheckSsl:
    def test_expired_cert_is_critical_vulnerability(self):
        expired_cert = {"notAfter": "Jan  1 00:00:00 2000 GMT"}
        fake_ssock = MagicMock()
        fake_ssock.getpeercert.return_value = expired_cert
        fake_ssock.version.return_value = "TLSv1.3"
        fake_ssock.__enter__.return_value = fake_ssock
        fake_ssock.__exit__.return_value = False

        fake_ctx = MagicMock()
        fake_ctx.wrap_socket.return_value = fake_ssock

        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.__exit__.return_value = False

        with patch.object(wc.ssl, "create_default_context", return_value=fake_ctx), \
             patch.object(wc.socket, "create_connection", return_value=fake_sock):
            findings = wc._check_ssl("https://example.test")

        expired = next(f for f in findings if f["title"] == "SSL Certificate Expired")
        assert expired["severity"] == "critical"
        assert expired["result_type"] == "vulnerability"

    def test_non_https_url_is_skipped(self):
        assert wc._check_ssl("http://example.test") == []
