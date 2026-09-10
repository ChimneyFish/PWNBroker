"""Tests for CPE-based CVE matching (app/scanner/cve_lookup.py).

No network access is used — requests.get is mocked throughout. Uses the
`app` fixture from conftest.py for a real (temp-file) DB so the
CpeResolutionCache/CpeCveCache caching paths can be exercised for real.
"""
import json
from unittest.mock import MagicMock, patch

from app.scanner import cve_lookup as cl


def _resp(status_code=200, json_data=None):
    m = MagicMock()
    m.status_code = status_code
    m.json.return_value = json_data or {}
    if status_code >= 400:
        m.raise_for_status.side_effect = Exception(f"HTTP {status_code}")
    else:
        m.raise_for_status.return_value = None
    return m


_CPE_DICT_RESPONSE = {
    "products": [
        {"cpe": {"cpeName": "cpe:2.3:a:apache:tomcat:9.0.1:*:*:*:*:*:*:*", "deprecated": False}},
        {"cpe": {"cpeName": "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*", "deprecated": False}},
    ]
}

_CVE_ITEM_TEMPLATE = {
    "descriptions": [{"lang": "en", "value": "A test vulnerability."}],
    "metrics": {
        "cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}],
    },
}


def _cve_item(cve_id, configurations=None):
    item = {"id": cve_id, **_CVE_ITEM_TEMPLATE}
    if configurations is not None:
        item["configurations"] = configurations
    return {"cve": item}


class TestCpe22To23:
    """Real cpe values nmap returned in the wild (from a subnet scan that
    silently produced zero vulnerabilities despite fingerprinting real,
    identifiable services with known version numbers) — nmap emits CPE 2.2
    URI-binding format, but NVD's cpeName API parameter requires CPE 2.3
    formatted strings. Passed through unconverted, cpeName matches nothing
    and NVD silently returns zero results — no error, no vulnerabilities."""

    def test_converts_real_nmap_cpe_values(self):
        cases = {
            "cpe:/o:linux:linux_kernel": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
            "cpe:/a:lighttpd:lighttpd:1.4.54": "cpe:2.3:a:lighttpd:lighttpd:1.4.54:*:*:*:*:*:*:*",
            "cpe:/a:gunicorn:gunicorn": "cpe:2.3:a:gunicorn:gunicorn:*:*:*:*:*:*:*:*",
            "cpe:/a:jesse_smith:bftpd:4.4": "cpe:2.3:a:jesse_smith:bftpd:4.4:*:*:*:*:*:*:*",
            "cpe:/a:thekelleys:dnsmasq:2.75": "cpe:2.3:a:thekelleys:dnsmasq:2.75:*:*:*:*:*:*:*",
            "cpe:/a:netatalk:netatalk:3.1.8": "cpe:2.3:a:netatalk:netatalk:3.1.8:*:*:*:*:*:*:*",
            "cpe:/a:cesanta:mongoose": "cpe:2.3:a:cesanta:mongoose:*:*:*:*:*:*:*:*",
            "cpe:/a:haproxy:haproxy": "cpe:2.3:a:haproxy:haproxy:*:*:*:*:*:*:*:*",
        }
        for cpe22, expected in cases.items():
            assert cl._cpe22_to_23(cpe22) == expected, cpe22

    def test_output_always_has_eleven_fields(self):
        result = cl._cpe22_to_23("cpe:/a:vendor:product:1.0")
        fields = result[len("cpe:2.3:"):].split(":")
        assert len(fields) == 11

    def test_non_cpe_input_returns_none(self):
        assert cl._cpe22_to_23("not-a-cpe-string") is None
        assert cl._cpe22_to_23("") is None
        assert cl._cpe22_to_23(None) is None

    def test_already_2_3_format_returns_none_rather_than_mangle_it(self):
        # This function only ever handles 2.2 URI input in practice (callers
        # only invoke it on nmap's raw `cpe` field, always 2.2 format) — but
        # it must fail safe rather than corrupt an already-valid string.
        assert cl._cpe22_to_23("cpe:2.3:a:apache:tomcat:9.0.1:*:*:*:*:*:*:*") is None


class TestResolveCpe:
    def test_disambiguates_by_product_token_and_version(self, app):
        with app.app_context():
            with patch.object(cl.requests, "get", return_value=_resp(json_data=_CPE_DICT_RESPONSE)) as mock_get:
                resolved = cl.resolve_cpe("Apache httpd", "2.4.41")

            assert resolved == "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"
            mock_get.assert_called_once()

    def test_returns_none_when_no_candidate_clears_bar(self, app):
        with app.app_context():
            with patch.object(cl.requests, "get", return_value=_resp(json_data={"products": []})):
                resolved = cl.resolve_cpe("totally_unknown_widget", "1.0")

            assert resolved is None

    def test_cache_hit_skips_http_call(self, app):
        with app.app_context():
            with patch.object(cl.requests, "get", return_value=_resp(json_data=_CPE_DICT_RESPONSE)):
                cl.resolve_cpe("Apache httpd", "2.4.41")

            with patch.object(cl.requests, "get") as mock_get:
                resolved = cl.resolve_cpe("Apache httpd", "2.4.41")

            mock_get.assert_not_called()
            assert resolved == "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"


class TestLookupCvesByCpe:
    def test_excludes_non_vulnerable_configuration_branch(self, app):
        cpe = "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"
        data = {
            "vulnerabilities": [
                _cve_item("CVE-2021-0001", configurations=[
                    {"nodes": [{"cpeMatch": [{"criteria": cpe, "vulnerable": True}]}]}
                ]),
                _cve_item("CVE-2021-0002", configurations=[
                    {"nodes": [{"cpeMatch": [{"criteria": cpe, "vulnerable": False}]}]}
                ]),
            ]
        }
        with app.app_context():
            with patch.object(cl.requests, "get", return_value=_resp(json_data=data)):
                results = cl.lookup_cves_by_cpe(cpe)

        ids = {r["cve_id"] for r in results}
        assert ids == {"CVE-2021-0001"}
        assert results[0]["match_confidence"] == "cpe"

    def test_cache_hit_skips_http_call(self, app):
        cpe = "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"
        data = {"vulnerabilities": [_cve_item("CVE-2021-0001")]}
        with app.app_context():
            with patch.object(cl.requests, "get", return_value=_resp(json_data=data)):
                cl.lookup_cves_by_cpe(cpe)

            with patch.object(cl.requests, "get") as mock_get:
                results = cl.lookup_cves_by_cpe(cpe)

            mock_get.assert_not_called()
            assert results[0]["cve_id"] == "CVE-2021-0001"


class TestLookupCvesForService:
    def test_uses_supplied_cpe_without_resolving(self, app):
        # Real callers (engine.py's _append_port_results) always pass
        # nmap's own `cpe` field here, which is CPE 2.2 URI-binding format
        # ("cpe:/a:vendor:product:version"), not the CPE 2.3 formatted
        # string NVD's API requires — this must get converted internally.
        nmap_cpe = "cpe:/a:apache:http_server:2.4.41"
        expected_23 = "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"
        data = {"vulnerabilities": [_cve_item("CVE-2021-0001")]}
        with app.app_context():
            with patch.object(cl, "resolve_cpe") as mock_resolve:
                with patch.object(cl.requests, "get", return_value=_resp(json_data=data)):
                    results = cl.lookup_cves_for_service("Apache httpd", "2.4.41", cpe=nmap_cpe)

            mock_resolve.assert_not_called()
            assert results[0]["cve_id"] == "CVE-2021-0001"
            assert results[0]["cpe"] == expected_23

    def test_falls_back_to_cpe_dictionary_when_nmap_cpe_unparsable(self, app):
        """A malformed/empty nmap `cpe` field must not silently produce zero
        results — it should fall back to resolve_cpe() same as no CPE at all."""
        data = {"vulnerabilities": [_cve_item("CVE-2021-0003")]}
        with app.app_context():
            with patch.object(cl, "resolve_cpe", return_value="cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*") as mock_resolve:
                with patch.object(cl.requests, "get", return_value=_resp(json_data=data)):
                    results = cl.lookup_cves_for_service("product", "1.0", cpe="not-a-real-cpe")

            mock_resolve.assert_called_once_with("product", "1.0")
            assert results[0]["cve_id"] == "CVE-2021-0003"

    def test_falls_back_to_keyword_when_no_cpe_resolvable(self, app):
        data = {"vulnerabilities": [_cve_item("CVE-2021-0002")]}
        with app.app_context():
            with patch.object(cl, "resolve_cpe", return_value=None):
                with patch.object(cl.requests, "get", return_value=_resp(json_data=data)):
                    results = cl.lookup_cves_for_service("totally_unknown_widget", "1.0")

            assert results[0]["match_confidence"] == "keyword"
            assert results[0]["cpe"] == ""


class TestNvdGet:
    def test_retries_on_429_then_succeeds(self, app):
        with app.app_context():
            with patch.object(cl.time, "sleep"):
                with patch.object(
                    cl.requests, "get",
                    side_effect=[_resp(status_code=429), _resp(status_code=200, json_data={"ok": True})],
                ) as mock_get:
                    data = cl._nvd_get("http://example.test", {}, "")

            assert data == {"ok": True}
            assert mock_get.call_count == 2

    def test_exhausts_retries_and_returns_none(self, app):
        with app.app_context():
            with patch.object(cl.time, "sleep"):
                with patch.object(cl.requests, "get", return_value=_resp(status_code=403)):
                    data = cl._nvd_get("http://example.test", {}, "", max_retries=3)

            assert data is None


class TestAppendPortResults:
    def test_populates_cpe_and_match_confidence(self, app):
        from app.scanner.engine import _append_port_results
        from app.models import Scan, Target

        with app.app_context():
            from app.extensions import db
            target = Target(name="t", host="1.2.3.4")
            db.session.add(target)
            db.session.commit()
            scan = Scan(name="s", target_id=target.id, scan_type="full")
            db.session.add(scan)
            db.session.commit()

            fake_cve = {
                "cve_id": "CVE-2021-0001",
                "description": "desc",
                "cvss_score": 9.8,
                "severity": "critical",
                "cpe": "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*",
                "match_confidence": "cpe",
            }
            ports = [{
                "host": "1.2.3.4", "port": 80, "protocol": "tcp",
                "service": "http", "product": "Apache httpd", "version": "2.4.41",
                "cpe": "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*",
            }]

            results = []
            with patch("app.scanner.cve_lookup.lookup_cves_for_service", return_value=[fake_cve]) as mock_lookup:
                _append_port_results(results, scan.id, ports, do_cve=True)

            mock_lookup.assert_called_once_with(
                "Apache httpd", "2.4.41",
                cpe="cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*",
            )

        port_row = next(r for r in results if r.result_type == "port")
        vuln_row = next(r for r in results if r.result_type == "vulnerability")
        assert port_row.cpe == "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"
        assert vuln_row.cpe == fake_cve["cpe"]
        assert vuln_row.match_confidence == "cpe"


class TestMatchConfidenceBadge:
    def test_scan_view_shows_cpe_and_keyword_badges(self, app, admin_client):
        from app.extensions import db
        from app.models import Target, Scan, ScanResult

        with app.app_context():
            target = Target(name="badge-test", host="1.2.3.4")
            db.session.add(target)
            db.session.commit()
            scan = Scan(name="badge scan", target_id=target.id, scan_type="full", status="done")
            db.session.add(scan)
            db.session.commit()
            db.session.add_all([
                ScanResult(
                    scan_id=scan.id, result_type="vulnerability", host="1.2.3.4",
                    severity="critical", title="CVE-2021-0001", cve_id="CVE-2021-0001",
                    cvss_score=9.8, match_confidence="cpe",
                    cpe="cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*",
                ),
                ScanResult(
                    scan_id=scan.id, result_type="vulnerability", host="1.2.3.4",
                    severity="medium", title="CVE-2021-0002", cve_id="CVE-2021-0002",
                    cvss_score=5.0, match_confidence="keyword",
                ),
            ])
            db.session.commit()
            scan_id = scan.id

        resp = admin_client.get(f"/scans/{scan_id}")
        body = resp.data.decode()
        assert resp.status_code == 200
        assert "CPE-matched" in body
        assert "Keyword match" in body

    def test_vulns_pages_show_badge_via_linked_scan_result(self, app, admin_client):
        """vulns.device / vulns.tickets render VulnTicket rows, which don't
        carry match_confidence themselves — they pick it up through the
        VulnTicket.scan_result relationship back to the originating
        ScanResult, auto-created by _auto_sync()."""
        from app.extensions import db
        from app.models import Target, Scan, ScanResult

        with app.app_context():
            target = Target(name="badge-vulns-test", host="1.2.3.4")
            db.session.add(target)
            db.session.commit()
            scan = Scan(name="badge vulns scan", target_id=target.id, scan_type="full", status="done")
            db.session.add(scan)
            db.session.commit()
            db.session.add_all([
                ScanResult(
                    scan_id=scan.id, result_type="vulnerability", host="1.2.3.4",
                    severity="critical", title="CVE-2021-0003", cve_id="CVE-2021-0003",
                    cvss_score=9.8, match_confidence="cpe",
                    cpe="cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*",
                ),
                ScanResult(
                    scan_id=scan.id, result_type="vulnerability", host="1.2.3.4",
                    severity="medium", title="CVE-2021-0004", cve_id="CVE-2021-0004",
                    cvss_score=5.0, match_confidence="keyword",
                ),
            ])
            db.session.commit()
            target_id = target.id

        device_resp = admin_client.get(f"/vulns/device/{target_id}")
        device_body = device_resp.data.decode()
        assert device_resp.status_code == 200
        assert "CPE-matched" in device_body
        assert "Keyword match" in device_body

        tickets_resp = admin_client.get("/vulns/tickets?status=all")
        tickets_body = tickets_resp.data.decode()
        assert tickets_resp.status_code == 200
        assert "CPE-matched" in tickets_body
        assert "Keyword match" in tickets_body


class TestEnrichScanCves:
    def test_creates_enrichment_rows_without_a_vuln_ticket(self, app):
        from app.grc.enrichment import enrich_scan_cves
        from app.models import CVEEnrichment

        with patch("app.grc.enrichment.fetch_epss", return_value={
            "CVE-2021-0001": {"score": 0.9, "percentile": 0.99}
        }):
            with patch("app.grc.enrichment.get_kev_index", return_value={
                "CVE-2021-0001": {"date_added": None, "due_date": None, "ransomware": False}
            }):
                enrich_scan_cves(["CVE-2021-0001"], app=app)

        with app.app_context():
            e = CVEEnrichment.query.filter_by(cve_id="CVE-2021-0001").first()
            assert e is not None
            assert e.epss_score == 0.9
            assert e.kev_listed is True
