"""Tests for app/scanner/osv_scanner.py's OSV REST API path.

Covers a real bug in _query_osv_api: OSV's /v1/querybatch endpoint
deliberately returns minimal {id, modified} records (no severity, aliases,
or summary) — but the code was using those records directly as if they were
full vulnerability objects. Every finding from the REST fallback path (used
whenever the osv-scanner CLI binary isn't installed) silently got a generic
"medium" severity, no CVE ID, and a blank description, which also breaks
downstream KEV/EPSS enrichment and threat correlation since those key off
cve_id.
"""
from unittest.mock import MagicMock, patch

from app.scanner import osv_scanner as osv


class TestCvss3BaseScore:
    """Reference vectors from the FIRST.org CVSS v3.1 spec / calculator —
    known-correct (vector, base_score) pairs."""

    def test_canonical_critical_vector(self):
        # The textbook 9.8 example used throughout the CVSS spec itself.
        v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        assert osv._cvss3_base_score(v) == 9.8

    def test_scope_changed_vector(self):
        v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H"
        assert osv._cvss3_base_score(v) == 9.6

    def test_low_severity_vector(self):
        v = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
        assert osv._cvss3_base_score(v) == 1.8

    def test_non_v3_vector_returns_none(self):
        assert osv._cvss3_base_score("CVSS:4.0/AV:N/AC:L") is None
        assert osv._cvss3_base_score("") is None
        assert osv._cvss3_base_score(None) is None

    def test_incomplete_vector_returns_none(self):
        assert osv._cvss3_base_score("CVSS:3.1/AV:N/AC:L") is None

    def test_matches_published_nvd_scores_for_real_cves(self):
        # Independently-published NVD base scores, not just hand arithmetic.
        assert osv._cvss3_base_score(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0    # Log4Shell
        assert osv._cvss3_base_score(
            "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0    # Struts2 CVE-2017-5638
        assert osv._cvss3_base_score(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N") == 7.5     # Heartbleed


class TestOsvSeverityPlainNumericFallback:
    def test_plain_numeric_score_still_works(self):
        vuln = {"severity": [{"type": "CVSS_V3", "score": "7.5"}]}
        assert osv._osv_severity(vuln) == 7.5

    def test_picks_highest_across_multiple_entries(self):
        vuln = {"severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
            {"type": "CVSS_V3", "score": "4.0"},
        ]}
        assert osv._osv_severity(vuln) == 9.8


def _resp(json_data):
    m = MagicMock()
    m.ok = True
    m.json.return_value = json_data
    return m


class TestFetchFullVulns:
    def test_fetches_each_unique_id_once(self):
        calls = []

        def fake_get(url, timeout=None):
            calls.append(url)
            vid = url.rsplit("/", 1)[-1]
            return _resp({"id": vid, "summary": f"summary for {vid}"})

        with patch.object(osv.requests, "get", side_effect=fake_get):
            full = osv._fetch_full_vulns({"GHSA-1", "GHSA-2"})

        assert set(full.keys()) == {"GHSA-1", "GHSA-2"}
        assert full["GHSA-1"]["summary"] == "summary for GHSA-1"
        assert len(calls) == 2

    def test_failed_fetch_is_silently_skipped(self):
        with patch.object(osv.requests, "get", side_effect=osv.requests.RequestException("boom")):
            full = osv._fetch_full_vulns({"GHSA-1"})
        assert full == {}


class TestQueryOsvApiEnrichment:
    def test_batch_results_are_enriched_with_full_records(self):
        batch_response = _resp({
            "results": [
                {"vulns": [{"id": "GHSA-xxxx"}]},
            ]
        })
        full_record = {
            "id": "GHSA-xxxx",
            "summary": "A real vulnerability",
            "severity": [{"type": "CVSS_V3",
                          "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "aliases": ["CVE-2024-0001"],
            "affected": [{"ranges": [{"events": [{"fixed": "1.2.3"}]}]}],
        }

        with patch.object(osv.requests, "post", return_value=batch_response), \
             patch.object(osv.requests, "get", return_value=_resp(full_record)):
            results = osv._query_osv_api([("somepkg", "1.0.0", "PyPI")])

        assert len(results) == 1
        pkg, vulns = results[0]
        assert pkg == ("somepkg", "1.0.0", "PyPI")
        assert vulns[0]["summary"] == "A real vulnerability"
        assert osv._aliases(vulns[0]) == ["CVE-2024-0001"]
        assert osv._osv_severity(vulns[0]) == 9.8

    def test_full_fetch_failure_falls_back_to_minimal_record(self):
        batch_response = _resp({"results": [{"vulns": [{"id": "GHSA-xxxx"}]}]})

        with patch.object(osv.requests, "post", return_value=batch_response), \
             patch.object(osv.requests, "get", side_effect=osv.requests.RequestException("boom")):
            results = osv._query_osv_api([("somepkg", "1.0.0", "PyPI")])

        pkg, vulns = results[0]
        assert vulns[0] == {"id": "GHSA-xxxx"}
