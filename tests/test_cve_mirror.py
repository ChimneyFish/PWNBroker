"""Local NVD + CVE.org mirror (app/cve_mirror). No network access: upstream
responses are built in-test and served through a patched requests.get."""
import gzip
import io
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from app.cve_mirror import parse, query, sync
from app.cve_mirror.versions import compare_versions, normalize_scanned_version, version_in_range


# ── fixtures / builders ──────────────────────────────────────────────────────

def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def nvd_item(cve_id, matches, score=9.8, status="Analyzed", desc="test vuln"):
    return {
        "id": cve_id, "published": "2024-07-01T13:15:00.000", "lastModified": "2024-07-02T00:00:00.000",
        "vulnStatus": status,
        "descriptions": [{"lang": "en", "value": desc}],
        "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {
            "baseScore": score, "baseSeverity": "CRITICAL", "vectorString": "CVSS:3.1/AV:N"}}]},
        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-787"}]}],
        "configurations": [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": matches}]}] if matches else [],
        "references": [{"url": "https://example.com/advisory"}, {"url": "javascript:alert(1)"}],
    }


def cm(criteria, **ranges):
    return {"vulnerable": True, "criteria": criteria, **ranges}


def cveorg_record(cve_id, vendor, product, versions, state="PUBLISHED", cpes=None, default=None):
    affected = {"vendor": vendor, "product": product, "versions": versions}
    if cpes:
        affected["cpes"] = cpes
    if default:
        affected["defaultStatus"] = default
    return {
        "dataType": "CVE_RECORD", "dataVersion": "5.1",
        "cveMetadata": {"cveId": cve_id, "state": state, "assignerShortName": "acme",
                        "datePublished": "2026-11-01T00:00:00.000Z", "dateUpdated": "2026-11-20T10:00:00.000Z"},
        "containers": {"cna": {
            "descriptions": [{"lang": "en", "value": f"{product} issue"}],
            "affected": [affected],
            "metrics": [{"cvssV3_1": {"baseScore": 8.1, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/x"}}],
        }},
    }


def mark_ready():
    sync._set_state("nvd", last_full_at=_utcnow(), last_sync_at=_utcnow(), status="ok")
    query.invalidate_caches()


@pytest.fixture()
def ctx(app):
    with app.app_context():
        query.invalidate_caches()
        yield app
        query.invalidate_caches()


# ── versions ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("a,b,expected", [
    ("2.4.49", "2.4.50", -1),
    ("2.4.9", "2.4.49", -1),
    ("2.4", "2.4.0", 0),
    ("9.6p1", "9.8p1", -1),
    ("9.6p1", "9.6", 1),
    ("9.6p1", "9.6.1", -1),
    ("1.0rc1", "1.0", -1),
    ("1.0b2", "1.0", -1),
    ("1.0", "1.0a", -1),
    ("1.1.1k", "1.1.1l", -1),
    ("v2.0.1", "2.0.1", 0),
    ("2.75", "2.78", -1),
    ("10.0", "9.9", 1),
])
def test_compare_versions(a, b, expected):
    assert compare_versions(a, b) == expected
    assert compare_versions(b, a) == -expected


def test_version_in_range():
    assert version_in_range("2.75", exact="*", end_excl="2.78")
    assert not version_in_range("2.78", exact="*", end_excl="2.78")
    assert version_in_range("2.78", exact="*", end_incl="2.78")
    assert version_in_range("8.5p1", exact="*", start_incl="8.5p1", end_excl="9.8p1")
    assert not version_in_range("8.4p1", exact="*", start_incl="8.5p1", end_excl="9.8p1")
    assert not version_in_range("1.0", exact="*", start_excl="1.0")
    assert version_in_range("1.4.54", exact="1.4.54")
    assert not version_in_range("1.4.55", exact="1.4.54")
    assert not version_in_range("1.0", exact="-")
    assert version_in_range("3.0", exact="*")          # NVD "all versions"
    assert not version_in_range("", exact="*")


def test_normalize_scanned_version():
    assert normalize_scanned_version("10.0p2 Debian 7+deb13u4") == "10.0p2"
    assert normalize_scanned_version("9.6p1 Ubuntu 3ubuntu13.20") == "9.6p1"
    assert normalize_scanned_version("2.0.0 or later") == ""      # only a lower bound
    assert normalize_scanned_version("") == ""
    assert normalize_scanned_version("unknown") == ""


# ── parsing ──────────────────────────────────────────────────────────────────

def test_parse_nvd_rejoins_split_versions_and_skips_platform_criteria():
    item = nvd_item("CVE-2024-6387", [
        cm("cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*"),
        cm("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", versionStartIncluding="8.5", versionEndExcluding="9.8"),
        {"vulnerable": False, "criteria": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"},
    ])
    row, matches = parse.parse_nvd(item)
    assert row["cve_id"] == "CVE-2024-6387" and row["nvd_has_config"] is True
    assert row["nvd_cvss_v3"] == 9.8 and row["nvd_severity"] == "CRITICAL"
    assert json.loads(row["cwe_ids"]) == ["CWE-787"]
    assert {m["version"] for m in matches} == {"9.6p1", "*"}
    assert all(m["product"] == "openssh" for m in matches)   # kernel platform row dropped


def test_parse_nvd_rejected_and_unanalysed():
    row, matches = parse.parse_nvd(nvd_item("CVE-2026-1", [], status="Rejected"))
    assert row["state"] == "REJECTED" and matches == [] and row["nvd_has_config"] is False


def test_parse_cveorg_ranges_and_names():
    rec = cveorg_record("CVE-2026-0001", "Acme Corp", "Widget Server", [
        {"version": "1.0", "lessThan": "1.4.2", "status": "affected", "versionType": "semver"},
        {"version": "2.0.1", "status": "affected"},
        {"version": "deadbeefcafe1234", "status": "affected", "versionType": "git"},
        {"version": "3.0", "status": "unaffected"},
    ])
    row, matches = parse.parse_cveorg(rec)
    assert row["in_cveorg"] and row["cna_cvss"] == 8.1 and row["assigner"] == "acme"
    assert row["cveorg_updated"] == datetime(2026, 11, 20, 10, 0)
    assert {(m["vendor"], m["product"]) for m in matches} == {("acme_corp", "widget_server")}
    got = {(m["version"], m["v_start_incl"], m["v_end_excl"]) for m in matches}
    assert got == {("*", "1.0", "1.4.2"), ("2.0.1", None, None)}


def test_parse_cveorg_prefers_cpes_and_handles_rejected():
    rec = cveorg_record("CVE-2026-0002", "The Apache Software Foundation", "Apache HTTP Server",
                        [{"version": "2.4.0", "lessThanOrEqual": "2.4.61", "status": "affected"}],
                        cpes=["cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"])
    _, matches = parse.parse_cveorg(rec)
    assert {(m["vendor"], m["product"], m["v_end_incl"]) for m in matches} == {("apache", "http_server", "2.4.61")}

    row, matches = parse.parse_cveorg(cveorg_record("CVE-2026-0003", "x", "y", [], state="REJECTED"))
    assert row["state"] == "REJECTED" and matches == []


def test_iter_json_array_streams_across_chunk_boundaries():
    doc = json.dumps({"format": "NVD_CVE", "vulnerabilities": [{"cve": {"id": f"CVE-2020-{i}", "pad": "x" * i}}
                                                               for i in range(300)]})
    out = list(sync.iter_json_array(io.StringIO(doc), "vulnerabilities", chunk_size=97))
    assert [o["cve"]["id"] for o in out] == [f"CVE-2020-{i}" for i in range(300)]
    assert list(sync.iter_json_array(io.StringIO('{"vulnerabilities": []}'), "vulnerabilities")) == []


# ── storage + matching ───────────────────────────────────────────────────────

def _load_scan13_fixtures():
    """The services from the real scan that reported zero vulnerabilities."""
    sync.store_batch("nvd", [parse.parse_nvd(i) for i in [
        nvd_item("CVE-2017-14491", [cm("cpe:2.3:a:thekelleys:dnsmasq:*:*:*:*:*:*:*:*", versionEndExcluding="2.78")]),
        nvd_item("CVE-2024-6387", [cm("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                                      versionStartIncluding="8.5", versionEndExcluding="9.8")], score=8.1),
        nvd_item("CVE-2023-0001", [cm("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", versionEndExcluding="9.0")], score=5.0),
        nvd_item("CVE-2022-0002", [cm("cpe:2.3:a:lighttpd:lighttpd:1.4.54:*:*:*:*:*:*:*")], score=7.5),
        nvd_item("CVE-2022-0003", [cm("cpe:2.3:a:haproxy:haproxy:*:*:*:*:*:*:*:*", versionEndExcluding="2.0.5")]),
        nvd_item("CVE-2021-9999", [cm("cpe:2.3:a:thekelleys:dnsmasq:*:*:*:*:*:*:*:*",
                                      versionEndExcluding="2.90")], status="Rejected"),
        nvd_item("CVE-2026-0010", []),   # in NVD, not analysed yet
    ]])
    sync.store_batch("cveorg", [
        parse.parse_cveorg(cveorg_record("CVE-2026-0010", "Simon Kelley", "dnsmasq",
                                         [{"version": "2.0", "lessThan": "2.91", "status": "affected"}],
                                         cpes=["cpe:2.3:a:thekelleys:dnsmasq:*:*:*:*:*:*:*:*"])),
        # NVD *has* analysed this one and says dnsmasq isn't affected; the CNA
        # row must not override that.
        parse.parse_cveorg(cveorg_record("CVE-2017-14491", "thekelleys", "dnsmasq",
                                         [{"version": "2.0", "lessThan": "9.0", "status": "affected"}])),
    ])
    mark_ready()


def test_lookup_scan13_services(ctx):
    _load_scan13_fixtures()

    cves, cpe = query.lookup_service("dnsmasq", "2.75", "cpe:2.3:a:thekelleys:dnsmasq:2.75:*:*:*:*:*:*:*")
    by_id = {c["cve_id"]: c for c in cves}
    assert set(by_id) == {"CVE-2017-14491", "CVE-2026-0010"}     # rejected CVE-2021-9999 excluded
    assert by_id["CVE-2017-14491"]["severity"] == "critical"
    assert by_id["CVE-2017-14491"]["mirror_source"] == "nvd"
    assert by_id["CVE-2026-0010"]["mirror_source"] == "cveorg"
    assert cpe == "cpe:2.3:a:thekelleys:dnsmasq:2.75:*:*:*:*:*:*:*"

    # nmap gave only the OS CPE for OpenSSH — must resolve OpenSSH itself.
    cves, cpe = query.lookup_service("OpenSSH", "9.6p1 Ubuntu 3ubuntu13.20",
                                     "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*")
    assert [c["cve_id"] for c in cves] == ["CVE-2024-6387"]
    assert cpe.startswith("cpe:2.3:a:openbsd:openssh:9.6p1")
    assert query.lookup_service("OpenSSH", "10.0p2 Debian 7+deb13u4", "")[0] == []

    # nmap's CPE has no version — the banner version fills it in...
    assert [c["cve_id"] for c in query.lookup_service(
        "HAProxy http proxy", "2.0.0", "cpe:2.3:a:haproxy:haproxy:*:*:*:*:*:*:*:*")[0]] == ["CVE-2022-0003"]
    # ...but "or later" is only a lower bound, not a version.
    assert query.lookup_service(
        "HAProxy http proxy", "2.0.0 or later", "cpe:2.3:a:haproxy:haproxy:*:*:*:*:*:*:*:*") == ([], "")
    assert [c["cve_id"] for c in query.lookup_service(
        "lighttpd", "1.4.54", "cpe:2.3:a:lighttpd:lighttpd:1.4.54:*:*:*:*:*:*:*")[0]] == ["CVE-2022-0002"]
    # No version at all — nothing to compare, nothing matched.
    assert query.lookup_service("Mongoose httpd", "", "cpe:2.3:a:cesanta:mongoose:*:*:*:*:*:*:*:*") == ([], "")


def test_cveorg_row_suppressed_once_nvd_has_analysed(ctx):
    _load_scan13_fixtures()
    ids = [c["cve_id"] for c in query.lookup("thekelleys", "dnsmasq", "2.80")]
    assert "CVE-2017-14491" not in ids        # NVD range ends < 2.78; CNA row ignored
    assert "CVE-2026-0010" in ids


def test_sources_do_not_clobber_each_other(ctx):
    _load_scan13_fixtures()
    r = query.get_cve("CVE-2026-0010")
    assert r["in_nvd"] and r["in_cveorg"]
    assert r["nvd_description"] == "test vuln" and r["cna_description"] == "dnsmasq issue"
    sync.store_batch("nvd", [parse.parse_nvd(nvd_item("CVE-2026-0010", [], desc="updated"))])
    r = query.get_cve("CVE-2026-0010")
    assert r["nvd_description"] == "updated" and r["cna_description"] == "dnsmasq issue" and r["in_cveorg"]


def test_scanner_uses_mirror_without_network(ctx):
    from app.scanner import cve_lookup
    _load_scan13_fixtures()
    with patch("app.scanner.cve_lookup.requests.get", side_effect=AssertionError("no NVD API call expected")):
        cves = cve_lookup.lookup_cves_for_service("dnsmasq", "2.75", cpe="cpe:/a:thekelleys:dnsmasq:2.75")
    assert "CVE-2017-14491" in [c["cve_id"] for c in cves]
    assert all(c["match_confidence"] == "cpe" for c in cves)
    assert cves[0]["cpe"].startswith("cpe:2.3:a:thekelleys:dnsmasq:2.75")


def test_scanner_falls_back_to_api_until_first_full_sync(ctx):
    from app.scanner import cve_lookup
    assert not query.is_ready()
    with patch.object(cve_lookup, "lookup_cves_by_cpe", return_value=[{"cve_id": "CVE-X"}]) as api:
        out = cve_lookup.lookup_cves_for_service("dnsmasq", "2.75", cpe="cpe:/a:thekelleys:dnsmasq:2.75")
    api.assert_called_once()
    assert out[0]["cve_id"] == "CVE-X"


def test_references_are_http_only(ctx):
    _load_scan13_fixtures()
    assert query.references(query.get_cve("CVE-2017-14491")) == ["https://example.com/advisory"]


def test_enrichment_reads_mirror(ctx):
    from app.grc.enrichment import mirror_nvd_record
    _load_scan13_fixtures()
    r = mirror_nvd_record("CVE-2017-14491")
    assert r["cvss_v3"] == 9.8 and r["cwe_ids"] == ["CWE-787"] and r["description"] == "test vuln"
    assert mirror_nvd_record("CVE-1999-0000") == {}


# ── sync orchestration ───────────────────────────────────────────────────────

def _resp(body=b"", js=None, text=""):
    r = MagicMock()
    r.raise_for_status.return_value = None
    r.iter_content.return_value = [body]
    r.json.return_value = js
    r.text = text
    r.__enter__ = lambda s: s
    r.__exit__ = lambda s, *a: False
    return r


def test_nvd_incremental_sync_skips_unchanged_feed(ctx, monkeypatch):
    feed = gzip.compress(json.dumps({"vulnerabilities": [{"cve": nvd_item(
        "CVE-2026-5555", [cm("cpe:2.3:a:thekelleys:dnsmasq:*:*:*:*:*:*:*:*", versionEndExcluding="3.0")])}]}).encode())
    calls = []

    def fake_get(url, **kw):
        calls.append(url)
        if url.endswith(".meta"):
            return _resp(text="lastModifiedDate:x\nsha256:ABC\n")
        return _resp(body=feed)

    monkeypatch.setattr(sync.requests, "get", fake_get)
    now = _utcnow()
    sync._set_state("nvd", last_full_at=now - timedelta(days=3), last_sync_at=now - timedelta(hours=2), cursor="OLD")
    assert sync.sync_nvd(ctx, ctx.config["CVE_MIRROR_WORK_DIR"]) == 1
    assert any(u.endswith("nvdcve-2.0-modified.json.gz") for u in calls)
    assert not any("nvdcve-2.0-2024" in u for u in calls)      # stayed incremental
    st = sync._state("nvd")
    assert st.cursor == "ABC" and st.status == "ok" and st.records == 1

    calls.clear()
    assert sync.sync_nvd(ctx, ctx.config["CVE_MIRROR_WORK_DIR"]) == 0                     # same sha -> nothing downloaded
    assert all(u.endswith(".meta") for u in calls)


def test_nvd_sync_goes_full_when_incremental_window_missed(ctx, monkeypatch, tmp_path):
    feed = gzip.compress(b'{"vulnerabilities": []}')
    calls = []
    monkeypatch.setattr(sync.requests, "get", lambda url, **kw: (calls.append(url), _resp(
        text="sha256:Z\n") if url.endswith(".meta") else _resp(body=feed))[1])
    now = _utcnow()
    sync._set_state("nvd", last_full_at=now - timedelta(days=30), last_sync_at=now - timedelta(days=10))
    sync.sync_nvd(ctx, str(tmp_path))
    assert any("nvdcve-2.0-2002" in u for u in calls) and any(f"nvdcve-2.0-{now.year}" in u for u in calls)
    assert sync._state("nvd").last_full_at > now - timedelta(minutes=1)


def test_cveorg_incremental_from_delta_log(ctx, monkeypatch, tmp_path):
    rec = cveorg_record("CVE-2026-7777", "Simon Kelley", "dnsmasq",
                        [{"version": "2.0", "lessThan": "2.91", "status": "affected"}])
    delta = [{"fetchTime": "2026-11-20T00:00:00Z", "new": [
                {"cveId": "CVE-2026-7777", "githubLink": "https://raw.example/CVE-2026-7777.json",
                 "dateUpdated": "2026-11-20T10:00:00.000Z"}],
              "updated": [{"cveId": "CVE-2026-0001", "githubLink": "https://raw.example/old.json",
                           "dateUpdated": "2026-11-01T00:00:00.000Z"}]},
             {"fetchTime": "2026-10-25T00:00:00Z", "new": [], "updated": []}]
    fetched = []

    class FakeSession:
        headers = {}

        def get(self, url, **kw):
            fetched.append(url)
            return _resp(js=delta if "deltaLog" in url else rec)

    monkeypatch.setattr(sync.requests, "Session", FakeSession)
    sync._set_state("cveorg", last_full_at=datetime(2026, 11, 1), last_sync_at=datetime(2026, 11, 19),
                    cursor="2026-11-10T00:00:00Z")
    assert sync.sync_cveorg(ctx, str(tmp_path)) == 1
    assert "https://raw.example/old.json" not in fetched       # older than the cursor
    st = sync._state("cveorg")
    assert st.cursor.startswith("2026-11-20T10:00") and st.status == "ok"
    assert query.get_cve("CVE-2026-7777")["in_cveorg"]


def test_run_sync_is_exclusive(ctx):
    with sync._lock(ctx):
        with pytest.raises(sync.SyncBusy):
            sync.run_sync(ctx)


def test_cve_db_pages(ctx, admin_client):
    _load_scan13_fixtures()
    r = admin_client.get("/cve-db/?q=dnsmasq")
    assert r.status_code == 200 and b"CVE-2017-14491" in r.data
    r = admin_client.get("/cve-db/?q=CVE-2024")
    assert b"CVE-2024-6387" in r.data
    r = admin_client.get("/cve-db/cve/CVE-2017-14491")
    assert r.status_code == 200 and b"thekelleys" in r.data and b"javascript:" not in r.data
    assert admin_client.get("/cve-db/cve/CVE-1999-0000").status_code == 404
    s = admin_client.get("/cve-db/status.json").get_json()
    assert s["ready"] is True and s["total"] >= 7


def test_parse_cveorg_range_written_in_version_string():
    rec = cveorg_record("CVE-2026-110779", "Netatalk", "netatalk", [
        {"version": ">= 3.1.0, < 4.5.2", "status": "affected"},
        {"version": "< 1.2", "status": "affected"},
        {"version": "<= garbage stuff", "status": "affected"},
    ])
    _, matches = parse.parse_cveorg(rec)
    got = {(m["version"], m["v_start_incl"], m["v_end_excl"], m["v_end_incl"]) for m in matches}
    assert ("*", "3.1.0", "4.5.2", None) in got and ("*", None, "1.2", None) in got
    assert len(got) == 3        # the unparsable one is kept as a literal (never matches)
    r = next(m for m in matches if m["v_end_excl"] == "4.5.2")
    assert version_in_range("3.1.8", "*", start_incl=r["v_start_incl"], end_excl=r["v_end_excl"])
    assert not version_in_range("4.5.2", "*", start_incl=r["v_start_incl"], end_excl=r["v_end_excl"])
