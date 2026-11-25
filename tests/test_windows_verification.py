"""Verifying findings on Windows hosts from the agent's inventory: Microsoft's
fixed builds settle Windows CVEs, program versions settle other software."""
import json
from datetime import datetime, timezone

from app.extensions import db

HOST = "10.0.0.20"
HTTPD = r"C:\Apache24\bin\httpd.exe"
TOMCAT = r"C:\Program Files\Apache Software Foundation\Tomcat 9.0\bin\tomcat9.exe"


def win_inventory(build="10.0.20348.2700", hotfixes=("KB5044281",), httpd_version="2.4.58",
                  **over):
    inv = {
        "schema": 1,
        "collected_at": "2026-11-24T12:00:00Z",
        "os": {"kernel": "Windows", "id": "windows", "pretty": "Windows Server 2022 Standard"},
        "package_manager": None,
        "ips": [HOST],
        "listeners": [
            {"port": 445, "proto": "tcp", "exe": None},
            {"port": 80, "proto": "tcp", "exe": HTTPD,
             "file": {"product": "Apache HTTP Server", "company": "Apache Software Foundation",
                      "product_version": httpd_version, "file_version": httpd_version + ".0"}},
            {"port": 8080, "proto": "tcp", "exe": TOMCAT,
             "file": {"product": "Commons Daemon Service Runner", "product_version": "1.3.4.0"}},
        ],
        "packages": {},
        "changelogs": {},
        "windows": {"build": build, "product": "Windows Server 2022 Standard",
                    "display_version": "21H2", "installation_type": "Server",
                    "hotfixes": list(hotfixes)},
        "programs": [
            {"name": "Apache Tomcat 9.0 Tomcat9", "version": "9.0.80",
             "publisher": "The Apache Software Foundation",
             "location": r"C:\Program Files\Apache Software Foundation\Tomcat 9.0"},
            {"name": "MySQL Workbench 8.0 CE", "version": "8.0.36", "publisher": "Oracle Corporation",
             "location": r"C:\Program Files\MySQL\MySQL Workbench 8.0"},
        ],
    }
    inv.update(over)
    return inv


def _mirror(app):
    from app.models import MirrorCpeMatch, MirrorMsrcFix
    with app.app_context():
        db.session.add_all([
            # SMB CVE: fixed in 20348.2849 on Server 2022, hotpatch build 2762
            MirrorMsrcFix(cve_id="CVE-2024-43642", doc_id="2024-Nov", build_line="10.0.20348",
                          fixed_ubr=2849, kb="KB5046616", product="Windows Server 2022"),
            MirrorMsrcFix(cve_id="CVE-2024-43642", doc_id="2024-Nov", build_line="10.0.20348",
                          fixed_ubr=2762, kb="KB5046540", product="Windows Server 2022, Hotpatch",
                          hotpatch=True),
            MirrorMsrcFix(cve_id="CVE-2024-43642", doc_id="2024-Nov", build_line="10.0.19045",
                          fixed_ubr=5131, kb="KB5046613", product="Windows 10 Version 22H2"),
            MirrorCpeMatch(cve_id="CVE-2024-38476", source="nvd", part="a", vendor="apache",
                           product="http_server", version="*", v_end_excl="2.4.60"),
            MirrorCpeMatch(cve_id="CVE-2023-46589", source="nvd", part="a", vendor="apache",
                           product="tomcat", version="*", v_start_incl="9.0.0", v_end_excl="9.0.83"),
            MirrorCpeMatch(cve_id="CVE-2024-20918", source="nvd", part="a", vendor="oracle",
                           product="mysql", version="*", v_end_incl="8.0.35"),
        ])
        db.session.commit()


def _findings(app):
    from app.models import Scan, ScanResult, Target
    from app.routes.vulns import _auto_sync
    with app.app_context():
        t = Target(name="win", host=HOST)
        db.session.add(t); db.session.commit()
        s = Scan(name="s", target_id=t.id, scan_type="full", status="done",
                 completed_at=datetime.now(timezone.utc))
        db.session.add(s); db.session.commit()
        common = dict(scan_id=s.id, result_type="vulnerability", host=HOST, protocol="tcp",
                      match_confidence="cpe", verification_status="unconfirmed", severity="high")
        db.session.add_all([
            ScanResult(port=445, service="microsoft-ds", cve_id="CVE-2024-43642",
                       title="Windows SMB DoS", cpe="cpe:2.3:o:microsoft:windows_server_2022:-:*:*:*:*:*:*:*",
                       description="Windows SMB Denial of Service Vulnerability", **common),
            ScanResult(port=80, service="http", cve_id="CVE-2024-38476", title="httpd SSRF",
                       cpe="cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*",
                       description="Apache HTTP Server backend response headers issue.", **common),
            ScanResult(port=8080, service="http", cve_id="CVE-2023-46589", title="Tomcat smuggling",
                       cpe="cpe:2.3:a:apache:tomcat:9.0.80:*:*:*:*:*:*:*",
                       description="Apache Tomcat request smuggling.", **common),
            ScanResult(port=3306, service="mysql", cve_id="CVE-2024-20918", title="MySQL issue",
                       cpe="cpe:2.3:a:oracle:mysql:8.0.35:*:*:*:*:*:*:*",
                       description="MySQL Server optimizer issue.", **common),
        ])
        db.session.commit()
        _auto_sync()


def _upload(app, client, inv):
    from app.scanner import agent_facts
    with app.app_context():
        from app.routes.threat import _get_cfg
        tok = _get_cfg().registration_token
    creds = client.post("/threat/api/register",
                        json={"hostname": "win1", "os": "win32", "reg_token": tok}).get_json()
    headers = {"X-Agent-ID": creds["agent_id"], "X-Agent-Token": creds["token"]}
    queued = []
    orig = agent_facts.reverify_in_background
    agent_facts.reverify_in_background = lambda a, aid: queued.append(aid)
    try:
        assert client.post("/threat/api/inventory", json=inv, headers=headers).status_code == 200
    finally:
        agent_facts.reverify_in_background = orig
    with app.app_context():
        for aid in queued:
            agent_facts.reverify_host_findings(aid)


def _verdicts(app):
    from app.models import ScanResult
    with app.app_context():
        out = {}
        for r in ScanResult.query.filter(ScanResult.cve_id.isnot(None)).all():
            ev = json.loads(r.verification_evidence or "{}")
            out[r.cve_id] = (r.verification_label, ev.get("detail", ""), ev.get("credentialed", ""))
        return out


def test_unpatched_windows_build_confirmed_and_software_versions_checked(app, client):
    _mirror(app)
    _findings(app)
    _upload(app, client, win_inventory())
    v = _verdicts(app)
    # Windows build 20348.2700 < 20348.2849 (KB5046616 not installed)
    assert v["CVE-2024-43642"][0] == "Confirmed"
    assert "10.0.20348.2849" in v["CVE-2024-43642"][1] and "KB5046616" in v["CVE-2024-43642"][1]
    # httpd.exe on :80 is 2.4.58, inside the affected range
    assert v["CVE-2024-38476"][0] == "Confirmed"
    assert "Apache HTTP Server 2.4.58" in v["CVE-2024-38476"][1]
    # tomcat9.exe lives in Tomcat's install folder → the program's version (9.0.80)
    assert v["CVE-2023-46589"][0] == "Confirmed"
    assert "Apache Tomcat 9.0 Tomcat9 9.0.80" in v["CVE-2023-46589"][1]
    # Only a name match (Workbench), not tied to a listener → not decided
    assert v["CVE-2024-20918"][0] == "Unverified"
    assert "isn't tied to the process listening" in v["CVE-2024-20918"][2]


def test_patched_build_and_upgraded_software_ruled_out(app, client):
    _mirror(app)
    _findings(app)
    _upload(app, client, win_inventory(build="10.0.20348.2966", httpd_version="2.4.62"))
    v = _verdicts(app)
    assert v["CVE-2024-43642"][0] == "Not exploitable"
    assert "Patched" in v["CVE-2024-43642"][1]
    assert v["CVE-2024-38476"][0] == "Not exploitable"
    assert "2.4.62 is outside the range" in v["CVE-2024-38476"][1]


def test_installed_kb_counts_as_patched(app, client):
    _mirror(app)
    _findings(app)
    _upload(app, client, win_inventory(hotfixes=("KB5046616",)))
    assert _verdicts(app)["CVE-2024-43642"][0] == "Not exploitable"


def test_hotpatch_build_left_undecided(app, client):
    _mirror(app)
    _findings(app)
    _upload(app, client, win_inventory(build="10.0.20348.2762"))
    v = _verdicts(app)["CVE-2024-43642"]
    assert v[0] == "Unverified" and "hotpatch" in v[2]


def test_windows_version_microsoft_doesnt_list_stays_unverified(app, client):
    """Absence from Microsoft's list may mean out of support, not unaffected."""
    _mirror(app)
    _findings(app)
    _upload(app, client, win_inventory(build="10.0.17763.6000"))
    v = _verdicts(app)["CVE-2024-43642"]
    assert v[0] == "Unverified" and "out of support" in v[2]


def test_windows_inventory_sanitized():
    from app.scanner.agent_facts import normalize_inventory
    inv = normalize_inventory({
        "windows": {"build": "10.0.19045.5131; drop", "hotfixes": ["KB5046613", "kb123", "x", 5]},
        "programs": [{"name": "  7-Zip 23.01 ", "version": "23.01"}, {"name": ""}, "junk"],
        "listeners": [{"port": 80, "exe": HTTPD, "file": {"product": "Apache HTTP Server",
                                                           "evil": "x", "product_version": "2.4.58"}}],
    })
    assert inv["windows"]["build"] == ""
    assert inv["windows"]["hotfixes"] == ["KB5046613"]
    assert [p["name"] for p in inv["programs"]] == ["7-Zip 23.01"]
    assert inv["listeners"][0]["file"] == {"product": "Apache HTTP Server", "product_version": "2.4.58"}
    assert normalize_inventory({})["windows"] is None


def test_parse_msrc_document():
    from app.cve_mirror.msrc import parse_document
    doc = {
        "ProductTree": {"FullProductName": [
            {"ProductID": "1", "Value": "Windows Server 2022"},
            {"ProductID": "2", "Value": "Windows Server 2022 (Server Core installation)"},
            {"ProductID": "3", "Value": "Microsoft Edge (Chromium-based)"},
            {"ProductID": "4", "Value": "Windows 11 Version 24H2 for x64-based Systems"},
        ]},
        "Vulnerability": [{"CVE": "CVE-2024-1", "Remediations": [
            {"Type": 2, "ProductID": ["1", "2"], "FixedBuild": "10.0.20348.2849",
             "Description": {"Value": "5046616"}, "SubType": "Security Update"},
            {"Type": 2, "ProductID": ["4"], "FixedBuild": "10.0.26100.2240",
             "Description": {"Value": "5046696"}, "SubType": "SecurityHotpatchUpdate"},
            {"Type": 2, "ProductID": ["3"], "FixedBuild": "130.0.2849.80"},
            {"Type": 3, "ProductID": ["1"], "FixedBuild": "10.0.20348.2849"},
            {"Type": 2, "ProductID": ["1"], "FixedBuild": "-"},
        ]}],
    }
    rows = parse_document("2024-Nov", doc)
    got = {(r["build_line"], r["fixed_ubr"], r["kb"], r["hotpatch"]) for r in rows}
    assert got == {("10.0.20348", 2849, "KB5046616", False), ("10.0.26100", 2240, "KB5046696", True)}


def test_msrc_sync_is_incremental(app, monkeypatch):
    from app.cve_mirror import msrc
    calls = []
    docs = {"value": [
        {"ID": "2020-Dec", "InitialReleaseDate": "2020-12-08T08:00:00Z", "CurrentReleaseDate": "2026-01-01T00:00:00Z"},
        {"ID": "2024-Nov", "InitialReleaseDate": "2024-11-12T08:00:00Z", "CurrentReleaseDate": "2024-12-01T00:00:00Z"},
    ]}
    doc = {"ProductTree": {"FullProductName": [{"ProductID": "1", "Value": "Windows 10 Version 22H2 for x64-based Systems"}]},
           "Vulnerability": [{"CVE": "CVE-2024-9", "Remediations": [
               {"Type": 2, "ProductID": ["1"], "FixedBuild": "10.0.19045.5131", "Description": {"Value": "5046613"}}]}]}

    class Resp:
        def __init__(self, data): self.data = data
        def raise_for_status(self): pass
        def json(self): return self.data

    def fake_get(url, **kw):
        calls.append(url)
        return Resp(docs if url.endswith("/updates") else doc)

    monkeypatch.setattr(msrc.requests, "get", fake_get)
    monkeypatch.setattr(msrc.requests.Session, "get", lambda self, url, **kw: fake_get(url))
    with app.app_context():
        assert msrc.sync_msrc(app) == 1
        assert [c.rsplit("/", 1)[-1] for c in calls] == ["updates", "2024-Nov"]   # pre-2021 skipped
        assert msrc.fixes_for("cve-2024-9")[0]["fixed_ubr"] == 5131
        calls.clear()
        msrc.sync_msrc(app)
        assert [c.rsplit("/", 1)[-1] for c in calls] == ["updates"]               # nothing changed
        from app.models import MirrorSyncState
        assert db.session.get(MirrorSyncState, "msrc").records == 1


def test_agent_page_shows_windows_inventory(app, client, admin_client):
    _upload(app, client, win_inventory())
    from app.models import EndpointAgent
    with app.app_context():
        aid = EndpointAgent.query.first().id
    page = admin_client.get(f"/threat/agents/{aid}").get_data(as_text=True)
    assert "10.0.20348.2700" in page and "Installed programs" in page
    assert "Apache HTTP Server" in page and "KB5044281" in page


def test_agent_file_info_harmless_off_windows():
    import importlib.util
    import pytest
    pytest.importorskip("psutil")
    pytest.importorskip("requests")
    spec = importlib.util.spec_from_file_location("agent_mod", "app/static/agent/pwnbroker_agent.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod._file_info("/bin/sh") == {}
    inv = mod.collect_inventory()
    assert inv["windows"] is None and inv["programs"] == []


def test_cve_db_page_lists_microsoft_source(admin_client):
    html = admin_client.get("/cve-db/").get_data(as_text=True)
    assert "Microsoft — Windows fixed builds (MSRC)" in html and 'id="src-msrc-status"' in html
    assert admin_client.get("/cve-db/status.json").get_json()["sources"]["msrc"]["status"] == "never"
