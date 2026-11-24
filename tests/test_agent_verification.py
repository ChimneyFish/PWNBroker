"""Endpoint agent host inventory → verifying scan findings without SSH.

The agent sends a read-only inventory; PwnBroker applies the same checks it
uses over SSH: vendor backports and unloaded modules rule findings out, and an
unpatched vulnerable package that owns the listening port is "installed"
(shown as Confirmed)."""
import json
from datetime import datetime, timedelta, timezone

import pytest

from app.extensions import db

HOST = "10.0.0.9"


def inventory(**over):
    inv = {
        "schema": 1,
        "collected_at": "2026-11-24T12:00:00Z",
        "os": {"kernel": "Linux", "id": "ubuntu", "pretty": "Ubuntu 22.04.4 LTS"},
        "package_manager": "deb",
        "ips": ["127.0.0.1", HOST, "fe80::1"],
        "listeners": [
            {"port": 80, "proto": "tcp", "exe": "/usr/sbin/apache2", "package": "apache2-bin"},
            {"port": 53, "proto": "udp", "exe": "/usr/sbin/dnsmasq", "package": "dnsmasq-base"},
        ],
        "packages": {
            "apache2-bin": ["2.4.52-1ubuntu4.26", "apache2"],
            "dnsmasq-base": ["2.75-1ubuntu0.16.04.1", "dnsmasq"],
        },
        "changelogs": {
            "apache2-bin": {"found": True, "trimmed": False, "entries": [
                ["apache2 (2.4.52-1ubuntu4.6) jammy-security; urgency=medium",
                 "- debian/patches/CVE-2023-25690-1.patch: fix request splitting"]]},
            "dnsmasq-base": {"found": True, "trimmed": False, "entries": []},
        },
        "apache_modules": ["core", "http", "ssl"],
        "nginx_build": None,
    }
    inv.update(over)
    return inv


def _agent(app, client, inv=None):
    """Register an agent through the API and (optionally) upload an inventory."""
    from app.scanner import agent_facts
    with app.app_context():
        from app.routes.threat import _get_cfg
        tok = _get_cfg().registration_token
    r = client.post("/threat/api/register", json={"hostname": "srv1", "os": "linux", "reg_token": tok})
    creds = r.get_json()
    headers = {"X-Agent-ID": creds["agent_id"], "X-Agent-Token": creds["token"]}
    if inv is not None:
        sync = []
        orig = agent_facts.reverify_in_background
        agent_facts.reverify_in_background = lambda a, aid: sync.append(aid)
        try:
            resp = client.post("/threat/api/inventory", json=inv, headers=headers)
        finally:
            agent_facts.reverify_in_background = orig
        assert resp.status_code == 200, resp.get_data(as_text=True)
        with app.app_context():
            for aid in sync:
                agent_facts.reverify_host_findings(aid)
    return headers


def _findings(app):
    """A scan with three version-matched CVEs and their (unverified) tickets."""
    from app.models import Scan, ScanResult, Target
    from app.routes.vulns import _auto_sync
    with app.app_context():
        t = Target(name="srv", host=HOST)
        db.session.add(t); db.session.commit()
        s = Scan(name="s", target_id=t.id, scan_type="full", status="done",
                 completed_at=datetime.now(timezone.utc))
        db.session.add(s); db.session.commit()
        common = dict(scan_id=s.id, result_type="vulnerability", host=HOST,
                      match_confidence="cpe", verification_status="unconfirmed")
        db.session.add_all([
            ScanResult(port=80, protocol="tcp", service="http", severity="high", **common,
                       cve_id="CVE-2023-25690", title="mod_proxy request splitting",
                       cpe="cpe:2.3:a:apache:http_server:2.4.52:*:*:*:*:*:*:*",
                       description="HTTP request splitting with mod_proxy."),
            ScanResult(port=80, protocol="tcp", service="http", severity="critical", **common,
                       cve_id="CVE-2099-0001", title="Apache core overflow",
                       cpe="cpe:2.3:a:apache:http_server:2.4.52:*:*:*:*:*:*:*",
                       description="Overflow in the core request parser."),
            ScanResult(port=53, protocol="udp", service="domain", severity="critical", **common,
                       cve_id="CVE-2017-14491", title="dnsmasq heap overflow",
                       cpe="cpe:2.3:a:thekelleys:dnsmasq:2.75:*:*:*:*:*:*:*",
                       description="Heap-based buffer overflow in dnsmasq."),
        ])
        db.session.commit()
        _auto_sync()
        return s.id


def _status(app):
    from app.models import VulnTicket
    with app.app_context():
        return {t.cve_id: (t.status, t.scan_result.verification_label)
                for t in VulnTicket.query.all()}


def test_inventory_upload_verifies_existing_findings(app, client):
    _findings(app)
    assert all(v == ("open", "Unverified") for v in _status(app).values())

    _agent(app, client, inventory())
    got = _status(app)
    # Ubuntu backported the fix → ruled out, ticket closed
    assert got["CVE-2023-25690"] == ("not_exploitable", "Not exploitable")
    # No vendor fix, and the package owns the listening process → Confirmed
    assert got["CVE-2099-0001"] == ("open", "Confirmed")
    assert got["CVE-2017-14491"] == ("open", "Confirmed")

    from app.models import ScanResult, VulnTicket
    with app.app_context():
        r = ScanResult.query.filter_by(cve_id="CVE-2017-14491").first()
        ev = json.loads(r.verification_evidence)
        assert ev["method"] == "agent" and "dnsmasq-base 2.75-1ubuntu0.16.04.1" in ev["detail"]
        t = VulnTicket.query.filter_by(cve_id="CVE-2017-14491").first()
        assert not t.is_unverified


def test_confirmed_filter_and_reports(app, client, admin_client):
    sid = _findings(app)
    _agent(app, client, inventory())
    page = admin_client.get("/vulns/tickets?status=confirmed").get_data(as_text=True)
    assert "CVE-2017-14491" in page and "CVE-2023-25690" not in page
    assert ">Confirmed" in page or "Confirmed\n</span>" in page
    from app.email_utils.report_builder import build_html_report
    from app.models import Scan
    with app.app_context():
        html = build_html_report([db.session.get(Scan, sid)])
    assert ">Confirmed</span>" in html
    assert "<b>2</b> were confirmed installed on the host" in html


def test_upgraded_package_is_not_confirmed(app, client):
    """The banner said 2.75 but the host now has 2.80 installed: don't claim
    the vulnerable build is installed."""
    _findings(app)
    inv = inventory()
    inv["packages"]["dnsmasq-base"] = ["2.80-1ubuntu1", "dnsmasq"]
    _agent(app, client, inv)
    assert _status(app)["CVE-2017-14491"] == ("open", "Unverified")


def test_trimmed_changelog_fetches_vendor_copy(app, client, monkeypatch):
    from app.scanner import ssh_verify
    calls = []

    def fake_vendor(os_id, source, version):
        calls.append((os_id, source, version))
        return "dnsmasq (2.75-1ubuntu0.16.04.3) xenial-security\n  * CVE-2017-14491 fix\n"
    monkeypatch.setattr(ssh_verify, "vendor_changelog", fake_vendor)
    _findings(app)
    inv = inventory()
    inv["changelogs"]["dnsmasq-base"] = {"found": True, "trimmed": True, "entries": []}
    _agent(app, client, inv)
    assert calls == [("ubuntu", "dnsmasq", "2.75-1ubuntu0.16.04.1")]
    assert _status(app)["CVE-2017-14491"] == ("not_exploitable", "Not exploitable")


def test_heartbeat_asks_for_inventory_until_sent(app, client):
    headers = _agent(app, client)
    hb = client.post("/threat/api/heartbeat", json={"agent_version": "2.0.0"}, headers=headers).get_json()
    assert hb["send_inventory"] is True and "apache2-bin" in hb["changelog_packages"]
    _agent_inv = client.post("/threat/api/inventory", json=inventory(), headers=headers)
    assert _agent_inv.status_code == 200
    hb = client.post("/threat/api/heartbeat", json={}, headers=headers).get_json()
    assert hb["send_inventory"] is False


def test_inventory_requires_agent_token(client):
    r = client.post("/threat/api/inventory", json=inventory(),
                    headers={"X-Agent-ID": "nope", "X-Agent-Token": "nope"})
    assert r.status_code == 403


def test_junk_inventory_rejected_and_sanitized():
    from app.scanner.agent_facts import normalize_inventory
    with pytest.raises(ValueError):
        normalize_inventory(["not", "a", "dict"])
    inv = normalize_inventory({
        "ips": ["127.0.0.1", "not-an-ip", "10.1.1.1", "fe80::1"],
        "package_manager": "evil",
        "packages": {"ok-pkg": ["1.0", "src"], "bad name; rm -rf /": ["1"], "x": "notalist"},
        "listeners": [{"port": 99999}, {"port": "22", "package": "openssh-server"}],
    })
    assert inv["ips"] == ["10.1.1.1"]
    assert inv["package_manager"] is None
    assert list(inv["packages"]) == ["ok-pkg"]
    assert inv["listeners"] == [{"port": 22, "proto": "tcp", "exe": None, "package": "openssh-server"}]


def test_ip_claimed_by_two_agents_is_not_trusted(app, client):
    _agent(app, client, inventory())
    _agent(app, client, inventory())
    from app.scanner.agent_facts import facts_for_host
    with app.app_context():
        assert facts_for_host(HOST) is None


def test_stale_inventory_not_used(app, client):
    _agent(app, client, inventory())
    from app.models import EndpointAgent
    from app.scanner.agent_facts import facts_for_host
    with app.app_context():
        assert facts_for_host(HOST) is not None
        a = EndpointAgent.query.first()
        a.inventory_at = datetime.now(timezone.utc) - timedelta(days=30)
        db.session.commit()
        assert facts_for_host(HOST) is None


def test_windows_host_keeps_windows_only_cves(app):
    """A Windows-only CVE must not be ruled out on a Windows host."""
    from app.models import EndpointAgent, ScanResult
    from app.scanner.agent_facts import AgentHostFacts
    from app.scanner.ssh_verify import evaluate_host
    with app.app_context():
        a = EndpointAgent(agent_id="w", token="t", hostname="win1")
        f = AgentHostFacts(a, {"os": {"kernel": "Windows", "pretty": "Windows 11"},
                               "package_manager": None, "listeners": [], "packages": {}})
        r = ScanResult(host=HOST, port=445, cve_id="CVE-2020-0796",
                       description="A remote code execution vulnerability on Windows 10.")
        (_, status, _, _), = evaluate_host(f, [r], {})
        assert status is None


def test_scan_time_verification_uses_agent(app, client, monkeypatch):
    """A new scan's findings are checked against the agent's inventory even
    with no SSH credentials (and with live checks unavailable)."""
    _agent(app, client, inventory())
    monkeypatch.setitem(app.config, "VULN_VERIFY", "0")
    from app.models import ScanResult
    from app.scanner.verify import verify_results
    with app.app_context():
        r = ScanResult(result_type="vulnerability", host=HOST, port=53, service="domain",
                       cve_id="CVE-2017-14491", match_confidence="cpe",
                       cpe="cpe:2.3:a:thekelleys:dnsmasq:2.75:*:*:*:*:*:*:*",
                       verification_status="unconfirmed")
        summary = verify_results([r], creds_of=lambda r: None)
        assert r.verification_status == "installed"
        assert summary["installed"] == 1 and summary["credentialed"][0]["via"] == "agent"


def test_agent_page_shows_inventory(app, client, admin_client):
    _findings(app)
    _agent(app, client, inventory())
    from app.models import EndpointAgent
    with app.app_context():
        aid = EndpointAgent.query.first().id
    page = admin_client.get(f"/threat/agents/{aid}").get_data(as_text=True)
    assert "Finding Verification" in page and "apache2-bin" in page
    assert "Confirmed findings" in page
    r = admin_client.post(f"/threat/agents/{aid}/inventory/refresh", follow_redirects=True)
    assert "fresh inventory" in r.get_data(as_text=True)
    with app.app_context():
        assert EndpointAgent.query.first().inventory_requested is True
