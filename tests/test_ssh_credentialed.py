"""Credentialed (SSH) checks: scanner/ssh_verify.py + target/scan settings.

The SSH layer is replaced with a fake host that answers the same shell
commands a real Debian/Ubuntu box would, so these tests exercise the real
parsing and verdict logic without a network."""
import gzip
import json
import re
from types import SimpleNamespace as N
from unittest.mock import patch

import pytest

from app.scanner import ssh_verify
from app.scanner.ssh_verify import (Creds, HostFacts, apply_ssh_form, apply_scan_cred_form,
                                    evaluate_host, _windows_only, _changelog_index)

APACHE_CHANGELOG = """apache2 (2.4.52-1ubuntu4.26) jammy-security; urgency=medium

  * SECURITY UPDATE: mod_proxy issue
    - debian/patches/CVE-2024-38474.patch: fix substitution encoding
    - CVE-2024-38474

 -- Someone <s@example.com>  Mon, 14 Jul 2025 12:29:02 -0400

apache2 (2.4.52-1ubuntu4.1) jammy-security; urgency=medium

  * SECURITY UPDATE: request smuggling
    - CVE-2022-22720
"""

APACHE_M = """Loaded Modules:
 core_module (static)
 so_module (static)
 proxy_module (shared)
 rewrite_module (shared)
"""


class FakeSession:
    """Answers the read-only commands HostFacts sends, like an Ubuntu host."""

    def __init__(self, changelog=APACHE_CHANGELOG, apache_m=APACHE_M, nginx_v=None,
                 listener=True, sudo=False, kernel="Linux"):
        self.changelog, self.apache_m, self.nginx_v = changelog, apache_m, nginx_v
        self.listener, self.sudo, self.kernel = listener, sudo, kernel
        self.commands = []

    def run(self, cmd, timeout=25):
        self.commands.append(cmd)
        if cmd.startswith("command -v dpkg-query"):
            return 0, "deb\n"
        if cmd.startswith("uname -s"):
            return 0, self.kernel + "\n"
        if "os-release" in cmd:
            return 0, "ubuntu|Ubuntu 22.04.5 LTS\n"
        if cmd.startswith("ss "):
            return (0, 'LISTEN 0 511 *:80 *:* users:(("apache2",pid=4242,fd=4))\n') if self.listener else (0, "")
        if cmd.startswith("readlink"):
            return 0, "/usr/sbin/apache2\n"
        if cmd.startswith("dpkg -S"):
            return (0, "apache2-bin: /usr/sbin/apache2\n") if "/usr/sbin/apache2" in cmd else (1, "")
        if cmd.startswith("dpkg-query -W"):
            if "apache2" in cmd:
                return 0, "installed|2.4.52-1ubuntu4.26|apache2"
            return 1, ""
        if "changelog.Debian" in cmd:
            return 0, self.changelog
        if "apache2ctl" in cmd:
            return 0, self.apache_m
        if "nginx" in cmd:
            return 0, self.nginx_v or ""
        if cmd.startswith("sudo -n true"):
            return (0 if self.sudo else 1), ""
        return 1, ""

    def has_sudo(self):
        return self.sudo

    def run_priv(self, cmd, timeout=25):
        return self.run(cmd, timeout)


def _finding(cve, desc="Some flaw.", port=80, cpe="cpe:2.3:a:apache:http_server:2.4.52:*:*:*:*:*:*:*"):
    return N(host="10.0.0.9", port=port, cve_id=cve, cpe=cpe, service="http", description=desc,
             verification_status="unconfirmed", verification_evidence=None)


# ── verdict logic ────────────────────────────────────────────────────────────

class TestEvaluateHost:
    def test_backported_fix_in_changelog_rules_cve_out_with_proof(self):
        facts = HostFacts(FakeSession())
        (r, status, detail, extra), = evaluate_host(facts, [_finding("CVE-2024-38474")], {})
        assert status == "not_exploitable"
        assert "apache2-bin 2.4.52-1ubuntu4.26" in detail and "backported" in detail
        assert "CVE-2024-38474" in extra["proof"]
        assert extra["proof"].startswith("apache2 (2.4.52-1ubuntu4.26)")

    def test_package_found_via_listening_process(self):
        sess = FakeSession()
        evaluate_host(HostFacts(sess), [_finding("CVE-2024-38474")], {})
        assert any(c.startswith("dpkg -S '/usr/sbin/apache2'") or c.startswith("dpkg -S /usr/sbin/apache2")
                   for c in sess.commands)

    def test_falls_back_to_product_package_when_process_not_visible(self):
        facts = HostFacts(FakeSession(listener=False))
        (_, status, detail, _), = evaluate_host(facts, [_finding("CVE-2022-22720")], {})
        assert status == "not_exploitable" and "apache2" in detail

    def test_cve_not_in_changelog_stays_unverified_with_a_note(self):
        facts = HostFacts(FakeSession())
        (_, status, detail, _), = evaluate_host(facts, [_finding("CVE-2023-99999")], {})
        assert status is None
        assert "no vendor fix listed for CVE-2023-99999" in detail

    def test_trimmed_changelog_fetches_full_vendor_changelog(self):
        trimmed = APACHE_CHANGELOG.split("apache2 (2.4.52-1ubuntu4.1)")[0] + \
            "# For older changelog entries, run 'apt-get changelog apache2-bin'\n"
        ssh_verify._vendor_cache.clear()
        with patch("requests.get") as get:
            get.return_value = N(status_code=200, text=APACHE_CHANGELOG)
            facts = HostFacts(FakeSession(changelog=trimmed))
            (_, status, _, _), = evaluate_host(facts, [_finding("CVE-2022-22720")], {})
        assert status == "not_exploitable"
        url = get.call_args[0][0]
        assert url == ("https://changelogs.ubuntu.com/changelogs/pool/main/a/apache2/"
                       "apache2_2.4.52-1ubuntu4.26/changelog")

    def test_trimmed_changelog_and_fetch_fails_says_so(self):
        trimmed = "apache2 (2.4.52-1ubuntu4.26) jammy; urgency=medium\n\n# For older changelog entries, run x\n"
        ssh_verify._vendor_cache.clear()
        with patch("requests.get", side_effect=__import__("requests").ConnectionError("offline")):
            facts = HostFacts(FakeSession(changelog=trimmed))
            (_, status, detail, _), = evaluate_host(facts, [_finding("CVE-2022-22720")], {})
        assert status is None and "full changelog wasn't available" in detail

    def test_apache_module_not_loaded_rules_out(self):
        facts = HostFacts(FakeSession())
        (_, status, detail, _), = evaluate_host(
            facts, [_finding("CVE-2099-1", "A flaw in mod_lua lets scripts crash the server.")], {})
        assert status == "not_exploitable" and "mod_lua" in detail

    def test_apache_module_loaded_does_not_rule_out(self):
        facts = HostFacts(FakeSession())
        (_, status, detail, _), = evaluate_host(
            facts, [_finding("CVE-2099-2", "mod_proxy and mod_lua mishandle headers.")], {})
        assert status is None and "mod_proxy is loaded" in detail

    def test_apache_module_list_unavailable_rules_nothing_out(self):
        facts = HostFacts(FakeSession(apache_m=""))
        (_, status, _, _), = evaluate_host(facts, [_finding("CVE-2099-3", "mod_lua flaw")], {})
        assert status is None

    def test_nginx_optional_module_absent_rules_out(self):
        nginx_v = "nginx version: nginx/1.18.0\nconfigure arguments: --with-http_ssl_module --with-http_v2_module\n"
        facts = HostFacts(FakeSession(nginx_v=nginx_v, listener=False))
        r = _finding("CVE-2022-41741", "A flaw in ngx_http_mp4_module allows memory corruption.",
                     cpe="cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*")
        (_, status, detail, _), = evaluate_host(facts, [r], {})
        assert status == "not_exploitable" and "ngx_http_mp4_module" in detail

    def test_nginx_module_compiled_in_is_kept(self):
        nginx_v = "configure arguments: --with-http_mp4_module\n"
        facts = HostFacts(FakeSession(nginx_v=nginx_v, listener=False))
        r = _finding("CVE-2022-41741", "ngx_http_mp4_module flaw", cpe="cpe:2.3:a:f5:nginx:1.18.0")
        (_, status, _, _), = evaluate_host(facts, [r], {})
        assert status is None

    def test_windows_only_cve_ruled_out_on_linux(self):
        facts = HostFacts(FakeSession())
        r = _finding("CVE-2024-38472", "SSRF in Apache HTTP Server on Windows allows to leak NTLM hashes.")
        (_, status, detail, _), = evaluate_host(facts, [r], {})
        assert status == "not_exploitable" and "only affects the product on Windows" in detail


def test_windows_only_detection():
    assert _windows_only("Out-of-bounds write in Apache HTTP Server on Windows while processing paths")
    assert not _windows_only("Affects Apache on Windows and Linux")
    assert not _windows_only("A buffer overflow in mod_ssl")
    assert not _windows_only("Windows clients connecting to the server can crash it")


def test_changelog_index_maps_cve_to_its_version_header():
    idx = _changelog_index(APACHE_CHANGELOG)
    assert idx["CVE-2022-22720"][0].startswith("apache2 (2.4.52-1ubuntu4.1)")
    assert idx["CVE-2024-38474"][0].startswith("apache2 (2.4.52-1ubuntu4.26)")


def test_vendor_changelog_rejects_unsafe_names():
    with patch("requests.get") as get:
        assert ssh_verify.vendor_changelog("ubuntu", "../../etc", "1.0") == ""
        assert ssh_verify.vendor_changelog("centos", "httpd", "1.0") == ""
    get.assert_not_called()


# ── verify_results integration ───────────────────────────────────────────────

class TestVerifyResultsWithCreds:
    def _rows(self, app):
        from app.models import ScanResult
        return [ScanResult(scan_id=1, result_type="vulnerability", host="10.0.0.9", port=80,
                           service="http", cve_id=c, cpe="cpe:2.3:a:apache:http_server:2.4.52",
                           match_confidence="cpe", verification_status="unconfirmed",
                           description="flaw") for c in ("CVE-2024-38474", "CVE-2023-99999")]

    def test_ssh_pass_rules_out_backports_and_keeps_the_rest_unverified(self, app):
        from app.scanner.verify import verify_results
        with app.app_context():
            rows = self._rows(app)
            creds = Creds(host="10.0.0.9", ssh_username="audit", ssh_password="pw")
            with patch.object(ssh_verify, "Session") as S, \
                 patch("app.scanner.verify.nuclei_bin", return_value=None):
                S.return_value.__enter__.return_value = FakeSession()
                summary = verify_results(rows, creds_of=lambda r: creds)
        fixed, other = rows
        assert fixed.result_type == "not_exploitable" and fixed.verification_status == "not_exploitable"
        assert fixed.evidence["method"] == "ssh" and fixed.evidence["target"] == "audit@10.0.0.9:22"
        assert other.result_type == "unverified"
        assert "no vendor fix listed" in other.evidence["credentialed"]
        assert summary["not_exploitable"] == 1 and summary["unconfirmed"] == 1
        assert summary["credentialed"][0]["ok"] and summary["credentialed"][0]["ruled_out"] == 1

    def test_login_failure_is_recorded_not_fatal(self, app):
        from app.scanner.verify import verify_results
        with app.app_context():
            rows = self._rows(app)
            creds = Creds(host="10.0.0.9", ssh_username="audit", ssh_password="bad")
            with patch.object(ssh_verify, "Session", side_effect=Exception("Authentication failed.")), \
                 patch("app.scanner.verify.nuclei_bin", return_value=None):
                summary = verify_results(rows, creds_of=lambda r: creds)
        assert all(r.result_type == "unverified" for r in rows)
        assert "couldn't log in as audit: Authentication failed." in rows[0].evidence["credentialed"]
        assert summary["credentialed"][0] == {"host": "10.0.0.9", "ok": False, "error": "Authentication failed.",
                                              "user": "audit", "ruled_out": 0, "checked": 2}

    def test_without_creds_nothing_logs_in(self, app):
        from app.scanner.verify import verify_results
        with app.app_context():
            rows = self._rows(app)
            with patch.object(ssh_verify, "Session") as S, \
                 patch("app.scanner.verify.nuclei_bin", return_value=None):
                verify_results(rows, creds_of=lambda r: None)
        S.assert_not_called()


# ── which login a scan uses ──────────────────────────────────────────────────

class TestCredsFor:
    def _setup(self, app, **scan_kw):
        from app.extensions import db
        from app.models import Target, Scan
        net = Target(name="net", host="10.0.0.0/24", ssh_username="netuser", ssh_password="np")
        one = Target(name="one", host="10.0.0.7", ssh_username="hostuser", ssh_password="hp")
        db.session.add_all([net, one]); db.session.flush()
        scan = Scan(name="s", target_id=net.id, scan_type="full", **scan_kw)
        db.session.add(scan); db.session.commit()
        return scan

    def test_target_mode_prefers_exact_host_then_scan_target(self, app):
        with app.app_context():
            scan = self._setup(app)
            assert ssh_verify.creds_for(scan, "10.0.0.7").ssh_username == "hostuser"
            c = ssh_verify.creds_for(scan, "10.0.0.8")
            assert (c.ssh_username, c.host, c.source) == ("netuser", "10.0.0.8", "target")

    def test_scan_mode_uses_scan_login_everywhere(self, app):
        with app.app_context():
            scan = self._setup(app, cred_mode="scan", ssh_username="scanuser", ssh_password="sp")
            assert ssh_verify.creds_for(scan, "10.0.0.7").ssh_username == "scanuser"

    def test_off_mode_never_logs_in(self, app):
        with app.app_context():
            scan = self._setup(app, cred_mode="off")
            assert ssh_verify.creds_for(scan, "10.0.0.7") is None

    def test_username_without_secret_is_not_a_login(self, app):
        with app.app_context():
            scan = self._setup(app, cred_mode="scan", ssh_username="u")
            assert ssh_verify.creds_for(scan, "10.0.0.7") is None


# ── form handling ────────────────────────────────────────────────────────────

class TestForms:
    def test_password_required(self):
        assert apply_ssh_form(N(), {"ssh_username": "u", "ssh_auth_type": "password"}) == "Enter the SSH password."

    def test_bad_key_rejected(self):
        err = apply_ssh_form(N(), {"ssh_username": "u", "ssh_auth_type": "key", "ssh_private_key": "garbage"})
        assert err and "Unsupported private key" in err

    def test_keep_saved_secret_on_edit(self):
        obj = N(ssh_username="u", ssh_port=22, ssh_auth_type="password", ssh_password="old",
                ssh_private_key=None, ssh_key_passphrase=None)
        assert apply_ssh_form(obj, {"ssh_username": "u2", "ssh_auth_type": "password"}, keep_secrets=True) is None
        assert (obj.ssh_username, obj.ssh_password) == ("u2", "old")

    def test_switching_to_password_drops_saved_key(self):
        obj = N(ssh_username="u", ssh_port=22, ssh_auth_type="key", ssh_password=None,
                ssh_private_key="KEY", ssh_key_passphrase="pp")
        apply_ssh_form(obj, {"ssh_username": "u", "ssh_auth_type": "password", "ssh_password": "pw"},
                       keep_secrets=True)
        assert (obj.ssh_private_key, obj.ssh_key_passphrase, obj.ssh_password) == (None, None, "pw")

    def test_scan_mode_requires_username(self):
        assert "username" in apply_scan_cred_form(N(), {"cred_mode": "scan"})

    def test_target_mode_clears_scan_login(self):
        obj = N()
        assert apply_scan_cred_form(obj, {"cred_mode": "target", "ssh_username": "ignored",
                                          "ssh_password": "x"}) is None
        assert obj.cred_mode == "target" and obj.ssh_username is None and obj.ssh_password is None


# ── routes ───────────────────────────────────────────────────────────────────

def _target(app, **kw):
    from app.extensions import db
    from app.models import Target
    with app.app_context():
        t = Target(name="srv", host="10.0.0.9", **kw)
        db.session.add(t); db.session.commit()
        return t.id


def _raw(app, table, col, row_id):
    from sqlalchemy import text
    from app.extensions import db
    with app.app_context():
        return db.session.execute(text(f"SELECT {col} FROM {table} WHERE id=:i"), {"i": row_id}).scalar()


class TestTargetCredentialRoutes:
    def test_attach_credentials_to_existing_target(self, app, admin_client):
        tid = _target(app)
        r = admin_client.get(f"/targets/{tid}/credentials")
        assert r.status_code == 200 and b"Credentialed CVE checks" in r.data
        admin_client.post(f"/targets/{tid}/credentials", data={
            "ssh_username": "audit", "ssh_port": "2222", "ssh_auth_type": "password", "ssh_password": "s3cret"})
        from app.models import Target
        with app.app_context():
            from app.extensions import db
            t = db.session.get(Target, tid)
            assert (t.ssh_username, t.ssh_port, t.ssh_password) == ("audit", 2222, "s3cret")
        assert _raw(app, "targets", "ssh_password", tid).startswith("enc:v1:")

    def test_edit_keeps_password_when_left_blank_and_remove_clears(self, app, admin_client):
        tid = _target(app, ssh_username="audit", ssh_password="keepme")
        admin_client.post(f"/targets/{tid}/credentials", data={
            "ssh_username": "audit2", "ssh_port": "22", "ssh_auth_type": "password", "ssh_password": ""})
        from app.models import Target
        from app.extensions import db
        with app.app_context():
            t = db.session.get(Target, tid)
            assert (t.ssh_username, t.ssh_password) == ("audit2", "keepme")
        admin_client.post(f"/targets/{tid}/credentials", data={"remove": "1"})
        with app.app_context():
            t = db.session.get(Target, tid)
            assert t.ssh_username is None and t.ssh_password is None

    def test_page_never_echoes_secret(self, app, admin_client):
        tid = _target(app, ssh_username="audit", ssh_password="do-not-show")
        assert b"do-not-show" not in admin_client.get(f"/targets/{tid}/credentials").data

    def test_test_login_uses_saved_secret(self, app, admin_client):
        tid = _target(app, ssh_username="audit", ssh_password="saved-pw")
        with patch("app.routes.targets.test_login", return_value={"ok": True, "user": "audit"}) as tl:
            r = admin_client.post(f"/targets/{tid}/credentials/test",
                                  data={"ssh_username": "audit", "ssh_auth_type": "password"})
        assert r.get_json()["ok"] and r.get_json()["host"] == "10.0.0.9"
        creds = tl.call_args[0][0]
        assert (creds.host, creds.ssh_password) == ("10.0.0.9", "saved-pw")

    def test_targets_list_links_to_credentials(self, app, admin_client):
        tid = _target(app)
        assert f"/targets/{tid}/credentials".encode() in admin_client.get("/targets/").data


class TestScanCredentialSettings:
    def test_scan_with_its_own_login_stores_it_encrypted(self, app, admin_client):
        tid = _target(app)
        with patch("threading.Thread.start"):
            admin_client.post("/scans/new", data={
                "name": "cred scan", "target_id": str(tid), "scan_type": "full", "port_range": "1-1024",
                "cred_mode": "scan", "ssh_username": "scanuser", "ssh_auth_type": "password",
                "ssh_password": "scan-pw"})
        from app.models import Scan
        with app.app_context():
            s = Scan.query.filter_by(name="cred scan").one()
            assert (s.cred_mode, s.ssh_username, s.ssh_password) == ("scan", "scanuser", "scan-pw")
            sid = s.id
        assert _raw(app, "scans", "ssh_password", sid).startswith("enc:v1:")

    def test_scan_mode_without_password_is_rejected(self, app, admin_client):
        tid = _target(app)
        with patch("threading.Thread.start"):
            r = admin_client.post("/scans/new", data={
                "name": "bad", "target_id": str(tid), "scan_type": "full", "port_range": "1-1024",
                "cred_mode": "scan", "ssh_username": "u", "ssh_auth_type": "password"})
        assert b"Enter the SSH password" in r.data
        from app.models import Scan
        with app.app_context():
            assert Scan.query.filter_by(name="bad").count() == 0

    def test_default_uses_target_login(self, app, admin_client):
        tid = _target(app)
        with patch("threading.Thread.start"):
            admin_client.post("/scans/new", data={
                "name": "plain", "target_id": str(tid), "scan_type": "full", "port_range": "1-1024"})
        from app.models import Scan
        with app.app_context():
            s = Scan.query.filter_by(name="plain").one()
            assert s.cred_mode == "target" and s.ssh_username is None

    def test_new_scan_form_shows_credential_options(self, admin_client):
        body = admin_client.get("/scans/new").data
        assert b'name="cred_mode"' in body and b"Credentialed Checks" in body

    def test_scheduled_scan_passes_login_to_each_run(self, app, admin_client):
        tid = _target(app)
        admin_client.post("/scans/schedule/new", data={
            "name": "nightly", "target_id": str(tid), "scan_type": "full", "port_range": "1-1024",
            "cron_expression": "0 2 * * *", "cred_mode": "scan", "ssh_username": "nightuser",
            "ssh_auth_type": "password", "ssh_password": "night-pw"})
        from datetime import datetime, timezone, timedelta
        from app.extensions import db
        from app.models import ScheduledScan, Scan
        from app.scheduler.jobs import _run_scheduled_scans
        with app.app_context():
            sched = ScheduledScan.query.filter_by(name="nightly").one()
            assert sched.ssh_password == "night-pw"
            sched.next_run = datetime.now(timezone.utc) - timedelta(minutes=1)
            db.session.commit()
        with patch("threading.Thread.start"):
            _run_scheduled_scans(app)
        with app.app_context():
            run = Scan.query.filter(Scan.name.like("nightly%")).one()
            assert (run.cred_mode, run.ssh_username, run.ssh_password) == ("scan", "nightuser", "night-pw")

    def test_scan_ssh_test_route_tests_against_selected_target(self, app, admin_client):
        tid = _target(app)
        with patch("app.routes.targets.test_login", return_value={"ok": True, "user": "u"}) as tl:
            r = admin_client.post("/scans/ssh-test", data={
                "target_id": str(tid), "ssh_username": "u", "ssh_auth_type": "password", "ssh_password": "p"})
        assert r.get_json()["ok"]
        assert tl.call_args[0][0].host == "10.0.0.9"

    def test_ssh_test_refuses_subnet(self, app, admin_client):
        from app.extensions import db
        from app.models import Target
        with app.app_context():
            t = Target(name="net", host="10.0.0.0/24"); db.session.add(t); db.session.commit(); tid = t.id
        r = admin_client.post("/scans/ssh-test", data={
            "target_id": str(tid), "ssh_username": "u", "ssh_auth_type": "password", "ssh_password": "p"})
        assert not r.get_json()["ok"] and "single host" in r.get_json()["error"]
