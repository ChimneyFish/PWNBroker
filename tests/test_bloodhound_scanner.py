"""Tests for app/scanner/bloodhound_scanner.py — collection, ingest, and the
hunting-query pipeline.

No real bloodhound-ce-python binary or BloodHound CE instance is used —
subprocess.run and BHClient are mocked throughout. A real end-to-end run
(collection -> ingest -> hunting queries) against an actual AD lab domain
and a live BloodHound CE instance was done manually during development;
that can't be part of the automated suite since it needs live infrastructure
CI shouldn't depend on, same reasoning as test_reaper_scanner.py's own
docstring.
"""
import json
import os
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from app.bloodhound.api_client import BloodHoundAPIError
from app.scanner import bloodhound_scanner as bh


def _make_target(**overrides):
    defaults = dict(
        host="corp.local", target_type="ad_domain",
        ad_dc_host="10.0.0.1", ad_username="svc_bloodhound",
        ad_auth_type="password", ad_password="hunter2", ad_nt_hash=None,
        last_bloodhound_ingest_at=None,
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


# ── _find_collector_binary ────────────────────────────────────────────────

def test_find_collector_binary_uses_env_override(tmp_path, monkeypatch):
    fake_bin = tmp_path / "bloodhound-ce-python"
    fake_bin.write_text("#!/bin/sh\necho hi\n")
    os.chmod(fake_bin, 0o755)
    monkeypatch.setenv("BLOODHOUND_COLLECTOR_BINARY", str(fake_bin))
    assert bh._find_collector_binary() == str(fake_bin)


def test_find_collector_binary_falls_back_to_path(monkeypatch):
    monkeypatch.delenv("BLOODHOUND_COLLECTOR_BINARY", raising=False)
    with patch.object(bh.shutil, "which", return_value="/usr/bin/bloodhound-ce-python"):
        assert bh._find_collector_binary() == "/usr/bin/bloodhound-ce-python"


def test_find_collector_binary_returns_none_when_nothing_found(monkeypatch):
    monkeypatch.delenv("BLOODHOUND_COLLECTOR_BINARY", raising=False)
    with patch.object(bh.shutil, "which", return_value=None):
        assert bh._find_collector_binary() is None


# ── run_collection: validation ────────────────────────────────────────────

class TestRunCollectionValidation:
    def test_requires_dc_host(self):
        result = bh.run_collection(_make_target(ad_dc_host=""))
        assert "error" in result

    def test_requires_username(self):
        result = bh.run_collection(_make_target(ad_username=""))
        assert "error" in result

    def test_password_auth_requires_password(self):
        result = bh.run_collection(_make_target(ad_auth_type="password", ad_password=""))
        assert "error" in result
        assert "password" in result["error"].lower()

    def test_hash_auth_requires_hash(self):
        result = bh.run_collection(_make_target(ad_auth_type="hash", ad_nt_hash=""))
        assert "error" in result
        assert "hash" in result["error"].lower()

    def test_missing_binary_reports_error(self):
        with patch.object(bh, "_find_collector_binary", return_value=None):
            result = bh.run_collection(_make_target())
        assert "error" in result
        assert "bloodhound-ce-python" in result["error"]


# ── run_collection: subprocess driving ────────────────────────────────────

class TestRunCollectionSubprocess:
    def test_success_finds_produced_zip(self):
        def fake_run(args, cwd, capture_output, text, timeout):
            with open(os.path.join(cwd, "collection_20260101.zip"), "wb") as f:
                f.write(b"PK\x03\x04fakezipcontent")
            result = MagicMock()
            result.stderr = ""
            result.stdout = ""
            return result

        with patch.object(bh, "_find_collector_binary", return_value="/fake/bloodhound-ce-python"):
            with patch.object(bh.subprocess, "run", side_effect=fake_run):
                result = bh.run_collection(_make_target())

        assert "zip_path" in result
        assert result["zip_path"].endswith(".zip")
        assert os.path.isfile(result["zip_path"])
        bh.shutil.rmtree(result["work_dir"], ignore_errors=True)

    def test_password_auth_passes_password_flag(self):
        captured = {}

        def fake_run(args, cwd, capture_output, text, timeout):
            captured["args"] = args
            result = MagicMock()
            result.stderr = ""
            result.stdout = ""
            return result

        with patch.object(bh, "_find_collector_binary", return_value="/fake/bloodhound-ce-python"):
            with patch.object(bh.subprocess, "run", side_effect=fake_run):
                bh.run_collection(_make_target(ad_password="hunter2"))

        assert "-p" in captured["args"]
        assert "hunter2" in captured["args"]
        assert "--hashes" not in captured["args"]

    def test_hash_auth_passes_hashes_flag_not_password(self):
        captured = {}

        def fake_run(args, cwd, capture_output, text, timeout):
            captured["args"] = args
            result = MagicMock()
            result.stderr = ""
            result.stdout = ""
            return result

        with patch.object(bh, "_find_collector_binary", return_value="/fake/bloodhound-ce-python"):
            with patch.object(bh.subprocess, "run", side_effect=fake_run):
                bh.run_collection(_make_target(ad_auth_type="hash", ad_nt_hash="aabbccddeeff00112233445566778899"))

        assert "--hashes" in captured["args"]
        assert ":aabbccddeeff00112233445566778899" in captured["args"]
        assert "-p" not in captured["args"]

    def test_no_zip_produced_is_reported_as_error(self):
        def fake_run(args, cwd, capture_output, text, timeout):
            result = MagicMock()
            result.stderr = "LDAP bind failed: invalid credentials"
            result.stdout = ""
            return result

        with patch.object(bh, "_find_collector_binary", return_value="/fake/bloodhound-ce-python"):
            with patch.object(bh.subprocess, "run", side_effect=fake_run):
                result = bh.run_collection(_make_target())

        assert "error" in result
        assert "invalid credentials" in result["error"]

    def test_timeout_is_reported_as_error(self):
        import subprocess as sp

        def fake_run(args, cwd, capture_output, text, timeout):
            raise sp.TimeoutExpired(cmd=args, timeout=timeout)

        with patch.object(bh, "_find_collector_binary", return_value="/fake/bloodhound-ce-python"):
            with patch.object(bh.subprocess, "run", side_effect=fake_run):
                result = bh.run_collection(_make_target())

        assert "error" in result
        assert "minute budget" in result["error"]


# ── ingest_and_wait ────────────────────────────────────────────────────────

class TestIngestAndWait:
    def _client(self, **method_overrides):
        client = MagicMock()
        client.start_file_upload.return_value = 42
        client.upload_file_data.return_value = None
        client.end_file_upload.return_value = None
        for name, value in method_overrides.items():
            getattr(client, name).side_effect = value if callable(value) else None
            if not callable(value):
                getattr(client, name).return_value = value
        return client

    def test_start_upload_failure_reported(self, tmp_path):
        zip_path = tmp_path / "c.zip"
        zip_path.write_bytes(b"x")
        client = self._client()
        client.start_file_upload.side_effect = BloodHoundAPIError("HTTP 401")
        result = bh.ingest_and_wait(client, str(zip_path))
        assert "error" in result
        assert "401" in result["error"]

    def test_upload_data_failure_reported(self, tmp_path):
        zip_path = tmp_path / "c.zip"
        zip_path.write_bytes(b"x")
        client = self._client()
        client.upload_file_data.side_effect = BloodHoundAPIError("HTTP 400")
        result = bh.ingest_and_wait(client, str(zip_path))
        assert "error" in result

    def test_polls_until_complete(self, tmp_path):
        zip_path = tmp_path / "c.zip"
        zip_path.write_bytes(b"x")
        client = self._client()
        client.get_job_status.side_effect = [
            {"status": 1}, {"status": 6}, {"status": 7}, {"status": 2},
        ]
        with patch.object(bh.time, "sleep"):
            result = bh.ingest_and_wait(client, str(zip_path))
        assert result == {"ok": True}
        assert client.get_job_status.call_count == 4

    def test_partially_complete_returns_ok_with_warning(self, tmp_path):
        zip_path = tmp_path / "c.zip"
        zip_path.write_bytes(b"x")
        client = self._client()
        client.get_job_status.return_value = {"status": 8}
        with patch.object(bh.time, "sleep"):
            result = bh.ingest_and_wait(client, str(zip_path))
        assert result["ok"] is True
        assert "warning" in result

    def test_failed_status_returns_error(self, tmp_path):
        zip_path = tmp_path / "c.zip"
        zip_path.write_bytes(b"x")
        client = self._client()
        client.get_job_status.return_value = {"status": 5}
        with patch.object(bh.time, "sleep"):
            result = bh.ingest_and_wait(client, str(zip_path))
        assert "error" in result
        assert "Failed" in result["error"]

    def test_status_check_error_reported(self, tmp_path):
        zip_path = tmp_path / "c.zip"
        zip_path.write_bytes(b"x")
        client = self._client()
        client.get_job_status.side_effect = BloodHoundAPIError("HTTP 500")
        result = bh.ingest_and_wait(client, str(zip_path))
        assert "error" in result

    def test_timeout_reported(self, tmp_path, monkeypatch):
        zip_path = tmp_path / "c.zip"
        zip_path.write_bytes(b"x")
        client = self._client()
        client.get_job_status.return_value = {"status": 1}  # never terminal
        monkeypatch.setattr(bh, "BLOODHOUND_INGEST_TIMEOUT_SECONDS", 0)
        result = bh.ingest_and_wait(client, str(zip_path))
        assert "error" in result
        assert "did not finish ingesting" in result["error"]


# ── _resolve_domain ────────────────────────────────────────────────────────

class TestResolveDomain:
    _SID = "S-1-5-21-1111111111-2222222222-3333333333"

    def test_matches_case_insensitively_and_trailing_dot(self):
        client = MagicMock()
        client.available_domains.return_value = [{"name": "CORP.LOCAL.", "id": self._SID}]
        sid, err = bh._resolve_domain(client, "corp.local")
        assert err is None
        assert sid == self._SID

    def test_no_match_reports_known_domains(self):
        client = MagicMock()
        client.available_domains.return_value = [{"name": "OTHER.LOCAL", "id": "S-1-5-21-1-2-3"}]
        sid, err = bh._resolve_domain(client, "corp.local")
        assert sid is None
        assert "OTHER.LOCAL" in err

    def test_api_error_reported(self):
        client = MagicMock()
        client.available_domains.side_effect = BloodHoundAPIError("HTTP 401")
        sid, err = bh._resolve_domain(client, "corp.local")
        assert sid is None
        assert "401" in err

    def test_malformed_sid_rejected(self):
        client = MagicMock()
        client.available_domains.return_value = [{"name": "corp.local", "id": "not-a-sid"}]
        sid, err = bh._resolve_domain(client, "corp.local")
        assert sid is None
        assert "unexpected domain SID" in err


# ── Cypher result parsing helpers ────────────────────────────────────────────

def _node(label=None, objectid=None, **props):
    n = {"properties": props}
    if label is not None:
        n["label"] = label
    if objectid is not None:
        n["objectId"] = objectid
    return n


class TestNodeHelpers:
    def test_principal_name_prefers_label(self):
        assert bh._principal_name(_node(label="JDOE@CORP.LOCAL", name="jdoe")) == "JDOE@CORP.LOCAL"

    def test_principal_name_falls_back_to_properties_name(self):
        assert bh._principal_name(_node(name="jdoe")) == "jdoe"

    def test_principal_name_falls_back_to_objectid(self):
        assert bh._principal_name(_node(objectid="S-1-5-21-1-2-3-1000")) == "S-1-5-21-1-2-3-1000"

    def test_node_objectid_reads_top_level_camel_case(self):
        assert bh._node_objectid(_node(objectid="S-1-5-21-1-2-3-512")) == "S-1-5-21-1-2-3-512"

    def test_node_objectid_falls_back_to_properties(self):
        n = {"properties": {"objectid": "S-1-5-21-1-2-3-512"}}
        assert bh._node_objectid(n) == "S-1-5-21-1-2-3-512"


class TestSeverityForHops:
    def test_close_hops_are_critical(self):
        assert bh._severity_for_hops(1) == "critical"
        assert bh._severity_for_hops(2) == "critical"

    def test_medium_hops_are_high(self):
        assert bh._severity_for_hops(3) == "high"
        assert bh._severity_for_hops(4) == "high"

    def test_far_hops_are_medium(self):
        assert bh._severity_for_hops(5) == "medium"
        assert bh._severity_for_hops(8) == "medium"


class TestPathReconstruction:
    def test_picks_the_globally_closest_node_not_the_deepest_chain(self):
        # Every non-sink node in a shortestPath() result is itself a valid
        # independent match for `n` (BloodHound returns one row per matching
        # start node) — so a node one hop from the sink represents a genuinely
        # shorter, separately-found path, even if it also happens to sit in
        # the middle of some other node's longer chain. The "shortest chain"
        # is the minimum over all of them, not the deepest reconstructable
        # walk. attacker --[HasSession]--> workstation --[MemberOf]--> helpdesk
        # --[GenericAll]--> DA: helpdesk's own 1-hop path wins.
        nodes = {
            "1": _node(label="ATTACKER@CORP.LOCAL"),
            "2": _node(label="WKSTN01"),
            "3": _node(label="HELP DESK@CORP.LOCAL"),
            "4": _node(label="DOMAIN ADMINS@CORP.LOCAL", objectid="S-1-5-21-1-2-3-512"),
        }
        edges = [
            {"source": "1", "target": "2", "label": "HasSession"},
            {"source": "2", "target": "3", "label": "MemberOf"},
            {"source": "3", "target": "4", "label": "GenericAll"},
        ]
        rev = bh._build_reverse_adjacency(edges)
        dist, pred = bh._bfs_distances_to_sink(rev, "4")
        min_dist, hop_str = bh._shortest_chain_to_sink(nodes, dist, pred, "4")
        assert min_dist == 1
        assert hop_str == "HELP DESK@CORP.LOCAL --[GenericAll]--> DOMAIN ADMINS@CORP.LOCAL"

    def test_full_predecessor_chain_is_walkable_for_a_deeper_node(self):
        # Same graph as above — a node further from the sink still has its
        # own correct, fully-reconstructable predecessor chain even though
        # it isn't the global minimum reported by _shortest_chain_to_sink.
        nodes = {
            "1": _node(label="ATTACKER@CORP.LOCAL"),
            "2": _node(label="WKSTN01"),
            "3": _node(label="HELP DESK@CORP.LOCAL"),
            "4": _node(label="DOMAIN ADMINS@CORP.LOCAL", objectid="S-1-5-21-1-2-3-512"),
        }
        edges = [
            {"source": "1", "target": "2", "label": "HasSession"},
            {"source": "2", "target": "3", "label": "MemberOf"},
            {"source": "3", "target": "4", "label": "GenericAll"},
        ]
        rev = bh._build_reverse_adjacency(edges)
        dist, pred = bh._bfs_distances_to_sink(rev, "4")
        assert dist["1"] == 3
        chain = ["1"]
        cur = "1"
        while cur != "4":
            cur, _ = pred[cur]
            chain.append(cur)
        assert [nodes[c]["label"] for c in chain] == [
            "ATTACKER@CORP.LOCAL", "WKSTN01", "HELP DESK@CORP.LOCAL", "DOMAIN ADMINS@CORP.LOCAL",
        ]

    def test_ignores_a_deeper_chain_in_favor_of_the_one_true_closer_node(self):
        # DA has exactly one direct predecessor (NEAR) — no tie at distance 1 —
        # so a longer chain feeding in further back must not be preferred.
        nodes = {
            "1": _node(label="FAR_START"),
            "2": _node(label="MID"),
            "3": _node(label="NEAR"),
            "4": _node(label="DA", objectid="S-1-5-21-1-2-3-512"),
        }
        edges = [
            {"source": "1", "target": "2", "label": "MemberOf"},
            {"source": "2", "target": "3", "label": "MemberOf"},
            {"source": "3", "target": "4", "label": "AdminTo"},
        ]
        rev = bh._build_reverse_adjacency(edges)
        dist, pred = bh._bfs_distances_to_sink(rev, "4")
        min_dist, hop_str = bh._shortest_chain_to_sink(nodes, dist, pred, "4")
        assert min_dist == 1
        assert hop_str == "NEAR --[AdminTo]--> DA"

    def test_no_candidates_returns_none(self):
        nodes = {"1": _node(label="DA", objectid="S-1-5-21-1-2-3-512")}
        min_dist, hop_str = bh._shortest_chain_to_sink(nodes, {"1": 0}, {}, "1")
        assert min_dist is None
        assert hop_str is None


# ── run_hunting_queries ──────────────────────────────────────────────────────

class TestHuntFlaggedNodes:
    def test_maps_nodes_to_confirmed_vulnerabilities(self):
        client = MagicMock()
        client.cypher.return_value = {"data": {"nodes": {
            "1": _node(label="SVC_SQL@CORP.LOCAL", admincount=False),
        }}}
        findings = bh._hunt_flagged_nodes(
            client, "MATCH ...", "Kerberoastable account: {name}", "{name} desc",
            base_severity="high", escalate_on_admincount=True, host="corp.local",
        )
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"
        assert findings[0]["verification_status"] == "confirmed"
        assert "SVC_SQL@CORP.LOCAL" in findings[0]["title"]

    def test_escalates_severity_for_admincount(self):
        client = MagicMock()
        client.cypher.return_value = {"data": {"nodes": {
            "1": _node(label="ADMIN_SVC@CORP.LOCAL", admincount=True),
        }}}
        findings = bh._hunt_flagged_nodes(
            client, "MATCH ...", "Kerberoastable account: {name}", "{name} desc",
            base_severity="high", escalate_on_admincount=True, host="corp.local",
        )
        assert findings[0]["severity"] == "critical"

    def test_no_escalation_when_disabled(self):
        client = MagicMock()
        client.cypher.return_value = {"data": {"nodes": {
            "1": _node(label="ADMIN_SVC@CORP.LOCAL", admincount=True),
        }}}
        findings = bh._hunt_flagged_nodes(
            client, "MATCH ...", "{name}", "{name} desc",
            base_severity="critical", escalate_on_admincount=False, host="corp.local",
        )
        assert findings[0]["severity"] == "critical"  # base, not further escalated

    def test_query_failure_reported_without_raising(self):
        client = MagicMock()
        client.cypher.side_effect = BloodHoundAPIError("HTTP 400: bad query")
        findings = bh._hunt_flagged_nodes(
            client, "MATCH ...", "Kerberoastable account: {name}", "{name} desc",
            base_severity="high", escalate_on_admincount=True, host="corp.local",
        )
        assert len(findings) == 1
        assert findings[0]["result_type"] == "info"

    def test_empty_result_is_empty_list(self):
        client = MagicMock()
        client.cypher.return_value = {"data": {"nodes": {}}}
        findings = bh._hunt_flagged_nodes(
            client, "MATCH ...", "{name}", "{name}",
            base_severity="high", escalate_on_admincount=True, host="corp.local",
        )
        assert findings == []


class TestRunHuntingQueries:
    _SID = "S-1-5-21-1-2-3"

    def test_rejects_malformed_domain_sid(self):
        client = MagicMock()
        findings = bh.run_hunting_queries(client, "not-a-sid", "corp.local")
        assert len(findings) == 1
        assert "unexpected domain SID" in findings[0]["title"]
        client.cypher.assert_not_called()

    def test_runs_six_queries_against_valid_domain(self):
        client = MagicMock()
        client.cypher.return_value = {"data": {"nodes": {}}}
        bh.run_hunting_queries(client, self._SID, "corp.local")
        # kerberoast, asrep, unconstrained delegation, dcsync, DA paths, EA paths
        assert client.cypher.call_count == 6

    def test_one_query_failing_does_not_abort_the_others(self):
        client = MagicMock()
        good = {"data": {"nodes": {"1": _node(label="SVC@CORP.LOCAL")}}}
        client.cypher.side_effect = [
            BloodHoundAPIError("boom"), good, good, good,
            {"data": {"nodes": {}, "edges": []}}, {"data": {"nodes": {}, "edges": []}},
        ]
        findings = bh.run_hunting_queries(client, self._SID, "corp.local")
        assert client.cypher.call_count == 6
        # the failed query's info result, plus 3 real findings from the others
        info_results = [f for f in findings if f["result_type"] == "info"]
        vuln_results = [f for f in findings if f["result_type"] == "vulnerability"]
        assert len(info_results) == 1
        assert len(vuln_results) == 3

    def test_shortest_path_findings_included(self):
        client = MagicMock()
        empty = {"data": {"nodes": {}, "edges": []}}
        path_resp = {"data": {
            "nodes": {
                "1": _node(label="ATTACKER"),
                "2": _node(label="DOMAIN ADMINS@CORP.LOCAL", objectid=f"{self._SID}-512"),
            },
            "edges": [{"source": "1", "target": "2", "label": "AdminTo"}],
        }}

        def side_effect(query, include_properties=True):
            if f"g.objectid = '{self._SID}-512'" in query:
                return path_resp
            return empty

        client.cypher.side_effect = side_effect
        findings = bh.run_hunting_queries(client, self._SID, "corp.local")
        path_findings = [f for f in findings if "Attack path to Domain Admins" in f.get("title", "")]
        assert len(path_findings) == 1
        assert path_findings[0]["severity"] == "critical"


# ── run_bloodhound_scan ────────────────────────────────────────────────────

class TestRunBloodhoundScan:
    def test_rejects_non_ad_domain_target(self):
        target = _make_target(target_type="host")
        findings = bh.run_bloodhound_scan(scan=None, target=target)
        assert len(findings) == 1
        assert "requires an AD Domain target" in findings[0]["title"]

    def test_rejects_none_target(self):
        findings = bh.run_bloodhound_scan(scan=None, target=None)
        assert len(findings) == 1
        assert findings[0]["result_type"] == "info"

    def test_collection_failure_surfaces_as_info_result(self):
        with patch.object(bh, "run_collection", return_value={"error": "bad creds"}):
            findings = bh.run_bloodhound_scan(scan=None, target=_make_target())
        assert len(findings) == 1
        assert findings[0]["severity"] == "info"
        assert "bad creds" in findings[0]["description"]

    def test_collection_success_without_bloodhound_config_reports_info(self, app, tmp_path):
        work_dir = tmp_path / "collected"
        work_dir.mkdir()
        zip_path = work_dir / "collection.zip"
        zip_path.write_bytes(b"x" * 1234)
        with app.app_context():
            with patch.object(bh, "run_collection", return_value={
                "zip_path": str(zip_path), "work_dir": str(work_dir),
            }):
                findings = bh.run_bloodhound_scan(scan=None, target=_make_target())
        assert len(findings) == 1
        assert "1234" in findings[0]["title"]
        assert "not configured" in findings[0]["title"]

    def test_collection_success_with_bloodhound_disabled_reports_info(self, app, tmp_path):
        from app.models import BloodHoundConfig
        from app.extensions import db as _db
        work_dir = tmp_path / "collected"
        work_dir.mkdir()
        zip_path = work_dir / "collection.zip"
        zip_path.write_bytes(b"x")
        with app.app_context():
            _db.session.add(BloodHoundConfig(enabled=False, token_id="t", token_key="k"))
            _db.session.commit()
            with patch.object(bh, "run_collection", return_value={
                "zip_path": str(zip_path), "work_dir": str(work_dir),
            }):
                findings = bh.run_bloodhound_scan(scan=None, target=_make_target())
        assert len(findings) == 1
        assert "not configured" in findings[0]["title"]

    def test_ingestion_failure_reported(self, app, tmp_path):
        from app.models import BloodHoundConfig
        from app.extensions import db as _db
        work_dir = tmp_path / "collected"
        work_dir.mkdir()
        zip_path = work_dir / "collection.zip"
        zip_path.write_bytes(b"x")
        with app.app_context():
            _db.session.add(BloodHoundConfig(enabled=True, token_id="t", token_key="k",
                                             api_url="http://localhost:8080"))
            _db.session.commit()
            with patch.object(bh, "run_collection", return_value={
                "zip_path": str(zip_path), "work_dir": str(work_dir),
            }):
                with patch.object(bh, "ingest_and_wait", return_value={"error": "upload failed"}):
                    findings = bh.run_bloodhound_scan(scan=None, target=_make_target())
        assert len(findings) == 1
        assert "ingestion failed" in findings[0]["title"].lower()
        assert "upload failed" in findings[0]["description"]

    def test_domain_not_found_reported(self, app, tmp_path):
        from app.models import BloodHoundConfig
        from app.extensions import db as _db
        work_dir = tmp_path / "collected"
        work_dir.mkdir()
        zip_path = work_dir / "collection.zip"
        zip_path.write_bytes(b"x")
        with app.app_context():
            _db.session.add(BloodHoundConfig(enabled=True, token_id="t", token_key="k",
                                             api_url="http://localhost:8080"))
            _db.session.commit()
            with patch.object(bh, "run_collection", return_value={
                "zip_path": str(zip_path), "work_dir": str(work_dir),
            }):
                with patch.object(bh, "ingest_and_wait", return_value={"ok": True}):
                    with patch.object(bh, "_resolve_domain", return_value=(None, "domain not found")):
                        findings = bh.run_bloodhound_scan(scan=None, target=_make_target())
        assert len(findings) == 1
        assert "domain wasn't found" in findings[0]["title"]

    def test_full_success_returns_summary_and_findings_and_sets_ingest_timestamp(self, app, tmp_path):
        from app.models import BloodHoundConfig
        from app.extensions import db as _db
        work_dir = tmp_path / "collected"
        work_dir.mkdir()
        zip_path = work_dir / "collection.zip"
        zip_path.write_bytes(b"x")
        target = _make_target()
        assert target.last_bloodhound_ingest_at is None
        with app.app_context():
            _db.session.add(BloodHoundConfig(enabled=True, token_id="t", token_key="k",
                                             api_url="http://localhost:8080"))
            _db.session.commit()
            with patch.object(bh, "run_collection", return_value={
                "zip_path": str(zip_path), "work_dir": str(work_dir),
            }):
                with patch.object(bh, "ingest_and_wait", return_value={"ok": True}):
                    with patch.object(bh, "_resolve_domain", return_value=("S-1-5-21-1-2-3", None)):
                        fake_finding = {"result_type": "vulnerability", "host": "corp.local",
                                        "severity": "critical", "title": "x", "description": "y"}
                        with patch.object(bh, "run_hunting_queries", return_value=[fake_finding]):
                            findings = bh.run_bloodhound_scan(scan=None, target=target)
        assert findings[0]["title"] == "BloodHound analysis complete"
        assert "1 finding" in findings[0]["description"]
        assert findings[1] == fake_finding
        assert target.last_bloodhound_ingest_at is not None
