"""
BloodHound CE integration — Active Directory attack-path analysis. Wired in
as the "bloodhound" scan type, launched from its own dedicated section (not
the generic New Scan form — same precedent as REAPER/OSV, see
reaper_scanner.py's docstring), against `ad_domain`-type Targets.

Collection uses `bloodhound-ce-python` (apt-installable on Kali, Impacket-
based — no Windows host needed, unlike SharpHound), invoked directly on
PATH rather than vendored under tools/ like PEN/REAPER's built-from-source
binaries, since it's an OS package here (see docs/deployment.md).

Phase 2 (this module, in full): upload the collector's zip to BloodHound CE
via app/bloodhound/api_client.py, wait for it to finish ingesting +
analyzing, resolve the target domain's SID, run a fixed set of hunting
Cypher queries against it, and turn the results into confirmed ScanResults
— Kerberoastable accounts, AS-REP roastable accounts, unconstrained
delegation, DCSync rights, and shortest paths to Domain Admins/Enterprise
Admins. `verification_status="confirmed"` is used throughout: these are
computed facts read directly off real collected AD data (not a version-
correlation guess), matching how nmap's NSE vuln scripts and PEN's exploit
confirmations earn "confirmed" elsewhere in this codebase.

Every hunting query resolves its target group by well-known RID (Domain
Admins = -512, Enterprise Admins = -519, Domain Controllers = -516)
suffixed onto the domain SID, rather than a "high value"/tier-zero tag —
RIDs are stable across BloodHound CE schema versions, tagging conventions
are not. Domain SIDs come from BloodHound's own available-domains response
and are sanity-checked against `_SID_RE` before being interpolated into a
Cypher string (BloodHound's cypher endpoint takes a raw query string, no
parameter binding — see api_client.py's module docstring).

One soft spot, called out here rather than silently assumed: the exact key
casing inside a returned node/edge object (top-level envelope vs. its
`properties` sub-dict) is read defensively (falls back across a few likely
key names) because it wasn't independently re-verified against a live
instance's raw JSON the way the file-upload endpoints were against the
OpenAPI spec. Worth a spot-check the first time this runs against a real
domain — see docs/deployment.md's BloodHound section.
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..bloodhound.api_client import BHClient, BloodHoundAPIError

# AD collection over LDAP/SMB/RPC against a large domain (many users/computers/
# groups/ACLs, with -c All walking every collection method) can run long —
# generous but bounded, matching the reasoning behind PEN/REAPER/backdoor's
# own timeouts.
BLOODHOUND_TIMEOUT_SECONDS = 1800  # 30 minutes

# Upload + BloodHound CE's own ingest/analysis pipeline for a single domain's
# worth of collection data. Shorter than collection itself — this is server-
# side processing of data already sitting on disk, not a live network walk.
BLOODHOUND_INGEST_TIMEOUT_SECONDS = 900  # 15 minutes
_INGEST_POLL_INTERVAL_SECONDS = 5

_COLLECTOR_BINARY_NAME = "bloodhound-ce-python"

# job-status enum, from BloodHound CE's own OpenAPI spec (enum.job-status) —
# see api_client.py's get_job_status() docstring.
_JOB_STATUS_NAMES = {
    -1: "Invalid", 0: "Ready", 1: "Running", 2: "Complete", 3: "Canceled",
    4: "Timed Out", 5: "Failed", 6: "Ingesting", 7: "Analyzing", 8: "Partially Complete",
}
_JOB_STATUS_COMPLETE = 2
_JOB_STATUS_PARTIALLY_COMPLETE = 8
_TERMINAL_JOB_STATUSES = {2, 3, 4, 5, 8}

# Well-known relative IDs — stable across every AD domain and every
# BloodHound CE schema version, unlike a "high value"/tier-zero tag.
_RID_DOMAIN_ADMINS = "512"
_RID_ENTERPRISE_ADMINS = "519"
_RID_DOMAIN_CONTROLLERS = "516"
_WELL_KNOWN_SID_ENTERPRISE_DCS = "S-1-5-9"  # forest-wide, not domain-relative

# A domain SID as BloodHound reports it (e.g. S-1-5-21-1234567890-...-...).
# Checked before any interpolation into a Cypher query string.
_SID_RE = re.compile(r'^S-1-5-21-\d+-\d+-\d+$')

# The standard "can this principal eventually control that one" abuse-edge
# set used for attack-path hunting. Deliberately excludes noisy structural
# edges (e.g. Contains) that don't represent a usable privilege.
_ABUSE_EDGES = (
    "MemberOf|HasSession|AdminTo|AllExtendedRights|AddMember|ForceChangePassword|"
    "GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|ExecuteDCOM|AllowedToDelegate|"
    "ReadLAPSPassword|AddAllowedToAct|AllowedToAct|SQLAdmin|WriteSPN|AddKeyCredentialLink|"
    "SyncLAPSPassword|CanRDP|DCSync"
)
_MAX_PATH_HOPS = 8
_MAX_PATHS_PER_QUERY = 100


def _find_collector_binary() -> Optional[str]:
    override = os.environ.get("BLOODHOUND_COLLECTOR_BINARY")
    if override and os.path.isfile(override) and os.access(override, os.X_OK):
        return override
    return shutil.which(_COLLECTOR_BINARY_NAME)


def run_collection(target) -> Dict:
    """Run bloodhound-ce-python against target (an ad_domain Target) and
    return {"zip_path": str, "work_dir": str} on success, or
    {"error": str} on failure. Never raises. Caller is responsible for
    cleaning up work_dir once the zip has been used (kept alive past this
    call so the caller can read/upload it before deletion)."""
    if not target.ad_dc_host or not target.ad_username:
        return {"error": "This target is missing AD collection credentials "
                          "(domain controller host and/or username)."}
    if target.ad_auth_type == "hash":
        if not target.ad_nt_hash:
            return {"error": "This target's auth method is set to NTLM hash, but no hash is configured."}
    elif not target.ad_password:
        return {"error": "This target's auth method is password, but no password is configured."}

    binary = _find_collector_binary()
    if not binary:
        return {"error": (
            f"'{_COLLECTOR_BINARY_NAME}' not found on PATH and "
            "BLOODHOUND_COLLECTOR_BINARY is not set. See docs/deployment.md "
            "for the setup step (apt install bloodhound-ce-python)."
        )}

    work_dir = tempfile.mkdtemp(prefix="bloodhound_collect_")
    prefix = "collection"

    args = [
        binary,
        "-d", target.host,
        "-dc", target.ad_dc_host,
        "-u", target.ad_username,
        "-c", "All",
        "--zip",
        "-op", prefix,
    ]
    if target.ad_auth_type == "hash" and target.ad_nt_hash:
        args += ["--hashes", f":{target.ad_nt_hash}"]
    else:
        args += ["-p", target.ad_password or ""]

    try:
        proc = subprocess.run(
            args, cwd=work_dir, capture_output=True, text=True,
            timeout=BLOODHOUND_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        shutil.rmtree(work_dir, ignore_errors=True)
        return {"error": f"Collection exceeded its {BLOODHOUND_TIMEOUT_SECONDS // 60}-minute budget and was terminated."}
    except Exception as e:
        shutil.rmtree(work_dir, ignore_errors=True)
        return {"error": f"Could not run the collector: {e}"}

    zip_files = list(Path(work_dir).glob(f"{prefix}*.zip"))
    if not zip_files:
        error_note = (proc.stderr or proc.stdout or "no output").strip()[-2000:]
        shutil.rmtree(work_dir, ignore_errors=True)
        return {"error": f"Collection produced no output: {error_note}"}

    return {"zip_path": str(zip_files[0]), "work_dir": work_dir}


def ingest_and_wait(client: BHClient, zip_path: str) -> Dict:
    """Upload a collection zip to BloodHound CE and block until it finishes
    ingesting + analyzing it. Returns {"ok": True} (optionally with a
    "warning" key for a partially-complete job) or {"error": str}. Never
    raises."""
    try:
        job_id = client.start_file_upload()
    except BloodHoundAPIError as e:
        return {"error": f"Could not start a BloodHound upload job: {e}"}

    try:
        with open(zip_path, "rb") as f:
            data = f.read()
        client.upload_file_data(job_id, data, content_type="application/zip")
        client.end_file_upload(job_id)
    except (BloodHoundAPIError, OSError) as e:
        return {"error": f"Uploading collection data failed: {e}"}

    deadline = time.monotonic() + BLOODHOUND_INGEST_TIMEOUT_SECONDS
    last_status = None
    while time.monotonic() < deadline:
        try:
            job = client.get_job_status(job_id)
        except BloodHoundAPIError as e:
            return {"error": f"Could not check upload job status: {e}"}
        last_status = job.get("status")
        if last_status in _TERMINAL_JOB_STATUSES:
            break
        time.sleep(_INGEST_POLL_INTERVAL_SECONDS)
    else:
        return {"error": (
            f"BloodHound did not finish ingesting within "
            f"{BLOODHOUND_INGEST_TIMEOUT_SECONDS // 60} minutes "
            f"(last status: {_JOB_STATUS_NAMES.get(last_status, last_status)})."
        )}

    if last_status == _JOB_STATUS_COMPLETE:
        return {"ok": True}
    if last_status == _JOB_STATUS_PARTIALLY_COMPLETE:
        return {"ok": True, "warning": "Some files in the collection failed to ingest (partially complete)."}
    return {"error": f"BloodHound job ended in status "
                      f"'{_JOB_STATUS_NAMES.get(last_status, last_status)}' rather than completing."}


def _resolve_domain(client: BHClient, target_host: str) -> Tuple[Optional[str], Optional[str]]:
    """Match target.host (the domain FQDN) against BloodHound's known
    domains. Returns (domain_sid, error) — exactly one is None."""
    try:
        domains = client.available_domains()
    except BloodHoundAPIError as e:
        return None, f"Could not list BloodHound's known domains: {e}"

    wanted = target_host.strip().rstrip(".").lower()
    for d in domains:
        name = (d.get("name") or "").strip().rstrip(".").lower()
        if name == wanted:
            sid = d.get("id")
            if not sid or not _SID_RE.match(sid):
                return None, f"BloodHound returned an unexpected domain SID format for '{target_host}': {sid!r}."
            return sid, None

    known = ", ".join(d.get("name", "?") for d in domains) or "none"
    return None, (
        f"BloodHound doesn't have domain '{target_host}' in its known domains yet (saw: {known}). "
        "Ingestion may still be finishing analysis — try again in a minute."
    )


# ── Cypher result parsing ────────────────────────────────────────────────────
# BloodHound's /api/v2/graphs/cypher returns {"data": {"nodes": {id: {...}},
# "edges": [{"source": id, "target": id, "label"/"kind": str, ...}]}}. Node
# envelopes carry `label`/`kind`/`objectId` at the top level and the raw
# collected attributes (hasspn, admincount, samaccountname, ...) under
# `properties` — read defensively (see module docstring) rather than assume
# one casing is the only one that will ever show up.

def _node_props(node: dict) -> dict:
    return node.get("properties") or {}


def _node_objectid(node: dict) -> Optional[str]:
    props = _node_props(node)
    return node.get("objectId") or node.get("objectid") or props.get("objectid") or props.get("objectId")


def _principal_name(node: dict) -> str:
    props = _node_props(node)
    return (node.get("label") or props.get("name") or props.get("samaccountname")
            or _node_objectid(node) or "unknown")


def _hunt_flagged_nodes(client: BHClient, query: str, title_fmt: str, description_fmt: str,
                         base_severity: str, escalate_on_admincount: bool, host: str) -> List[Dict]:
    try:
        resp = client.cypher(query, include_properties=True)
    except BloodHoundAPIError as e:
        return [{
            "result_type": "info", "host": host, "severity": "info",
            "title": f"BloodHound hunting query failed: {title_fmt.split(':')[0]}",
            "description": str(e),
        }]

    nodes = ((resp.get("data") or {}).get("nodes")) or {}
    findings = []
    for node_id, node in nodes.items():
        props = _node_props(node)
        name = _principal_name(node)
        severity = "critical" if (escalate_on_admincount and props.get("admincount")) else base_severity
        findings.append({
            "result_type": "vulnerability",
            "host": host,
            "severity": severity,
            "title": title_fmt.format(name=name),
            "description": description_fmt.format(name=name),
            "verification_status": "confirmed",
            "raw_data": json.dumps({"node_id": node_id, "node": node}),
        })
    return findings


def _build_reverse_adjacency(edges: list) -> dict:
    rev = {}
    for e in edges:
        src, tgt = e.get("source"), e.get("target")
        label = e.get("label") or e.get("kind") or "?"
        if src is None or tgt is None:
            continue
        rev.setdefault(tgt, []).append((src, label))
    return rev


def _bfs_distances_to_sink(rev: dict, sink_id) -> Tuple[dict, dict]:
    """BFS backward from sink_id over the reverse-adjacency map. Since the
    input edges are exactly the union of BloodHound's own shortestPath
    results, a node's BFS distance here from the sink equals its true
    shortest-path length in the full graph — this isn't an approximation."""
    dist = {sink_id: 0}
    pred = {}
    q = deque([sink_id])
    while q:
        cur = q.popleft()
        for src, label in rev.get(cur, []):
            if src not in dist:
                dist[src] = dist[cur] + 1
                pred[src] = (cur, label)
                q.append(src)
    return dist, pred


def _shortest_chain_to_sink(nodes: dict, dist: dict, pred: dict, sink_id) -> Tuple[Optional[int], Optional[str]]:
    candidates = [(d, nid) for nid, d in dist.items() if nid != sink_id]
    if not candidates:
        return None, None
    min_dist, start_id = min(candidates, key=lambda x: (x[0], str(x[1])))

    chain_ids = [start_id]
    edge_labels = []
    cur = start_id
    while cur != sink_id:
        nxt, label = pred[cur]
        edge_labels.append(label)
        chain_ids.append(nxt)
        cur = nxt

    names = [_principal_name(nodes.get(nid, {})) for nid in chain_ids]
    hop_str = names[0]
    for label, name in zip(edge_labels, names[1:]):
        hop_str += f" --[{label}]--> {name}"
    return min_dist, hop_str


def _severity_for_hops(hops: int) -> str:
    if hops <= 2:
        return "critical"
    if hops <= 4:
        return "high"
    return "medium"


def _hunt_shortest_paths(client: BHClient, domain_sid: str, rid: str, group_name: str, host: str) -> List[Dict]:
    sink_sid = f"{domain_sid}-{rid}"
    query = (
        f"MATCH p=shortestPath((n)-[:{_ABUSE_EDGES}*1..{_MAX_PATH_HOPS}]->(g:Group)) "
        f"WHERE g.objectid = '{sink_sid}' AND n.objectid <> g.objectid "
        f"RETURN p LIMIT {_MAX_PATHS_PER_QUERY}"
    )
    try:
        resp = client.cypher(query, include_properties=True)
    except BloodHoundAPIError as e:
        return [{
            "result_type": "info", "host": host, "severity": "info",
            "title": f"BloodHound hunting query failed: paths to {group_name}",
            "description": str(e),
        }]

    data = resp.get("data") or {}
    nodes = data.get("nodes") or {}
    edges = data.get("edges") or []
    if not nodes or not edges:
        return []  # no attack path exists to this group — not an error, just nothing to report

    sink_id = next((nid for nid, n in nodes.items() if _node_objectid(n) == sink_sid), None)
    if sink_id is None:
        return []

    rev = _build_reverse_adjacency(edges)
    dist, pred = _bfs_distances_to_sink(rev, sink_id)
    min_dist, hop_str = _shortest_chain_to_sink(nodes, dist, pred, sink_id)
    if min_dist is None:
        return []

    principal_count = len(dist) - 1  # everyone reachable to the sink, excluding the sink itself
    return [{
        "result_type": "vulnerability",
        "host": host,
        "severity": _severity_for_hops(min_dist),
        "title": f"Attack path to {group_name} ({min_dist} hop{'s' if min_dist != 1 else ''})",
        "description": (
            f"{principal_count} principal(s) have a discovered path to {group_name}. "
            f"Shortest: {hop_str}"
        ),
        "verification_status": "confirmed",
        "raw_data": json.dumps({
            "target_group": group_name, "target_sid": sink_sid,
            "shortest_hops": min_dist, "principal_count": principal_count,
            "nodes": nodes, "edges": edges,
        }),
    }]


def run_hunting_queries(client: BHClient, domain_sid: str, host: str) -> List[Dict]:
    """Run the fixed hunting-query set against one already-ingested domain.
    Never raises — a single query's failure is reported as an info result
    without aborting the rest (see module docstring)."""
    if not _SID_RE.match(domain_sid or ""):
        return [{
            "result_type": "info", "host": host, "severity": "info",
            "title": "BloodHound returned an unexpected domain SID format",
            "description": f"Got: {domain_sid!r} — skipping hunting queries as a precaution.",
        }]

    findings: List[Dict] = []

    findings += _hunt_flagged_nodes(
        client,
        "MATCH (n:User) WHERE n.hasspn = true AND n.enabled = true RETURN n LIMIT 500",
        "Kerberoastable account: {name}",
        "{name} has a Service Principal Name set and is enabled, making its Kerberos "
        "service ticket crackable offline (Kerberoasting) if its password is weak.",
        base_severity="high", escalate_on_admincount=True, host=host,
    )

    findings += _hunt_flagged_nodes(
        client,
        "MATCH (n:User) WHERE n.dontreqpreauth = true AND n.enabled = true RETURN n LIMIT 500",
        "AS-REP roastable account: {name}",
        "{name} has Kerberos pre-authentication disabled and is enabled, letting an "
        "attacker request and crack its AS-REP offline without any credentials.",
        base_severity="high", escalate_on_admincount=True, host=host,
    )

    findings += _hunt_flagged_nodes(
        client,
        f"MATCH (c:Computer) WHERE c.unconstraineddelegation = true "
        f"AND NOT (c)-[:MemberOf*1..]->(:Group {{objectid: '{domain_sid}-{_RID_DOMAIN_CONTROLLERS}'}}) "
        f"RETURN c LIMIT 500",
        "Unconstrained delegation: {name}",
        "{name} is trusted for unconstrained delegation and is not a domain controller — "
        "compromising it lets an attacker impersonate any user who authenticates to it "
        "(including Domain Admins) by capturing their TGT.",
        base_severity="critical", escalate_on_admincount=False, host=host,
    )

    excluded_sids = [
        f"{domain_sid}-{_RID_DOMAIN_ADMINS}",
        f"{domain_sid}-{_RID_ENTERPRISE_ADMINS}",
        f"{domain_sid}-{_RID_DOMAIN_CONTROLLERS}",
        _WELL_KNOWN_SID_ENTERPRISE_DCS,
    ]
    exclude_clause = " AND ".join(f"n.objectid <> '{sid}'" for sid in excluded_sids)
    findings += _hunt_flagged_nodes(
        client,
        f"MATCH (n)-[:DCSync]->(d:Domain) WHERE d.objectid = '{domain_sid}' AND {exclude_clause} "
        f"RETURN n LIMIT 500",
        "DCSync rights: {name}",
        "{name} holds replication rights (GetChanges + GetChangesAll) on the domain, "
        "outside the expected built-in administrative groups — this lets it dump every "
        "credential in Active Directory via DCSync, equivalent to Domain Admin.",
        base_severity="critical", escalate_on_admincount=False, host=host,
    )

    for rid, group_name in ((_RID_DOMAIN_ADMINS, "Domain Admins"), (_RID_ENTERPRISE_ADMINS, "Enterprise Admins")):
        findings += _hunt_shortest_paths(client, domain_sid, rid, group_name, host)

    return findings


def run_bloodhound_scan(scan, target) -> List[Dict]:
    """Top-level entry point called from engine.py. Never raises — failures
    come back as a single info-severity result, matching every other
    scanner integration in this codebase.

    Runs collection, uploads + ingests the result into BloodHound CE, resolves
    the target domain's SID, and runs the hunting-query set — returning real
    confirmed vulnerability findings when everything succeeds, or an
    explanatory info result at whichever stage failed."""
    host = target.host if target else "unknown"

    if target is None or target.target_type != "ad_domain":
        return [{
            "result_type": "info", "host": host, "severity": "info",
            "title": "BloodHound scan requires an AD Domain target",
            "description": "This scan's target isn't an AD Domain target — "
                            "BloodHound only analyzes Active Directory domains.",
        }]

    collection = run_collection(target)
    if "error" in collection:
        return [{
            "result_type": "info", "host": host, "severity": "info",
            "title": "BloodHound collection failed",
            "description": collection["error"],
        }]

    try:
        zip_size = os.path.getsize(collection["zip_path"])

        from ..models import BloodHoundConfig
        cfg = BloodHoundConfig.query.first()
        if not cfg or not cfg.enabled or not cfg.token_id or not cfg.token_key:
            return [{
                "result_type": "info", "host": host, "severity": "info",
                "title": f"AD data collected ({zip_size} bytes) — BloodHound CE not configured",
                "description": "Configure and enable BloodHound CE in Settings to analyze this "
                                "data. Nothing was uploaded.",
            }]

        client = BHClient(cfg.api_url, cfg.token_id, cfg.token_key, verify_ssl=cfg.verify_ssl)

        ingest_result = ingest_and_wait(client, collection["zip_path"])
        if "error" in ingest_result:
            return [{
                "result_type": "info", "host": host, "severity": "info",
                "title": "BloodHound ingestion failed",
                "description": f"Collected {zip_size} bytes but could not ingest them into "
                                f"BloodHound CE: {ingest_result['error']}",
            }]

        domain_sid, err = _resolve_domain(client, target.host)
        if err:
            return [{
                "result_type": "info", "host": host, "severity": "info",
                "title": "BloodHound ingestion succeeded but the domain wasn't found",
                "description": err,
            }]

        findings = run_hunting_queries(client, domain_sid, host)

        # Set on the already-session-attached Target; engine.py's own final
        # db.session.commit() (after all ScanResult rows are saved) persists
        # this too — no separate commit needed here.
        target.last_bloodhound_ingest_at = datetime.now(timezone.utc)

        vuln_count = sum(1 for f in findings if f.get("result_type") == "vulnerability")
        summary_desc = (f"Collected {zip_size} bytes from {target.host}, ingested into BloodHound CE, "
                         f"and ran the attack-path hunting queries. {vuln_count} finding(s).")
        if ingest_result.get("warning"):
            summary_desc += f" ({ingest_result['warning']})"

        summary = [{
            "result_type": "info", "host": host, "severity": "info",
            "title": "BloodHound analysis complete",
            "description": summary_desc,
        }]
        return summary + findings
    finally:
        shutil.rmtree(collection["work_dir"], ignore_errors=True)
