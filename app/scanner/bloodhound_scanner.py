"""
BloodHound CE integration — Active Directory attack-path analysis. Wired in
as the "bloodhound" scan type, launched from its own dedicated section (not
the generic New Scan form — same precedent as REAPER/OSV, see
reaper_scanner.py's docstring), against `ad_domain`-type Targets.

Collection uses `bloodhound-ce-python` (apt-installable on Kali, Impacket-
based — no Windows host needed, unlike SharpHound), invoked directly on
PATH rather than vendored under tools/ like PEN/REAPER's built-from-source
binaries, since it's an OS package here (see docs/deployment.md).

Phase 1 scope: this module runs the collector and reports what it produced.
The ingest-into-BloodHound-CE and hunting-Cypher-query pipeline (uploading
the collection output via app/bloodhound/api_client.py and turning attack-
path findings into confirmed ScanResults) is Phase 2 — see the project plan.
Until then, a successful collection is reported as an informational result
rather than a vulnerability, since nothing has actually been analyzed yet.
"""
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

# AD collection over LDAP/SMB/RPC against a large domain (many users/computers/
# groups/ACLs, with -c All walking every collection method) can run long —
# generous but bounded, matching the reasoning behind PEN/REAPER/backdoor's
# own timeouts.
BLOODHOUND_TIMEOUT_SECONDS = 1800  # 30 minutes

_COLLECTOR_BINARY_NAME = "bloodhound-ce-python"


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


def run_bloodhound_scan(scan, target) -> List[Dict]:
    """Top-level entry point called from engine.py. Never raises — failures
    come back as a single info-severity result, matching every other
    scanner integration in this codebase.

    Phase 1: runs collection only and reports the outcome as an
    informational result. Phase 2 replaces the success branch with:
    upload the zip via app/bloodhound/api_client.py, run the hunting Cypher
    queries, and return real vulnerability findings instead."""
    host = target.host if target else "unknown"

    if target is None or target.target_type != "ad_domain":
        return [{
            "result_type": "info", "host": host, "severity": "info",
            "title": "BloodHound scan requires an AD Domain target",
            "description": "This scan's target isn't an AD Domain target — "
                            "BloodHound only analyzes Active Directory domains.",
        }]

    result = run_collection(target)
    if "error" in result:
        return [{
            "result_type": "info", "host": host, "severity": "info",
            "title": "BloodHound collection failed",
            "description": result["error"],
        }]

    try:
        zip_size = os.path.getsize(result["zip_path"])
    finally:
        shutil.rmtree(result["work_dir"], ignore_errors=True)

    return [{
        "result_type": "info", "host": host, "severity": "info",
        "title": "AD data collected — analysis pipeline not yet configured",
        "description": (
            f"Collected {zip_size} bytes of Active Directory data from {target.host} "
            "via bloodhound-ce-python. Uploading this to BloodHound CE and running "
            "attack-path analysis isn't wired up yet in this build."
        ),
    }]
