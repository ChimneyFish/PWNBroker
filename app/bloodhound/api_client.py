"""
HMAC-signed API client for BloodHound CE.

BloodHound CE authenticates API requests with a Token ID + Token Key pair
(not a bearer token) via a 3-step chained HMAC-SHA256 signature. Reference
implementation: SpecterOps/bloodhound-docs/docs/assets/apiclient.py — this
client's _sign() mirrors it exactly (same timestamp handling, same chain
order) so it's worth diffing against that file if signature verification
ever starts failing after a BloodHound CE upgrade.

Kept separate from app/scanner/bloodhound_scanner.py because it's needed by
both the scanner (running hunting Cypher queries) and the Settings
"Test Connection" route (app/routes/settings.py) — the same separation
already used for app/email_security/graph_client.py (shared by the O365
mailbox sync job and its own settings test route).

Phase 2 adds the ingest (file-upload) methods below `cypher()`. Their paths
and response shapes were confirmed against BloodHound CE's actual published
OpenAPI spec (SpecterOps/bloodhound-docs, docs/openapi.json) rather than
guessed — see the job-status enum comment on get_job_status() for the
source of the status codes. The one thing that spec doesn't pin down is the
exact key casing inside a Cypher query's node/edge objects (node/edge
envelope vs. their `properties` sub-dict) — app/scanner/bloodhound_scanner.py
reads those defensively and that should still be spot-checked against a
live instance's actual JSON before treating hunting-query output as
gospel.
"""
import base64
import hashlib
import hmac
import json as _json
import logging
from datetime import datetime

import requests

log = logging.getLogger(__name__)


class BloodHoundAPIError(Exception):
    """Raised for a request that failed at the HTTP/network/auth level —
    not for a Cypher query that legitimately returns zero rows."""


class BHClient:
    """HMAC-signed client for one BloodHound CE instance."""

    def __init__(self, base_url: str, token_id: str, token_key: str,
                 verify_ssl: bool = False, timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.token_id = token_id
        self.token_key = token_key
        self.verify_ssl = verify_ssl
        self.timeout = timeout

    def _sign(self, method: str, uri: str, body: bytes):
        """3-step chained HMAC-SHA256, per BloodHound's documented scheme:
        1. OperationKey = HMAC(token_key, method + uri)
        2. DateKey      = HMAC(OperationKey, timestamp truncated to the hour)
        3. Signature    = HMAC(DateKey, body)
        Returns (request_date_str, base64_signature_str). The truncated
        hour is deliberately imprecise (it's a coarse anti-replay window,
        not a request-freshness guarantee) — matching the reference client
        exactly matters more here than "improving" the precision, since the
        server independently recomputes the same truncation to verify.
        """
        request_date = datetime.now().astimezone().isoformat("T")

        digester = hmac.new(self.token_key.encode(), None, hashlib.sha256)
        digester.update(f"{method}{uri}".encode())

        digester = hmac.new(digester.digest(), None, hashlib.sha256)
        digester.update(request_date[:13].encode())  # hour precision, e.g. "2026-01-01T23"

        digester = hmac.new(digester.digest(), None, hashlib.sha256)
        if body:
            digester.update(body)

        return request_date, base64.b64encode(digester.digest()).decode()

    def _request(self, method: str, uri: str, json_body=None, raw_body: bytes = None,
                 content_type: str = "application/json") -> requests.Response:
        body = _json.dumps(json_body).encode("utf-8") if json_body is not None else (raw_body or b"")

        request_date, signature = self._sign(method, uri, body)
        headers = {
            "User-Agent": "pwnbroker-bloodhound-client",
            "Authorization": f"bhesignature {self.token_id}",
            "RequestDate": request_date,
            "Signature": signature,
            "Content-Type": content_type,
        }

        try:
            return requests.request(
                method, f"{self.base_url}{uri}", data=body, headers=headers,
                timeout=self.timeout, verify=self.verify_ssl,
            )
        except requests.RequestException as e:
            raise BloodHoundAPIError(f"Request to BloodHound CE failed: {e}") from e

    # ── Read/analysis endpoints ──────────────────────────────────────────────

    def available_domains(self) -> list:
        resp = self._request("GET", "/api/v2/available-domains")
        if not resp.ok:
            raise BloodHoundAPIError(
                f"GET /api/v2/available-domains returned HTTP {resp.status_code}: {resp.text[:300]}")
        return resp.json().get("data", [])

    def cypher(self, query: str, include_properties: bool = True) -> dict:
        resp = self._request("POST", "/api/v2/graphs/cypher",
                             json_body={"query": query, "include_properties": include_properties})
        if not resp.ok:
            raise BloodHoundAPIError(
                f"POST /api/v2/graphs/cypher returned HTTP {resp.status_code}: {resp.text[:300]}")
        return resp.json()

    def test_connection(self) -> dict:
        """Used by Settings > BloodHound CE > Test Connection. Returns
        {"ok": True, "detail": ...} / {"error": ...} rather than raising —
        the same shape app/email_security/graph_client.py's test_connection()
        already uses, so the settings route/JS can treat every integration's
        test-connection result identically."""
        try:
            domains = self.available_domains()
            return {"ok": True, "detail": f"Connected — {len(domains)} domain(s) known to BloodHound."}
        except BloodHoundAPIError as e:
            return {"error": str(e)}

    # ── Ingest endpoints ──────────────────────────────────────────────────────
    # Paths confirmed against docs/openapi.json in SpecterOps/bloodhound-docs
    # (CreateFileUploadJob, UploadFileToJob, EndFileUploadJob, ListFileUploadJobs,
    # GetCompletedTasks operationIds) — not guessed.

    _UPLOAD_START_PATH        = "/api/v2/file-upload/start"
    _UPLOAD_DATA_PATH_FMT     = "/api/v2/file-upload/{job_id}"
    _UPLOAD_END_PATH_FMT      = "/api/v2/file-upload/{job_id}/end"
    _JOB_LIST_PATH            = "/api/v2/file-upload"
    _COMPLETED_TASKS_PATH_FMT = "/api/v2/file-upload/{job_id}/completed-tasks"

    def start_file_upload(self) -> int:
        resp = self._request("POST", self._UPLOAD_START_PATH)
        if not resp.ok:
            raise BloodHoundAPIError(
                f"Could not start a BloodHound file-upload job: HTTP {resp.status_code}: {resp.text[:300]}")
        return resp.json()["data"]["id"]

    def upload_file_data(self, job_id: int, data: bytes, content_type: str = "application/zip"):
        # Content-Type must be one of the enum values BloodHound's OpenAPI spec
        # declares for this endpoint (application/json, application/zip,
        # application/zip-compressed, application/x-zip-compressed) — anything
        # else is rejected before the body is even looked at.
        uri = self._UPLOAD_DATA_PATH_FMT.format(job_id=job_id)
        resp = self._request("POST", uri, raw_body=data, content_type=content_type)
        if not resp.ok:
            raise BloodHoundAPIError(
                f"Uploading collection data failed: HTTP {resp.status_code}: {resp.text[:300]}")

    def end_file_upload(self, job_id: int):
        uri = self._UPLOAD_END_PATH_FMT.format(job_id=job_id)
        resp = self._request("POST", uri)
        if not resp.ok:
            raise BloodHoundAPIError(
                f"Finalizing the upload job failed: HTTP {resp.status_code}: {resp.text[:300]}")

    def get_job_status(self, job_id: int) -> dict:
        """Returns the file-upload-job record ({"id", "status", "status_message",
        "total_files", "failed_files", ...}). `status` is an integer enum
        (from BloodHound's own OpenAPI spec, enum.job-status):
        -1 Invalid, 0 Ready, 1 Running, 2 Complete, 3 Canceled, 4 Timed Out,
        5 Failed, 6 Ingesting, 7 Analyzing, 8 Partially Complete.

        There's no GET-by-id endpoint for a single job — list jobs filtered
        by id instead (ListFileUploadJobs' `id` query param, `eq:<id>`
        predicate syntax), same as every other filterable list endpoint in
        this API.
        """
        resp = self._request("GET", f"{self._JOB_LIST_PATH}?id=eq:{job_id}")
        if not resp.ok:
            raise BloodHoundAPIError(
                f"Checking upload job status failed: HTTP {resp.status_code}: {resp.text[:300]}")
        rows = resp.json().get("data", [])
        if not rows:
            raise BloodHoundAPIError(f"BloodHound has no record of file-upload job {job_id}.")
        return rows[0]

    def list_completed_tasks(self, job_id: int) -> list:
        """Per-file detail (name + any errors) for a job — useful to explain
        *why* a job ended up "Partially Complete" or "Failed", not for
        polling overall job status (use get_job_status() for that)."""
        uri = self._COMPLETED_TASKS_PATH_FMT.format(job_id=job_id)
        resp = self._request("GET", uri)
        if not resp.ok:
            raise BloodHoundAPIError(
                f"Checking completed tasks failed: HTTP {resp.status_code}: {resp.text[:300]}")
        return resp.json().get("data", [])
