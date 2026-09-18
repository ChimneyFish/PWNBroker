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

Phase 1 scope: cypher(), available_domains(), and test_connection() are
implemented and exercised (Settings' test-connection route uses
available_domains()). The file-upload/ingest methods are present but their
exact endpoint paths are marked TODO-VERIFY below — two documentation
sources disagree on the precise upload-start path, and BloodHound CE's own
live OpenAPI spec (Settings > API Explorer, once the container is running)
is the actual source of truth. Confirm before Phase 2 wires these into the
scan pipeline.
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

    # ── Ingest endpoints (Phase 2 — paths need live verification) ────────────
    # TODO-VERIFY: confirm these paths against the running instance's own
    # OpenAPI spec (Settings > API Explorer) before wiring them into the scan
    # pipeline — two documentation sources disagree on the upload-start path
    # ("/api/v2/file-upload/start" vs "/api/v2/collection-uploads/file-upload").
    # Kept as named constants specifically so a correction is a one-line change.

    _UPLOAD_START_PATH       = "/api/v2/file-upload/start"
    _UPLOAD_DATA_PATH_FMT    = "/api/v2/file-upload/{job_id}"
    _UPLOAD_END_PATH_FMT     = "/api/v2/file-upload/{job_id}/end"
    _UPLOAD_STATUS_PATH_FMT  = "/api/v2/file-upload/{job_id}/completed-tasks"

    def start_file_upload(self) -> int:
        resp = self._request("POST", self._UPLOAD_START_PATH)
        if not resp.ok:
            raise BloodHoundAPIError(
                f"Could not start a BloodHound file-upload job: HTTP {resp.status_code}: {resp.text[:300]}")
        return resp.json()["data"]["id"]

    def upload_file_data(self, job_id: int, data: bytes, content_type: str = "application/zip"):
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

    def upload_status(self, job_id: int) -> dict:
        uri = self._UPLOAD_STATUS_PATH_FMT.format(job_id=job_id)
        resp = self._request("GET", uri)
        if not resp.ok:
            raise BloodHoundAPIError(
                f"Checking upload status failed: HTTP {resp.status_code}: {resp.text[:300]}")
        return resp.json()
