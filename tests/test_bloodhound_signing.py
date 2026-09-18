"""Tests for app/bloodhound/api_client.py's HMAC request signing.

BloodHound CE's auth scheme is a 3-step chained HMAC-SHA256 (Token ID +
Token Key, not a bearer token) — see the module docstring in api_client.py
for the reference implementation this mirrors. These tests independently
re-derive the expected signature from the documented spec (not by importing
or copying api_client's own _sign()) so a transposed step or wrong
timestamp truncation would actually be caught, rather than a test that just
re-asserts whatever the implementation happens to compute.
"""
import base64
import hashlib
import hmac
from datetime import datetime, timezone
from unittest.mock import patch

from app.bloodhound.api_client import BHClient


def _expected_signature(token_key: str, method: str, uri: str, request_date: str, body: bytes) -> str:
    """Independent re-implementation of the 3-step chain, written directly
    against the documented spec rather than derived from api_client.py."""
    step1 = hmac.new(token_key.encode(), (method + uri).encode(), hashlib.sha256).digest()
    step2 = hmac.new(step1, request_date[:13].encode(), hashlib.sha256).digest()
    step3 = hmac.new(step2, body, hashlib.sha256).digest()
    return base64.b64encode(step3).decode()


class TestSignatureComputation:
    def test_sign_matches_independent_reimplementation_with_body(self):
        client = BHClient("https://localhost:8080", "token-id-123", "supersecretkey")
        fixed_date = "2026-01-01T23:35:25.318306-08:00"

        with patch("app.bloodhound.api_client.datetime") as mock_dt:
            mock_dt.now.return_value.astimezone.return_value.isoformat.return_value = fixed_date
            request_date, signature = client._sign("POST", "/api/v2/graphs/cypher", b'{"query":"MATCH (n) RETURN n"}')

        expected = _expected_signature(
            "supersecretkey", "POST", "/api/v2/graphs/cypher", fixed_date, b'{"query":"MATCH (n) RETURN n"}',
        )
        assert request_date == fixed_date
        assert signature == expected

    def test_sign_matches_independent_reimplementation_empty_body(self):
        client = BHClient("https://localhost:8080", "token-id-123", "supersecretkey")
        fixed_date = "2026-06-15T09:00:00.000000+00:00"

        with patch("app.bloodhound.api_client.datetime") as mock_dt:
            mock_dt.now.return_value.astimezone.return_value.isoformat.return_value = fixed_date
            request_date, signature = client._sign("GET", "/api/v2/available-domains", b"")

        expected = _expected_signature(
            "supersecretkey", "GET", "/api/v2/available-domains", fixed_date, b"",
        )
        assert signature == expected

    def test_signature_changes_if_token_key_differs(self):
        fixed_date = "2026-01-01T23:35:25.318306-08:00"
        with patch("app.bloodhound.api_client.datetime") as mock_dt:
            mock_dt.now.return_value.astimezone.return_value.isoformat.return_value = fixed_date
            sig_a = BHClient("url", "id", "key-a")._sign("GET", "/x", b"")[1]
            sig_b = BHClient("url", "id", "key-b")._sign("GET", "/x", b"")[1]
        assert sig_a != sig_b

    def test_signature_changes_if_method_or_uri_differs(self):
        fixed_date = "2026-01-01T23:35:25.318306-08:00"
        client = BHClient("url", "id", "samekey")
        with patch("app.bloodhound.api_client.datetime") as mock_dt:
            mock_dt.now.return_value.astimezone.return_value.isoformat.return_value = fixed_date
            sig_get = client._sign("GET", "/api/v2/available-domains", b"")[1]
            sig_post = client._sign("POST", "/api/v2/available-domains", b"")[1]
            sig_other_uri = client._sign("GET", "/api/v2/graphs/cypher", b"")[1]
        assert sig_get != sig_post
        assert sig_get != sig_other_uri

    def test_signature_changes_if_body_differs(self):
        fixed_date = "2026-01-01T23:35:25.318306-08:00"
        client = BHClient("url", "id", "samekey")
        with patch("app.bloodhound.api_client.datetime") as mock_dt:
            mock_dt.now.return_value.astimezone.return_value.isoformat.return_value = fixed_date
            sig_a = client._sign("POST", "/x", b'{"a":1}')[1]
            sig_b = client._sign("POST", "/x", b'{"a":2}')[1]
        assert sig_a != sig_b


class TestHourTruncation:
    """The DateKey step deliberately truncates to hour precision — verify
    the truncation actually truncates (same hour -> same DateKey-derived
    signature) rather than accidentally using full second/microsecond
    precision, which would make every request from a real client fail
    against a server that recomputes on its own clock a moment later."""

    def test_same_hour_different_seconds_yields_same_signature(self):
        client = BHClient("url", "id", "samekey")
        with patch("app.bloodhound.api_client.datetime") as mock_dt:
            mock_dt.now.return_value.astimezone.return_value.isoformat.return_value = "2026-01-01T23:00:00.000000-08:00"
            _, sig1 = client._sign("GET", "/x", b"")
        with patch("app.bloodhound.api_client.datetime") as mock_dt:
            mock_dt.now.return_value.astimezone.return_value.isoformat.return_value = "2026-01-01T23:59:59.999999-08:00"
            _, sig2 = client._sign("GET", "/x", b"")
        assert sig1 == sig2

    def test_different_hour_yields_different_signature(self):
        client = BHClient("url", "id", "samekey")
        with patch("app.bloodhound.api_client.datetime") as mock_dt:
            mock_dt.now.return_value.astimezone.return_value.isoformat.return_value = "2026-01-01T22:59:59.000000-08:00"
            _, sig1 = client._sign("GET", "/x", b"")
        with patch("app.bloodhound.api_client.datetime") as mock_dt:
            mock_dt.now.return_value.astimezone.return_value.isoformat.return_value = "2026-01-01T23:00:00.000000-08:00"
            _, sig2 = client._sign("GET", "/x", b"")
        assert sig1 != sig2


class TestRequestHeaders:
    def test_headers_have_expected_shape(self):
        client = BHClient("https://localhost:8080", "my-token-id", "my-token-key")
        fixed_date = "2026-01-01T23:35:25.318306-08:00"

        captured = {}

        def fake_request(method, url, data=None, headers=None, timeout=None, verify=None):
            captured["method"] = method
            captured["url"] = url
            captured["headers"] = headers
            captured["data"] = data
            import requests
            resp = requests.Response()
            resp.status_code = 200
            resp._content = b'{"data": []}'
            return resp

        with patch("app.bloodhound.api_client.datetime") as mock_dt:
            mock_dt.now.return_value.astimezone.return_value.isoformat.return_value = fixed_date
            with patch("app.bloodhound.api_client.requests.request", side_effect=fake_request):
                client.available_domains()

        headers = captured["headers"]
        assert headers["Authorization"] == "bhesignature my-token-id"
        assert headers["RequestDate"] == fixed_date
        assert "Signature" in headers
        assert headers["Content-Type"] == "application/json"
        assert captured["url"] == "https://localhost:8080/api/v2/available-domains"
        assert captured["method"] == "GET"
