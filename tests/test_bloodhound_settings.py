"""Tests for the Settings > BloodHound CE card: saving config and the
/settings/test-bloodhound connectivity check, mirroring the existing
O365 settings test conventions (see settings.py's test_o365 route)."""
from unittest.mock import patch

import pytest
import re

from app.bloodhound.api_client import BHClient, BloodHoundAPIError


def _csrf_token(client, path="/settings/"):
    r = client.get(path)
    return re.search(r'name="csrf_token" value="([^"]+)"', r.data.decode()).group(1)


class TestBHClientTestConnection:
    def test_ok_shape_matches_graph_client_convention(self):
        """Must match app/email_security/graph_client.py's test_connection()
        shape exactly ({"ok": True, "detail": ...} / {"error": ...}) since
        the settings page's JS handles every integration's test-connection
        result identically."""
        client = BHClient("https://localhost:8080", "id", "key")
        with patch.object(client, "available_domains", return_value=[{"name": "corp.local"}]):
            result = client.test_connection()
        assert result == {"ok": True, "detail": "Connected — 1 domain(s) known to BloodHound."}

    def test_error_shape(self):
        client = BHClient("https://localhost:8080", "id", "key")
        with patch.object(client, "available_domains", side_effect=BloodHoundAPIError("boom")):
            result = client.test_connection()
        assert result == {"error": "boom"}


class TestSettingsRoute:
    def test_bloodhound_card_renders(self, app, admin_client):
        resp = admin_client.get("/settings/")
        assert b"BloodHound CE" in resp.data
        assert b"Token ID" in resp.data

    def test_saving_config_persists_and_encrypts_token_key(self, app, admin_client):
        token = _csrf_token(admin_client)
        resp = admin_client.post("/settings/", data={
            "form": "bloodhound", "bloodhound_enabled": "on",
            "api_url": "https://bh.internal:8080", "token_id": "token-id-1",
            "token_key": "supersecretkey", "csrf_token": token,
        }, follow_redirects=True)
        assert b"BloodHound CE settings saved" in resp.data

        with app.app_context():
            from sqlalchemy import text
            from app.extensions import db
            from app.models import BloodHoundConfig

            cfg = BloodHoundConfig.query.first()
            assert cfg.api_url == "https://bh.internal:8080"
            assert cfg.token_id == "token-id-1"
            assert cfg.token_key == "supersecretkey"  # ORM transparently decrypts

            raw = db.session.execute(
                text("SELECT token_key FROM bloodhound_config WHERE id = :id"), {"id": cfg.id}
            ).scalar()
            assert raw.startswith("enc:v1:")

    def test_resaving_without_token_key_keeps_existing_value(self, app, admin_client):
        token = _csrf_token(admin_client)
        admin_client.post("/settings/", data={
            "form": "bloodhound", "api_url": "https://bh.internal:8080",
            "token_id": "token-id-1", "token_key": "originalsecret", "csrf_token": token,
        }, follow_redirects=True)

        token = _csrf_token(admin_client)
        admin_client.post("/settings/", data={
            "form": "bloodhound", "api_url": "https://bh.internal:8080",
            "token_id": "token-id-1", "token_key": "", "csrf_token": token,
        }, follow_redirects=True)

        with app.app_context():
            from app.models import BloodHoundConfig
            assert BloodHoundConfig.query.first().token_key == "originalsecret"

    def test_test_connection_requires_token(self, app, admin_client):
        resp = admin_client.post("/settings/test-bloodhound", json={})
        assert resp.get_json() == {"error": "Token ID and Token Key are both required."}

    def test_test_connection_uses_saved_config_when_form_fields_blank(self, app, admin_client):
        token = _csrf_token(admin_client)
        admin_client.post("/settings/", data={
            "form": "bloodhound", "api_url": "https://bh.internal:8080",
            "token_id": "saved-id", "token_key": "savedkey", "csrf_token": token,
        }, follow_redirects=True)

        with patch("app.bloodhound.api_client.BHClient.test_connection",
                   return_value={"ok": True, "detail": "Connected — 0 domain(s) known to BloodHound."}) as mock_test:
            resp = admin_client.post("/settings/test-bloodhound", json={})

        assert resp.get_json()["ok"] is True
        mock_test.assert_called_once()

    def test_test_connection_prefers_unsaved_form_values(self, app, admin_client):
        """Same fallback-to-DB pattern as /test-o365 and /test-keys: values
        typed into the form but not yet saved take precedence. The route
        imports BHClient locally (from ..bloodhound.api_client import
        BHClient) inside the view function, so the patch target is the
        client's defining module, not app.routes.settings."""
        captured = {}

        class FakeClient:
            def __init__(self, api_url, token_id, token_key, verify_ssl=False):
                captured["api_url"] = api_url
                captured["token_id"] = token_id
                captured["token_key"] = token_key

            def test_connection(self):
                return {"ok": True, "detail": "ok"}

        with patch("app.bloodhound.api_client.BHClient", FakeClient):
            resp = admin_client.post("/settings/test-bloodhound", json={
                "api_url": "https://unsaved.example:8080",
                "token_id": "unsaved-id", "token_key": "unsavedkey",
            })

        assert captured["api_url"] == "https://unsaved.example:8080"
        assert captured["token_id"] == "unsaved-id"
        assert captured["token_key"] == "unsavedkey"
