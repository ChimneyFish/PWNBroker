"""Tests for the Microsoft Graph client (app/email_security/graph_client.py).
All requests.* calls are mocked — no real network access."""
from unittest.mock import MagicMock, patch

from app.email_security import graph_client as gc


def _resp(status_code=200, json_data=None, text=""):
    r = MagicMock()
    r.status_code = status_code
    r.json.return_value = json_data or {}
    r.text = text
    return r


# ── get_app_token ────────────────────────────────────────────────────────────

def test_get_app_token_success():
    with patch("requests.post", return_value=_resp(200, {"access_token": "tok123"})) as m:
        token, err = gc.get_app_token("tenant", "client", "secret")
    assert token == "tok123"
    assert err is None
    assert "tenant/oauth2/v2.0/token" in m.call_args[0][0]


def test_get_app_token_failure_returns_error():
    with patch("requests.post", return_value=_resp(401, {"error_description": "invalid client secret"})):
        token, err = gc.get_app_token("tenant", "client", "wrong-secret")
    assert token is None
    assert "invalid client secret" in err


def test_get_app_token_network_exception():
    with patch("requests.post", side_effect=Exception("connection refused")):
        token, err = gc.get_app_token("tenant", "client", "secret")
    assert token is None
    assert "connection refused" in err


# ── test_connection ──────────────────────────────────────────────────────────

def test_connection_ok():
    with patch.object(gc, "get_app_token", return_value=("tok", None)), \
         patch("requests.get", return_value=_resp(200, {"value": [{"displayName": "Acme Corp"}]})):
        result = gc.test_connection("t", "c", "s")
    assert result["ok"] is True
    assert "Acme Corp" in result["detail"]


def test_connection_token_failure_short_circuits():
    with patch.object(gc, "get_app_token", return_value=(None, "bad creds")):
        result = gc.test_connection("t", "c", "s")
    assert result == {"error": "bad creds"}


def test_connection_403_gives_permission_hint():
    with patch.object(gc, "get_app_token", return_value=("tok", None)), \
         patch("requests.get", return_value=_resp(403, text="Forbidden")):
        result = gc.test_connection("t", "c", "s")
    assert "permissions" in result["error"]


# ── list_mailboxes ───────────────────────────────────────────────────────────

def test_list_mailboxes_single_page():
    page = {"value": [
        {"id": "u1", "userPrincipalName": "jane@corp.com", "displayName": "Jane Doe", "mail": "jane@corp.com"},
    ]}
    with patch("requests.get", return_value=_resp(200, page)):
        mailboxes, err = gc.list_mailboxes("tok")
    assert err is None
    assert mailboxes == [{"user_id": "u1", "upn": "jane@corp.com", "display_name": "Jane Doe"}]


def test_list_mailboxes_follows_pagination():
    page1 = {"value": [{"id": "u1", "userPrincipalName": "a@corp.com", "displayName": "A"}],
             "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?page=2"}
    page2 = {"value": [{"id": "u2", "userPrincipalName": "b@corp.com", "displayName": "B"}]}
    with patch("requests.get", side_effect=[_resp(200, page1), _resp(200, page2)]) as m:
        mailboxes, err = gc.list_mailboxes("tok")
    assert err is None
    assert [mb["user_id"] for mb in mailboxes] == ["u1", "u2"]
    assert m.call_count == 2


def test_list_mailboxes_http_error():
    with patch("requests.get", return_value=_resp(500, text="server error")):
        mailboxes, err = gc.list_mailboxes("tok")
    assert mailboxes == []
    assert "500" in err


# ── delta_messages ───────────────────────────────────────────────────────────

def test_delta_messages_single_page_with_delta_link():
    page = {"value": [{"id": "m1"}], "@odata.deltaLink": "https://graph.microsoft.com/deltalink1"}
    with patch("requests.get", return_value=_resp(200, page)):
        result = gc.delta_messages("tok", "u1", "inbox")
    assert result["messages"] == [{"id": "m1"}]
    assert result["delta_link"] == "https://graph.microsoft.com/deltalink1"
    assert "error" not in result


def test_delta_messages_follows_pagination_across_pages():
    page1 = {"value": [{"id": "m1"}], "@odata.nextLink": "https://graph.microsoft.com/page2"}
    page2 = {"value": [{"id": "m2"}], "@odata.deltaLink": "https://graph.microsoft.com/deltalink2"}
    with patch("requests.get", side_effect=[_resp(200, page1), _resp(200, page2)]):
        result = gc.delta_messages("tok", "u1", "inbox")
    assert [m["id"] for m in result["messages"]] == ["m1", "m2"]
    assert result["delta_link"] == "https://graph.microsoft.com/deltalink2"


def test_delta_messages_expired_token_signals_resync():
    with patch("requests.get", return_value=_resp(410)):
        result = gc.delta_messages("tok", "u1", "inbox", delta_link="https://stale-link")
    assert result["delta_link"] is None
    assert result["resync_required"] is True


def test_delta_messages_http_error_preserves_existing_delta_link():
    with patch("requests.get", return_value=_resp(500, text="boom")):
        result = gc.delta_messages("tok", "u1", "inbox", delta_link="https://existing-link")
    assert result["delta_link"] == "https://existing-link"
    assert "error" in result


# ── normalize_message ────────────────────────────────────────────────────────

def test_normalize_message_html_body():
    raw = {
        "id": "m1",
        "from": {"emailAddress": {"name": "Jane Doe", "address": "jane@corp.com"}},
        "toRecipients": [{"emailAddress": {"address": "bob@corp.com"}},
                         {"emailAddress": {"address": ""}}],
        "subject": "hi",
        "body": {"contentType": "html", "content": "<p>hello</p>"},
        "receivedDateTime": "2026-01-01T00:00:00Z",
        "bodyPreview": "hello",
    }
    msg = gc.normalize_message(raw)
    assert msg["sender_email"] == "jane@corp.com"
    assert msg["sender_name"] == "Jane Doe"
    assert msg["recipients"] == ["bob@corp.com"]
    assert msg["body_html"] == "<p>hello</p>"
    assert msg["body_text"] == ""


def test_normalize_message_text_body_and_missing_fields():
    raw = {"id": "m2", "body": {"contentType": "text", "content": "plain text body"}}
    msg = gc.normalize_message(raw)
    assert msg["sender_email"] == ""
    assert msg["recipients"] == []
    assert msg["body_text"] == "plain text body"
    assert msg["body_html"] == ""
