"""Thin Microsoft Graph client for the O365 email-security integration.

Uses the app-only OAuth2 client-credentials flow (Mail.Read / User.Read.All,
tenant-wide, admin-consented) — no signed-in user, no browser redirect, so it
can run unattended from the scheduler like every other poller in this app.
"""
import requests

_TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
_GRAPH     = "https://graph.microsoft.com/v1.0"
_SCOPE     = "https://graph.microsoft.com/.default"
_TIMEOUT   = 20

_MESSAGE_SELECT = "id,subject,from,toRecipients,receivedDateTime,bodyPreview,body"


def get_app_token(tenant_id, client_id, client_secret):
    """Returns (token, error) — exactly one is None."""
    try:
        r = requests.post(
            _TOKEN_URL.format(tenant=tenant_id),
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": _SCOPE,
            },
            timeout=_TIMEOUT,
        )
        if r.status_code != 200:
            try:
                detail = r.json().get("error_description")
            except Exception:
                detail = None
            detail = detail or r.text or f"HTTP {r.status_code}"
            return None, detail[:300]
        return r.json().get("access_token"), None
    except Exception as e:
        return None, str(e)


def test_connection(tenant_id, client_id, client_secret):
    token, err = get_app_token(tenant_id, client_id, client_secret)
    if err:
        return {"error": err}
    try:
        r = requests.get(f"{_GRAPH}/organization",
                         headers={"Authorization": f"Bearer {token}"}, timeout=_TIMEOUT)
        if r.status_code == 200:
            orgs = r.json().get("value", [])
            name = orgs[0].get("displayName") if orgs else "tenant"
            return {"ok": True, "detail": f"Connected to {name}"}
        if r.status_code == 403:
            return {"error": "Token accepted but missing Graph API permissions "
                              "(grant Mail.Read + User.Read.All, application type, with admin consent)."}
        return {"error": f"HTTP {r.status_code}: {r.text[:200]}"}
    except Exception as e:
        return {"error": str(e)}


def list_mailboxes(token):
    """Enumerate every licensed user with a mailbox, tenant-wide.
    Returns (mailboxes, error) — mailboxes is a list of
    {"user_id","upn","display_name"} dicts."""
    mailboxes = []
    url = (f"{_GRAPH}/users"
           "?$select=id,userPrincipalName,displayName,mail,accountEnabled"
           "&$filter=accountEnabled eq true and mail ne null"
           "&$top=999")
    headers = {"Authorization": f"Bearer {token}"}
    try:
        while url:
            r = requests.get(url, headers=headers, timeout=_TIMEOUT)
            if r.status_code != 200:
                return mailboxes, f"HTTP {r.status_code}: {r.text[:200]}"
            data = r.json()
            for u in data.get("value", []):
                mailboxes.append({
                    "user_id":      u["id"],
                    "upn":          u.get("userPrincipalName") or u.get("mail"),
                    "display_name": u.get("displayName") or "",
                })
            url = data.get("@odata.nextLink")
        return mailboxes, None
    except Exception as e:
        return mailboxes, str(e)


def delta_messages(token, user_id, folder, delta_link=None, max_pages=20):
    """Fetch new/changed messages in a mailbox folder ('inbox' or 'sentitems')
    since the last delta_link, following pagination.

    Returns {"messages": [...], "delta_link": <str or None>, "error": <str, optional>}.
    Each message is Graph's raw JSON shape (mapped to our normalized dict by
    the caller) with fields limited to _MESSAGE_SELECT.
    """
    headers = {"Authorization": f"Bearer {token}", "Prefer": "outlook.body-content-type=\"html\""}
    url = delta_link or (f"{_GRAPH}/users/{user_id}/mailFolders/{folder}/messages/delta"
                         f"?$select={_MESSAGE_SELECT}")
    messages = []
    new_delta_link = delta_link

    try:
        for _ in range(max_pages):
            r = requests.get(url, headers=headers, timeout=_TIMEOUT)
            if r.status_code == 410:
                # Delta token expired/invalidated — caller should restart from scratch.
                return {"messages": messages, "delta_link": None,
                        "error": "delta_gone", "resync_required": True}
            if r.status_code != 200:
                return {"messages": messages, "delta_link": new_delta_link,
                        "error": f"HTTP {r.status_code}: {r.text[:200]}"}
            data = r.json()
            messages.extend(data.get("value", []))
            if "@odata.deltaLink" in data:
                new_delta_link = data["@odata.deltaLink"]
                url = None
                break
            url = data.get("@odata.nextLink")
            if not url:
                break
        return {"messages": messages, "delta_link": new_delta_link}
    except Exception as e:
        return {"messages": messages, "delta_link": new_delta_link, "error": str(e)}


def normalize_message(raw: dict) -> dict:
    """Map Graph's message JSON onto the flat shape analyzer.classify_message expects."""
    frm = (raw.get("from") or {}).get("emailAddress") or {}
    recipients = [
        (rec.get("emailAddress") or {}).get("address", "")
        for rec in raw.get("toRecipients") or []
    ]
    body = raw.get("body") or {}
    body_content = body.get("content") or ""
    is_html = (body.get("contentType") or "").lower() == "html"

    return {
        "id":          raw.get("id"),
        "sender_email": frm.get("address", ""),
        "sender_name":  frm.get("name", ""),
        "recipients":   [r for r in recipients if r],
        "subject":      raw.get("subject") or "",
        "body_html":    body_content if is_html else "",
        "body_text":    body_content if not is_html else "",
        "received_at":  raw.get("receivedDateTime"),
        "snippet":      (raw.get("bodyPreview") or "")[:500],
    }
