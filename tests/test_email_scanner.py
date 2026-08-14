"""Tests for the O365 scan orchestration (app/email_security/scanner.py).
Uses the real sqlite-backed `app` fixture; graph_client's network calls are
mocked so no real Graph API access happens."""
import json
from unittest.mock import patch

from app.extensions import db
from app.models import O365Config, MonitoredMailbox, EmailScanResult
from app.email_security import scanner


def _enabled_cfg():
    cfg = O365Config(enabled=True, tenant_id="t", client_id="c", client_secret="s")
    db.session.add(cfg)
    db.session.commit()
    return cfg


def _raw_message(msg_id, sender="external@othercorp.com", subject="hi",
                 body_html="", to=("jane@corp.com",)):
    return {
        "id": msg_id,
        "from": {"emailAddress": {"name": "Sender", "address": sender}},
        "toRecipients": [{"emailAddress": {"address": t}} for t in to],
        "subject": subject,
        "body": {"contentType": "html", "content": body_html},
        "receivedDateTime": "2026-01-01T00:00:00Z",
        "bodyPreview": subject,
    }


# ── sync_mailboxes ───────────────────────────────────────────────────────────

def test_sync_mailboxes_not_configured_returns_negative_one(app):
    with app.app_context():
        assert scanner.sync_mailboxes() == -1


def test_sync_mailboxes_creates_new_mailbox_rows(app):
    with app.app_context():
        _enabled_cfg()
        mailboxes = [{"user_id": "u1", "upn": "jane@corp.com", "display_name": "Jane"}]
        with patch.object(scanner.graph_client, "get_app_token", return_value=("tok", None)), \
             patch.object(scanner.graph_client, "list_mailboxes", return_value=(mailboxes, None)):
            count = scanner.sync_mailboxes()

        assert count == 1
        mb = MonitoredMailbox.query.filter_by(user_id="u1").first()
        assert mb is not None
        assert mb.upn == "jane@corp.com"
        assert mb.enabled is True


def test_sync_mailboxes_disables_mailboxes_no_longer_in_tenant(app):
    with app.app_context():
        _enabled_cfg()
        db.session.add(MonitoredMailbox(user_id="departed", upn="gone@corp.com", enabled=True))
        db.session.commit()

        with patch.object(scanner.graph_client, "get_app_token", return_value=("tok", None)), \
             patch.object(scanner.graph_client, "list_mailboxes", return_value=([], None)):
            scanner.sync_mailboxes()

        mb = MonitoredMailbox.query.filter_by(user_id="departed").first()
        assert mb is not None  # not deleted
        assert mb.enabled is False


def test_sync_mailboxes_token_failure_sets_error_status(app):
    with app.app_context():
        cfg = _enabled_cfg()
        with patch.object(scanner.graph_client, "get_app_token", return_value=(None, "bad creds")):
            count = scanner.sync_mailboxes()
        assert count == -1
        assert cfg.status == "error"
        assert cfg.last_error == "bad creds"


# ── poll_mail ────────────────────────────────────────────────────────────────

def test_poll_mail_persists_only_flagged_messages(app):
    with app.app_context():
        _enabled_cfg()
        mb = MonitoredMailbox(user_id="u1", upn="jane@corp.com", enabled=True)
        db.session.add(mb)
        db.session.commit()

        clean_msg = _raw_message("clean1", subject="lunch tomorrow?")
        shadow_it_msg = _raw_message("shadow1", sender="notify@notion.so",
                                     subject="Welcome to Notion! Verify your email")

        def fake_delta(token, user_id, folder, delta_link=None, max_pages=20):
            if folder == "inbox":
                return {"messages": [clean_msg, shadow_it_msg], "delta_link": "dl-inbox"}
            return {"messages": [], "delta_link": "dl-sent"}

        with patch.object(scanner.graph_client, "get_app_token", return_value=("tok", None)), \
             patch.object(scanner.graph_client, "delta_messages", side_effect=fake_delta):
            flagged = scanner.poll_mail()

        assert flagged == 1
        assert EmailScanResult.query.count() == 1
        result = EmailScanResult.query.first()
        assert result.message_id == "shadow1"
        assert result.is_shadow_it is True

        mb = MonitoredMailbox.query.filter_by(user_id="u1").first()
        assert mb.inbox_delta_link == "dl-inbox"
        assert mb.sentitems_delta_link == "dl-sent"


def test_poll_mail_skips_already_seen_message_id(app):
    with app.app_context():
        _enabled_cfg()
        mb = MonitoredMailbox(user_id="u1", upn="jane@corp.com", enabled=True)
        db.session.add(mb)
        db.session.commit()

        shadow_it_msg = _raw_message("shadow1", sender="notify@notion.so",
                                     subject="Welcome to Notion! Verify your email")

        def fake_delta(token, user_id, folder, delta_link=None, max_pages=20):
            if folder == "inbox":
                return {"messages": [shadow_it_msg], "delta_link": f"dl-{delta_link or '0'}"}
            return {"messages": [], "delta_link": None}

        with patch.object(scanner.graph_client, "get_app_token", return_value=("tok", None)), \
             patch.object(scanner.graph_client, "delta_messages", side_effect=fake_delta):
            first = scanner.poll_mail()
            second = scanner.poll_mail()

        assert first == 1
        assert second == 0  # same message_id already persisted
        assert EmailScanResult.query.count() == 1


def test_poll_mail_dlp_check_uses_all_monitored_mailboxes_as_internal_domains(app):
    with app.app_context():
        _enabled_cfg()
        mb = MonitoredMailbox(user_id="u1", upn="jane.doe@corp.com", enabled=True)
        db.session.add(mb)
        db.session.commit()

        outbound_msg = _raw_message("out1", sender="jane.doe@corp.com",
                                    subject="fwd: contract", to=("jane.doe1985@gmail.com",))

        def fake_delta(token, user_id, folder, delta_link=None, max_pages=20):
            if folder == "sentitems":
                return {"messages": [outbound_msg], "delta_link": "dl-sent"}
            return {"messages": [], "delta_link": "dl-inbox"}

        with patch.object(scanner.graph_client, "get_app_token", return_value=("tok", None)), \
             patch.object(scanner.graph_client, "delta_messages", side_effect=fake_delta):
            flagged = scanner.poll_mail()

        assert flagged == 1
        result = EmailScanResult.query.first()
        assert result.direction == "outbound"
        assert result.is_dlp_risk is True
        detail = json.loads(result.dlp_detail)
        assert detail["recipient_domain"] == "gmail.com"


def test_poll_mail_disabled_mailbox_is_not_polled(app):
    with app.app_context():
        _enabled_cfg()
        mb = MonitoredMailbox(user_id="u1", upn="jane@corp.com", enabled=False)
        db.session.add(mb)
        db.session.commit()

        with patch.object(scanner.graph_client, "get_app_token", return_value=("tok", None)), \
             patch.object(scanner.graph_client, "delta_messages") as mock_delta:
            scanner.poll_mail()

        mock_delta.assert_not_called()


def test_poll_mail_not_configured_returns_negative_one(app):
    with app.app_context():
        assert scanner.poll_mail() == -1
