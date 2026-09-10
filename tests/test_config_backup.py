"""Tests for app/config_backup.py (export/decrypt/restore logic) and the
/settings/backup/export|import routes it's wired into.

Scope: the 7 Settings-page config singletons, PaloAltoFirewall, and Target
(SSH credentials) — see config_backup.py's module docstring for why each is
included and why users/scan data are deliberately excluded.
"""
import io

import pytest

from app import config_backup as cb


class TestExportDecryptRoundTrip:
    def test_round_trips_a_secret_value(self, app):
        with app.app_context():
            from app.extensions import db
            from app.models import ThreatConfig

            db.session.add(ThreatConfig(nvd_api_key="secret-nvd-key-123"))
            db.session.commit()

            blob = cb.export_backup("correct horse battery staple")
            payload = cb.decrypt_backup(blob, "correct horse battery staple")

        assert payload["configs"]["threat"]["nvd_api_key"] == "secret-nvd-key-123"

    def test_wrong_passphrase_is_rejected(self, app):
        with app.app_context():
            blob = cb.export_backup("the-real-passphrase")
            with pytest.raises(cb.BackupError, match="Incorrect passphrase"):
                cb.decrypt_backup(blob, "not-the-real-passphrase")

    def test_export_requires_nonempty_passphrase(self, app):
        with app.app_context():
            with pytest.raises(cb.BackupError):
                cb.export_backup("")

    def test_decrypt_rejects_garbage_input(self, app):
        with app.app_context():
            with pytest.raises(cb.BackupError, match="doesn't look like"):
                cb.decrypt_backup(b"not even json", "whatever")

    def test_decrypt_rejects_foreign_json(self, app):
        with app.app_context():
            with pytest.raises(cb.BackupError, match="doesn't look like"):
                cb.decrypt_backup(b'{"hello": "world"}', "whatever")

    def test_decrypt_rejects_unsupported_version(self, app):
        with app.app_context():
            import json
            blob = cb.export_backup("pw")
            envelope = json.loads(blob)
            envelope["version"] = 999
            with pytest.raises(cb.BackupError, match="Unsupported backup format version"):
                cb.decrypt_backup(json.dumps(envelope).encode(), "pw")

    def test_tampered_ciphertext_is_rejected(self, app):
        with app.app_context():
            import json
            blob = cb.export_backup("pw")
            envelope = json.loads(blob)
            envelope["ciphertext"] = envelope["ciphertext"][:-4] + "abcd"
            with pytest.raises(cb.BackupError, match="Incorrect passphrase"):
                cb.decrypt_backup(json.dumps(envelope).encode(), "pw")


class TestBuildBackupPayload:
    def test_captures_all_seven_singleton_sections(self, app):
        with app.app_context():
            payload = cb.build_backup_payload()
        assert set(payload["configs"].keys()) == {
            "email", "cloud", "atlassian", "threat", "time", "sso", "o365",
        }

    def test_missing_singleton_is_none_not_an_error(self, app):
        with app.app_context():
            payload = cb.build_backup_payload()
        # A fresh test DB has none of these configured yet.
        assert payload["configs"]["threat"] is None

    def test_captures_target_ssh_credentials(self, app):
        with app.app_context():
            from app.extensions import db
            from app.models import Target

            db.session.add(Target(name="t1", host="10.0.0.5",
                                   ssh_username="admin", ssh_password="hunter2"))
            db.session.commit()

            payload = cb.build_backup_payload()

        target = next(t for t in payload["targets"] if t["host"] == "10.0.0.5")
        assert target["ssh_username"] == "admin"
        assert target["ssh_password"] == "hunter2"

    def test_captures_paloalto_firewall_credentials(self, app):
        with app.app_context():
            from app.extensions import db
            from app.models import PaloAltoFirewall

            db.session.add(PaloAltoFirewall(name="fw1", hostname="fw.local",
                                             api_key="paloalto-secret"))
            db.session.commit()

            payload = cb.build_backup_payload()

        fw = next(f for f in payload["paloalto_firewalls"] if f["name"] == "fw1")
        assert fw["api_key"] == "paloalto-secret"


class TestRestoreBackup:
    def test_restores_singleton_config_into_empty_db(self, app):
        with app.app_context():
            from app.models import ThreatConfig

            payload = {"configs": {"threat": {"nvd_api_key": "restored-key",
                                               "registration_token": "tok"}},
                       "paloalto_firewalls": [], "targets": []}
            summary = cb.restore_backup(payload)

            assert summary["configs_restored"] == 1
            tc = ThreatConfig.query.first()
            assert tc.nvd_api_key == "restored-key"

    def test_restore_overwrites_existing_singleton(self, app):
        with app.app_context():
            from app.extensions import db
            from app.models import ThreatConfig

            db.session.add(ThreatConfig(nvd_api_key="old-key"))
            db.session.commit()

            payload = {"configs": {"threat": {"nvd_api_key": "new-key"}},
                       "paloalto_firewalls": [], "targets": []}
            cb.restore_backup(payload)

            assert ThreatConfig.query.count() == 1
            assert ThreatConfig.query.first().nvd_api_key == "new-key"

    def test_firewall_matched_by_name_updates_not_duplicates(self, app):
        with app.app_context():
            from app.extensions import db
            from app.models import PaloAltoFirewall

            db.session.add(PaloAltoFirewall(name="fw1", hostname="old.local", api_key="old-key"))
            db.session.commit()

            payload = {"configs": {}, "targets": [], "paloalto_firewalls": [
                {"name": "fw1", "hostname": "new.local", "api_key": "new-key"},
            ]}
            summary = cb.restore_backup(payload)

            assert summary["firewalls_updated"] == 1
            assert summary["firewalls_created"] == 0
            assert PaloAltoFirewall.query.count() == 1
            fw = PaloAltoFirewall.query.first()
            assert fw.hostname == "new.local"
            assert fw.api_key == "new-key"

    def test_target_matched_by_host_updates_not_duplicates(self, app):
        with app.app_context():
            from app.extensions import db
            from app.models import Target

            db.session.add(Target(name="old-name", host="10.0.0.5"))
            db.session.commit()

            payload = {"configs": {}, "paloalto_firewalls": [], "targets": [
                {"name": "new-name", "host": "10.0.0.5",
                 "ssh_username": "admin", "ssh_password": "hunter2"},
            ]}
            summary = cb.restore_backup(payload)

            assert summary["targets_updated"] == 1
            assert Target.query.count() == 1
            t = Target.query.first()
            assert t.name == "new-name"
            assert t.ssh_password == "hunter2"

    def test_new_target_is_created_when_host_not_found(self, app):
        with app.app_context():
            from app.models import Target

            payload = {"configs": {}, "paloalto_firewalls": [], "targets": [
                {"name": "brand-new", "host": "10.0.0.9"},
            ]}
            summary = cb.restore_backup(payload)

            assert summary["targets_created"] == 1
            assert Target.query.filter_by(host="10.0.0.9").first() is not None

    def test_created_by_is_never_restored(self, app):
        """created_by is a FK to a user id from the *exporting* database —
        restoring it verbatim risks an FK violation or misattributing the
        record to a different admin post-rebuild."""
        with app.app_context():
            from app.models import Target

            payload = {"configs": {}, "paloalto_firewalls": [], "targets": [
                {"name": "t", "host": "10.0.0.9", "created_by": 99999},
            ]}
            cb.restore_backup(payload)

            t = Target.query.filter_by(host="10.0.0.9").first()
            assert t.created_by is None

    def test_datetime_columns_are_parsed_not_left_as_strings(self, app):
        with app.app_context():
            from app.models import PaloAltoFirewall

            payload = {"configs": {}, "targets": [], "paloalto_firewalls": [
                {"name": "fw1", "hostname": "fw.local",
                 "last_polled_at": "2026-01-01T00:00:00+00:00"},
            ]}
            cb.restore_backup(payload)

            fw = PaloAltoFirewall.query.first()
            import datetime
            assert isinstance(fw.last_polled_at, datetime.datetime)

    def test_unknown_columns_in_backup_are_ignored_not_errors(self, app):
        """A backup made by a newer/older app version may carry columns this
        version doesn't have — must not crash the restore."""
        with app.app_context():
            from app.models import ThreatConfig

            payload = {"configs": {"threat": {
                "nvd_api_key": "key", "some_future_field": "unknown-to-us",
            }}, "paloalto_firewalls": [], "targets": []}
            cb.restore_backup(payload)  # must not raise

            assert ThreatConfig.query.first().nvd_api_key == "key"


class TestBackupRoutes:
    def test_export_requires_admin(self, app, client):
        with app.app_context():
            from app.extensions import db
            from app.models import User
            u = User(username="regular", email="r@example.test", role="user",
                     must_change_password=False)
            u.set_password("password123")
            db.session.add(u)
            db.session.commit()
        client.post("/login", data={"username": "regular", "password": "password123"})

        resp = client.post("/settings/backup/export", data={
            "export_passphrase": "testpass123", "export_passphrase_confirm": "testpass123",
        })
        assert resp.status_code in (302, 403)
        assert resp.content_type != "application/json"

    def test_export_rejects_short_passphrase(self, app, admin_client):
        resp = admin_client.post("/settings/backup/export", data={
            "export_passphrase": "short", "export_passphrase_confirm": "short",
        }, follow_redirects=True)
        assert b"at least 8 characters" in resp.data

    def test_export_rejects_mismatched_passphrases(self, app, admin_client):
        resp = admin_client.post("/settings/backup/export", data={
            "export_passphrase": "testpass123", "export_passphrase_confirm": "different123",
        }, follow_redirects=True)
        assert b"do not match" in resp.data

    def test_export_returns_downloadable_file(self, app, admin_client):
        resp = admin_client.post("/settings/backup/export", data={
            "export_passphrase": "testpass123", "export_passphrase_confirm": "testpass123",
        })
        assert resp.status_code == 200
        assert resp.content_type == "application/json"
        assert "attachment" in resp.headers.get("Content-Disposition", "")

    def test_export_then_import_round_trip_via_routes(self, app, admin_client):
        with app.app_context():
            from app.extensions import db
            from app.models import ThreatConfig
            db.session.add(ThreatConfig(nvd_api_key="route-test-key"))
            db.session.commit()

        export_resp = admin_client.post("/settings/backup/export", data={
            "export_passphrase": "testpass123", "export_passphrase_confirm": "testpass123",
        })
        blob = export_resp.data

        with app.app_context():
            from app.extensions import db
            from app.models import ThreatConfig
            ThreatConfig.query.delete()
            db.session.commit()

        import_resp = admin_client.post("/settings/backup/import", data={
            "backup_file": (io.BytesIO(blob), "backup.json"),
            "import_passphrase": "testpass123",
        }, content_type="multipart/form-data", follow_redirects=True)

        assert b"Configuration restored" in import_resp.data
        with app.app_context():
            from app.models import ThreatConfig
            assert ThreatConfig.query.first().nvd_api_key == "route-test-key"

    def test_import_with_wrong_passphrase_shows_error(self, app, admin_client):
        export_resp = admin_client.post("/settings/backup/export", data={
            "export_passphrase": "testpass123", "export_passphrase_confirm": "testpass123",
        })
        blob = export_resp.data

        resp = admin_client.post("/settings/backup/import", data={
            "backup_file": (io.BytesIO(blob), "backup.json"),
            "import_passphrase": "wrong-passphrase",
        }, content_type="multipart/form-data", follow_redirects=True)

        assert b"Incorrect passphrase" in resp.data

    def test_import_without_file_shows_error(self, app, admin_client):
        resp = admin_client.post("/settings/backup/import", data={
            "import_passphrase": "testpass123",
        }, content_type="multipart/form-data", follow_redirects=True)
        assert b"Choose a backup file" in resp.data

    def test_settings_page_renders_backup_section(self, app, admin_client):
        resp = admin_client.get("/settings/")
        assert b"Configuration Backup" in resp.data
        assert b"Export Configuration" in resp.data
        assert b"Restore Configuration" in resp.data
