"""Tests for app/scanner/engine.py::_enrich_assets.

Previously this only updated hostname/os_name on an Asset that already
existed for a discovered IP — a subnet scan finding a host nobody had
manually pre-added as an Asset left it completely out of the inventory,
contradicting "scan a subnet and it puts everything it finds into the asset
database." Now it creates the Asset record too.
"""
from unittest.mock import patch

import pytest

from app.scanner.engine import _enrich_assets


class TestEnrichAssets:
    def test_creates_asset_for_newly_discovered_host(self, app):
        with app.app_context():
            from app.extensions import db
            from app.models import Target, Asset

            target = Target(name="t", host="10.0.0.0/24")
            db.session.add(target)
            db.session.commit()

            assert Asset.query.count() == 0

            _enrich_assets(target.id, {
                "10.0.0.5": {"hostname": "webserver.local", "os_name": "Linux 5.x"},
            })

            asset = Asset.query.filter_by(ip_address="10.0.0.5").first()
            assert asset is not None
            assert asset.target_id == target.id
            assert asset.hostname == "webserver.local"
            assert asset.os_name == "Linux 5.x"
            assert asset.first_seen is not None
            assert asset.last_seen is not None

    def test_updates_last_seen_and_fills_blank_fields_on_existing_asset(self, app):
        with app.app_context():
            from app.extensions import db
            from app.models import Target, Asset

            target = Target(name="t", host="10.0.0.0/24")
            db.session.add(target)
            db.session.commit()
            asset = Asset(ip_address="10.0.0.9", target_id=target.id)
            db.session.add(asset)
            db.session.commit()
            asset_id = asset.id
            assert asset.last_seen is None

            _enrich_assets(target.id, {
                "10.0.0.9": {"hostname": "db01.local", "os_name": "Windows Server 2019"},
            })

            refreshed = Asset.query.get(asset_id)
            assert refreshed.hostname == "db01.local"
            assert refreshed.os_name == "Windows Server 2019"
            assert refreshed.last_seen is not None

    def test_does_not_overwrite_existing_hostname(self, app):
        with app.app_context():
            from app.extensions import db
            from app.models import Target, Asset

            target = Target(name="t", host="10.0.0.0/24")
            db.session.add(target)
            db.session.commit()
            asset = Asset(ip_address="10.0.0.9", target_id=target.id, hostname="already-named")
            db.session.add(asset)
            db.session.commit()

            _enrich_assets(target.id, {"10.0.0.9": {"hostname": "new-name", "os_name": None}})

            assert Asset.query.filter_by(ip_address="10.0.0.9").first().hostname == "already-named"

    def test_multiple_new_hosts_all_get_created(self, app):
        with app.app_context():
            from app.extensions import db
            from app.models import Target, Asset

            target = Target(name="t", host="10.0.0.0/24")
            db.session.add(target)
            db.session.commit()

            _enrich_assets(target.id, {
                "10.0.0.1": {"hostname": None, "os_name": None},
                "10.0.0.2": {"hostname": None, "os_name": None},
                "10.0.0.3": {"hostname": None, "os_name": None},
            })

            assert Asset.query.filter_by(target_id=target.id).count() == 3

    def test_duplicate_ip_target_is_rejected_by_db_constraint(self, app):
        """Asset has a unique constraint on (ip_address, target_id) — this
        locks in that the constraint actually exists and is enforced, which
        is what makes the IntegrityError-recovery path below meaningful."""
        with app.app_context():
            from sqlalchemy.exc import IntegrityError
            from app.extensions import db
            from app.models import Target, Asset

            target = Target(name="t", host="10.0.0.0/24")
            db.session.add(target)
            db.session.commit()

            db.session.add(Asset(ip_address="10.0.0.5", target_id=target.id))
            db.session.commit()

            db.session.add(Asset(ip_address="10.0.0.5", target_id=target.id))
            with pytest.raises(IntegrityError):
                db.session.commit()
            db.session.rollback()

    def test_insert_race_recovers_instead_of_crashing_the_scan(self, app):
        """Simulates the actual race _enrich_assets is written to survive:
        another thread's Asset row for the same (ip, target_id) lands in the
        database in the window between this function's existence check and
        its own insert committing.

        A genuinely concurrent version of this is awkward to force
        deterministically against SQLite in a single-process test, so this
        drives the same real failure mode directly: a real, already-committed
        "winner" row exists for the key, the function's *own* existence
        check is mocked to report a miss (simulating that it ran before the
        winner's insert), so its own insert attempt hits a real UNIQUE
        constraint violation from SQLite — not a fabricated exception — and
        the recovery path's own re-query (also through the mock) is handed
        the real winner. The commit should fail with IntegrityError, and the
        function should recover by updating the winner's row rather than
        letting the exception escape (which would otherwise propagate out of
        run_scan's per-host loop and abort the rest of the scan over an
        entirely benign inventory-bookkeeping collision)."""
        with app.app_context():
            from unittest.mock import MagicMock
            from app.extensions import db
            from app.models import Target, Asset

            target = Target(name="t", host="10.0.0.0/24")
            db.session.add(target)
            db.session.commit()

            winner = Asset(ip_address="10.0.0.5", target_id=target.id, hostname="winner")
            db.session.add(winner)
            db.session.commit()
            winner_id = winner.id

            mock_query = MagicMock()
            # 1st call: _enrich_assets's own existence check — report a miss.
            # 2nd call: the re-query inside its except block — hand back the
            # real winner row.
            mock_query.filter_by.return_value.first.side_effect = [None, winner]

            with patch.object(Asset, "query", mock_query):
                _enrich_assets(target.id, {
                    "10.0.0.5": {"hostname": "new-name", "os_name": "Linux 6.x"},
                })

            refreshed = db.session.get(Asset, winner_id)
            # The winner's own hostname is preserved, not clobbered by the
            # data this call was trying to write.
            assert refreshed.hostname == "winner"
            # But fields the winner didn't already have get filled in.
            assert refreshed.os_name == "Linux 6.x"
            assert db.session.query(Asset).filter_by(
                ip_address="10.0.0.5", target_id=target.id).count() == 1
