"""Tests for app/routes/assets.py::_sync_assets and the Asset unique
constraint it (and _enrich_assets) relies on to avoid duplicate inventory
rows for the same host."""
from unittest.mock import patch

from app.routes.assets import _sync_assets


def _make_scan_result(db, Target, Scan, ScanResult, host, target_name):
    target = Target(name=target_name, host="10.0.0.0/24")
    db.session.add(target)
    db.session.commit()
    scan = Scan(name="s", target_id=target.id, scan_type="full", status="done")
    db.session.add(scan)
    db.session.commit()
    db.session.add(ScanResult(scan_id=scan.id, result_type="port", host=host, severity="info"))
    db.session.commit()
    return target


class TestSyncAssets:
    def test_creates_asset_from_scan_result_host(self, app):
        with app.app_context():
            from app.extensions import db
            from app.models import Target, Scan, ScanResult, Asset

            target = _make_scan_result(db, Target, Scan, ScanResult, "10.0.0.5", "t1")
            _sync_assets()

            asset = Asset.query.filter_by(ip_address="10.0.0.5", target_id=target.id).first()
            assert asset is not None

    def test_skips_urls_and_cidrs_as_hosts(self, app):
        with app.app_context():
            from app.extensions import db
            from app.models import Target, Scan, ScanResult, Asset

            target = Target(name="t1", host="10.0.0.0/24")
            db.session.add(target)
            db.session.commit()
            scan = Scan(name="s", target_id=target.id, scan_type="full", status="done")
            db.session.add(scan)
            db.session.commit()
            db.session.add(ScanResult(scan_id=scan.id, result_type="info",
                                       host="https://example.test", severity="info"))
            db.session.add(ScanResult(scan_id=scan.id, result_type="info",
                                       host="10.0.0.0/24", severity="info"))
            db.session.commit()

            _sync_assets()

            assert Asset.query.filter_by(target_id=target.id).count() == 0

    def test_existing_asset_gets_last_seen_updated_not_duplicated(self, app):
        with app.app_context():
            from app.extensions import db
            from app.models import Target, Scan, ScanResult, Asset

            target = _make_scan_result(db, Target, Scan, ScanResult, "10.0.0.5", "t1")
            _sync_assets()
            assert Asset.query.filter_by(ip_address="10.0.0.5").count() == 1

            # A second, later scan against the same host.
            scan2 = Scan(name="s2", target_id=target.id, scan_type="full", status="done")
            db.session.add(scan2)
            db.session.commit()
            db.session.add(ScanResult(scan_id=scan2.id, result_type="port",
                                       host="10.0.0.5", severity="info"))
            db.session.commit()

            _sync_assets()

            assert Asset.query.filter_by(ip_address="10.0.0.5").count() == 1

    def test_one_collision_does_not_lose_other_new_assets_in_the_batch(self, app):
        """Regression test: the batch used to be one big commit, so an
        IntegrityError from a single race'd host used to roll back every
        other legitimate new asset in the same _sync_assets() pass too.

        Forces the collision the same way test_enrich_assets.py does: a
        real, already-committed "winner" row for 10.0.0.2, with the
        `existing` snapshot _sync_assets() takes up front mocked to miss it
        (simulating that the winner's insert landed after that snapshot),
        so its own insert attempt hits a real UNIQUE constraint violation.
        """
        with app.app_context():
            from unittest.mock import MagicMock
            from app.extensions import db
            from app.models import Target, Scan, ScanResult, Asset

            target = Target(name="t1", host="10.0.0.0/24")
            db.session.add(target)
            db.session.commit()
            scan = Scan(name="s", target_id=target.id, scan_type="full", status="done")
            db.session.add(scan)
            db.session.commit()
            for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
                db.session.add(ScanResult(scan_id=scan.id, result_type="port",
                                           host=ip, severity="info"))
            db.session.commit()

            winner = Asset(ip_address="10.0.0.2", target_id=target.id, hostname="winner")
            db.session.add(winner)
            db.session.commit()

            # _sync_assets() builds `existing` via a single Asset.query.all()
            # call up front — make that one call return an empty list, as if
            # the winner's row didn't exist yet when the snapshot was taken.
            # Everything else about Asset.query (filter_by, etc.) still
            # behaves normally via `wraps`.
            mock_query = MagicMock(wraps=Asset.query)
            mock_query.all.side_effect = [[]]

            with patch.object(Asset, "query", mock_query):
                _sync_assets()

            assets = Asset.query.filter_by(target_id=target.id).all()
            ips = {a.ip_address for a in assets}
            assert ips == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}
            # The pre-existing winner row is still the one on record, not
            # duplicated or replaced.
            winner_row = next(a for a in assets if a.ip_address == "10.0.0.2")
            assert winner_row.hostname == "winner"
