"""Tests for app/scanner/engine.py::_enrich_assets.

Previously this only updated hostname/os_name on an Asset that already
existed for a discovered IP — a subnet scan finding a host nobody had
manually pre-added as an Asset left it completely out of the inventory,
contradicting "scan a subnet and it puts everything it finds into the asset
database." Now it creates the Asset record too.
"""
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
