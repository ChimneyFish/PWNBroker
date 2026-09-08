"""Tests for app/__init__.py's _migrate_dedupe_assets/_migrate_indexes pair,
which retrofit the Asset(ip_address, target_id) unique constraint onto
already-deployed databases that predate it and may have accumulated real
duplicate rows from the pre-fix race in _enrich_assets()/_sync_assets().

The test `app` fixture always creates a brand-new database via
db.create_all(), which bakes the unique constraint in from the start (SQLite
implements it as an internal sqlite_autoindex_*, separate from and
unaffected by dropping the named uq_asset_ip_target index) — so there's no
duplicate-free way to get real duplicate rows into a freshly-created assets
table. These tests instead drop and recreate the table using its
pre-constraint shape, to actually simulate what an existing deployed
database predating this migration looks like.
"""
import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app import _migrate_dedupe_assets, _migrate_indexes

_LEGACY_ASSETS_TABLE = """
CREATE TABLE assets (
    id INTEGER NOT NULL,
    ip_address VARCHAR(100) NOT NULL,
    hostname VARCHAR(256),
    mac_address VARCHAR(20),
    os_name VARCHAR(200),
    target_id INTEGER,
    first_seen DATETIME,
    last_seen DATETIME,
    status VARCHAR(20),
    notes TEXT,
    created_at DATETIME,
    PRIMARY KEY (id),
    FOREIGN KEY(target_id) REFERENCES targets (id) ON DELETE SET NULL
)
"""


def _recreate_assets_without_constraint(db):
    db.session.execute(text("DROP TABLE assets"))
    db.session.execute(text(_LEGACY_ASSETS_TABLE))
    db.session.commit()


class TestMigrateDedupeAssets:
    def test_removes_duplicates_and_keeps_most_recent(self, app):
        with app.app_context():
            from app.extensions import db
            from app.models import Target, Asset

            target = Target(name="t", host="10.0.0.0/24")
            db.session.add(target)
            db.session.commit()
            target_id = target.id

            _recreate_assets_without_constraint(db)

            db.session.execute(text(
                "INSERT INTO assets (ip_address, target_id, hostname, first_seen, last_seen) "
                "VALUES ('10.0.0.5', :tid, 'old', datetime('now'), datetime('now'))"
            ), {"tid": target_id})
            db.session.execute(text(
                "INSERT INTO assets (ip_address, target_id, hostname, first_seen, last_seen) "
                "VALUES ('10.0.0.5', :tid, 'new', datetime('now'), datetime('now'))"
            ), {"tid": target_id})
            db.session.commit()
            assert Asset.query.filter_by(ip_address="10.0.0.5", target_id=target_id).count() == 2

            _migrate_dedupe_assets(app)

            remaining = Asset.query.filter_by(ip_address="10.0.0.5", target_id=target_id).all()
            assert len(remaining) == 1
            assert remaining[0].hostname == "new"  # highest id == most recently inserted

    def test_leaves_distinct_hosts_untouched(self, app):
        with app.app_context():
            from app.extensions import db
            from app.models import Target, Asset

            target = Target(name="t", host="10.0.0.0/24")
            db.session.add(target)
            db.session.commit()

            _recreate_assets_without_constraint(db)
            db.session.execute(text(
                "INSERT INTO assets (ip_address, target_id, first_seen, last_seen) "
                "VALUES ('10.0.0.1', :tid, datetime('now'), datetime('now'))"
            ), {"tid": target.id})
            db.session.execute(text(
                "INSERT INTO assets (ip_address, target_id, first_seen, last_seen) "
                "VALUES ('10.0.0.2', :tid, datetime('now'), datetime('now'))"
            ), {"tid": target.id})
            db.session.commit()

            _migrate_dedupe_assets(app)

            assert Asset.query.filter_by(target_id=target.id).count() == 2

    def test_index_creation_succeeds_after_dedupe_and_enforces_uniqueness(self, app):
        with app.app_context():
            from app.extensions import db
            from app.models import Target, Asset

            target = Target(name="t", host="10.0.0.0/24")
            db.session.add(target)
            db.session.commit()
            target_id = target.id

            _recreate_assets_without_constraint(db)
            db.session.execute(text(
                "INSERT INTO assets (ip_address, target_id, first_seen, last_seen) "
                "VALUES ('10.0.0.5', :tid, datetime('now'), datetime('now'))"
            ), {"tid": target_id})
            db.session.execute(text(
                "INSERT INTO assets (ip_address, target_id, first_seen, last_seen) "
                "VALUES ('10.0.0.5', :tid, datetime('now'), datetime('now'))"
            ), {"tid": target_id})
            db.session.commit()

            # Without dedupe first, creating the unique index over existing
            # duplicates must fail — this is *why* dedupe has to run first.
            with pytest.raises(Exception):
                db.session.execute(text(
                    "CREATE UNIQUE INDEX uq_test_no_dedupe ON assets (ip_address, target_id)"
                ))
                db.session.commit()
            db.session.rollback()

            _migrate_dedupe_assets(app)
            _migrate_indexes(app)  # must not raise now that duplicates are gone

            with pytest.raises(IntegrityError):
                db.session.execute(text(
                    "INSERT INTO assets (ip_address, target_id, first_seen, last_seen) "
                    "VALUES ('10.0.0.5', :tid, datetime('now'), datetime('now'))"
                ), {"tid": target_id})
                db.session.commit()
            db.session.rollback()
