import os
import json
from flask import Flask, redirect, url_for, flash, request
from flask_login import current_user
from .extensions import db, login_manager, mail, scheduler, csrf, limiter
from config import Config


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    _base = os.path.dirname(os.path.dirname(__file__))
    os.makedirs(os.path.join(_base, "data"), exist_ok=True)
    _ev_dir = os.path.join(_base, "evidence_uploads")
    os.makedirs(_ev_dir, exist_ok=True)
    app.config.setdefault("EVIDENCE_UPLOAD_DIR", _ev_dir)

    _configure_logging(app, _base)

    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    if app.config["SQLALCHEMY_DATABASE_URI"].startswith("sqlite"):
        _tune_sqlite(app)

    login_manager.login_view = "auth.login"
    login_manager.login_message_category = "warning"

    from .models import User

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    from .routes.auth import auth_bp
    from .routes.dashboard import dashboard_bp
    from .routes.scans import scans_bp
    from .routes.targets import targets_bp
    from .routes.reports import reports_bp
    from .routes.settings import settings_bp
    from .routes.users import users_bp
    from .routes.api import api_bp
    from .routes.atlassian import atlassian_bp
    from .routes.dependency import dependency_bp
    from .routes.threat import threat_bp
    from .routes.vulns import vulns_bp
    from .routes.assets import assets_bp
    from .routes.grc import grc_bp
    from .routes.activity import activity_bp
    from .routes.eol import eol_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(scans_bp)
    app.register_blueprint(targets_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(atlassian_bp)
    app.register_blueprint(dependency_bp)
    app.register_blueprint(threat_bp)
    app.register_blueprint(vulns_bp)
    app.register_blueprint(assets_bp)
    app.register_blueprint(grc_bp)
    app.register_blueprint(activity_bp)
    app.register_blueprint(eol_bp)

    @app.template_global("now")
    def _now():
        from datetime import datetime, timezone
        return datetime.now(timezone.utc)

    @app.template_filter("localdt")
    def _localdt(dt, fmt="%b %d %H:%M"):
        """Convert a UTC datetime to the configured app timezone for display."""
        from datetime import timezone as _utc
        from zoneinfo import ZoneInfo
        if dt is None:
            return "—"
        from .models import TimeConfig
        cfg = TimeConfig.query.first()
        tz_name = (cfg.timezone if cfg else None) or "UTC"
        try:
            tz = ZoneInfo(tz_name)
        except Exception:
            tz = ZoneInfo("UTC")
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=_utc.utc)
        return dt.astimezone(tz).strftime(fmt)

    @app.template_global("app_timezone")
    def _app_timezone():
        from .models import TimeConfig
        cfg = TimeConfig.query.first()
        return (cfg.timezone if cfg else None) or "UTC"

    @app.template_filter("fromjson")
    def _fromjson(s):
        if not s:
            return {}
        try:
            return json.loads(s)
        except Exception:
            return {}

    @app.template_test("startswith")
    def _startswith(s, prefix):
        return isinstance(s, str) and s.startswith(prefix)

    @app.route("/healthz")
    def _healthz():
        from flask import jsonify
        from sqlalchemy import text
        try:
            db.session.execute(text("SELECT 1"))
            return jsonify({"status": "ok"}), 200
        except Exception as e:
            app.logger.error(f"Health check DB probe failed: {e}")
            return jsonify({"status": "error"}), 503

    @app.errorhandler(404)
    def _not_found(e):
        from flask import render_template
        return render_template("errors/404.html"), 404

    @app.errorhandler(429)
    def _rate_limited(e):
        from flask import render_template
        return render_template("errors/429.html"), 429

    @app.errorhandler(500)
    def _server_error(e):
        from flask import render_template
        app.logger.error(f"Unhandled exception: {e}", exc_info=True)
        return render_template("errors/500.html"), 500

    _PASSWORD_CHANGE_EXEMPT_ENDPOINTS = {"users.profile", "auth.logout", "static"}

    @app.before_request
    def _require_password_change():
        if (current_user.is_authenticated
                and getattr(current_user, "must_change_password", False)
                and request.endpoint not in _PASSWORD_CHANGE_EXEMPT_ENDPOINTS):
            flash("You must set a new password before continuing.", "warning")
            return redirect(url_for("users.profile"))

    with app.app_context():
        db.create_all()
        _migrate_vuln_ticket_scan_result_nullable(app)
        _migrate_columns(app)
        _migrate_encrypt_secrets(app)
        _seed_admin(app)
        _recover_orphaned_scans(app)
        _start_scheduler(app)

    return app


def _configure_logging(app, base_dir):
    """Rotating file log alongside gunicorn's stdout capture, so there's
    something to inspect after gunicorn's own log window has scrolled past."""
    import logging
    from logging.handlers import RotatingFileHandler

    log_dir = os.path.join(base_dir, "data", "logs")
    os.makedirs(log_dir, exist_ok=True)

    level = getattr(logging, os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO)
    handler = RotatingFileHandler(os.path.join(log_dir, "app.log"),
                                  maxBytes=10 * 1024 * 1024, backupCount=5)
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)s [%(name)s] %(message)s"))
    handler.setLevel(level)
    app.logger.addHandler(handler)
    app.logger.setLevel(level)


def _tune_sqlite(app):
    """WAL mode lets readers and writers proceed concurrently instead of
    blocking on the single main database file; NORMAL synchronous is the
    recommended pairing with WAL (still durable against app crashes, just not
    against an OS-level power loss mid-write, which is an acceptable trade for
    this workload)."""
    from sqlalchemy import event
    from sqlalchemy.engine import Engine

    @event.listens_for(Engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()


def _migrate_vuln_ticket_scan_result_nullable(app):
    """vuln_tickets.scan_result_id used to be NOT NULL, which raised an
    IntegrityError whenever a scan was deleted (SQLAlchemy nulls the FK on the
    ticket instead of deleting it, since the ticket is meant to outlive the
    scan that first surfaced it). Rebuild the table with the column nullable,
    preserving existing rows. No-op on a fresh install or once already fixed."""
    from sqlalchemy import text
    from .models import VulnTicket

    with db.engine.connect() as conn:
        info = conn.execute(text("PRAGMA table_info(vuln_tickets)")).fetchall()
        col = next((row for row in info if row[1] == "scan_result_id"), None)
        if not col or not col[3]:
            return  # table doesn't exist yet, or column is already nullable

        conn.execute(text("ALTER TABLE vuln_tickets RENAME TO vuln_tickets_old"))
        conn.commit()

    VulnTicket.__table__.create(bind=db.engine)

    with db.engine.connect() as conn:
        cols = ", ".join(c.name for c in VulnTicket.__table__.columns)
        conn.execute(text(f"INSERT INTO vuln_tickets ({cols}) SELECT {cols} FROM vuln_tickets_old"))
        conn.execute(text("DROP TABLE vuln_tickets_old"))
        conn.commit()


def _migrate_columns(app):
    """Add new columns to existing tables without Alembic."""
    from sqlalchemy import text
    new_cols = {
        "users": [
            ("must_change_password", "BOOLEAN DEFAULT 0"),
        ],
        "targets": [
            ("ssh_port",         "INTEGER DEFAULT 22"),
            ("ssh_username",     "VARCHAR(100)"),
            ("ssh_auth_type",    "VARCHAR(20) DEFAULT 'password'"),
            ("ssh_password",     "VARCHAR(512)"),
            ("ssh_private_key",  "TEXT"),
            ("ssh_key_passphrase","VARCHAR(512)"),
            ("target_type",      "VARCHAR(20) DEFAULT 'host'"),
            ("last_enum_at",     "DATETIME"),
        ],
        "scans": [
            ("scan_path", "VARCHAR(512)"),
            ("auto_remediate", "BOOLEAN DEFAULT 0"),
        ],
        "scan_results": [
            ("fixed_version", "VARCHAR(100)"),
            ("package_name", "VARCHAR(200)"),
            ("package_version", "VARCHAR(100)"),
            ("ecosystem", "VARCHAR(50)"),
            ("is_remediated", "BOOLEAN DEFAULT 0"),
        ],
        "threat_configs": [
            ("securitytrails_api_key",  "VARCHAR(512)"),
            ("greynoise_api_key",       "VARCHAR(512)"),  # legacy — no longer read by app code
            ("dnsdumpster_api_key",     "VARCHAR(512)"),
            ("nvd_api_key",             "VARCHAR(512)"),
            ("github_advisory_token",   "VARCHAR(512)"),
            ("urlhaus_api_key",        "VARCHAR(512)"),
            ("criminalip_api_key",     "VARCHAR(512)"),
            ("vulners_api_key",        "VARCHAR(512)"),
            ("hybridanalysis_api_key", "VARCHAR(512)"),
            ("phishtank_api_key",      "VARCHAR(512)"),
            ("socradar_api_key",       "VARCHAR(512)"),
        ],
        "vuln_tickets": [
            ("vuln_name", "VARCHAR(300)"),
            ("host_ip",   "VARCHAR(100)"),
            ("risk_justification", "TEXT"),
        ],
        "risk_entries": [
            ("vuln_ticket_id", "INTEGER"),
        ],
        "scheduled_scans": [
            ("asset_group_id", "INTEGER"),
        ],
        "ioc_records": [
            ("pulsedrive_result", "TEXT"),
        ],
        "soc_cases": [
            ("pulsedrive_result", "TEXT"),
            ("paloalto_result",   "TEXT"),
        ],
        "policies": [
            ("content",      "TEXT"),
            ("template_key", "VARCHAR(50)"),
        ],
        "evidence_files": [
            ("policy_id", "INTEGER"),
        ],
    }
    with db.engine.connect() as conn:
        for table, cols in new_cols.items():
            existing = [row[1] for row in conn.execute(text(f"PRAGMA table_info({table})")).fetchall()]
            for col_name, col_type in cols:
                if col_name not in existing:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_type}"))
        conn.commit()


def _migrate_encrypt_secrets(app):
    """Encrypt any legacy-plaintext values sitting in secret columns.

    Reads/writes via raw SQL (not the ORM) so we see the literal stored bytes
    rather than whatever the EncryptedString type decorator would transparently
    decrypt — that's what lets this safely re-run on every boot: already
    -encrypted values (enc:v1: prefix) are left untouched, only real legacy
    plaintext gets encrypted.
    """
    from sqlalchemy import text
    from . import crypto

    plan = [
        ("threat_configs", "id", [
            "otx_api_key", "virustotal_api_key", "abuseipdb_api_key",
            "securitytrails_api_key", "dnsdumpster_api_key", "nvd_api_key",
            "github_advisory_token", "urlhaus_api_key", "criminalip_api_key",
            "vulners_api_key", "hybridanalysis_api_key", "phishtank_api_key",
            "socradar_api_key",
        ]),
        ("paloalto_firewalls", "id", ["api_key", "password"]),
        ("targets", "id", ["ssh_password", "ssh_private_key", "ssh_key_passphrase"]),
    ]

    total = 0
    with db.engine.connect() as conn:
        for table, pk, cols in plan:
            col_list = ", ".join([pk] + cols)
            rows = conn.execute(text(f"SELECT {col_list} FROM {table}")).fetchall()
            for row in rows:
                row_id = row[0]
                updates = {}
                for i, col in enumerate(cols, start=1):
                    val = row[i]
                    if val and not crypto.is_encrypted(val):
                        updates[col] = crypto.encrypt(val)
                if updates:
                    set_clause = ", ".join(f"{c} = :{c}" for c in updates)
                    updates["_id"] = row_id
                    conn.execute(text(f"UPDATE {table} SET {set_clause} WHERE {pk} = :_id"), updates)
                    total += len(updates)
        conn.commit()

    if total:
        app.logger.info(f"Encrypted {total} previously-plaintext secret value(s) at rest.")


def _seed_admin(app):
    from .models import User
    if not User.query.filter_by(role="admin").first():
        admin = User(username="admin", email="admin@localhost", role="admin",
                     must_change_password=True)
        admin.set_password("admin")
        db.session.add(admin)
        db.session.commit()
        app.logger.info("Default admin created — must change password on first login.")


def _recover_orphaned_scans(app):
    """A scan's worker runs on a daemon thread (see scanner/engine.py) that
    doesn't survive a process restart — any scan still marked 'running' at
    boot was actually killed mid-scan, not still in progress."""
    from datetime import datetime, timezone
    from .models import Scan
    orphaned = Scan.query.filter_by(status="running").all()
    if not orphaned:
        return
    now = datetime.now(timezone.utc)
    for scan in orphaned:
        scan.status = "failed"
        scan.completed_at = now
    db.session.commit()
    app.logger.warning(f"Marked {len(orphaned)} orphaned 'running' scan(s) as failed after restart.")


def _start_scheduler(app):
    from .scheduler.jobs import register_jobs
    from .extensions import scheduler as _sched
    if not _sched.running:
        register_jobs(app)
        _sched.start()
