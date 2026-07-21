import os
import json
from flask import Flask
from .extensions import db, login_manager, mail, scheduler
from config import Config


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    if app.config.get("SECRET_KEY") == "change-me-in-production":
        import warnings
        warnings.warn(
            "SECRET_KEY is the insecure default. Set the SECRET_KEY environment variable.",
            stacklevel=2,
        )

    _base = os.path.dirname(os.path.dirname(__file__))
    os.makedirs(os.path.join(_base, "data"), exist_ok=True)
    _ev_dir = os.path.join(_base, "evidence_uploads")
    os.makedirs(_ev_dir, exist_ok=True)
    app.config.setdefault("EVIDENCE_UPLOAD_DIR", _ev_dir)

    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)

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

    with app.app_context():
        db.create_all()
        _migrate_vuln_ticket_scan_result_nullable(app)
        _migrate_columns(app)
        _seed_admin(app)
        _start_scheduler(app)

    return app


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


def _seed_admin(app):
    from .models import User
    if not User.query.filter_by(role="admin").first():
        admin = User(username="admin", email="admin@localhost", role="admin")
        admin.set_password("admin")
        db.session.add(admin)
        db.session.commit()
        app.logger.info("Default admin created — change the password immediately.")


def _start_scheduler(app):
    from .scheduler.jobs import register_jobs
    from .extensions import scheduler as _sched
    if not _sched.running:
        register_jobs(app)
        _sched.start()
