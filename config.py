import os
import secrets
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


def _get_or_create_secret_key():
    """Use SECRET_KEY from the environment if set (required for multi-instance
    deployments). Otherwise generate a random key on first boot and persist it
    to disk so restarts don't invalidate every session."""
    env_key = os.environ.get("SECRET_KEY")
    if env_key:
        return env_key

    key_path = os.path.join(BASE_DIR, "data", "secret_key.txt")
    os.makedirs(os.path.dirname(key_path), exist_ok=True)
    if os.path.exists(key_path):
        existing = open(key_path).read().strip()
        if existing:
            return existing

    key = secrets.token_hex(32)
    with open(key_path, "w") as f:
        f.write(key)
    os.chmod(key_path, 0o600)
    return key


class Config:
    SECRET_KEY = _get_or_create_secret_key()
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'data', 'scanner.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # `timeout` (busy-wait before "database is locked") is a sqlite3-only connect
    # arg — only set it when we're actually on sqlite, so a future DATABASE_URL
    # pointing at Postgres/MySQL doesn't choke on an unsupported kwarg.
    SQLALCHEMY_ENGINE_OPTIONS = (
        {"connect_args": {"timeout": 30}} if SQLALCHEMY_DATABASE_URI.startswith("sqlite") else {}
    )

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "true").lower() == "true"

    # Mail
    MAIL_SERVER = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT = int(os.environ.get("MAIL_PORT", 587))
    MAIL_USE_TLS = os.environ.get("MAIL_USE_TLS", "true").lower() == "true"
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME", "")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD", "")
    MAIL_DEFAULT_SENDER = os.environ.get("MAIL_DEFAULT_SENDER", "")

    # Scanner
    NMAP_PATH = os.environ.get("NMAP_PATH", "/usr/bin/nmap")
    NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # Scheduler
    SCHEDULER_API_ENABLED = False
    JOBS = []
