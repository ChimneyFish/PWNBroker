"""
Configuration backup/restore — lets an admin snapshot the app's entire
configuration (integration settings and their API keys/passwords, Palo Alto
firewall credentials, per-Target SSH credentials) to a downloadable file and
later restore it, e.g. after rebuilding the server from scratch.

The exported file is passphrase-encrypted, not tied to this server's own
data/encryption_key.txt (crypto.py) — that key is what protects secrets at
rest *in this database*, but a rebuilt server generates a brand-new one on
first boot, so an export encrypted with it would become permanently
unreadable in exactly the disaster-recovery scenario this feature exists
for. Instead the backup derives its own key from an admin-supplied
passphrase (PBKDF2-HMAC-SHA256, per-export random salt), so the file is
self-contained and portable to any PwnBroker instance that knows the
passphrase.

Scope: the 7 Settings-page config singletons, all PaloAltoFirewall rows, and
all Target rows (SSH-credential-bearing target settings only make sense
alongside the Target they belong to, so the whole row is included, not just
the credential fields). Does NOT include: users/passwords, scan history,
scan results, tickets, or any other operational data — this is a
configuration backup, not a full database backup.
"""
import base64
import json
import os
from datetime import datetime, timezone

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .extensions import db

FORMAT_MARKER = "pwnbroker-config-backup"
FORMAT_VERSION = 1

# OWASP's current (2023+) minimum recommendation for PBKDF2-HMAC-SHA256.
PBKDF2_ITERATIONS = 600_000
_SALT_BYTES = 16

# (model_attr_on_module, human label) — the 7 Settings-page singletons.
# Every column except id/updated_at is captured; EncryptedString columns
# decrypt transparently through the ORM, so this reads plaintext without
# touching crypto.py directly.
_SINGLETON_CONFIGS = [
    ("EmailConfig", "email"),
    ("CloudConfig", "cloud"),
    ("AtlassianConfig", "atlassian"),
    ("ThreatConfig", "threat"),
    ("TimeConfig", "time"),
    ("SSOConfig", "sso"),
    ("O365Config", "o365"),
]

_SKIP_COLUMNS = {"id", "updated_at", "created_at"}


class BackupError(Exception):
    """Raised for any restore failure the caller should show to the user
    (wrong passphrase, corrupt/foreign file, unreadable format) rather than
    a raw exception with an internal traceback."""


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                      iterations=PBKDF2_ITERATIONS)
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


def _row_to_dict(row) -> dict:
    return {
        c.name: getattr(row, c.name)
        for c in row.__table__.columns
        if c.name not in _SKIP_COLUMNS
    }


def build_backup_payload() -> dict:
    """Gather everything in scope into a single plain-dict payload, ready to
    be JSON-serialized and encrypted. Datetime columns are ISO-formatted
    since json.dumps can't handle them directly."""
    from . import models

    payload = {
        "format": FORMAT_MARKER,
        "version": FORMAT_VERSION,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "configs": {},
        "paloalto_firewalls": [],
        "targets": [],
    }

    for model_name, key in _SINGLETON_CONFIGS:
        model = getattr(models, model_name)
        row = model.query.first()
        payload["configs"][key] = _row_to_dict(row) if row else None

    payload["paloalto_firewalls"] = [
        _row_to_dict(fw) for fw in models.PaloAltoFirewall.query.all()
    ]
    payload["targets"] = [
        _row_to_dict(t) for t in models.Target.query.all()
    ]

    return json.loads(json.dumps(payload, default=_json_default))


def _json_default(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def export_backup(passphrase: str) -> bytes:
    """Return the encrypted backup file content for the given passphrase."""
    if not passphrase:
        raise BackupError("A passphrase is required to encrypt the backup.")

    payload = build_backup_payload()
    plaintext = json.dumps(payload).encode("utf-8")

    salt = os.urandom(_SALT_BYTES)
    key = _derive_key(passphrase, salt)
    ciphertext = Fernet(key).encrypt(plaintext)

    envelope = {
        "format": FORMAT_MARKER,
        "version": FORMAT_VERSION,
        "kdf": "pbkdf2-sha256",
        "iterations": PBKDF2_ITERATIONS,
        "salt": base64.b64encode(salt).decode("ascii"),
        "ciphertext": ciphertext.decode("ascii"),
    }
    return json.dumps(envelope, indent=2).encode("utf-8")


def decrypt_backup(file_bytes: bytes, passphrase: str) -> dict:
    """Decrypt and parse an exported backup file. Raises BackupError with a
    user-facing message on any failure — wrong passphrase, truncated/edited
    file, or a file that isn't one of these backups at all."""
    if not passphrase:
        raise BackupError("A passphrase is required to decrypt this backup.")

    try:
        envelope = json.loads(file_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise BackupError("This doesn't look like a PwnBroker configuration backup file.")

    if not isinstance(envelope, dict) or envelope.get("format") != FORMAT_MARKER:
        raise BackupError("This doesn't look like a PwnBroker configuration backup file.")
    if envelope.get("version") != FORMAT_VERSION:
        raise BackupError(f"Unsupported backup format version: {envelope.get('version')!r}.")

    try:
        salt = base64.b64decode(envelope["salt"])
        iterations = int(envelope["iterations"])
        ciphertext = envelope["ciphertext"].encode("ascii")
    except (KeyError, ValueError):
        raise BackupError("This backup file is corrupt or incomplete.")

    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))

    try:
        plaintext = Fernet(key).decrypt(ciphertext)
    except InvalidToken:
        raise BackupError("Incorrect passphrase, or the backup file has been corrupted or tampered with.")

    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise BackupError("Decrypted backup content is corrupt.")

    if payload.get("format") != FORMAT_MARKER:
        raise BackupError("Decrypted content is not a valid PwnBroker configuration backup.")

    return payload


# created_by is a FK to users.id from the *exporting* database — users
# aren't part of this backup's scope, so that id may not exist at all after
# a rebuild, or may now belong to a completely different account. Restoring
# it verbatim risks an FK violation or silently mis-attributing the record
# to the wrong admin; leaving it untouched (new rows keep it NULL, existing
# rows keep whatever they already had) is the only safe default.
_RESTORE_SKIP_COLUMNS = {"created_by"}


def _apply_row(model, existing, fields: dict):
    """Set fields from a decrypted backup's dict onto a model instance.

    Datetime columns are detected from the column's actual SQLAlchemy type
    rather than a hand-maintained name list — the earlier version of this
    function used a fixed set of "known" datetime column names and it was
    already wrong (missed O365Config.last_tested_at/last_mailbox_sync_at/
    last_mail_poll_at and PaloAltoFirewall.last_log_time), silently leaving
    those as raw ISO strings instead of datetime objects after a restore.
    """
    columns = {c.name: c for c in model.__table__.columns}
    for col_name, value in fields.items():
        col = columns.get(col_name)
        if col is None or col_name in _RESTORE_SKIP_COLUMNS:
            continue  # unknown column (older/newer app version) or deliberately skipped
        if value is not None and isinstance(col.type, db.DateTime):
            try:
                value = datetime.fromisoformat(value)
            except (ValueError, TypeError):
                value = None
        setattr(existing, col_name, value)


def restore_backup(payload: dict) -> dict:
    """Apply a decrypted backup payload to the database. Upserts:
    - Each of the 7 singleton configs (create if none exists, else overwrite
      every field on the existing row).
    - PaloAltoFirewall rows, matched by `name` (create if no firewall with
      that name exists, else overwrite).
    - Target rows, matched by `host` (create if no target with that host
      exists, else overwrite — including its SSH credential fields).

    Matching by name/host rather than id means restoring into a database
    that already has *some* of these records (not just a totally empty
    rebuilt one) updates them in place instead of creating duplicates.
    Returns a summary dict of what was created/updated for a confirmation
    message.
    """
    from . import models

    summary = {"configs_restored": 0, "firewalls_created": 0, "firewalls_updated": 0,
               "targets_created": 0, "targets_updated": 0}

    for model_name, key in _SINGLETON_CONFIGS:
        fields = payload.get("configs", {}).get(key)
        if not fields:
            continue
        model = getattr(models, model_name)
        row = model.query.first()
        if not row:
            row = model()
            db.session.add(row)
        _apply_row(model, row, fields)
        summary["configs_restored"] += 1

    for fw_fields in payload.get("paloalto_firewalls", []):
        name = fw_fields.get("name")
        if not name:
            continue
        existing = models.PaloAltoFirewall.query.filter_by(name=name).first()
        if existing:
            _apply_row(models.PaloAltoFirewall, existing, fw_fields)
            summary["firewalls_updated"] += 1
        else:
            fw = models.PaloAltoFirewall()
            _apply_row(models.PaloAltoFirewall, fw, fw_fields)
            db.session.add(fw)
            summary["firewalls_created"] += 1

    for t_fields in payload.get("targets", []):
        host = t_fields.get("host")
        if not host:
            continue
        existing = models.Target.query.filter_by(host=host).first()
        if existing:
            _apply_row(models.Target, existing, t_fields)
            summary["targets_updated"] += 1
        else:
            t = models.Target()
            _apply_row(models.Target, t, t_fields)
            db.session.add(t)
            summary["targets_created"] += 1

    db.session.commit()
    return summary
