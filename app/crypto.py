"""
Encryption-at-rest for secret DB columns (API keys, SSH credentials, firewall
credentials). Uses Fernet (symmetric, authenticated) with a key generated on
first boot and persisted to disk — same pattern as config.py's SECRET_KEY.

Encrypted values are prefixed "enc:v1:" so plaintext-vs-encrypted is always
detectable without a separate migration flag: encrypt()/migrate_plaintext()
are safe to call on every boot, not just once.
"""
import os
from cryptography.fernet import Fernet, InvalidToken

_PREFIX = "enc:v1:"
_fernet = None


def _key_path():
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, "data", "encryption_key.txt")


def _get_fernet():
    global _fernet
    if _fernet is not None:
        return _fernet

    path = _key_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        key = open(path, "rb").read().strip()
    else:
        key = Fernet.generate_key()
        with open(path, "wb") as f:
            f.write(key)
        os.chmod(path, 0o600)

    _fernet = Fernet(key)
    return _fernet


def is_encrypted(value):
    return isinstance(value, str) and value.startswith(_PREFIX)


def encrypt(value):
    """Encrypt a plaintext string. No-op (returns as-is) for None/empty/
    already-encrypted values, so this is safe to call idempotently."""
    if not value or is_encrypted(value):
        return value
    token = _get_fernet().encrypt(value.encode()).decode()
    return _PREFIX + token


def decrypt(value):
    """Decrypt a value produced by encrypt(). Returns legacy plaintext as-is
    (pre-migration values, or if called before the boot-time migration runs)."""
    if not value or not is_encrypted(value):
        return value
    token = value[len(_PREFIX):]
    try:
        return _get_fernet().decrypt(token.encode()).decode()
    except InvalidToken:
        # Wrong/rotated key — surface as missing rather than crash the caller.
        return None
