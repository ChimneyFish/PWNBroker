"""Test-only license signing with a throwaway Ed25519 key."""
import base64
import json
import uuid
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_KEY = Ed25519PrivateKey.generate()
TEST_PUBLIC_PEM = _KEY.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def _b64(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def make_license(days=365, customer="Test Co", key=None, **extra):
    """days: days until expiry from today (negative = already expired)."""
    today = datetime.now(timezone.utc).date()
    payload = {"v": 1, "license_id": str(uuid.uuid4()), "customer": customer,
               "issued": today.isoformat(),
               "expires": (today + timedelta(days=days)).isoformat(),
               "grace_days": 14, **extra}
    p = _b64(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    s = _b64((key or _KEY).sign(p.encode()))
    return f"-----BEGIN PWNBROKER LICENSE-----\n{p}.{s}\n-----END PWNBROKER LICENSE-----\n"
