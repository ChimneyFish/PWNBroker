"""
License verification and enforcement.

A license is a small JSON payload signed with the vendor's Ed25519 private key
(tools/licensing/pwnbroker_license.py). The app only holds the PUBLIC key
below, so it can check a license but not mint one; editing the expiry inside
a license file breaks the signature.

Lifecycle (all dates UTC, `expires` is inclusive — valid through that day):
    valid      more than WARN_DAYS left           → full access
    expiring   WARN_DAYS or fewer left            → full access + renewal banner
    grace      expired, within grace_days         → READ-ONLY: browsing/reporting
                                                    works, changes and scheduled
                                                    jobs stop, agents keep reporting
    locked     expired past grace / missing /     → everything redirects to the
               invalid / wrong install / clock      License page
               rolled back

Works fully offline. Files live in LICENSE_DIR (default data/):
    license.key          the installed license
    install_id.txt       random per-install ID, for optionally binding a license
    license_state.json   highest clock time seen (rollback detection)
"""
import base64
import json
import os
import threading
import uuid
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEANUcM7QnDQi9DgNKyyGvL+uKwyc4F57FiJ8H4gt+quPM=
-----END PUBLIC KEY-----
"""

WARN_DAYS = 30
DEFAULT_GRACE_DAYS = 14
# Clock may legitimately drift/be corrected backwards a little (NTP, DST
# misconfig); only a larger jump back is treated as tampering.
CLOCK_TOLERANCE = timedelta(hours=48)
_STATE_WRITE_INTERVAL = timedelta(hours=1)

LICENSE_FILE = "license.key"
INSTALL_ID_FILE = "install_id.txt"
STATE_FILE = "license_state.json"

_lock = threading.Lock()
_cache = {}  # (path, mtime, pubkey) -> (payload | None, error | None)


class LicenseError(ValueError):
    pass


@dataclass
class LicenseStatus:
    state: str                      # valid | expiring | grace | locked
    message: str
    payload: dict = field(default_factory=dict)
    days_left: int | None = None    # days until expiry (negative once expired)
    grace_left: int | None = None   # days of read-only grace remaining

    @property
    def full_access(self):
        return self.state in ("valid", "expiring")

    @property
    def read_only(self):
        return self.state == "grace"

    @property
    def locked(self):
        return self.state == "locked"

    @property
    def customer(self):
        return self.payload.get("customer")

    @property
    def expires(self):
        return self.payload.get("expires")


# ── paths / config ──────────────────────────────────────────────────────────

def _dir(app):
    return app.config["LICENSE_DIR"]


def _public_key(app):
    pem = app.config.get("LICENSE_PUBLIC_KEY") or _PUBLIC_KEY_PEM
    return serialization.load_pem_public_key(pem.encode())


def install_id(app):
    """Stable random ID for this install. Shown on the License page so a
    customer can send it in when buying, if you choose to bind licenses."""
    path = os.path.join(_dir(app), INSTALL_ID_FILE)
    try:
        with open(path) as f:
            v = f.read().strip()
            if v:
                return v
    except FileNotFoundError:
        pass
    os.makedirs(_dir(app), exist_ok=True)
    v = uuid.uuid4().hex[:16].upper()
    v = "-".join(v[i:i + 4] for i in range(0, 16, 4))
    with open(path, "w") as f:
        f.write(v)
    return v


# ── parsing / verification ──────────────────────────────────────────────────

def _unb64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def parse_and_verify(text, app):
    """Return the payload dict of a correctly-signed license, else raise
    LicenseError. Accepts the armored file or just the inner token."""
    body = "".join(l.strip() for l in (text or "").splitlines()
                   if l.strip() and not l.strip().startswith("-----"))
    if "." not in body:
        raise LicenseError("Not a PWNBroker license.")
    p_b64, s_b64 = body.split(".", 1)
    try:
        sig = _unb64(s_b64)
        _public_key(app).verify(sig, p_b64.encode())
    except (InvalidSignature, ValueError):
        raise LicenseError("License signature is invalid — the file was altered or not issued by PWNBroker.")
    try:
        payload = json.loads(_unb64(p_b64))
        date.fromisoformat(payload["expires"])
        payload["customer"]
    except (ValueError, KeyError, TypeError):
        raise LicenseError("License contents are malformed.")
    bound = payload.get("install_id")
    if bound and bound != install_id(app):
        raise LicenseError(f"This license is bound to install {bound}, not this one ({install_id(app)}).")
    return payload


def _load(app):
    path = os.path.join(_dir(app), LICENSE_FILE)
    try:
        mtime = os.stat(path).st_mtime_ns
    except FileNotFoundError:
        return None, "No license installed."
    key = (path, mtime, app.config.get("LICENSE_PUBLIC_KEY"))
    with _lock:
        if key in _cache:
            return _cache[key]
    try:
        with open(path) as f:
            result = (parse_and_verify(f.read(), app), None)
    except LicenseError as e:
        result = (None, str(e))
    with _lock:
        _cache.clear()
        _cache[key] = result
    return result


def install_license(text, app):
    """Verify and atomically install a license. Raises LicenseError."""
    payload = parse_and_verify(text, app)
    os.makedirs(_dir(app), exist_ok=True)
    path = os.path.join(_dir(app), LICENSE_FILE)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(text.strip() + "\n")
    os.replace(tmp, path)
    return payload


# ── clock rollback ──────────────────────────────────────────────────────────

def _check_clock(app, now):
    """Record the highest time seen; report if the clock is now far behind it
    (someone winding the date back to stretch an expired license)."""
    path = os.path.join(_dir(app), STATE_FILE)
    last = None
    try:
        with open(path) as f:
            last = datetime.fromisoformat(json.load(f)["last_seen"])
    except (FileNotFoundError, ValueError, KeyError, TypeError):
        pass
    if last and now < last - CLOCK_TOLERANCE:
        return f"System clock is behind the last time this install was seen running ({last:%Y-%m-%d %H:%M} UTC). Correct the server time."
    if last is None or now - last > _STATE_WRITE_INTERVAL:
        try:
            os.makedirs(_dir(app), exist_ok=True)
            tmp = path + ".tmp"
            with open(tmp, "w") as f:
                json.dump({"last_seen": now.isoformat()}, f)
            os.replace(tmp, path)
        except OSError:
            pass
    return None


# ── status ──────────────────────────────────────────────────────────────────

def status(app, now=None):
    now = now or datetime.now(timezone.utc)
    payload, err = _load(app)
    if err:
        return LicenseStatus("locked", err)

    clock_err = _check_clock(app, now)
    if clock_err:
        return LicenseStatus("locked", clock_err, payload)

    expires = date.fromisoformat(payload["expires"])
    days_left = (expires - now.date()).days
    grace = int(payload.get("grace_days", DEFAULT_GRACE_DAYS))

    if days_left < 0:
        grace_left = grace + days_left  # days_left is negative
        if grace_left >= 0:
            return LicenseStatus(
                "grace",
                f"License expired on {expires:%b %d, %Y}. PWNBroker is read-only — "
                f"scans and changes are paused. Full lock in {grace_left + 1} day(s).",
                payload, days_left, grace_left)
        return LicenseStatus("locked", f"License expired on {expires:%b %d, %Y}.",
                             payload, days_left, 0)
    if days_left <= WARN_DAYS:
        return LicenseStatus("expiring",
                             f"License expires in {days_left} day(s) ({expires:%b %d, %Y}).",
                             payload, days_left)
    return LicenseStatus("valid", f"Licensed through {expires:%b %d, %Y}.", payload, days_left)


# ── enforcement ─────────────────────────────────────────────────────────────

# Always reachable, whatever the license state: getting in, fixing the
# license, and the forced password-change / MFA-setup flows (which have their
# own redirects — not exempting them here would ping-pong between the two).
_EXEMPT_ENDPOINTS = {
    "static", "_healthz",
    "license.index", "license.upload",
    "users.profile", "users.mfa_setup",
}
_EXEMPT_PREFIXES = ("auth.",)
# Machine-to-machine ingestion (endpoint agents). Keeps reporting during the
# grace period so monitoring doesn't go dark the day a renewal is late.
_AGENT_PREFIXES = ("threat.api_",)


def _is_exempt(endpoint):
    return endpoint in _EXEMPT_ENDPOINTS or endpoint.startswith(_EXEMPT_PREFIXES)


def _wants_html(request):
    return "text/html" in (request.headers.get("Accept") or "")


def init_app(app):
    from flask import flash, g, jsonify, redirect, request, url_for

    app.config.setdefault("LICENSE_DIR", os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data"))

    def _deny(msg):
        if _wants_html(request) and request.method == "GET":
            return redirect(url_for("license.index"))
        if _wants_html(request):
            flash(msg, "danger")
            return redirect(request.referrer or url_for("license.index"))
        return jsonify({"ok": False, "error": msg}), 402

    @app.before_request
    def _enforce_license():
        st = status(app)
        g.license = st
        if st.full_access:
            return None
        ep = request.endpoint or ""
        if _is_exempt(ep):
            return None
        if st.read_only:
            if request.method in ("GET", "HEAD", "OPTIONS") or ep.startswith(_AGENT_PREFIXES):
                return None
            return _deny("License expired — PWNBroker is read-only until a renewed license is installed.")
        return _deny(st.message)

    @app.context_processor
    def _license_ctx():
        from flask import g as _g
        return {"license_status": getattr(_g, "license", None)}


def licensed_job(app, fn):
    """Wrap a scheduler job so it only runs with full license access."""
    def _wrapped(*a, **kw):
        st = status(app)
        if not st.full_access:
            app.logger.warning(f"Skipping scheduled job {fn.__name__}: {st.message}")
            return None
        return fn(*a, **kw)
    _wrapped.__name__ = fn.__name__
    return _wrapped
