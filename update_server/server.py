"""
PWNBroker update server — vendor-hosted, listens on port 7585.

Installs POST their license to /v1/check; an active license gets the newest
release for its channel plus a short-lived download link. Releases are
published by dropping a built release directory (tools/release/build_release.py
publish) into $PWNUPD_ROOT/releases/<version>/.

    $PWNUPD_ROOT/
        releases/<version>/{manifest.json, manifest.sig, pwnbroker-<v>.tar.gz,
                            pwnbroker-<v>-install.run}   (installer: optional)
        yanked.txt          versions to stop offering (one per line)
        revoked.txt         license IDs to refuse (one per line)
        server_secret.txt   HMAC key for download tokens (auto-created)
        checkins.db         last check-in per install (who's on what version)

The server never signs anything: releases arrive pre-signed, so a compromise
of this box can't push malicious code to customers (installs verify the
release signature with a key this server doesn't have).

Customers reach it at https://pwnbroker.space:7585/updates.

Run:  gunicorn -b 0.0.0.0:7585 --certfile cert.pem --keyfile key.pem 'server:create_app()'
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from datetime import date, datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from flask import Flask, abort, jsonify, request, send_file

TOKEN_TTL = 3600
# Customers use https://pwnbroker.space:7585/updates, so routes are
# served under this prefix. They also answer at / so a reverse proxy that
# strips the prefix still works. Override with PWNUPD_PREFIX.
DEFAULT_PREFIX = "/updates"


class _PrefixMiddleware:
    def __init__(self, wsgi_app, prefix):
        self.wsgi_app, self.prefix = wsgi_app, prefix.rstrip("/")

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "")
        if self.prefix and (path == self.prefix or path.startswith(self.prefix + "/")):
            environ["SCRIPT_NAME"] = environ.get("SCRIPT_NAME", "") + self.prefix
            environ["PATH_INFO"] = path[len(self.prefix):] or "/"
        return self.wsgi_app(environ, start_response)
CHANNEL_ACCESS = {"stable": ("stable",), "beta": ("stable", "beta")}


def _vt(v):
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", v or "")
    return tuple(int(x) for x in m.groups()) if m else None


def _unb64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def create_app(root=None, license_public_key_pem=None, prefix=None):
    app = Flask(__name__)
    app.wsgi_app = _PrefixMiddleware(app.wsgi_app, prefix if prefix is not None
                                     else os.environ.get("PWNUPD_PREFIX", DEFAULT_PREFIX))
    root = root or os.environ.get("PWNUPD_ROOT", "/srv/pwnbroker-updates")
    rel_dir = os.path.join(root, "releases")
    os.makedirs(rel_dir, exist_ok=True)
    app.config["MAX_CONTENT_LENGTH"] = 256 * 1024

    pem = license_public_key_pem
    if pem is None:
        key_path = os.path.expanduser(os.environ.get(
            "PWNUPD_LICENSE_PUBKEY", "~/.pwnbroker-license/public_key.pem"))
        pem = open(key_path).read()
    lic_key = serialization.load_pem_public_key(pem.encode())

    secret_path = os.path.join(root, "server_secret.txt")
    if not os.path.exists(secret_path):
        fd = os.open(secret_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_hex(32))
    secret = open(secret_path).read().strip().encode()

    db_path = os.path.join(root, "checkins.db")
    with sqlite3.connect(db_path) as con:
        con.execute("""CREATE TABLE IF NOT EXISTS checkins (
            license_id TEXT, install_id TEXT, customer TEXT, version TEXT, channel TEXT,
            ip TEXT, last_seen TEXT, PRIMARY KEY (license_id, install_id))""")

    def _lines(name):
        try:
            return {l.strip() for l in open(os.path.join(root, name)) if l.strip() and not l.startswith("#")}
        except FileNotFoundError:
            return set()

    def _verify_license(text):
        body = "".join(l.strip() for l in (text or "").splitlines()
                       if l.strip() and not l.strip().startswith("-----"))
        try:
            p_b64, s_b64 = body.split(".", 1)
            lic_key.verify(_unb64(s_b64), p_b64.encode())
            payload = json.loads(_unb64(p_b64))
            expires = date.fromisoformat(payload["expires"])
        except (ValueError, KeyError, InvalidSignature, TypeError):
            return None, ("Invalid license.", 403)
        if payload.get("license_id") in _lines("revoked.txt"):
            return None, ("This license has been revoked.", 403)
        if expires < datetime.now(timezone.utc).date():
            return None, (f"License expired on {expires} — renew to receive updates.", 402)
        return payload, None

    def _releases(channels):
        yanked = _lines("yanked.txt")
        out = []
        for v in os.listdir(rel_dir):
            d = os.path.join(rel_dir, v)
            if not (_vt(v) and v not in yanked and os.path.exists(os.path.join(d, "manifest.sig"))):
                continue
            try:
                raw = open(os.path.join(d, "manifest.json"), "rb").read()
                m = json.loads(raw)
            except (OSError, ValueError):
                continue
            if m.get("version") == v and m.get("channel") in channels:
                out.append((_vt(v), v, raw, m))
        return sorted(out, reverse=True)

    def _token(version, license_id, exp):
        msg = f"{version}|{license_id}|{exp}".encode()
        return hmac.new(secret, msg, hashlib.sha256).hexdigest()

    @app.get("/v1/health")
    def health():
        return jsonify({"ok": True})

    @app.post("/v1/check")
    def check():
        body = request.get_json(silent=True) or {}
        payload, err = _verify_license(body.get("license"))
        if err:
            return jsonify({"error": err[0]}), err[1]
        install_id = str(body.get("install_id") or "")[:64]
        if payload.get("install_id") and payload["install_id"] != install_id:
            return jsonify({"error": "License is bound to a different install."}), 403
        channel = body.get("channel") if body.get("channel") in CHANNEL_ACCESS else "stable"
        current = _vt(str(body.get("version") or "")) or (0, 0, 0)

        with sqlite3.connect(db_path) as con:
            con.execute("INSERT OR REPLACE INTO checkins VALUES (?,?,?,?,?,?,?)", (
                payload.get("license_id"), install_id, payload.get("customer"),
                str(body.get("version"))[:20], channel, request.remote_addr,
                datetime.now(timezone.utc).isoformat(timespec="seconds")))

        rels = _releases(CHANNEL_ACCESS[channel])
        if not rels or rels[0][0] <= current:
            return jsonify({"update": False, "latest": rels[0][1] if rels else None})
        _, v, raw, m = rels[0]
        exp = int(time.time()) + TOKEN_TTL
        lid = payload.get("license_id", "")
        sig = open(os.path.join(rel_dir, v, "manifest.sig")).read().strip()
        return jsonify({
            "update": True, "version": v, "released": m.get("released"),
            "changelog": m.get("changelog", ""),
            "manifest": raw.decode(), "signature": sig,
            "download": f"/v1/download/{v}?l={lid}&e={exp}&t={_token(v, lid, exp)}",
        })

    @app.get("/v1/download/<version>")
    def download(version):
        if not _vt(version):
            abort(404)
        lid, exp, tok = request.args.get("l", ""), request.args.get("e", "0"), request.args.get("t", "")
        if not exp.isdigit() or int(exp) < time.time() or \
                not hmac.compare_digest(tok, _token(version, lid, int(exp))):
            return jsonify({"error": "Download link expired or invalid."}), 403
        if lid in _lines("revoked.txt") or version in _lines("yanked.txt"):
            return jsonify({"error": "Not available."}), 403
        path = os.path.join(rel_dir, version, f"pwnbroker-{version}.tar.gz")
        if not os.path.exists(path):
            abort(404)
        return send_file(path, mimetype="application/gzip", as_attachment=True)

    @app.post("/v1/installer")
    def installer():
        """Single-file installer for a new server, for anyone holding an active
        license. The body is the license key file as-is (or JSON {"license": …}):

            curl -fsS --data-binary @license.key \\
                 https://pwnbroker.space:7585/updates/v1/installer -o pwnbroker-install.run
        """
        body = request.get_json(silent=True)
        text = body.get("license") if isinstance(body, dict) else request.get_data(as_text=True)
        payload, err = _verify_license(text)
        if err:
            return jsonify({"error": err[0]}), err[1]
        channel = request.args.get("channel") if request.args.get("channel") in CHANNEL_ACCESS else "stable"
        for _, v, _, _ in _releases(CHANNEL_ACCESS[channel]):
            path = os.path.join(rel_dir, v, f"pwnbroker-{v}-install.run")
            if os.path.exists(path):
                with sqlite3.connect(db_path) as con:
                    con.execute("INSERT OR REPLACE INTO checkins VALUES (?,?,?,?,?,?,?)", (
                        payload.get("license_id"), "installer-download", payload.get("customer"), v,
                        channel, request.remote_addr,
                        datetime.now(timezone.utc).isoformat(timespec="seconds")))
                return send_file(path, mimetype="application/octet-stream", as_attachment=True,
                                 download_name=f"pwnbroker-{v}-install.run")
        return jsonify({"error": "No installer has been published yet."}), 404

    return app
