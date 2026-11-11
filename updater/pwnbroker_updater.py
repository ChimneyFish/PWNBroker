#!/usr/bin/env python3
"""
PWNBroker updater — runs as root from systemd (pwnbroker-updater.timer hourly,
plus pwnbroker-updater.path when an admin clicks "Check"/"Install" in the UI).

The web app itself never modifies its own code: it runs sandboxed as the
unprivileged `pwnbroker` user (ProtectSystem=strict) and can only drop a
request file into data/. This separate process does the privileged work, and
will only ever install a release whose manifest is signed by the vendor's
release key below — so even a compromised web app can at most trigger an
update to a genuine, newer release.

Install sequence (any failure after the stop rolls everything back):
    check server → verify manifest signature → download → verify sha256
    → stop service → back up code + data/ → apply files → pip install
      (only if requirements changed) → post-install hook → start service
    → health check → done          (failure → restore backup → start → report)

    run                  timer/path entry point: honors data/update_request.json,
                         auto-update setting and maintenance window
    check                ask the server, print what's available
    install [--offline F.pwnupdate] [--force]
    rollback             restore the most recent backup
    status               print data/update_status.json

Stdlib + `cryptography` only (already in the app's venv).
"""
import argparse
import base64
import fcntl
import hashlib
import json
import os
import re
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

_RELEASE_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAMmlMkCCvulXgVyvT52pFoo+N7YP+6x1nniCm3zERAwo=
-----END PUBLIC KEY-----
"""
DEFAULT_UPDATE_URL = "https://pwnbroker.space:7585/updates"   # overridden by PWNBROKER_UPDATE_URL in .env
CHANNELS = ("stable", "beta")
KEEP_BACKUPS = 3
HEALTH_TIMEOUT = 180

# Never deleted, overwritten or included in code backups: runtime state and
# things setup.sh installs next to the code.
PRESERVE = ("data", "logs", "evidence_uploads", "venv", "docker", ".git", ".env",
            "tools/pen", "tools/reaper", "tools/backdoor_detector", "tools/nuclei", "releases_out",
            "app/static/agent/PwnBrokerAgentSetup.exe")
RELEASE_FILES = ".release_files"


class UpdateError(Exception):
    pass


def _now():
    return datetime.now(timezone.utc)


def parse_version(v):
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", (v or "").strip())
    if not m:
        raise UpdateError(f"Bad version string {v!r}")
    return tuple(int(x) for x in m.groups())


def _preserved(rel):
    rel = rel.strip("/")
    return any(rel == p or rel.startswith(p + "/") for p in PRESERVE)


class Updater:
    service = "pwnbroker"

    def __init__(self, install_dir, backup_dir=None, unit_file=None, public_key_pem=None):
        self.dir = os.path.abspath(install_dir)
        self.data = os.path.join(self.dir, "data")
        self.backup_dir = backup_dir or os.environ.get("PWNBROKER_BACKUP_DIR", "/var/backups/pwnbroker")
        self.unit_file = unit_file or f"/etc/systemd/system/{self.service}.service"
        self.pubkey = serialization.load_pem_public_key(
            (public_key_pem or _RELEASE_PUBLIC_KEY_PEM).encode())
        self.env = self._read_env()
        # requirements.txt hash the venv was last installed from (this run).
        self._installed_requirements_hash = self._requirements_hash()

    # ── small helpers ────────────────────────────────────────────────────────

    def _p(self, *parts):
        return os.path.join(self.dir, *parts)

    def _read_env(self):
        env = {}
        try:
            for line in open(self._p(".env")):
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    env[k.strip()] = v.strip().strip('"').strip("'")
        except FileNotFoundError:
            pass
        return env

    @property
    def update_url(self):
        return (os.environ.get("PWNBROKER_UPDATE_URL") or self.env.get("PWNBROKER_UPDATE_URL")
                or DEFAULT_UPDATE_URL).rstrip("/")

    def current_version(self):
        m = re.search(r'__version__\s*=\s*"([^"]+)"', open(self._p("app", "version.py")).read())
        return m.group(1) if m else "0.0.0"

    def _read_json(self, name, default):
        try:
            with open(os.path.join(self.data, name)) as f:
                return json.load(f)
        except (FileNotFoundError, ValueError):
            return default

    def _write_json(self, name, obj, mode=0o644):
        path = os.path.join(self.data, name)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(obj, f, indent=2)
        os.chmod(tmp, mode)
        os.replace(tmp, path)

    def settings(self):
        s = self._read_json("update_settings.json", {})
        out = {"auto_update": True, "channel": "stable", "window_start": 2, "window_end": 5}
        if isinstance(s.get("auto_update"), bool):
            out["auto_update"] = s["auto_update"]
        if s.get("channel") in CHANNELS:
            out["channel"] = s["channel"]
        for k in ("window_start", "window_end"):
            if isinstance(s.get(k), int) and 0 <= s[k] <= 23:
                out[k] = s[k]
        return out

    def status(self):
        return self._read_json("update_status.json", {})

    def set_status(self, state, message="", **extra):
        st = self.status()
        st.update({"state": state, "message": message, "current": self.current_version(),
                   "updated_at": _now().isoformat(timespec="seconds")}, **extra)
        if state in ("installed", "rolled_back", "error"):
            hist = st.get("history", [])
            hist.insert(0, {"at": st["updated_at"], "state": state, "message": message})
            st["history"] = hist[:15]
        self._write_json("update_status.json", st)
        print(f"[{state}] {message}")

    def log(self, msg):
        print(msg, flush=True)

    # ── server ───────────────────────────────────────────────────────────────

    def _ssl_ctx(self):
        ca = os.environ.get("PWNBROKER_UPDATE_CA") or self.env.get("PWNBROKER_UPDATE_CA")
        return ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()

    def _http(self, path, body=None, timeout=60):
        url = self.update_url + path
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, headers={
            "Content-Type": "application/json", "User-Agent": f"pwnbroker-updater/{self.current_version()}"})
        ctx = self._ssl_ctx() if url.startswith("https") else None
        try:
            return urllib.request.urlopen(req, timeout=timeout, context=ctx)
        except urllib.error.HTTPError as e:
            try:
                msg = json.loads(e.read()).get("error")
            except Exception:
                msg = None
            raise UpdateError(msg or f"Update server returned HTTP {e.code}")
        except (urllib.error.URLError, socket.timeout, OSError) as e:
            raise UpdateError(f"Can't reach update server {self.update_url}: {getattr(e, 'reason', e)}")

    def check(self, channel):
        try:
            lic = open(os.path.join(self.data, "license.key")).read()
        except FileNotFoundError:
            raise UpdateError("No license installed — updates require an active license.")
        try:
            install_id = open(os.path.join(self.data, "install_id.txt")).read().strip()
        except FileNotFoundError:
            install_id = ""
        with self._http("/v1/check", {"license": lic, "install_id": install_id,
                                      "version": self.current_version(), "channel": channel}) as r:
            return json.loads(r.read())

    def download(self, path, dest):
        with self._http(path, timeout=300) as r, open(dest, "wb") as f:
            shutil.copyfileobj(r, f)

    # ── verification ─────────────────────────────────────────────────────────

    def verify_manifest(self, raw, sig_b64, force=False):
        try:
            self.pubkey.verify(base64.b64decode(sig_b64), raw)
        except (InvalidSignature, ValueError):
            raise UpdateError("Release signature is INVALID — refusing to install.")
        m = json.loads(raw)
        if m.get("product") != "pwnbroker":
            raise UpdateError("Release is not for PWNBroker.")
        new, cur = parse_version(m["version"]), parse_version(self.current_version())
        if new < cur or (new == cur and not force):
            raise UpdateError(f"Release {m['version']} is not newer than installed {self.current_version()}.")
        return m

    @staticmethod
    def verify_archive(path, manifest):
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        if h.hexdigest() != manifest["sha256"]:
            raise UpdateError("Downloaded release doesn't match its signed checksum — refusing to install.")

    # ── service control (overridable in tests) ───────────────────────────────

    def systemctl(self, *args):
        subprocess.run(["systemctl", *args, self.service], check=True)

    def health_url(self):
        try:
            unit = open(self.unit_file).read()
        except FileNotFoundError:
            return "https://127.0.0.1:443/healthz"
        bind = re.search(r"--bind\s+(\S+)", unit)
        host, _, port = (bind.group(1) if bind else "0.0.0.0:443").rpartition(":")
        host = "127.0.0.1" if host in ("", "0.0.0.0", "[::]", "::") else host
        scheme = "https" if "--certfile" in unit else "http"
        return f"{scheme}://{host}:{port}/healthz"

    def wait_healthy(self, timeout=HEALTH_TIMEOUT):
        url = self.health_url()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE   # local self-signed cert
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(url, timeout=5, context=ctx if url.startswith("https") else None) as r:
                    if r.status == 200:
                        return True
            except Exception:
                pass
            time.sleep(3)
        return False

    def pip_install(self):
        subprocess.run([self._p("venv", "bin", "python3"), "-m", "pip", "install", "-q",
                        "-r", self._p("requirements.txt")], check=True)
        subprocess.run(["chown", "-R", "pwnbroker:pwnbroker", self._p("venv")], check=False)

    def run_post_install(self):
        hook = self._p("updater", "post_install.py")
        if os.path.exists(hook):
            subprocess.run([self._p("venv", "bin", "python3"), hook], check=True,
                           env={**os.environ, "PWNBROKER_INSTALL_DIR": self.dir})

    def scans_running(self):
        url = self.env.get("DATABASE_URL", f"sqlite:///{self._p('data', 'scanner.db')}")
        if not url.startswith("sqlite:///"):
            return False
        try:
            con = sqlite3.connect(f"file:{url[len('sqlite:///'):]}?mode=ro", uri=True, timeout=5)
            n = con.execute("SELECT COUNT(*) FROM scans WHERE status = 'running'").fetchone()[0]
            con.close()
            return n > 0
        except sqlite3.Error:
            return False

    # ── backup / restore ─────────────────────────────────────────────────────

    def _requirements_hash(self):
        try:
            return hashlib.sha256(open(self._p("requirements.txt"), "rb").read()).hexdigest()
        except FileNotFoundError:
            return ""

    def _code_paths(self):
        for root, dirs, files in os.walk(self.dir):
            rel_root = os.path.relpath(root, self.dir)
            rel_root = "" if rel_root == "." else rel_root
            dirs[:] = [d for d in dirs if not _preserved(os.path.join(rel_root, d))
                       and d != "__pycache__"]
            for f in files:
                rel = os.path.join(rel_root, f)
                if not _preserved(rel):
                    yield rel

    def backup(self, to_version):
        ts = _now().strftime("%Y%m%dT%H%M%SZ")
        d = os.path.join(self.backup_dir, f"{ts}_{self.current_version()}")
        os.makedirs(d, mode=0o700)
        with tarfile.open(os.path.join(d, "code.tar.gz"), "w:gz") as t:
            for rel in self._code_paths():
                t.add(self._p(rel), arcname=rel, recursive=False)
        with tarfile.open(os.path.join(d, "data.tar.gz"), "w:gz") as t:
            t.add(self.data, arcname="data",
                  filter=lambda ti: None if ti.name.startswith(
                      ("data/logs", "data/.update", "data/nuclei-templates", "data/nuclei-home")) else ti)
        meta = {"from_version": self.current_version(), "to_version": to_version,
                "created": _now().isoformat(timespec="seconds"),
                "requirements_sha256": self._requirements_hash()}
        json.dump(meta, open(os.path.join(d, "meta.json"), "w"), indent=2)
        self._prune_backups()
        return d

    def _prune_backups(self):
        dirs = sorted(x for x in os.listdir(self.backup_dir)
                      if os.path.isdir(os.path.join(self.backup_dir, x)))
        for old in dirs[:-KEEP_BACKUPS]:
            shutil.rmtree(os.path.join(self.backup_dir, old), ignore_errors=True)

    def latest_backup(self):
        try:
            dirs = sorted(x for x in os.listdir(self.backup_dir)
                          if os.path.exists(os.path.join(self.backup_dir, x, "meta.json")))
        except FileNotFoundError:
            dirs = []
        if not dirs:
            raise UpdateError(f"No backups found in {self.backup_dir}")
        return os.path.join(self.backup_dir, dirs[-1])

    @staticmethod
    def _extract(tar, dest):
        try:
            tar.extractall(dest, filter="data")
        except TypeError:  # Python without extraction filters
            tar.extractall(dest)

    def restore(self, backup):
        """Put code and data/ back exactly as they were before an update."""
        meta = json.load(open(os.path.join(backup, "meta.json")))
        for rel in self._code_paths():
            try:
                os.remove(self._p(rel))
            except OSError:
                pass
        with tarfile.open(os.path.join(backup, "code.tar.gz")) as t:
            self._extract(t, self.dir)
        db_files = [f for f in os.listdir(self.data) if f.endswith(("-wal", "-shm"))]
        for f in db_files:
            os.remove(os.path.join(self.data, f))
        with tarfile.open(os.path.join(backup, "data.tar.gz")) as t:
            self._extract(t, self.dir)
        subprocess.run(["chown", "-R", "pwnbroker:pwnbroker", self.data], check=False)
        if meta.get("requirements_sha256") != self._installed_requirements_hash:
            # The failed update may have upgraded packages — put the old pins back.
            try:
                self.pip_install()
            except Exception as e:
                self.log(f"pip reinstall during rollback failed: {e}")
        return meta

    # ── install ──────────────────────────────────────────────────────────────

    def apply(self, archive, manifest):
        new_files = set(manifest["files"])
        old_files = set(self._read_release_files())
        for rel in old_files - new_files:
            if not _preserved(rel):
                try:
                    os.remove(self._p(rel))
                except OSError:
                    pass
        with tarfile.open(archive) as t:
            members = [m for m in t.getmembers() if not _preserved(m.name)]
            try:
                t.extractall(self.dir, members=members, filter="data")
            except TypeError:
                t.extractall(self.dir, members=members)
        with open(self._p(RELEASE_FILES), "w") as f:
            json.dump(sorted(new_files), f)

    def _read_release_files(self):
        try:
            return json.load(open(self._p(RELEASE_FILES)))
        except (FileNotFoundError, ValueError):
            return []

    def install(self, raw_manifest, sig_b64, archive, force=False):
        manifest = self.verify_manifest(raw_manifest, sig_b64, force=force)
        self.verify_archive(archive, manifest)
        old_version = self.current_version()
        self.set_status("installing", f"Installing {manifest['version']} (from {old_version})…")

        old_req = self._requirements_hash()
        backup = None
        try:
            self.systemctl("stop")
            backup = self.backup(manifest["version"])
            self.apply(archive, manifest)
            if self._requirements_hash() != old_req:
                self.log("requirements.txt changed — installing dependencies")
                self._installed_requirements_hash = self._requirements_hash()
                self.pip_install()
            self.run_post_install()
            self.systemctl("start")
            if not self.wait_healthy():
                raise UpdateError("PWNBroker didn't come back healthy after the update.")
        except Exception as e:
            reason = str(e) or e.__class__.__name__
            self.log(f"Update failed: {reason} — rolling back")
            try:
                self.systemctl("stop")
            except Exception:
                pass
            if backup:
                self.restore(backup)
            self.systemctl("start")
            healthy = self.wait_healthy()
            self.set_status("rolled_back",
                            f"Update to {manifest['version']} failed ({reason}); restored {old_version}"
                            + ("" if healthy else " — WARNING: service not healthy after rollback, check journalctl -u pwnbroker"),
                            available=None)
            raise UpdateError(reason)
        self.set_status("installed", f"Updated {old_version} → {manifest['version']}", available=None,
                        changelog=manifest.get("changelog", ""))
        return manifest

    def install_from_server(self, info, force=False):
        with tempfile.TemporaryDirectory(prefix="pwnbroker-update-") as tmp:
            archive = os.path.join(tmp, "release.tar.gz")
            self.download(info["download"], archive)
            return self.install(info["manifest"].encode(), info["signature"], archive, force=force)

    def install_offline(self, bundle, force=False):
        with tempfile.TemporaryDirectory(prefix="pwnbroker-update-") as tmp:
            with tarfile.open(bundle) as t:
                names = set(t.getnames())
                if not {"manifest.json", "manifest.sig"} <= names:
                    raise UpdateError("Not a PWNBroker update bundle.")
                raw = t.extractfile("manifest.json").read()
                sig = t.extractfile("manifest.sig").read().decode()
                manifest = self.verify_manifest(raw, sig, force=force)
                if manifest["file"] not in names:
                    raise UpdateError("Update bundle is missing its release archive.")
                archive = os.path.join(tmp, "release.tar.gz")
                with open(archive, "wb") as f:
                    shutil.copyfileobj(t.extractfile(manifest["file"]), f)
            return self.install(raw, sig, archive, force=force)

    # ── scheduled entry point ────────────────────────────────────────────────

    def in_window(self, s, now=None):
        h = (now or datetime.now()).hour   # server local time
        a, b = s["window_start"], s["window_end"]
        if a == b:
            return True
        return a <= h < b if a < b else (h >= a or h < b)

    def pop_request(self):
        path = os.path.join(self.data, "update_request.json")
        try:
            with open(path) as f:
                req = json.load(f)
        except (FileNotFoundError, ValueError):
            req = None
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        if isinstance(req, dict) and req.get("action") in ("check", "install", "install_offline"):
            return req["action"]
        return None

    def run(self):
        action = self.pop_request()
        s = self.settings()

        if action == "install_offline":
            bundle = os.path.join(self.data, "update_offline.pwnupdate")
            try:
                self.install_offline(bundle)
            except Exception as e:
                if self.status().get("state") != "rolled_back":
                    self.set_status("error", str(e))
            finally:
                if os.path.exists(bundle):
                    os.remove(bundle)
            return

        self.set_status("checking", "Checking for updates…")
        try:
            info = self.check(s["channel"])
        except UpdateError as e:
            self.set_status("error", str(e), last_check=_now().isoformat(timespec="seconds"))
            return
        checked = _now().isoformat(timespec="seconds")
        if not info.get("update"):
            self.set_status("up_to_date", f"PWNBroker {self.current_version()} is the latest {s['channel']} release.",
                            last_check=checked, available=None, latest=info.get("latest"))
            return

        avail = {k: info.get(k) for k in ("version", "changelog", "released")}
        try:
            parse_version(avail["version"])   # server data is untrusted until the manifest is verified
        except UpdateError as e:
            self.set_status("error", str(e), last_check=checked)
            return
        manual = action == "install"
        if not manual:
            if not s["auto_update"]:
                self.set_status("available", f"Version {avail['version']} is available.",
                                last_check=checked, available=avail)
                return
            if not self.in_window(s):
                self.set_status("available", f"Version {avail['version']} will install during the "
                                f"{s['window_start']:02d}:00–{s['window_end']:02d}:00 maintenance window.",
                                last_check=checked, available=avail)
                return
            if self.scans_running():
                self.set_status("available", f"Version {avail['version']} is waiting for running scans to finish.",
                                last_check=checked, available=avail)
                return
        try:
            self.install_from_server(info)
        except Exception as e:
            if self.status().get("state") != "rolled_back":
                self.set_status("error", str(e), last_check=checked, available=avail)


def _lock(install_dir):
    path = "/run/lock/pwnbroker-updater.lock" if os.access("/run/lock", os.W_OK) \
        else os.path.join(install_dir, "data", ".updater.lock")
    fh = open(path, "w")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        sys.exit("Another updater run is in progress.")
    return fh


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--install-dir", default=os.environ.get(
        "PWNBROKER_INSTALL_DIR", os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("run"); sub.add_parser("check"); sub.add_parser("rollback"); sub.add_parser("status")
    i = sub.add_parser("install")
    i.add_argument("--offline", metavar="FILE.pwnupdate")
    i.add_argument("--force", action="store_true", help="reinstall even if not newer")
    args = ap.parse_args()

    u = Updater(args.install_dir)
    if args.cmd == "status":
        print(json.dumps(u.status(), indent=2)); return
    if os.geteuid() != 0 and args.cmd != "check":
        sys.exit("Must run as root.")
    _lock_fh = _lock(u.dir)  # noqa: F841 — held for the process lifetime
    try:
        if args.cmd == "run":
            u.run()
        elif args.cmd == "check":
            info = u.check(u.settings()["channel"])
            print(json.dumps({k: v for k, v in info.items() if k not in ("manifest", "signature")}, indent=2))
        elif args.cmd == "install":
            if args.offline:
                m = u.install_offline(args.offline, force=args.force)
            else:
                info = u.check(u.settings()["channel"])
                if not info.get("update") and not args.force:
                    print(f"Already on the latest release ({u.current_version()})."); return
                m = u.install_from_server(info, force=args.force)
            print(f"Installed {m['version']}")
        elif args.cmd == "rollback":
            b = u.latest_backup()
            u.systemctl("stop")
            meta = u.restore(b)
            u.systemctl("start")
            ok = u.wait_healthy()
            u.set_status("rolled_back", f"Manually rolled back to {meta['from_version']}"
                         + ("" if ok else " — service not healthy, check journalctl -u pwnbroker"))
    except UpdateError as e:
        sys.exit(f"Error: {e}")


if __name__ == "__main__":
    main()
