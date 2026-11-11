#!/usr/bin/env python3
"""PWNBroker release builder (vendor-side). Never ship the release private key.

    keygen                     create the Ed25519 release-signing keypair (once)
    build  [--channel C]       package the committed HEAD as a signed release
           [--notes TEXT | --notes-file F] [--bump major|minor|patch]
    publish VERSION DEST       rsync a built release to the update server,
                               e.g. root@pwnbroker.space:/srv/pwnbroker-updates/releases/
    installer VERSION          (re)build the single-file installer for a built release
    verify DIR                 check a built release's signature and hash

Output goes to releases_out/<version>/ (git-ignored):
    pwnbroker-<version>.tar.gz   the app files
    manifest.json                version, channel, sha256, changelog …
    manifest.sig                 Ed25519 signature over manifest.json (base64)
    pwnbroker-<version>.pwnupdate  all three in one file, for offline installs
    pwnbroker-<version>-install.run  single-file installer for new servers
                                   (sudo bash pwnbroker-<v>-install.run)

The release key is separate from the license key (a leak of one doesn't
compromise the other). Default location ~/.pwnbroker-release/ (override with
--key-dir or PWNBROKER_RELEASE_KEY_DIR). After keygen, paste the printed
public key into updater/pwnbroker_updater.py (_RELEASE_PUBLIC_KEY_PEM).
"""
import argparse
import base64
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT = os.path.join(ROOT, "releases_out")
VERSION_FILE = os.path.join(ROOT, "app", "version.py")
CHANNELS = ("stable", "beta")

# Vendor-only / dev-only paths that never go to customers.
EXCLUDE_PREFIXES = (
    "tests/", "tools/licensing/", "tools/release/", "update_server/",
    ".github/", ".claude/", "installer/", "docs/licensing.md", "docs/releasing.md",
    "pytest.ini",
)


def _key_dir(args):
    return os.path.expanduser(args.key_dir or os.environ.get("PWNBROKER_RELEASE_KEY_DIR")
                              or "~/.pwnbroker-release")


def _load_private(args):
    path = os.path.join(_key_dir(args), "release_private_key.pem")
    if not os.path.exists(path):
        sys.exit(f"No release key at {path} — run `keygen` first.")
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def _git(*a):
    return subprocess.run(["git", "-C", ROOT, *a], check=True,
                          capture_output=True).stdout


def read_version():
    m = re.search(r'__version__\s*=\s*"(\d+\.\d+\.\d+)"', open(VERSION_FILE).read())
    if not m:
        sys.exit(f"Couldn't parse __version__ from {VERSION_FILE}")
    return m.group(1)


def _bump(kind):
    v = [int(x) for x in read_version().split(".")]
    i = {"major": 0, "minor": 1, "patch": 2}[kind]
    v[i] += 1
    for j in range(i + 1, 3):
        v[j] = 0
    new = ".".join(map(str, v))
    s = open(VERSION_FILE).read()
    open(VERSION_FILE, "w").write(re.sub(r'__version__\s*=\s*"[^"]+"', f'__version__ = "{new}"', s))
    _git("add", "app/version.py")
    _git("commit", "-q", "-m", f"Release {new}")
    _git("tag", f"v{new}")
    print(f"Bumped version → {new} (committed and tagged v{new})")
    return new


def _excluded(path):
    return path.startswith(EXCLUDE_PREFIXES) or path in {p.rstrip("/") for p in EXCLUDE_PREFIXES}


def _build_tarball(commit):
    """Repackage `git archive <commit>` minus vendor-only paths. Only
    committed content ships — never whatever happens to be in the worktree."""
    src = tarfile.open(fileobj=io.BytesIO(_git("archive", "--format=tar", commit)))
    buf = io.BytesIO()
    files = []
    with tarfile.open(fileobj=buf, mode="w:gz", compresslevel=9) as out:
        for m in src.getmembers():
            if _excluded(m.name) or not (m.isfile() or m.isdir() or m.issym()):
                continue
            m.uid = m.gid = 0
            m.uname = m.gname = "root"
            m.mtime = int(datetime.now(timezone.utc).timestamp())
            out.addfile(m, src.extractfile(m) if m.isfile() else None)
            if m.isfile() or m.issym():
                files.append(m.name)
    return buf.getvalue(), files


def sign_manifest(priv, manifest):
    raw = json.dumps(manifest, indent=2, sort_keys=True).encode()
    return raw, base64.b64encode(priv.sign(raw))


def cmd_keygen(args):
    d = _key_dir(args)
    path = os.path.join(d, "release_private_key.pem")
    if os.path.exists(path) and not args.force:
        sys.exit(f"{path} already exists — refusing to overwrite (installs would reject "
                 "every future release). Use --force if you really mean it.")
    os.makedirs(d, mode=0o700, exist_ok=True)
    priv = Ed25519PrivateKey.generate()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))
    pub = priv.public_key().public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    open(os.path.join(d, "release_public_key.pem"), "w").write(pub)
    print(f"Release key: {path}  (BACK THIS UP — keep it secret)")
    print("Paste into updater/pwnbroker_updater.py as _RELEASE_PUBLIC_KEY_PEM:\n")
    print(pub)


def cmd_build(args):
    priv = _load_private(args)
    if _git("status", "--porcelain", "--untracked-files=no").strip() and not args.allow_dirty:
        sys.exit("Working tree has uncommitted changes — commit first (releases are built from "
                 "HEAD only), or pass --allow-dirty to build HEAD anyway.")
    version = _bump(args.bump) if args.bump else read_version()
    commit = _git("rev-parse", "HEAD").decode().strip()
    notes = open(args.notes_file).read() if args.notes_file else (args.notes or "")

    tar_bytes, files = _build_tarball(commit)
    req = _git("show", f"{commit}:requirements.txt")
    name = f"pwnbroker-{version}.tar.gz"
    manifest = {
        "product": "pwnbroker",
        "version": version,
        "channel": args.channel,
        "commit": commit,
        "released": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "file": name,
        "size": len(tar_bytes),
        "sha256": hashlib.sha256(tar_bytes).hexdigest(),
        "requirements_sha256": hashlib.sha256(req).hexdigest(),
        "files": sorted(files),
        "changelog": notes.strip(),
    }
    raw, sig = sign_manifest(priv, manifest)

    d = os.path.join(OUT, version)
    if os.path.exists(os.path.join(d, "manifest.json")) and not args.force:
        sys.exit(f"{d} already exists — bump the version (--bump patch) or pass --force.")
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, name), "wb").write(tar_bytes)
    open(os.path.join(d, "manifest.json"), "wb").write(raw)
    open(os.path.join(d, "manifest.sig"), "wb").write(sig)
    # Offline bundle: one file an admin can upload on the Updates page.
    with tarfile.open(os.path.join(d, f"pwnbroker-{version}.pwnupdate"), "w") as b:
        for fn in ("manifest.json", "manifest.sig", name):
            b.add(os.path.join(d, fn), arcname=fn)
    print(f"Built {version} ({args.channel}) from {commit[:10]}: {len(files)} files, "
          f"{len(tar_bytes) / 1e6:.1f} MB → {d}")
    path, digest = make_installer(d, version, priv.public_key())
    print(f"Installer: {path}  ({os.path.getsize(path) / 1e6:.1f} MB, sha256 {digest[:16]}…)")


HEADER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "installer_header.sh")
PAYLOAD_MARKER = b"__PWNBROKER_PAYLOAD_BELOW__\n"


def installer_name(version):
    return f"pwnbroker-{version}-install.run"


def make_installer(d, version, public_key):
    """One self-extracting file: installer_header.sh + an uncompressed tar of
    (manifest.json, manifest.sig, pwnbroker-<v>.tar.gz). The header checks the
    payload checksum and the release signature, then runs the bundled setup.sh."""
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w", format=tarfile.USTAR_FORMAT) as t:
        for fn in ("manifest.json", "manifest.sig", f"pwnbroker-{version}.tar.gz"):
            info = t.gettarinfo(os.path.join(d, fn), arcname=fn)
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            with open(os.path.join(d, fn), "rb") as f:
                t.addfile(info, f)
    payload = payload.getvalue()
    pub_pem = public_key.public_bytes(serialization.Encoding.PEM,
                                      serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    pub_body = "\n".join(l for l in pub_pem.strip().splitlines() if not l.startswith("-----"))
    header = open(HEADER, "rb").read()
    if not header.endswith(PAYLOAD_MARKER):
        sys.exit(f"{HEADER} must end with the payload marker line")
    for k, v in ((b"@VERSION@", version), (b"@PAYLOAD_SHA256@", hashlib.sha256(payload).hexdigest()),
                 (b"@RELEASE_PUBKEY@", pub_body)):
        header = header.replace(k, v.encode())
    path = os.path.join(d, installer_name(version))
    with open(path, "wb") as f:
        f.write(header + payload)
    os.chmod(path, 0o755)
    digest = hashlib.sha256(header + payload).hexdigest()
    with open(path + ".sha256", "w") as f:
        f.write(f"{digest}  {installer_name(version)}\n")
    return path, digest


def cmd_installer(args):
    d = os.path.join(OUT, args.version)
    if not os.path.exists(os.path.join(d, "manifest.sig")):
        sys.exit(f"No built release at {d} — run `build` first.")
    path, digest = make_installer(d, args.version, _load_private(args).public_key())
    print(f"Installer: {path}\n  sha256 {digest}")


def cmd_publish(args):
    d = os.path.join(OUT, args.version)
    if not os.path.exists(os.path.join(d, "manifest.sig")):
        sys.exit(f"No built release at {d}")
    dest = args.dest.rstrip("/") + "/" + args.version + "/"
    files = [os.path.join(d, f) for f in ("manifest.json", "manifest.sig", f"pwnbroker-{args.version}.tar.gz")]
    inst = os.path.join(d, installer_name(args.version))
    if os.path.exists(inst):  # served (license-gated) by the update server's /v1/installer
        files[2:2] = [inst, inst + ".sha256"]
    # Upload under a temp name then rename, so the server never serves a
    # half-uploaded release (it ignores directories without manifest.sig).
    host, _, path = dest.partition(":")
    if path:
        subprocess.run(["ssh", host, f"mkdir -p '{path}'"], check=True)
    subprocess.run(["rsync", "-av", "--exclude", "manifest.sig", *files, dest], check=True)
    subprocess.run(["rsync", "-av", os.path.join(d, "manifest.sig"), dest], check=True)
    print(f"Published {args.version} → {dest}")


def cmd_verify(args):
    d = args.dir
    raw = open(os.path.join(d, "manifest.json"), "rb").read()
    sig = base64.b64decode(open(os.path.join(d, "manifest.sig"), "rb").read())
    try:
        _load_private(args).public_key().verify(sig, raw)
        print("signature: VALID")
    except InvalidSignature:
        sys.exit("signature: INVALID")
    m = json.loads(raw)
    h = hashlib.sha256(open(os.path.join(d, m["file"]), "rb").read()).hexdigest()
    print("sha256:", "OK" if h == m["sha256"] else "MISMATCH")
    print(f"version {m['version']} · channel {m['channel']} · {len(m['files'])} files")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--key-dir")
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen"); k.add_argument("--force", action="store_true"); k.set_defaults(fn=cmd_keygen)
    b = sub.add_parser("build")
    b.add_argument("--channel", choices=CHANNELS, default="stable")
    b.add_argument("--bump", choices=("major", "minor", "patch"),
                   help="bump app/version.py, commit and tag before building")
    b.add_argument("--notes"); b.add_argument("--notes-file")
    b.add_argument("--allow-dirty", action="store_true")
    b.add_argument("--force", action="store_true", help="overwrite an existing build of this version")
    b.set_defaults(fn=cmd_build)
    p = sub.add_parser("publish"); p.add_argument("version"); p.add_argument("dest"); p.set_defaults(fn=cmd_publish)
    i = sub.add_parser("installer"); i.add_argument("version"); i.set_defaults(fn=cmd_installer)
    v = sub.add_parser("verify"); v.add_argument("dir"); v.set_defaults(fn=cmd_verify)
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
