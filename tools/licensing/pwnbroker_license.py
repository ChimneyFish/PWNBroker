#!/usr/bin/env python3
"""PWNBroker license issuer — vendor-side tool. Never ship the private key.

    keygen                       create the Ed25519 signing keypair (once)
    issue  --customer NAME       sign a new annual license
    renew  OLD.lic               re-issue a license, extended a year past its
                                 current expiry (early renewal loses no days)
    inspect FILE.lic             show a license's contents and verify it

The private key lives in ~/.pwnbroker-license/ by default (override with
--key-dir or PWNBROKER_LICENSE_KEY_DIR). Back it up: without it you cannot
issue renewals that existing installs will accept. After keygen, paste the
printed public key into app/licensing.py (_PUBLIC_KEY_PEM).

Only depends on `cryptography`, which the app already requires.
"""
import argparse
import base64
import json
import os
import sys
import uuid
from datetime import date, datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

BEGIN = "-----BEGIN PWNBROKER LICENSE-----"
END = "-----END PWNBROKER LICENSE-----"
DEFAULT_YEARS = 1
DEFAULT_GRACE = 14


def _key_dir(args):
    return os.path.expanduser(args.key_dir or os.environ.get("PWNBROKER_LICENSE_KEY_DIR")
                              or "~/.pwnbroker-license")


def _b64(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _load_private(args):
    path = os.path.join(_key_dir(args), "private_key.pem")
    if not os.path.exists(path):
        sys.exit(f"No private key at {path} — run `keygen` first.")
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def _public_pem(priv):
    return priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def _parse(text):
    body = "".join(l.strip() for l in text.splitlines()
                   if l.strip() and not l.startswith("-----"))
    payload_b64, sig_b64 = body.split(".", 1)
    return json.loads(_unb64(payload_b64)), payload_b64, _unb64(sig_b64)


def _sign(priv, payload):
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    p = _b64(raw)
    s = _b64(priv.sign(p.encode()))
    lines = [p + "." + s]
    wrapped = "\n".join(lines[0][i:i + 64] for i in range(0, len(lines[0]), 64))
    return f"{BEGIN}\n{wrapped}\n{END}\n"


def _write(text, out, payload):
    out = out or f"{payload['customer'].lower().replace(' ', '_')}_{payload['expires']}.lic"
    with open(out, "w") as f:
        f.write(text)
    print(f"Wrote {out}")
    _show(payload)


def _add_years(d, n):
    """Same calendar date n years later (Feb 29 -> Feb 28), so the renewal
    anniversary never drifts across leap years."""
    try:
        return d.replace(year=d.year + n)
    except ValueError:
        return d.replace(year=d.year + n, day=28)


def _term_end(base, args):
    return base + timedelta(days=args.days) if args.days else _add_years(base, args.years)


def _show(p):
    for k in ("license_id", "customer", "issued", "expires", "grace_days", "install_id", "notes"):
        if p.get(k) not in (None, ""):
            print(f"  {k:<11} {p[k]}")


def cmd_keygen(args):
    d = _key_dir(args)
    priv_path = os.path.join(d, "private_key.pem")
    if os.path.exists(priv_path) and not args.force:
        sys.exit(f"{priv_path} already exists. Refusing to overwrite (it would invalidate "
                 "every license you've issued). Use --force if you really mean it.")
    os.makedirs(d, mode=0o700, exist_ok=True)
    priv = Ed25519PrivateKey.generate()
    pem = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    pub = _public_pem(priv)
    with open(os.path.join(d, "public_key.pem"), "w") as f:
        f.write(pub)
    print(f"Private key: {priv_path}  (BACK THIS UP — keep it secret)")
    print("Paste this into app/licensing.py as _PUBLIC_KEY_PEM:\n")
    print(pub)


def cmd_issue(args):
    priv = _load_private(args)
    today = datetime.now(timezone.utc).date()
    payload = {
        "v": 1,
        "license_id": str(uuid.uuid4()),
        "customer": args.customer,
        "issued": today.isoformat(),
        "expires": (date.fromisoformat(args.expires) if args.expires
                    else _term_end(today, args)).isoformat(),
        "grace_days": args.grace_days,
    }
    if args.install_id:
        payload["install_id"] = args.install_id.strip()
    if args.notes:
        payload["notes"] = args.notes
    _write(_sign(priv, payload), args.out, payload)


def cmd_renew(args):
    priv = _load_private(args)
    with open(args.license) as f:
        old, _, _ = _parse(f.read())
    today = datetime.now(timezone.utc).date()
    # Extend from the later of today / current expiry, so renewing early keeps
    # the customer's anniversary date and renewing late doesn't backdate.
    base = max(today, date.fromisoformat(old["expires"]))
    payload = dict(old)
    payload.update({
        "license_id": str(uuid.uuid4()),
        "issued": today.isoformat(),
        "expires": _term_end(base, args).isoformat(),
        "renews": old.get("license_id"),
    })
    if args.install_id is not None:
        if args.install_id:
            payload["install_id"] = args.install_id.strip()
        else:
            payload.pop("install_id", None)
    _write(_sign(priv, payload), args.out, payload)


def cmd_inspect(args):
    from cryptography.exceptions import InvalidSignature
    with open(args.license) as f:
        payload, p_b64, sig = _parse(f.read())
    _show(payload)
    try:
        _load_private(args).public_key().verify(sig, p_b64.encode())
        print("  signature   VALID (matches your key)")
    except InvalidSignature:
        print("  signature   INVALID for your key")
    except SystemExit:
        print("  signature   not checked (no private key here)")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--key-dir", help="directory holding private_key.pem (default ~/.pwnbroker-license)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("keygen"); k.add_argument("--force", action="store_true")
    k.set_defaults(fn=cmd_keygen)

    i = sub.add_parser("issue")
    i.add_argument("--customer", required=True)
    i.add_argument("--years", type=int, default=DEFAULT_YEARS, help="term in years (default 1)")
    i.add_argument("--days", type=int, help="term in days instead (e.g. 30 for a trial)")
    i.add_argument("--expires", help="explicit expiry date YYYY-MM-DD (overrides --days)")
    i.add_argument("--grace-days", type=int, default=DEFAULT_GRACE)
    i.add_argument("--install-id", help="bind to one install (shown on its License page)")
    i.add_argument("--notes")
    i.add_argument("-o", "--out")
    i.set_defaults(fn=cmd_issue)

    r = sub.add_parser("renew")
    r.add_argument("license")
    r.add_argument("--years", type=int, default=DEFAULT_YEARS)
    r.add_argument("--days", type=int)
    r.add_argument("--install-id", help="rebind (empty string to unbind)")
    r.add_argument("-o", "--out")
    r.set_defaults(fn=cmd_renew)

    n = sub.add_parser("inspect"); n.add_argument("license"); n.set_defaults(fn=cmd_inspect)

    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
