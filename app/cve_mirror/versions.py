"""Version comparison for evaluating NVD / CVE.org affected-version ranges
locally (what NVD's cpeName API used to do server-side).

Versions are split into numeric and alphabetic runs and compared run by run:
    "2.4.49"  -> [2, 4, 49]
    "9.6p1"   -> [9, 6, "p", 1]          (OpenSSH portable patch level)
    "1.0rc1"  -> [1, 0, "~rc", 1]        (pre-release, sorts BEFORE 1.0)
Numbers compare numerically; a pre-release tag (alpha/beta/rc/pre/dev...)
sorts below "nothing", any other letter run (p, a-z suffixes) above it, so
1.0rc1 < 1.0 < 1.0a < 1.0p1 < 1.0.1. That's not every scheme's semantics
(none is), but it's right for the common ones, and every match it produces is
still a version-inferred finding that verify.py has to prove.
"""
import re

_RUN_RE = re.compile(r"\d+|[a-z]+")
# Single-letter "a"/"b"/"m" only count as pre-release markers when followed
# by a number after a numeric run ("1.0b2"); "1.0a" alone is a post-release suffix.


def _tokens(v: str):
    v = (v or "").strip().lower()
    # NVD escapes some punctuation inside CPE fields ("1.0\(1\)").
    v = v.replace("\\", "")
    if v.startswith("v") and len(v) > 1 and v[1].isdigit():
        v = v[1:]
    runs = _RUN_RE.findall(v)
    out = []
    for i, r in enumerate(runs):
        if r.isdigit():
            out.append((1, int(r)))      # numbers outrank any pre-release tag
            continue
        followed_by_num = i + 1 < len(runs) and runs[i + 1].isdigit()
        is_pre = r in ("alpha", "beta", "rc", "pre", "dev", "preview", "snapshot") or (
            r in ("a", "b", "m") and followed_by_num and i > 0)
        out.append((-1, r) if is_pre else (0, r))
    return out


def compare_versions(a: str, b: str) -> int:
    """-1 if a < b, 0 if equal, 1 if a > b."""
    ta, tb = _tokens(a), _tokens(b)
    for x, y in zip(ta, tb):
        if x == y:
            continue
        if x[0] != y[0]:
            return -1 if x[0] < y[0] else 1
        return -1 if x[1] < y[1] else 1
    if len(ta) == len(tb):
        return 0
    # The longer one continues with a token; compare it against "end of version".
    # A trailing ".0" is equal to nothing (2.4 == 2.4.0).
    longer, sign = (ta[len(tb):], 1) if len(ta) > len(tb) else (tb[len(ta):], -1)
    for kind, val in longer:
        if kind == 1 and val == 0:
            continue
        if kind == -1:           # pre-release suffix: less than the bare version
            return -sign
        return sign
    return 0


def normalize_scanned_version(v: str) -> str:
    """nmap's version field carries distro packaging after the upstream
    version ("10.0p2 Debian 7+deb13u4", "2.0.0 or later") — keep the upstream
    version token only. Returns "" if there's no usable version."""
    v = (v or "").strip()
    if not v:
        return ""
    # "2.0.0 or later" / "2.x or newer": nmap only knows a lower bound, so
    # matching it as exactly 2.0.0 would report that release's CVEs on a host
    # that's almost certainly running something newer.
    if re.search(r"\bor (later|newer|greater|above)\b|\+$", v, re.I):
        return ""
    first = v.split()[0]
    return first if any(c.isdigit() for c in first) else ""


def version_in_range(version: str, exact=None, start_incl=None, start_excl=None,
                     end_incl=None, end_excl=None) -> bool:
    """Does `version` fall within one affected-version criterion?
    exact: a specific version ("*" or None = no exact pin; "-" = N/A)."""
    if not version:
        return False
    if exact and exact not in ("*", "-"):
        return compare_versions(version, exact) == 0
    if exact == "-":
        return False
    if start_incl and compare_versions(version, start_incl) < 0:
        return False
    if start_excl and compare_versions(version, start_excl) <= 0:
        return False
    if end_incl and compare_versions(version, end_incl) > 0:
        return False
    if end_excl and compare_versions(version, end_excl) >= 0:
        return False
    return True
