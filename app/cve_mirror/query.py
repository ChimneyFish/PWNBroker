"""Read side of the local CVE mirror — what scans and enrichment call."""
import json
import re
import threading
import time

from sqlalchemy import text

from .parse import norm_name, split_cpe23
from .versions import normalize_scanned_version, version_in_range

_lock = threading.Lock()
_ready_cache = {"at": 0.0, "value": False}
_product_index = None   # {token: [(part, vendor, product, weight)]}


def invalidate_caches():
    global _product_index
    with _lock:
        _product_index = None
        _ready_cache["at"] = 0.0


def _engine():
    from ..extensions import db
    return db.engines["cvemirror"]


def is_ready() -> bool:
    """True once a full NVD sync has populated the mirror. Until then callers
    fall back to the live NVD API."""
    now = time.time()
    if now - _ready_cache["at"] < 60:
        return _ready_cache["value"]
    ready = False
    try:
        with _engine().connect() as conn:
            ready = bool(conn.execute(text(
                "SELECT 1 FROM mirror_sync_state WHERE source = 'nvd' AND last_full_at IS NOT NULL"
            )).first())
    except Exception:
        ready = False
    _ready_cache.update(at=now, value=ready)
    return ready


def _tokens(s):
    return set(t for t in re.split(r"[^a-z0-9]+", (s or "").lower()) if t)


def _load_product_index():
    global _product_index
    with _lock:
        if _product_index is not None:
            return _product_index
        idx = {}
        with _engine().connect() as conn:
            rows = conn.execute(text(
                "SELECT part, vendor, product, COUNT(*) FROM mirror_cpe_matches "
                "WHERE source = 'nvd' GROUP BY part, vendor, product")).all()
        for part, vendor, product, n in rows:
            for t in _tokens(product):
                idx.setdefault(t, []).append((part, vendor, product, n))
        _product_index = idx
        return idx


def resolve_product(product: str):
    """Map a banner product name ("OpenSSH", "Mongoose httpd", "lighttpd") to
    the (part, vendor, product) NVD uses, or None. Every token of the chosen
    CPE product name must appear in the banner, so a generic name can't
    hijack a specific one; exact-name and vendor-token matches rank first,
    then how widely NVD uses the name."""
    if not product or product.lower() in ("unknown",):
        return None
    scanned = _tokens(product)
    if not scanned:
        return None
    exact = norm_name(product)
    idx = _load_product_index()
    best, best_score = None, None
    seen = set()
    for t in scanned:
        for cand in idx.get(t, ()):
            if cand in seen:
                continue
            seen.add(cand)
            part, vendor, prod, n = cand
            ptoks = _tokens(prod)
            if not ptoks or not ptoks <= scanned:
                continue
            if len(prod) < 3 and prod != exact:
                continue
            score = (
                10 if prod == exact else 0,
                2 if _tokens(vendor) & scanned else 0,
                1 if part == "a" else 0,
                len(ptoks),
                n,
            )
            if best_score is None or score > best_score:
                best, best_score = (part, vendor, prod), score
    return best


def _severity(score, fallback=None):
    if score is None:
        f = (fallback or "").lower()
        return f if f in ("critical", "high", "medium", "low") else "info"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def lookup(vendor: str, product: str, version: str):
    """Every published CVE whose affected-version criteria include
    vendor:product at `version`. NVD's analysed configurations are used where
    NVD has them; CVE.org's CNA data covers CVEs NVD hasn't analysed yet."""
    version = normalize_scanned_version(version)
    if not vendor or not product or not version:
        return []
    vtok = _tokens(vendor)
    with _engine().connect() as conn:
        rows = conn.execute(text(
            "SELECT cve_id, source, vendor, version, v_start_incl, v_start_excl, v_end_incl, v_end_excl "
            "FROM mirror_cpe_matches WHERE product = :p AND (vendor = :v OR source = 'cveorg')"),
            {"p": product, "v": vendor}).all()
        nvd_hits, org_hits = set(), set()
        for cve_id, source, r_vendor, exact, si, se, ei, ee in rows:
            if source == "cveorg" and r_vendor != vendor and not (_tokens(r_vendor) & vtok):
                continue
            if version_in_range(version, exact, si, se, ei, ee):
                (nvd_hits if source == "nvd" else org_hits).add(cve_id)
        ids = list(nvd_hits | org_hits)
        if not ids:
            return []
        details = {}
        for i in range(0, len(ids), 500):
            chunk = ids[i:i + 500]
            params = {f"i{n}": v for n, v in enumerate(chunk)}
            for r in conn.execute(text(
                    "SELECT cve_id, state, nvd_has_config, nvd_description, cna_description, "
                    "nvd_cvss_v3, nvd_cvss_v2, cna_cvss, nvd_severity, cna_severity "
                    f"FROM mirror_cves WHERE cve_id IN ({', '.join(':' + k for k in params)})"),
                    params).mappings():
                details[r["cve_id"]] = r

    out = []
    for cve_id in ids:
        d = details.get(cve_id)
        if not d or d["state"] == "REJECTED":
            continue
        # CNA-only match: use it only while NVD has no analysed config of its
        # own for this CVE — once NVD has analysed it, NVD's ranges decide.
        if cve_id not in nvd_hits and d["nvd_has_config"]:
            continue
        score = next((s for s in (d["nvd_cvss_v3"], d["cna_cvss"], d["nvd_cvss_v2"]) if s is not None), None)
        out.append({
            "cve_id": cve_id,
            "description": d["nvd_description"] or d["cna_description"] or "",
            "cvss_score": score,
            "severity": _severity(score, d["nvd_severity"] or d["cna_severity"]),
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "match_confidence": "cpe",
            "mirror_source": "nvd" if cve_id in nvd_hits else "cveorg",
        })
    out.sort(key=lambda c: (c.get("cvss_score") or 0, c["cve_id"]), reverse=True)
    return out


def lookup_service(product: str, version: str, nmap_cpe23: str = ""):
    """CVEs for a scanned service. Uses nmap's CPE when it names the
    application (adding the banner version when nmap's CPE has none), and
    otherwise resolves the product name against the mirror — nmap often
    reports only the *OS* CPE for a service (OpenSSH ports carry
    cpe:/o:linux:linux_kernel), which says nothing about the application.
    Returns (cves, cpe23_used)."""
    version = normalize_scanned_version(version)
    target = None
    f = split_cpe23(nmap_cpe23) if nmap_cpe23 else None
    if f and f["part"] == "a":
        target = (f["vendor"], f["product"])
        if f["version"] not in ("*", "-", ""):
            version = version or f["version"]
    if target is None:
        r = resolve_product(product)
        if r:
            target = (r[1], r[2])
    if not target or not version:
        return [], ""
    results = lookup(target[0], target[1], version)
    if not results and f:
        # nmap's own CPE naming occasionally differs from NVD's — try the
        # mirror's resolution of the banner product before giving up.
        r = resolve_product(product)
        if r and (r[1], r[2]) != target:
            target = (r[1], r[2])
            results = lookup(target[0], target[1], version)
    cpe = f"cpe:2.3:a:{target[0]}:{target[1]}:{version}:*:*:*:*:*:*:*"
    return results, cpe


def affected_ranges(cve_id: str, vendor: str, product: str):
    """The affected-version criteria for one CVE on vendor:product, as
    (exact, start_incl, start_excl, end_incl, end_excl) tuples — NVD's when
    NVD has analysed the CVE, else the CNA's. [] if none; None if the mirror
    can't be read."""
    try:
        with _engine().connect() as conn:
            rows = conn.execute(text(
                "SELECT source, vendor, version, v_start_incl, v_start_excl, v_end_incl, v_end_excl "
                "FROM mirror_cpe_matches WHERE cve_id = :c AND product = :p"),
                {"c": (cve_id or "").upper(), "p": product}).all()
    except Exception:
        return None
    vtok = _tokens(vendor)
    nvd = [tuple(r[2:]) for r in rows if r[0] == "nvd" and r[1] == vendor]
    if nvd:
        return nvd
    return [tuple(r[2:]) for r in rows
            if r[0] == "cveorg" and (r[1] == vendor or _tokens(r[1]) & vtok)]


def get_cve(cve_id: str):
    """Mirror record for one CVE as a dict, or None."""
    with _engine().connect() as conn:
        r = conn.execute(text("SELECT * FROM mirror_cves WHERE cve_id = :c"),
                         {"c": (cve_id or "").upper()}).mappings().first()
    return dict(r) if r else None


def search(q: str, limit: int = 50):
    """CVE id prefix, or a product/vendor name, or description text."""
    q = (q or "").strip()
    if not q:
        return []
    with _engine().connect() as conn:
        if re.match(r"^cve-\d{0,4}(-\d*)?$", q, re.I):
            rows = conn.execute(text(
                "SELECT * FROM mirror_cves WHERE cve_id LIKE :q ORDER BY cve_id DESC LIMIT :l"),
                {"q": q.upper() + "%", "l": limit}).mappings().all()
        else:
            name = norm_name(q)
            ids = [r[0] for r in conn.execute(text(
                "SELECT DISTINCT cve_id FROM mirror_cpe_matches WHERE product = :p OR vendor = :p "
                "ORDER BY cve_id DESC LIMIT :l"), {"p": name, "l": limit}).all()]
            if ids:
                params = {f"i{n}": v for n, v in enumerate(ids)}
                rows = conn.execute(text(
                    f"SELECT * FROM mirror_cves WHERE cve_id IN ({', '.join(':' + k for k in params)}) "
                    "ORDER BY published DESC"), params).mappings().all()
            else:
                rows = conn.execute(text(
                    "SELECT * FROM mirror_cves WHERE nvd_description LIKE :q OR cna_description LIKE :q "
                    "ORDER BY published DESC LIMIT :l"), {"q": f"%{q}%", "l": limit}).mappings().all()
    return [dict(r) for r in rows]


def stats():
    from ..models import MirrorSyncState
    out = {"sources": {s.source: s for s in MirrorSyncState.query.all()}}
    try:
        with _engine().connect() as conn:
            out["total"] = conn.execute(text("SELECT COUNT(*) FROM mirror_cves")).scalar() or 0
            out["rejected"] = conn.execute(text(
                "SELECT COUNT(*) FROM mirror_cves WHERE state = 'REJECTED'")).scalar() or 0
            out["nvd_backlog"] = conn.execute(text(
                "SELECT COUNT(*) FROM mirror_cves WHERE state = 'PUBLISHED' AND "
                "(in_nvd = :f OR nvd_has_config = :f)"), {"f": False}).scalar() or 0
            out["cpe_rows"] = conn.execute(text("SELECT COUNT(*) FROM mirror_cpe_matches")).scalar() or 0
            out["newest"] = conn.execute(text("SELECT MAX(published) FROM mirror_cves")).scalar()
    except Exception:
        out.update(total=0, rejected=0, nvd_backlog=0, cpe_rows=0, newest=None)
    out["ready"] = is_ready()
    return out


def references(row):
    """Upstream reference URLs, http(s) only — they're rendered as links."""
    try:
        refs = json.loads(row.get("references") or "[]")
    except ValueError:
        return []
    return [u for u in refs if isinstance(u, str) and u.lower().startswith(("https://", "http://"))]
