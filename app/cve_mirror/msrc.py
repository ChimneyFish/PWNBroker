"""Microsoft's fixed Windows builds per CVE, from the MSRC CVRF API.

Each monthly security update document (api.msrc.microsoft.com/cvrf/v3.0,
public, no key) lists, for every CVE and every affected Windows version, the
update that fixes it and — since mid-2021 — the exact build that contains the
fix ("FixedBuild": "10.0.19045.5131"). Windows updates are cumulative, so a
host whose build is at or past that number on the same Windows version is
patched, and one below it is not. That turns the build number the PwnBroker
agent reports into a definite answer for Windows OS CVEs (SMB, RDP, HTTP.sys,
IIS, ...).

Only Windows products are kept; documents released before 2021 carry no
Windows build numbers and are skipped.
"""
import logging
import re

import requests
from sqlalchemy import text

log = logging.getLogger(__name__)

FIRST_DOC_DATE = "2021-01-01"
_BUILD_RE = re.compile(r"^(\d+\.\d+\.\d+)\.(\d+)$")
_DOC_ID_RE = re.compile(r"^\d{4}-[A-Za-z]{3}$")
_COLS = ("cve_id", "doc_id", "build_line", "fixed_ubr", "kb", "product", "hotpatch")


def parse_document(doc_id, doc):
    """One CVRF document → mirror_msrc_fixes rows."""
    names = {p.get("ProductID"): p.get("Value") or ""
             for p in (doc.get("ProductTree") or {}).get("FullProductName") or []}
    rows, seen = [], set()
    for v in doc.get("Vulnerability") or []:
        cve = (v.get("CVE") or "").strip().upper()
        if not cve.startswith("CVE-"):
            continue
        for rem in v.get("Remediations") or []:
            if rem.get("Type") != 2:                 # 2 = vendor fix
                continue
            m = _BUILD_RE.match((rem.get("FixedBuild") or "").strip())
            if not m:
                continue
            kb = str((rem.get("Description") or {}).get("Value") or "").strip()
            kb = f"KB{kb}" if kb.isdigit() else kb[:16]
            hot = "hotpatch" in (rem.get("SubType") or "").lower()
            for pid in rem.get("ProductID") or []:
                name = names.get(pid, "")
                if not name.startswith("Windows"):
                    continue
                hp = hot or "hotpatch" in name.lower()
                key = (cve, m.group(1), int(m.group(2)), kb, hp)
                if key in seen:                       # x64/ARM64/Server Core share a build
                    continue
                seen.add(key)
                rows.append({"cve_id": cve, "doc_id": doc_id, "build_line": m.group(1),
                             "fixed_ubr": int(m.group(2)), "kb": kb, "product": name[:160],
                             "hotpatch": hp})
    return rows


def _engine():
    from ..extensions import db
    return db.engines["cvemirror"]


def _store(doc_id, rows):
    with _engine().begin() as conn:
        conn.execute(text("DELETE FROM mirror_msrc_fixes WHERE doc_id = :d"), {"d": doc_id})
        if rows:
            conn.execute(text(f"INSERT INTO mirror_msrc_fixes ({', '.join(_COLS)}) "
                              f"VALUES ({', '.join(':' + c for c in _COLS)})"), rows)


def count():
    try:
        with _engine().connect() as conn:
            return conn.execute(text("SELECT COUNT(DISTINCT cve_id) FROM mirror_msrc_fixes")).scalar() or 0
    except Exception:
        return 0


def sync_msrc(app, tmp=None, full=False, progress=None):
    """Fetch the security update documents that changed since the last sync
    (all of them from 2021 on, the first time). Returns rows written."""
    from .sync import _UA, _now, _set_state, _state
    base = app.config.get("MSRC_CVRF_API", "https://api.msrc.microsoft.com/cvrf/v3.0").rstrip("/")
    hdr = {**_UA, "Accept": "application/json"}
    st = _state("msrc")
    full = full or not st.last_full_at
    cursor = None if full else st.cursor

    r = requests.get(f"{base}/updates", headers=hdr, timeout=60)
    r.raise_for_status()
    docs = [d for d in r.json().get("value") or []
            if _DOC_ID_RE.match(d.get("ID") or "")
            and (d.get("InitialReleaseDate") or "") >= FIRST_DOC_DATE
            and (not cursor or (d.get("CurrentReleaseDate") or "") > cursor)]
    # Oldest change first, cursor advanced per document: an interrupted sync
    # resumes where it stopped instead of skipping documents.
    docs.sort(key=lambda d: d.get("CurrentReleaseDate") or "")
    _set_state("msrc", status="running",
               message=f"{'full' if full else 'incremental'} sync: {len(docs)} document(s)")
    n = 0
    with requests.Session() as s:
        s.headers.update(hdr)
        for i, d in enumerate(docs, 1):
            if progress:
                progress("msrc", f"Microsoft {d['ID']} ({i}/{len(docs)})")
            resp = s.get(f"{base}/cvrf/{d['ID']}", timeout=300)
            resp.raise_for_status()
            rows = parse_document(d["ID"], resp.json())
            _store(d["ID"], rows)
            n += len(rows)
            _set_state("msrc", cursor=d.get("CurrentReleaseDate"))
    now = _now()
    _set_state("msrc", status="ok", last_sync_at=now, last_full_at=now if full else st.last_full_at,
               records=count(),
               message=f"{'full' if full else 'incremental'} sync: {len(docs)} document(s), {n} fixes")
    return n


# ── read side ────────────────────────────────────────────────────────────────

def fixes_for(cve_id):
    """[{build_line, fixed_ubr, kb, product, hotpatch}] Microsoft lists for a
    CVE — empty if it isn't a Windows CVE Microsoft has build data for, None
    if the table can't be read."""
    try:
        with _engine().connect() as conn:
            rows = conn.execute(text(
                "SELECT build_line, fixed_ubr, kb, product, hotpatch FROM mirror_msrc_fixes "
                "WHERE cve_id = :c"), {"c": (cve_id or "").upper()}).mappings().all()
    except Exception:
        return None
    return [dict(r) for r in rows]
