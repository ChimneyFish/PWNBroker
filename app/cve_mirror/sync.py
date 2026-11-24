"""Keep the local CVE mirror in step with NVD and CVE.org.

NVD (nvd.nist.gov JSON 2.0 feeds, no API key or rate limit involved)
    full         nvdcve-2.0-<year>.json.gz for 2002..this year (2002 also
                 holds 1999-2001), then the modified feed
    incremental  nvdcve-2.0-modified.json.gz — every CVE changed in the last
                 8 days; skipped when its .meta sha256 hasn't changed

CVE.org (github.com/CVEProject/cvelistV5 — the official CVE List)
    full         the nightly "all_CVEs_at_midnight" release bundle
    incremental  cves/deltaLog.json (~30 days of new/updated records), each
                 changed record fetched individually

An incremental falls back to a full sync when the last good sync is older
than the upstream's incremental window, so a mirror that was offline for a
month heals itself instead of silently missing CVEs.
"""
import fcntl
import gzip
import io
import json
import logging
import os
import re
import shutil
import time
import zipfile
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import requests
from sqlalchemy import text

from .parse import parse_cveorg, parse_nvd, parse_dt

log = logging.getLogger(__name__)

_BATCH = 1000
_NVD_FIRST_YEAR = 2002
_NVD_INCR_WINDOW = timedelta(days=7)        # modified feed covers 8 days
_CVEORG_DELTA_MAX = 4000                    # more changes than this -> full bundle is cheaper
_UA = {"User-Agent": "PWNBroker-CVE-Mirror/1.0"}

_NVD_COLS = ("state", "published", "in_nvd", "nvd_status", "nvd_last_modified", "nvd_description",
             "nvd_cvss_v3", "nvd_cvss_v3_vector", "nvd_cvss_v2", "nvd_severity", "cwe_ids",
             "nvd_has_config", "references")
_CVEORG_COLS = ("state", "published", "in_cveorg", "cveorg_updated", "assigner",
                "cna_description", "cna_cvss", "cna_cvss_vector", "cna_severity")
_MATCH_COLS = ("cve_id", "source", "part", "vendor", "product", "version",
               "v_start_incl", "v_start_excl", "v_end_incl", "v_end_excl")


class SyncBusy(Exception):
    pass


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _data_dir(app):
    """Lock file + download scratch space. Under data/ by default — the only
    tree the systemd sandbox lets the service write to."""
    return app.config.get("CVE_MIRROR_WORK_DIR") or os.path.join(os.path.dirname(app.root_path), "data")


@contextmanager
def _lock(app):
    path = os.path.join(_data_dir(app), "cve_mirror.lock")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fh = open(path, "w")
    try:
        try:
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SyncBusy("A CVE mirror sync is already running")
        yield
    finally:
        try:
            fcntl.flock(fh, fcntl.LOCK_UN)
        finally:
            fh.close()


def _engine():
    from ..extensions import db
    return db.engines["cvemirror"]


# ── storage ──────────────────────────────────────────────────────────────────

def _upsert_sql(cols):
    """Only the given source's columns are written on conflict. `published`
    keeps whichever source set it first; `state` lets REJECTED win."""
    all_cols = ("cve_id",) + cols
    sets = []
    for c in cols:
        if c == "published":
            sets.append("published = COALESCE(mirror_cves.published, excluded.published)")
        elif c == "state":
            sets.append("state = CASE WHEN excluded.state = 'REJECTED' THEN 'REJECTED' "
                        "ELSE excluded.state END")
        else:
            sets.append(f'"{c}" = excluded."{c}"')
    col_list = ", ".join(f'"{c}"' for c in all_cols)
    vals = ", ".join(f":{c}" for c in all_cols)
    return text(f"INSERT INTO mirror_cves ({col_list}) VALUES ({vals}) "
                f"ON CONFLICT (cve_id) DO UPDATE SET {', '.join(sets)}")


_INSERT_MATCH = text(
    f"INSERT INTO mirror_cpe_matches ({', '.join(_MATCH_COLS)}) "
    f"VALUES ({', '.join(':' + c for c in _MATCH_COLS)})")


def _db_value(v):
    """Raw text() inserts bypass SQLAlchemy's DateTime type — format datetimes
    the way it stores them on SQLite (so ORM reads round-trip) instead of
    relying on sqlite3's default adapter, deprecated since Python 3.12."""
    if isinstance(v, datetime):
        return v.strftime("%Y-%m-%d %H:%M:%S.%f")
    return v


def store_batch(source, parsed):
    """parsed: list of (cve_row, matches). Replaces this source's CPE matches
    for every CVE in the batch, in one transaction."""
    if not parsed:
        return 0
    cols = _NVD_COLS if source == "nvd" else _CVEORG_COLS
    # Last record wins if a batch carries the same CVE twice (feed overlap).
    by_id = {}
    for row, matches in parsed:
        if row.get("cve_id"):
            by_id[row["cve_id"]] = (row, matches)
    rows = [{"cve_id": r["cve_id"], **{c: _db_value(r.get(c)) for c in cols}} for r, _ in by_id.values()]
    match_rows = [m for _, ms in by_id.values() for m in ms]
    ids = list(by_id)
    with _engine().begin() as conn:
        conn.execute(_upsert_sql(cols), rows)
        for i in range(0, len(ids), 500):
            chunk = ids[i:i + 500]
            params = {f"i{n}": v for n, v in enumerate(chunk)}
            conn.execute(text(
                f"DELETE FROM mirror_cpe_matches WHERE source = :src AND cve_id IN "
                f"({', '.join(':' + k for k in params)})"), {"src": source, **params})
        if match_rows:
            conn.execute(_INSERT_MATCH, match_rows)
    return len(rows)


def _store_stream(source, items, parser):
    n, buf = 0, []
    for item in items:
        try:
            buf.append(parser(item))
        except Exception as e:      # one malformed record mustn't sink a sync
            log.warning("CVE mirror: skipping unparsable %s record: %s", source, e)
            continue
        if len(buf) >= _BATCH:
            n += store_batch(source, buf)
            buf = []
    n += store_batch(source, buf)
    return n


# ── state ────────────────────────────────────────────────────────────────────

def _state(source):
    from ..extensions import db
    from ..models import MirrorSyncState
    st = db.session.get(MirrorSyncState, source)
    if not st:
        st = MirrorSyncState(source=source, status="never")
        db.session.add(st)
        db.session.commit()
    return st


def _set_state(source, **kw):
    from ..extensions import db
    st = _state(source)
    for k, v in kw.items():
        setattr(st, k, v)
    db.session.commit()


def _count(source):
    col = "in_nvd" if source == "nvd" else "in_cveorg"
    with _engine().connect() as conn:
        return conn.execute(text(f"SELECT COUNT(*) FROM mirror_cves WHERE {col} = :t"),
                            {"t": True}).scalar() or 0


# ── download helpers ─────────────────────────────────────────────────────────

def _download(url, dest, timeout=120):
    with requests.get(url, stream=True, timeout=timeout, headers=_UA) as r:
        r.raise_for_status()
        tmp = dest + ".part"
        with open(tmp, "wb") as f:
            for chunk in r.iter_content(1 << 20):
                f.write(chunk)
        os.replace(tmp, dest)
    return dest


_SEP_RE = re.compile(r"[\s,]*")


def iter_json_array(fh, key, chunk_size=1 << 20):
    """Stream the elements of the top-level array `key` from a large JSON
    document without loading it whole (a year of NVD data is ~300 MB of
    JSON). fh is a text-mode file object."""
    dec = json.JSONDecoder()
    marker = f'"{key}"'
    buf = ""
    # find the array start
    while True:
        chunk = fh.read(chunk_size)
        if not chunk:
            return
        buf += chunk
        i = buf.find(marker)
        if i >= 0:
            j = buf.find("[", i + len(marker))
            if j >= 0:
                buf = buf[j + 1:]
                break
        else:
            buf = buf[-len(marker):]
    eof, pos = False, 0
    while True:
        m = _SEP_RE.match(buf, pos)
        pos = m.end()
        if pos < len(buf) and buf[pos] == "]":
            return
        try:
            if pos >= len(buf):
                raise json.JSONDecodeError("need more data", buf, pos)
            obj, pos = dec.raw_decode(buf, pos)
        except json.JSONDecodeError:
            if eof:
                raise
            chunk = fh.read(chunk_size)
            if not chunk:
                eof = True
            # Drop what's been consumed only when refilling — slicing after
            # every record would copy the buffer quadratically.
            buf, pos = buf[pos:] + chunk, 0
            continue
        yield obj


# ── NVD ──────────────────────────────────────────────────────────────────────

def _nvd_items(path):
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        for v in iter_json_array(fh, "vulnerabilities"):
            cve = v.get("cve")
            if cve:
                yield cve


def _nvd_feed(app, tmp, name):
    base = app.config.get("NVD_FEED_URL", "https://nvd.nist.gov/feeds/json/cve/2.0").rstrip("/")
    path = os.path.join(tmp, f"nvdcve-2.0-{name}.json.gz")
    _download(f"{base}/nvdcve-2.0-{name}.json.gz", path)
    try:
        return _store_stream("nvd", _nvd_items(path), parse_nvd)
    finally:
        os.remove(path)


def _nvd_modified_sha(app):
    base = app.config.get("NVD_FEED_URL", "https://nvd.nist.gov/feeds/json/cve/2.0").rstrip("/")
    r = requests.get(f"{base}/nvdcve-2.0-modified.meta", timeout=30, headers=_UA)
    r.raise_for_status()
    for line in r.text.splitlines():
        if line.lower().startswith("sha256:"):
            return line.split(":", 1)[1].strip()
    return None


def sync_nvd(app, tmp, full=False, progress=None):
    st = _state("nvd")
    if not full and (not st.last_full_at or not st.last_sync_at
                     or _now() - st.last_sync_at > _NVD_INCR_WINDOW):
        full = True
    _set_state("nvd", status="running", message="full sync" if full else "incremental sync")
    n = 0
    if full:
        for year in range(_NVD_FIRST_YEAR, _now().year + 1):
            if progress:
                progress("nvd", f"NVD {year}")
            n += _nvd_feed(app, tmp, str(year))
            log.info("CVE mirror: NVD %d loaded (%d records so far)", year, n)
    sha = _nvd_modified_sha(app)
    if full or not sha or sha != st.cursor:
        if progress:
            progress("nvd", "NVD recent changes")
        n += _nvd_feed(app, tmp, "modified")
    now = _now()
    _set_state("nvd", status="ok", cursor=sha, last_sync_at=now,
               last_full_at=now if full else st.last_full_at,
               records=_count("nvd"),
               message=f"{'full' if full else 'incremental'} sync: {n} records written")
    return n


# ── CVE.org ──────────────────────────────────────────────────────────────────

def _cveorg_bundle_url(app):
    r = requests.get(app.config.get("CVEORG_RELEASES_API"), timeout=30,
                     headers={**_UA, "Accept": "application/vnd.github+json"})
    r.raise_for_status()
    for a in r.json().get("assets", []):
        if "all_CVEs" in a.get("name", "") and a["name"].endswith(".zip"):
            return a["browser_download_url"]
    raise RuntimeError("CVE.org release has no all_CVEs bundle")


def _iter_cveorg_zip(path):
    """The bundle is a zip holding cves.zip, which holds cves/<year>/<n>xxx/*.json."""
    with zipfile.ZipFile(path) as outer:
        inner_name = next((n for n in outer.namelist() if n.endswith(".zip")), None)
        if inner_name:
            inner_path = path + ".inner.zip"
            with outer.open(inner_name) as src, open(inner_path, "wb") as dst:
                shutil.copyfileobj(src, dst, 1 << 20)
            try:
                yield from _iter_cveorg_zip(inner_path)
            finally:
                os.remove(inner_path)
            return
        for name in outer.namelist():
            base = os.path.basename(name)
            if not (base.startswith("CVE-") and base.endswith(".json")):
                continue
            with outer.open(name) as f:
                try:
                    yield json.load(io.TextIOWrapper(f, encoding="utf-8"))
                except ValueError as e:
                    log.warning("CVE mirror: bad CVE.org record %s: %s", name, e)


def _max_updated(state_cursor, rows_seen):
    best = parse_dt(state_cursor) if state_cursor else None
    for d in rows_seen:
        if d and (best is None or d > best):
            best = d
    return best.isoformat() + "Z" if best else state_cursor


def sync_cveorg(app, tmp, full=False, progress=None):
    st = _state("cveorg")
    session = requests.Session()
    session.headers.update(_UA)
    entries = None

    if not full and st.last_full_at and st.cursor:
        r = session.get(app.config.get("CVEORG_DELTA_LOG_URL"), timeout=120)
        r.raise_for_status()
        log_entries = r.json()
        oldest = min((parse_dt(e.get("fetchTime")) for e in log_entries if e.get("fetchTime")), default=None)
        cursor = parse_dt(st.cursor)
        if oldest is None or cursor is None or cursor < oldest:
            full = True     # gap is older than the delta log covers
        else:
            latest = {}
            for e in log_entries:
                for kind in ("new", "updated"):
                    for c in e.get(kind) or []:
                        d = parse_dt(c.get("dateUpdated"))
                        if d and d > cursor and c.get("githubLink"):
                            prev = latest.get(c["cveId"])
                            if not prev or d > prev[0]:
                                latest[c["cveId"]] = (d, c["githubLink"])
            if len(latest) > _CVEORG_DELTA_MAX:
                full = True
            else:
                entries = latest
    else:
        full = True

    _set_state("cveorg", status="running", message="full sync" if full else "incremental sync")
    dates = []

    def _tracked(records):
        for rec in records:
            dates.append(parse_dt((rec.get("cveMetadata") or {}).get("dateUpdated")))
            yield rec

    if full:
        if progress:
            progress("cveorg", "CVE.org bundle download")
        path = os.path.join(tmp, "cvelist_all.zip")
        _download(_cveorg_bundle_url(app), path, timeout=600)
        try:
            if progress:
                progress("cveorg", "CVE.org bundle import")
            n = _store_stream("cveorg", _tracked(_iter_cveorg_zip(path)), parse_cveorg)
        finally:
            os.remove(path)
    else:
        def _fetch():
            for cve_id, (_, url) in entries.items():
                try:
                    r = session.get(url, timeout=30)
                    r.raise_for_status()
                    yield r.json()
                except Exception as e:
                    log.warning("CVE mirror: could not fetch %s from CVE.org: %s", cve_id, e)
        n = _store_stream("cveorg", _tracked(_fetch()), parse_cveorg)

    now = _now()
    _set_state("cveorg", status="ok", cursor=_max_updated(st.cursor if not full else None, dates),
               last_sync_at=now, last_full_at=now if full else st.last_full_at,
               records=_count("cveorg"),
               message=f"{'full' if full else 'incremental'} sync: {n} records written")
    return n


# ── entry point ──────────────────────────────────────────────────────────────

_progress = {}


def progress_snapshot():
    return dict(_progress)


def run_sync(app, full=False, sources=("nvd", "cveorg")):
    """Sync the mirror. Safe to call from a scheduler or a request thread;
    a second concurrent call raises SyncBusy. Each source is independent —
    one failing doesn't stop the other."""
    results = {}
    with app.app_context():
        with _lock(app):
            tmp = os.path.join(_data_dir(app), "cve_mirror_tmp")
            shutil.rmtree(tmp, ignore_errors=True)
            os.makedirs(tmp, exist_ok=True)

            def progress(src, step):
                _progress[src] = {"step": step, "at": time.time()}

            try:
                for src, fn in (("nvd", sync_nvd), ("cveorg", sync_cveorg)):
                    if src not in sources:
                        continue
                    t0 = time.time()
                    try:
                        results[src] = fn(app, tmp, full=full, progress=progress)
                        log.info("CVE mirror: %s sync done in %.0fs (%d records)",
                                 src, time.time() - t0, results[src])
                    except Exception as e:
                        from ..extensions import db
                        db.session.rollback()
                        log.exception("CVE mirror: %s sync failed", src)
                        _set_state(src, status="error", message=str(e)[:500])
                        results[src] = e
                    finally:
                        _progress.pop(src, None)
            finally:
                shutil.rmtree(tmp, ignore_errors=True)
            from .query import invalidate_caches
            invalidate_caches()
    return results
