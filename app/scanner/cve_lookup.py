import json
import logging
import re
import threading
import time
from datetime import datetime, timezone
from flask import current_app
from typing import List, Dict, Optional

import requests
from sqlalchemy.exc import IntegrityError

log = logging.getLogger(__name__)

# NVD's rate limit (5 req/30s unauthenticated, 50 req/30s with a key) is
# global, not per-thread — a scan against a group of hosts spawns one thread
# per host (see scheduler/jobs.py), and without this lock those threads each
# independently pace and back off against the same limit, guaranteeing 403s
# and stacking exponential backoffs (up to minutes per call, per thread) once
# more than a couple of scans overlap. Serializing calls here makes the
# pacing/backoff sleeps additive instead of concurrent, which is the only way
# a fixed per-call delay actually respects a shared limit.
_NVD_CALL_LOCK = threading.Lock()


def _get_nvd_api_key() -> str:
    """Return NVD API key: env var first, DB ThreatConfig as fallback."""
    key = current_app.config.get("NVD_API_KEY", "")
    if not key:
        try:
            from ..models import ThreatConfig
            cfg = ThreatConfig.query.first()
            if cfg and cfg.nvd_api_key:
                key = cfg.nvd_api_key
        except Exception:
            pass
    return key


def _nvd_get(url: str, params: dict, api_key: str, max_retries: int = 5) -> Optional[dict]:
    """GET against an NVD endpoint, paced to the documented rate limit
    (5 req/30s unauthenticated, 50 req/30s with a key) with exponential
    backoff on 403/429. Returns the parsed JSON body, or None on failure."""
    if not url:
        return None
    headers = {"apiKey": api_key} if api_key else {}
    delay = 0.7 if api_key else 6.5

    with _NVD_CALL_LOCK:
        for attempt in range(max_retries):
            try:
                resp = requests.get(url, params=params, headers=headers, timeout=15)
            except requests.RequestException as e:
                log.warning("NVD request failed (attempt %d/%d) for %s %r: %s",
                            attempt + 1, max_retries, url, params, e)
                time.sleep(delay * (2 ** attempt))
                continue

            if resp.status_code in (403, 429):
                log.warning("NVD returned %d (attempt %d/%d) for %s %r%s",
                            resp.status_code, attempt + 1, max_retries, url, params,
                            "" if api_key else " — no API key configured, using the unauthenticated rate limit")
                time.sleep(delay * (2 ** attempt))
                continue

            try:
                resp.raise_for_status()
                data = resp.json()
            except Exception as e:
                log.warning("NVD returned an unusable response for %s %r: HTTP %d: %s",
                            url, params, resp.status_code, e)
                return None

            time.sleep(delay)
            return data

    log.warning("NVD request exhausted all %d retries for %s %r — giving up", max_retries, url, params)
    return None


def _commit_cache_row(db, model, filter_kwargs, row):
    """Commit a new/updated cache row. A subnet scan resolves the same
    product/version (or CPE) on many hosts at once via one thread per host
    (see scheduler/jobs.py), so two threads can both miss the cache for the
    same key and race to INSERT it — the loser's commit hits the table's
    unique constraint. That's a harmless duplicate lookup, not a real error,
    so fall back to whatever the winner wrote instead of failing the scan."""
    try:
        db.session.commit()
        return row
    except IntegrityError:
        db.session.rollback()
        return model.query.filter_by(**filter_kwargs).first()


def _score_to_severity(score) -> str:
    if score is None:
        return "info"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _parse_cve_item(cve: dict) -> Dict:
    """Extract {cve_id, description, cvss_score, severity, url} from an NVD
    `vulnerabilities[].cve` object. Shared by the CPE and keyword lookup paths."""
    cve_id = cve.get("id", "")
    descriptions = cve.get("descriptions", [])
    desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "")

    metrics = cve.get("metrics", {})
    cvss_score = None
    severity = "info"

    for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(version_key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            severity = _score_to_severity(cvss_score)
            break

    return {
        "cve_id": cve_id,
        "description": desc,
        "cvss_score": cvss_score,
        "severity": severity,
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }


def _cpe_is_vulnerable(cve: dict, cpe: str) -> bool:
    """NVD's `cpeName` query returns every CVE whose configuration criteria
    reference that CPE, including branches explicitly marked not vulnerable
    for it — filter those out. Default to True if no matching criteria entry
    is found (shouldn't normally happen given we queried by this exact CPE)."""
    for config in cve.get("configurations", []) or []:
        for node in config.get("nodes", []) or []:
            for m in node.get("cpeMatch", []) or []:
                if m.get("criteria") == cpe:
                    return m.get("vulnerable", True)
    return True


_CPE23_FIELD_COUNT = 11  # part,vendor,product,version,update,edition,language,sw_edition,target_sw,target_hw,other


def _cpe22_to_23(cpe22: str) -> Optional[str]:
    """Convert a CPE 2.2 URI-binding string (nmap's native `cpe` field
    format, e.g. "cpe:/a:lighttpd:lighttpd:1.4.54") to a CPE 2.3 formatted
    string (e.g. "cpe:2.3:a:lighttpd:lighttpd:1.4.54:*:*:*:*:*:*:*").

    NVD's CVE API's `cpeName` parameter validates strictly against the CPE
    2.3 schema — passing a 2.2 URI through unconverted doesn't raise an
    error, it just matches nothing, so every port nmap fingerprinted well
    enough to supply its own CPE for (which is most of them — nmap embeds a
    CPE in its service-detection output for most well-known software)
    silently produced zero CVEs. Returns None if the input isn't a
    recognizable CPE 2.2 URI.
    """
    if not cpe22 or not cpe22.startswith("cpe:/"):
        return None
    body = cpe22[len("cpe:/"):]
    parts = body.split(":")
    if not parts or not parts[0]:
        return None
    # CPE 2.2 fields (in order): part, vendor, product, version, update,
    # edition, language — each optional/omittable from the right.
    fields = (parts + ["*"] * 7)[:7]
    fields = [f if f else "*" for f in fields]
    # 2.3 adds 4 trailing fields (sw_edition, target_sw, target_hw, other)
    # that 2.2 has no equivalent for.
    fields += ["*"] * (_CPE23_FIELD_COUNT - len(fields))
    return "cpe:2.3:" + ":".join(fields)


_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _tokens(s: str) -> set:
    return set(_TOKEN_RE.findall((s or "").lower()))


def _score_cpe_candidate(cpe_name: str, product: str, version: str) -> int:
    """Score a CPE dictionary candidate against the discovered product/version.
    Higher is better; a large negative score disqualifies a version mismatch."""
    parts = cpe_name.split(":")
    if len(parts) < 6:
        return -100

    vendor, prod, cand_version = parts[3], parts[4], parts[5]

    score = 2 * len(_tokens(product) & (_tokens(vendor) | _tokens(prod)))

    version = (version or "").strip()
    if version:
        if cand_version == version:
            score += 5
        elif cand_version in ("*", "-", ""):
            pass
        else:
            score -= 10  # candidate pins a different, non-matching version

    return score


def resolve_cpe(product: str, version: str = "") -> Optional[str]:
    """Resolve a product/version pair to a best-guess CPE 2.3 string via
    NVD's CPE dictionary. Cached in CpeResolutionCache (30-day TTL, negative
    results cached too) so repeated scans don't re-resolve the same service."""
    from ..extensions import db
    from ..models import CpeResolutionCache

    if not product or product.lower() in ("unknown", ""):
        return None

    key = f"{product.strip().lower()}|{version.strip().lower()}"
    cached = CpeResolutionCache.query.filter_by(product_key=key).first()
    if cached and not cached.is_stale:
        return cached.resolved_cpe

    api_key = _get_nvd_api_key()
    url = current_app.config.get("NVD_CPE_API_URL")
    keyword = f"{product} {version}".strip()
    data = _nvd_get(url, {"keywordSearch": keyword, "resultsPerPage": 30}, api_key)

    resolved = None
    if data:
        best_score = 1  # require at least some product/vendor token overlap
        for item in data.get("products", []):
            cpe_obj = item.get("cpe", {})
            if cpe_obj.get("deprecated"):
                continue
            name = cpe_obj.get("cpeName", "")
            if not name:
                continue
            score = _score_cpe_candidate(name, product, version)
            if score > best_score:
                best_score = score
                resolved = name

    if cached:
        cached.resolved_cpe = resolved
        cached.fetched_at = datetime.now(timezone.utc)
    else:
        cached = CpeResolutionCache(product_key=key, resolved_cpe=resolved)
        db.session.add(cached)
    cached = _commit_cache_row(db, CpeResolutionCache, {"product_key": key}, cached)

    return cached.resolved_cpe if cached else resolved


def lookup_cves_by_cpe(cpe: str, max_results: int = 20) -> List[Dict]:
    """CVE lookup via NVD's exact-CPE match (`cpeName`), which makes NVD apply
    its own version-range configuration matching server-side, instead of a
    text-relevance keyword search."""
    from ..extensions import db
    from ..models import CpeCveCache

    cached = CpeCveCache.query.filter_by(cache_key=cpe).first()
    if cached and not cached.is_stale:
        try:
            return json.loads(cached.cve_data)
        except Exception:
            pass

    api_key = _get_nvd_api_key()
    url = current_app.config.get("NVD_API_URL")
    data = _nvd_get(url, {"cpeName": cpe, "resultsPerPage": max_results}, api_key)

    cves = []
    if data:
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            if not _cpe_is_vulnerable(cve, cpe):
                continue
            parsed = _parse_cve_item(cve)
            parsed["match_confidence"] = "cpe"
            cves.append(parsed)

    if cached:
        cached.cve_data = json.dumps(cves)
        cached.lookup_type = "cpe"
        cached.fetched_at = datetime.now(timezone.utc)
    else:
        cached = CpeCveCache(cache_key=cpe, lookup_type="cpe", cve_data=json.dumps(cves))
        db.session.add(cached)
    winner = _commit_cache_row(db, CpeCveCache, {"cache_key": cpe}, cached)
    if winner is not cached and winner is not None:
        try:
            return json.loads(winner.cve_data)
        except Exception:
            pass

    return cves


def lookup_cves_by_keyword(product: str, version: str = "", max_results: int = 5) -> List[Dict]:
    """Free-text NVD keyword search — fallback for services with no
    resolvable CPE. Text-relevance only, no version-range awareness, so
    callers should tag/treat these as lower confidence than a CPE match."""
    from ..extensions import db
    from ..models import CpeCveCache

    cache_key = f"kw:{product}:{version}".strip().lower()
    cached = CpeCveCache.query.filter_by(cache_key=cache_key).first()
    if cached and not cached.is_stale:
        try:
            return json.loads(cached.cve_data)
        except Exception:
            pass

    keyword = f"{product} {version}".strip()
    api_key = _get_nvd_api_key()
    url = current_app.config.get("NVD_API_URL")
    data = _nvd_get(url, {"keywordSearch": keyword, "resultsPerPage": max_results}, api_key)

    cves = []
    if data:
        for item in data.get("vulnerabilities", []):
            parsed = _parse_cve_item(item.get("cve", {}))
            parsed["match_confidence"] = "keyword"
            cves.append(parsed)

    if cached:
        cached.cve_data = json.dumps(cves)
        cached.lookup_type = "keyword"
        cached.fetched_at = datetime.now(timezone.utc)
    else:
        cached = CpeCveCache(cache_key=cache_key, lookup_type="keyword", cve_data=json.dumps(cves))
        db.session.add(cached)
    winner = _commit_cache_row(db, CpeCveCache, {"cache_key": cache_key}, cached)
    if winner is not cached and winner is not None:
        try:
            return json.loads(winner.cve_data)
        except Exception:
            pass

    return cves


def lookup_cves_for_service(product: str, version: str = "", max_results: int = 5, cpe: str = "") -> List[Dict]:
    """Look up CVEs for a discovered service. Prefers exact CPE matching
    (using nmap's own `cpe`, or resolving one via the NVD CPE dictionary) and
    only falls back to free-text keyword search when no CPE can be resolved
    at all — a wrong CPE guess would silently produce wrong CVEs, so
    `resolve_cpe` returns None rather than guess in that case."""
    if not product or product in ("unknown", ""):
        return []

    # nmap reports its own `cpe` field in CPE 2.2 URI-binding format
    # ("cpe:/a:vendor:product:version"), but NVD's `cpeName` query parameter
    # requires the CPE 2.3 formatted string — passed through unconverted it
    # doesn't error, it just matches nothing, silently producing zero CVEs
    # for every service nmap fingerprinted well enough to supply a CPE for.
    nmap_cpe_23 = _cpe22_to_23(cpe) if cpe else None
    if cpe and not nmap_cpe_23:
        log.warning("Could not parse nmap-supplied CPE %r for %s %s; falling back to CPE dictionary resolution",
                    cpe, product, version)

    resolved_cpe = nmap_cpe_23 or resolve_cpe(product, version)

    if resolved_cpe:
        results = lookup_cves_by_cpe(resolved_cpe, max_results)
        for r in results:
            r["cpe"] = resolved_cpe
        return results

    results = lookup_cves_by_keyword(product, version, max_results)
    for r in results:
        r["cpe"] = ""
    return results
