"""
Fetch and cache NVD, EPSS, and MITRE ATT&CK data for CVEs in the environment.
All functions are safe to call with an active Flask app context.
"""
import json
import os
import time
import logging
from datetime import datetime, timezone, timedelta

import requests

log = logging.getLogger(__name__)

_EPSS_URL   = "https://api.first.org/data/v1/epss"
_NVD_URL    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data"
    "/master/enterprise-attack/enterprise-attack.json"
)
_ATTACK_CACHE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "data", "attack_enterprise.json",
)
_ATTACK_MAX_AGE_DAYS = 30
_SESSION = requests.Session()
_SESSION.headers["User-Agent"] = "PwnBroker/1.0 (+security-research)"


# ── EPSS ─────────────────────────────────────────────────────────────────────

def fetch_epss(cve_ids: list[str]) -> dict[str, dict]:
    """
    Batch-fetch EPSS scores for up to 100 CVE IDs.
    Returns {cve_id: {score, percentile}}.
    """
    if not cve_ids:
        return {}
    results = {}
    # API supports up to 100 CVEs per request
    for chunk in _chunks(cve_ids, 100):
        try:
            resp = _SESSION.get(
                _EPSS_URL,
                params={"cve": ",".join(chunk)},
                timeout=15,
            )
            resp.raise_for_status()
            for row in resp.json().get("data", []):
                cid = row.get("cve", "").upper()
                results[cid] = {
                    "score":      float(row.get("epss", 0)),
                    "percentile": float(row.get("percentile", 0)),
                }
        except Exception as e:
            log.warning("EPSS fetch failed: %s", e)
    return results


# ── NVD ──────────────────────────────────────────────────────────────────────

def fetch_nvd(cve_id: str, api_key: str | None = None) -> dict:
    """
    Fetch NVD data for a single CVE.
    Returns a dict with cvss_v3, cvss_v2, severity, cwe_ids, description, published.
    """
    headers = {}
    if api_key:
        headers["apiKey"] = api_key
    try:
        resp = _SESSION.get(
            _NVD_URL,
            params={"cveId": cve_id},
            headers=headers,
            timeout=15,
        )
        resp.raise_for_status()
        items = resp.json().get("vulnerabilities", [])
        if not items:
            return {}
        cve = items[0]["cve"]

        # CVSS v3
        cvss_v3 = cvss_v3_vec = severity = None
        for metric in cve.get("metrics", {}).get("cvssMetricV31", []):
            d = metric.get("cvssData", {})
            cvss_v3     = d.get("baseScore")
            cvss_v3_vec = d.get("vectorString")
            severity    = d.get("baseSeverity")
            break
        if not cvss_v3:
            for metric in cve.get("metrics", {}).get("cvssMetricV30", []):
                d = metric.get("cvssData", {})
                cvss_v3     = d.get("baseScore")
                cvss_v3_vec = d.get("vectorString")
                severity    = d.get("baseSeverity")
                break

        # CVSS v2
        cvss_v2 = None
        for metric in cve.get("metrics", {}).get("cvssMetricV2", []):
            cvss_v2 = metric.get("cvssData", {}).get("baseScore")
            if not severity:
                severity = metric.get("baseSeverity")
            break

        # CWE
        cwe_ids = []
        for weakness in cve.get("weaknesses", []):
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en" and desc.get("value", "").startswith("CWE-"):
                    cwe_ids.append(desc["value"])

        # Description
        description = ""
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # Published date
        published = None
        pub_str = cve.get("published")
        if pub_str:
            try:
                published = datetime.fromisoformat(pub_str.replace("Z", "+00:00"))
            except Exception:
                pass

        return {
            "cvss_v3":     cvss_v3,
            "cvss_v3_vec": cvss_v3_vec,
            "cvss_v2":     cvss_v2,
            "severity":    severity,
            "cwe_ids":     cwe_ids,
            "description": description,
            "published":   published,
        }
    except Exception as e:
        log.warning("NVD fetch failed for %s: %s", cve_id, e)
        return {}


# ── MITRE ATT&CK ─────────────────────────────────────────────────────────────

def _attack_cache_fresh() -> bool:
    if not os.path.exists(_ATTACK_CACHE):
        return False
    mtime = datetime.fromtimestamp(os.path.getmtime(_ATTACK_CACHE), tz=timezone.utc)
    return (datetime.now(timezone.utc) - mtime).days < _ATTACK_MAX_AGE_DAYS


def refresh_attack_cache() -> bool:
    """Download and cache ATT&CK Enterprise STIX JSON. Returns True on success."""
    try:
        log.info("Downloading ATT&CK Enterprise STIX…")
        resp = _SESSION.get(_ATTACK_URL, timeout=60, stream=True)
        resp.raise_for_status()
        os.makedirs(os.path.dirname(_ATTACK_CACHE), exist_ok=True)
        with open(_ATTACK_CACHE, "wb") as f:
            for chunk in resp.iter_content(chunk_size=65536):
                f.write(chunk)
        log.info("ATT&CK cache written to %s", _ATTACK_CACHE)
        return True
    except Exception as e:
        log.warning("ATT&CK cache refresh failed: %s", e)
        return False


def build_cve_technique_index() -> dict[str, list[dict]]:
    """
    Parse the cached ATT&CK STIX bundle and return a dict:
    {cve_id: [{id, name, tactic}, ...]}
    """
    if not os.path.exists(_ATTACK_CACHE):
        return {}
    try:
        with open(_ATTACK_CACHE, "r", encoding="utf-8") as f:
            bundle = json.load(f)
    except Exception as e:
        log.warning("ATT&CK cache parse failed: %s", e)
        return {}

    index: dict[str, list[dict]] = {}

    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        # Extract technique ID and name
        tech_id = tech_name = tactic = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tech_id   = ref.get("external_id", "")
                tech_name = obj.get("name", "")
        # Get tactic
        phases = obj.get("kill_chain_phases", [])
        if phases:
            tactic = phases[0].get("phase_name", "").replace("-", " ").title()

        if not tech_id:
            continue

        # Find CVE references
        for ref in obj.get("external_references", []):
            if ref.get("source_name", "").lower() == "cve":
                cve_id = ref.get("external_id", "").upper()
                if cve_id:
                    index.setdefault(cve_id, [])
                    entry = {"id": tech_id, "name": tech_name, "tactic": tactic}
                    if entry not in index[cve_id]:
                        index[cve_id].append(entry)

    return index


def get_techniques_for_cves(cve_ids: list[str]) -> dict[str, list[dict]]:
    """
    Return ATT&CK technique mapping for the given CVE IDs.
    Refreshes the cache if stale.
    """
    if not _attack_cache_fresh():
        refresh_attack_cache()
    index = build_cve_technique_index()
    return {cid: index.get(cid.upper(), []) for cid in cve_ids}


# ── Orchestrator ──────────────────────────────────────────────────────────────

def enrich_all_cves(app=None):
    """
    Main enrichment job: fetch EPSS + NVD + ATT&CK for every unique CVE
    in the database that hasn't been refreshed in the last 24 hours.
    Safe to call from a scheduler thread.
    """
    _app = app or _get_app()
    with _app.app_context():
        from ..models import VulnTicket, CVEEnrichment, ThreatConfig
        from ..extensions import db

        # Collect all unique CVEs in the system
        rows = (VulnTicket.query
                .with_entities(VulnTicket.cve_id)
                .filter(VulnTicket.cve_id.isnot(None))
                .distinct().all())
        all_cves = [r.cve_id for r in rows if r.cve_id]
        if not all_cves:
            return

        now     = datetime.now(timezone.utc)
        cutoff  = now - timedelta(hours=24)
        cfg     = ThreatConfig.query.first()
        nvd_key = cfg.nvd_api_key if cfg else None

        # Only re-fetch stale entries
        stale = []
        for cve_id in all_cves:
            e = CVEEnrichment.query.filter_by(cve_id=cve_id).first()
            if not e or not e.epss_fetched_at or e.epss_fetched_at < cutoff:
                stale.append(cve_id)

        if not stale:
            return

        log.info("Enriching %d CVEs: %s", len(stale), stale)

        # 1. Batch EPSS
        epss_data = fetch_epss(stale)

        # 2. ATT&CK (uses cache, not per-CVE request)
        attack_index = get_techniques_for_cves(stale)

        # 3. NVD + upsert (rate-limited: 5 req/30s without key)
        delay = 6.5 if not nvd_key else 0.7
        for cve_id in stale:
            e = CVEEnrichment.query.filter_by(cve_id=cve_id).first()
            if not e:
                e = CVEEnrichment(cve_id=cve_id)
                db.session.add(e)

            # EPSS
            if cve_id in epss_data:
                e.epss_score      = epss_data[cve_id]["score"]
                e.epss_percentile = epss_data[cve_id]["percentile"]
                e.epss_fetched_at = now

            # ATT&CK
            techs = attack_index.get(cve_id, [])
            e.attack_techniques = json.dumps(techs) if techs else "[]"
            e.attack_fetched_at = now

            # NVD
            nvd = fetch_nvd(cve_id, nvd_key)
            if nvd:
                e.cvss_v3        = nvd.get("cvss_v3")
                e.cvss_v3_vector = nvd.get("cvss_v3_vec")
                e.cvss_v2        = nvd.get("cvss_v2")
                e.nvd_severity   = nvd.get("severity")
                e.cwe_ids        = json.dumps(nvd.get("cwe_ids", []))
                e.nvd_description = nvd.get("description")
                e.nvd_published  = nvd.get("published")
                e.nvd_fetched_at = now

            db.session.commit()
            time.sleep(delay)

        log.info("CVE enrichment complete.")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _chunks(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def _get_app():
    from flask import current_app
    return current_app._get_current_object()
