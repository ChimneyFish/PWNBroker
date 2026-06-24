import requests
import time
from flask import current_app
from typing import List, Dict


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


def lookup_cves_for_service(product: str, version: str = "", max_results: int = 5) -> List[Dict]:
    if not product or product in ("unknown", ""):
        return []

    keyword = f"{product} {version}".strip()
    api_key = _get_nvd_api_key()
    url = current_app.config.get("NVD_API_URL")

    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results,
    }

    try:
        resp = requests.get(url, params=params, headers=headers, timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        return []

    cves = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
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

        cves.append({
            "cve_id": cve_id,
            "description": desc,
            "cvss_score": cvss_score,
            "severity": severity,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        })

        time.sleep(0.1)

    return cves


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
