"""
GitHub Advisory Database (GHSA) integration.

Queries the GitHub GraphQL API for known vulnerabilities by package/ecosystem.
Any GitHub personal access token works for public advisory data (no special
scopes required). Set one in Settings → Threat Intel APIs.
"""
import json
import re

import requests

GHSA_GRAPHQL = "https://api.github.com/graphql"

# OSV ecosystem name → GHSA SecurityAdvisoryEcosystem GraphQL enum
ECO_TO_GHSA = {
    "PyPI":      "PIP",
    "npm":       "NPM",
    "Go":        "GO",
    "crates.io": "RUST",
    "RubyGems":  "RUBYGEMS",
    "Packagist": "COMPOSER",
    "Maven":     "MAVEN",
    "NuGet":     "NUGET",
}

_QUERY = """
query($eco: SecurityAdvisoryEcosystem!, $pkg: String!) {
  securityVulnerabilities(
    ecosystem: $eco, package: $pkg, first: 20,
    orderBy: {field: UPDATED_AT, direction: DESC}
  ) {
    nodes {
      advisory {
        ghsaId
        summary
        severity
        cvss { score vectorString }
        identifiers { type value }
        publishedAt
        withdrawnAt
      }
      vulnerableVersionRange
      firstPatchedVersion { identifier }
    }
  }
}
"""

_SEV_MAP = {"CRITICAL": "critical", "HIGH": "high",
            "MODERATE": "medium",   "LOW": "low"}
_SEV_CVSS = {"CRITICAL": 9.5, "HIGH": 7.5, "MODERATE": 5.5, "LOW": 3.5}


# ── Version comparison ────────────────────────────────────────────────────────

def _vtuple(v: str) -> tuple:
    v = re.sub(r"[^0-9.]", "", v.split("+")[0].split("-")[0])
    parts = v.split(".")
    out = []
    for p in parts[:4]:
        try:
            out.append(int(p))
        except ValueError:
            out.append(0)
    while len(out) < 4:
        out.append(0)
    return tuple(out)


def _in_range(version: str, range_str: str) -> bool:
    """Return True if *version* falls within the GHSA *vulnerableVersionRange*."""
    if not range_str or not version:
        return False
    try:
        v = _vtuple(version)
    except Exception:
        return False
    for part in [c.strip() for c in range_str.split(",") if c.strip()]:
        m = re.match(r"^([><=!]+)\s*(.+)$", part)
        if not m:
            continue
        op, rhs = m.group(1), m.group(2).strip()
        try:
            rv = _vtuple(rhs)
        except Exception:
            continue
        checks = {
            ">=": v >= rv, ">": v > rv,
            "<=": v <= rv, "<": v < rv,
            "=": v == rv, "==": v == rv,
            "!=": v != rv, "!": v != rv,
        }
        if not checks.get(op, True):
            return False
    return True


# ── Main query ────────────────────────────────────────────────────────────────

def query_ghsa(packages: list, github_token: str, host: str = "") -> list:
    """
    Query GHSA for each (name, version, ecosystem) in *packages*.

    Returns a list of ScanResult-ready dicts.  Results that duplicate known
    OSV findings should be filtered by the caller using ``_dedupe_key``.
    """
    if not github_token or not packages:
        return []

    headers = {
        "Authorization": f"bearer {github_token}",
        "Content-Type": "application/json",
    }

    results = []
    seen_ghsa: set = set()

    for name, version, ecosystem in packages:
        ghsa_eco = ECO_TO_GHSA.get(ecosystem)
        if not ghsa_eco:
            continue

        try:
            resp = requests.post(
                GHSA_GRAPHQL,
                json={"query": _QUERY, "variables": {"eco": ghsa_eco, "pkg": name}},
                headers=headers,
                timeout=20,
            )
            if not resp.ok:
                continue
            data = resp.json()
        except requests.RequestException:
            continue

        nodes = (
            (data.get("data") or {})
            .get("securityVulnerabilities", {})
            .get("nodes", [])
        )

        for node in nodes:
            adv = node.get("advisory") or {}
            if adv.get("withdrawnAt"):
                continue

            vuln_range = node.get("vulnerableVersionRange", "")
            if not _in_range(version, vuln_range):
                continue

            ghsa_id = adv.get("ghsaId", "")
            if (name, ghsa_id) in seen_ghsa:
                continue
            seen_ghsa.add((name, ghsa_id))

            severity_raw = (adv.get("severity") or "MODERATE").upper()
            cvss_raw     = (adv.get("cvss") or {}).get("score")
            cvss_score   = float(cvss_raw) if cvss_raw else _SEV_CVSS.get(severity_raw, 5.5)
            sev_label    = _SEV_MAP.get(severity_raw, "medium")

            identifiers = adv.get("identifiers", [])
            cve_id      = next(
                (i["value"] for i in identifiers if i.get("type") == "CVE"),
                None,
            )

            fixed_ver = (node.get("firstPatchedVersion") or {}).get("identifier")

            from .osv_scanner import _remediation_cmd
            remediation = _remediation_cmd(ecosystem, name, fixed_ver)

            results.append({
                "result_type":     "vulnerability",
                "host":            host,
                "severity":        sev_label,
                "title":           f"{name} — {ghsa_id}",
                "description":     (adv.get("summary") or "")[:1000],
                "cve_id":          cve_id,
                "cvss_score":      round(cvss_score, 1),
                "remediation":     remediation,
                "package_name":    name,
                "package_version": version,
                "ecosystem":       ecosystem,
                "fixed_version":   fixed_ver,
                "raw_data": json.dumps({
                    "source":  "ghsa",
                    "ghsa_id": ghsa_id,
                    "aliases": [i["value"] for i in identifiers],
                    "range":   vuln_range,
                }),
            })

    return results


def dedupe_key(result: dict) -> tuple:
    """Return a hashable key used to de-duplicate against OSV results."""
    raw = {}
    try:
        raw = json.loads(result.get("raw_data") or "{}")
    except Exception:
        pass
    return (
        (result.get("package_name") or "").lower(),
        result.get("cve_id") or raw.get("ghsa_id") or result.get("title", ""),
    )
