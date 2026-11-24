"""Turn upstream records into mirror rows.

parse_nvd(item)     NVD JSON 2.0 `vulnerabilities[].cve` object
parse_cveorg(rec)   CVE JSON 5.x record (CVEProject/cvelistV5)

Each returns (cve_row: dict, matches: list[dict]) where cve_row holds only
that source's columns of MirrorCve and matches are MirrorCpeMatch rows.
"""
import json
import re
from datetime import datetime, timezone

_MAX_REFS = 25
_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"}


def parse_dt(s):
    """ISO-8601 (with or without offset/Z) -> naive UTC datetime, or None.
    Mirror datetimes are stored naive-UTC so comparisons never mix kinds."""
    if not s:
        return None
    try:
        d = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except ValueError:
        return None
    if d.tzinfo is not None:
        d = d.astimezone(timezone.utc).replace(tzinfo=None)
    return d


def _cpe_unescape(s):
    return (s or "").replace("\\", "")


def split_cpe23(cpe):
    """'cpe:2.3:a:vendor:product:version:update:...' -> dict, or None."""
    if not cpe or not cpe.startswith("cpe:2.3:"):
        return None
    # Split on ':' not preceded by a backslash escape.
    parts = re.split(r"(?<!\\):", cpe)
    if len(parts) < 7:
        return None
    return {"part": parts[2], "vendor": _cpe_unescape(parts[3]).lower(),
            "product": _cpe_unescape(parts[4]).lower(),
            "version": _cpe_unescape(parts[5]), "update": _cpe_unescape(parts[6])}


def _cpe_version(fields):
    """NVD splits some versions across version+update ('9.6' + 'p1' for
    OpenSSH 9.6p1) — rejoin them so they compare against a banner version."""
    v, u = fields["version"], fields["update"]
    if v not in ("*", "-", "") and u not in ("*", "-", ""):
        if re.match(r"^[a-z]+\d*$", u, re.I):
            return v + u
        return f"{v}-{u}"
    return v or "*"


def _severity(score):
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


# ── NVD ──────────────────────────────────────────────────────────────────────

def _primary_metric(metrics, key):
    """NVD can list several scorers per version — prefer NVD's own Primary."""
    lst = metrics.get(key) or []
    for m in lst:
        if m.get("type") == "Primary":
            return m
    return lst[0] if lst else None


def parse_nvd(cve):
    cve_id = cve.get("id", "")
    desc = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    metrics = cve.get("metrics", {}) or {}

    v3 = v3_vec = sev = None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        m = _primary_metric(metrics, key)
        if m:
            d = m.get("cvssData", {})
            v3, v3_vec = d.get("baseScore"), d.get("vectorString")
            sev = (d.get("baseSeverity") or "").upper() or _severity(v3)
            # v4.0 only if there's no 3.x — keeps scores comparable with the
            # rest of the platform, which is CVSS 3-based.
            if key != "cvssMetricV40" or not (metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30")):
                break
    m2 = _primary_metric(metrics, "cvssMetricV2")
    v2 = m2.get("cvssData", {}).get("baseScore") if m2 else None
    if not sev and m2:
        sev = (m2.get("baseSeverity") or "").upper() or _severity(v2)

    cwes = sorted({d.get("value") for w in cve.get("weaknesses", []) or []
                   for d in w.get("description", []) or []
                   if (d.get("value") or "").startswith("CWE-")})

    matches, seen = [], set()
    for config in cve.get("configurations", []) or []:
        for node in config.get("nodes", []) or []:
            if node.get("negate"):
                continue
            for m in node.get("cpeMatch", []) or []:
                if not m.get("vulnerable"):
                    continue            # platform/"running on" criteria
                f = split_cpe23(m.get("criteria", ""))
                if not f:
                    continue
                row = {"cve_id": cve_id, "source": "nvd", "part": f["part"],
                       "vendor": f["vendor"], "product": f["product"],
                       "version": _cpe_version(f),
                       "v_start_incl": m.get("versionStartIncluding"),
                       "v_start_excl": m.get("versionStartExcluding"),
                       "v_end_incl": m.get("versionEndIncluding"),
                       "v_end_excl": m.get("versionEndExcluding")}
                key = tuple(row.values())
                if key not in seen:
                    seen.add(key)
                    matches.append(row)

    status = cve.get("vulnStatus") or ""
    refs = [r.get("url") for r in (cve.get("references") or [])[:_MAX_REFS] if r.get("url")]
    row = {
        "cve_id": cve_id,
        "state": "REJECTED" if status == "Rejected" else "PUBLISHED",
        "published": parse_dt(cve.get("published")),
        "in_nvd": True,
        "nvd_status": status[:32],
        "nvd_last_modified": parse_dt(cve.get("lastModified")),
        "nvd_description": desc,
        "nvd_cvss_v3": v3,
        "nvd_cvss_v3_vector": (v3_vec or "")[:100] or None,
        "nvd_cvss_v2": v2,
        "nvd_severity": sev if sev in _SEVERITIES else _severity(v3 if v3 is not None else v2),
        "cwe_ids": json.dumps(cwes),
        "nvd_has_config": bool(matches),
        "references": json.dumps(refs),
    }
    return row, matches


# ── CVE.org (CVE JSON 5) ─────────────────────────────────────────────────────

def norm_name(s):
    """CNA vendor/product free text -> CPE-style token ('Apache HTTP Server'
    -> 'apache_http_server'), so it can be compared with CPE fields."""
    return re.sub(r"[^a-z0-9]+", "_", (s or "").lower()).strip("_")


_HEXISH = re.compile(r"^[0-9a-f]{12,}$", re.I)
_UNKNOWN = {"", "n/a", "na", "unknown", "unspecified", "*", "-"}


_RANGE_TERM = re.compile(r"^\s*(>=|<=|>|<|=)\s*v?([0-9][^\s,]*)\s*$")
_RANGE_KEYS = {">=": "v_start_incl", ">": "v_start_excl", "<=": "v_end_incl", "<": "v_end_excl"}


def _parse_range_expr(s):
    """Many CNAs (notably GitHub's) put the whole range in the version string
    — ">= 3.1.0, < 4.5.2", "< 1.2" — instead of using lessThan. Returns the
    range columns, or None if `s` isn't such an expression."""
    if not s or not any(op in s for op in "<>"):
        return None
    out = {"v_start_incl": None, "v_start_excl": None, "v_end_incl": None, "v_end_excl": None}
    for term in s.split(","):
        m = _RANGE_TERM.match(term)
        if not m or m.group(1) == "=":
            return None
        out[_RANGE_KEYS[m.group(1)]] = m.group(2)[:64]
    return out


def _affected_rows(cve_id, affected):
    rows = []
    for a in affected or []:
        cpes = [split_cpe23(c) for c in (a.get("cpes") or [])]
        cpes = [c for c in cpes if c and c["vendor"] not in _UNKNOWN and c["product"] not in _UNKNOWN]
        if cpes:
            names = {(c["part"], c["vendor"], c["product"]) for c in cpes}
        else:
            vendor, product = norm_name(a.get("vendor")), norm_name(a.get("product"))
            if vendor in _UNKNOWN or product in _UNKNOWN or not vendor or not product:
                continue
            names = {("a", vendor, product)}

        ranges = []
        for v in a.get("versions") or []:
            if v.get("status") != "affected":
                continue
            if (v.get("versionType") or "").lower() == "git":
                continue
            ver = (v.get("version") or "").strip()
            if _HEXISH.match(ver):
                continue
            lt, lte = v.get("lessThan"), v.get("lessThanOrEqual")
            expr = _parse_range_expr(ver) if not (lt or lte) else None
            if expr:
                ranges.append({"version": "*", **expr})
            elif lt or lte:
                if (lt or lte).strip() in ("*", ""):
                    lt = lte = None
                start = ver if ver.lower() not in _UNKNOWN and ver != "0" else None
                ranges.append({"version": "*", "v_start_incl": start, "v_start_excl": None,
                               "v_end_incl": lte if lte else None,
                               "v_end_excl": lt if lt and not lte else None})
            elif ver.lower() not in _UNKNOWN:
                ranges.append({"version": ver, "v_start_incl": None, "v_start_excl": None,
                               "v_end_incl": None, "v_end_excl": None})
        if not ranges:
            # No usable version data — only an explicit "everything affected"
            # default is matchable; otherwise there's nothing to compare against.
            if a.get("defaultStatus") != "affected":
                continue
            ranges = [{"version": "*", "v_start_incl": None, "v_start_excl": None,
                       "v_end_incl": None, "v_end_excl": None}]

        for part, vendor, product in names:
            for r in ranges:
                rows.append({"cve_id": cve_id, "source": "cveorg", "part": part,
                             "vendor": vendor[:128], "product": product[:128],
                             **{k: (str(v)[:64] if v else v) for k, v in r.items()}})
    # dedupe
    out, seen = [], set()
    for r in rows:
        k = tuple(r.values())
        if k not in seen:
            seen.add(k)
            out.append(r)
    return out


def _cna_metric(containers):
    """Best CVSS from the CNA, else from an ADP (CISA's vulnrichment)."""
    for c in containers:
        for m in c.get("metrics") or []:
            for key in ("cvssV3_1", "cvssV3_0", "cvssV4_0"):
                d = m.get(key)
                if d and d.get("baseScore") is not None:
                    return d.get("baseScore"), d.get("vectorString"), (d.get("baseSeverity") or "").upper()
    return None, None, None


def parse_cveorg(rec):
    meta = rec.get("cveMetadata", {}) or {}
    cve_id = meta.get("cveId", "")
    state = (meta.get("state") or "PUBLISHED").upper()
    containers = rec.get("containers", {}) or {}
    cna = containers.get("cna", {}) or {}
    adps = containers.get("adp", []) or []

    desc = next((d.get("value", "") for d in cna.get("descriptions", []) or []
                 if (d.get("lang") or "").lower().startswith("en")), "")
    if state == "REJECTED" and not desc:
        desc = next((d.get("value", "") for d in cna.get("rejectedReasons", []) or []), "")

    score, vec, sev = _cna_metric([cna] + adps)
    matches = []
    if state != "REJECTED":
        matches = _affected_rows(cve_id, cna.get("affected"))
        for adp in adps:
            matches += [m for m in _affected_rows(cve_id, adp.get("affected")) if m not in matches]

    row = {
        "cve_id": cve_id,
        "state": "REJECTED" if state == "REJECTED" else "PUBLISHED",
        "published": parse_dt(meta.get("datePublished")),
        "in_cveorg": True,
        "cveorg_updated": parse_dt(meta.get("dateUpdated")),
        "assigner": (meta.get("assignerShortName") or "")[:64],
        "cna_description": desc,
        "cna_cvss": score,
        "cna_cvss_vector": (vec or "")[:100] or None,
        "cna_severity": sev if sev in _SEVERITIES else _severity(score),
    }
    return row, matches
