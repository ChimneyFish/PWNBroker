import socket
import requests
from bs4 import BeautifulSoup


def _resolve(hostname):
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None


def query_crtsh(domain):
    """
    Query crt.sh certificate transparency logs.
    Returns (list of {subdomain, source, first_seen}, error_str | None).
    """
    try:
        r = requests.get("https://crt.sh/",
                         params={"q": f"%.{domain}", "output": "json"},
                         timeout=20)
        r.raise_for_status()
        rows = r.json()
    except Exception as e:
        return [], f"crt.sh error: {e}"

    seen = {}
    for row in rows:
        for raw in (row.get("name_value", ""), row.get("common_name", "")):
            for name in raw.splitlines():
                name = name.strip().lower().lstrip("*.")
                if not name:
                    continue
                if name != domain and not name.endswith(f".{domain}"):
                    continue
                if name not in seen:
                    seen[name] = row.get("not_before", "")[:10]

    return [{"subdomain": sub, "source": "crt.sh", "first_seen": fs}
            for sub, fs in seen.items()], None


def query_dnsdumpster_api(domain, api_key):
    """
    Use the official DNSDumpster API (requires key).
    Returns (list of {subdomain, record_type, value, source, first_seen}, error_str | None).
    """
    try:
        r = requests.get(
            f"https://api.dnsdumpster.com/domain/{domain}",
            headers={"X-API-Key": api_key},
            timeout=20,
        )
        if r.status_code == 401:
            return [], "DNSDumpster API error: invalid API key"
        if r.status_code == 429:
            return [], "DNSDumpster API error: rate limit hit"
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        return [], f"DNSDumpster API error: {e}"

    results = []
    seen = set()

    type_map = {"a": "A", "aaaa": "AAAA", "cname": "CNAME", "mx": "MX", "ns": "NS"}
    for rtype, label in type_map.items():
        for record in data.get(rtype, []):
            host = record.get("host", "").strip().lower().rstrip(".")
            if not host:
                continue
            if host != domain and not host.endswith(f".{domain}"):
                continue

            if rtype in ("a", "aaaa"):
                ips = record.get("ips", [])
                if isinstance(ips, list) and ips:
                    value = ips[0].get("ip", "") if isinstance(ips[0], dict) else str(ips[0])
                else:
                    value = record.get("ip", "")
            elif rtype == "cname":
                value = (record.get("target") or record.get("value") or "").lower().rstrip(".")
            elif rtype == "mx":
                target = (record.get("target") or record.get("exchange") or "").rstrip(".")
                priority = record.get("priority", "")
                value = f"{priority} {target}".strip() if priority else target
            elif rtype == "ns":
                value = (record.get("target") or record.get("ns") or "").rstrip(".")
            else:
                value = ""

            key = f"{label}:{host}"
            if key not in seen:
                seen.add(key)
                results.append({
                    "subdomain": host,
                    "record_type": label,
                    "value": value,
                    "source": "DNSDumpster",
                    "first_seen": "",
                })

    return results, None


def query_dnsdumpster_scrape(domain):
    """
    Scrape DNSDumpster for subdomain records (keyless fallback).
    Returns (list of {subdomain, source, first_seen}, error_str | None).
    """
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (PwnBroker subdomain scanner)"})

    try:
        r = session.get("https://dnsdumpster.com/", timeout=15)
        r.raise_for_status()
    except Exception as e:
        return [], f"DNSDumpster error: {e}"

    soup = BeautifulSoup(r.text, "html.parser")
    csrf_input = soup.find("input", {"name": "csrfmiddlewaretoken"})
    if not csrf_input:
        return [], "DNSDumpster error: could not find CSRF token"
    csrf = csrf_input["value"]

    try:
        r = session.post(
            "https://dnsdumpster.com/",
            data={"csrfmiddlewaretoken": csrf, "targetip": domain, "user": "free"},
            headers={"Referer": "https://dnsdumpster.com/"},
            timeout=20,
        )
        r.raise_for_status()
    except Exception as e:
        return [], f"DNSDumpster error: {e}"

    soup = BeautifulSoup(r.text, "html.parser")
    results = []
    seen = set()

    for table in soup.find_all("table"):
        for row in table.find_all("tr"):
            cells = row.find_all("td")
            if not cells:
                continue
            raw = cells[0].get_text(separator="\n").strip().splitlines()
            for candidate in raw:
                candidate = candidate.strip().lower().rstrip(".")
                if not candidate:
                    continue
                if candidate != domain and not candidate.endswith(f".{domain}"):
                    continue
                if candidate not in seen:
                    seen.add(candidate)
                    results.append({"subdomain": candidate,
                                    "source": "DNSDumpster",
                                    "first_seen": ""})

    return results, None


def enumerate(domain, dnsdumpster_key=None):
    """
    Run crt.sh + DNSDumpster (API if key provided, scrape otherwise).
    Returns {domain, subdomains, total, errors, sources_used}.
    Each subdomain: {subdomain, ip, sources, first_seen}.
    """
    domain = domain.strip().lower()
    errors = []
    merged = {}   # subdomain -> {sources: set, first_seen: str}

    # crt.sh (always keyless)
    rows, err = query_crtsh(domain)
    if err:
        errors.append(err)
    for row in rows:
        sub = row["subdomain"]
        if sub not in merged:
            merged[sub] = {"sources": set(), "first_seen": row.get("first_seen", "")}
        merged[sub]["sources"].add(row["source"])
        if row.get("first_seen") and not merged[sub]["first_seen"]:
            merged[sub]["first_seen"] = row["first_seen"]

    # DNSDumpster — API preferred, scrape as fallback
    if dnsdumpster_key:
        rows, err = query_dnsdumpster_api(domain, dnsdumpster_key)
    else:
        rows, err = query_dnsdumpster_scrape(domain)
    if err:
        errors.append(err)
    for row in rows:
        sub = row["subdomain"]
        if sub not in merged:
            merged[sub] = {"sources": set(), "first_seen": row.get("first_seen", "")}
        merged[sub]["sources"].add(row["source"])
        if row.get("first_seen") and not merged[sub]["first_seen"]:
            merged[sub]["first_seen"] = row["first_seen"]

    subdomains = [
        {
            "subdomain": sub,
            "ip":        _resolve(sub),
            "sources":   sorted(meta["sources"]),
            "first_seen": meta["first_seen"],
        }
        for sub, meta in sorted(merged.items())
    ]

    return {
        "domain":       domain,
        "subdomains":   subdomains,
        "total":        len(subdomains),
        "errors":       errors,
        "sources_used": ["crt.sh", "DNSDumpster"],
    }


def enumerate_dns_records(domain, dnsdumpster_key=None):
    """
    Enumerate all DNS record types for domain target monitoring.
    Returns list of {name, record_type, value, source, first_seen}.
    Deduplicates by (name, record_type).
    """
    domain = domain.strip().lower()
    seen = {}  # (name, record_type) -> dict

    rows, _ = query_crtsh(domain)
    for row in rows:
        name = row["subdomain"]
        key = (name, "A")
        if key not in seen:
            seen[key] = {
                "name": name,
                "record_type": "A",
                "value": _resolve(name) or "",
                "source": "crt.sh",
                "first_seen": row.get("first_seen", ""),
            }

    if dnsdumpster_key:
        rows, _ = query_dnsdumpster_api(domain, dnsdumpster_key)
    else:
        rows, _ = query_dnsdumpster_scrape(domain)

    for row in rows:
        name = row["subdomain"]
        rtype = row.get("record_type", "A")
        key = (name, rtype)
        if key not in seen:
            seen[key] = {
                "name": name,
                "record_type": rtype,
                "value": row.get("value", ""),
                "source": "DNSDumpster",
                "first_seen": row.get("first_seen", ""),
            }
        else:
            if not seen[key]["value"] and row.get("value"):
                seen[key]["value"] = row["value"]

    return list(seen.values())
