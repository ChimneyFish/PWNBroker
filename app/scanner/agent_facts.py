"""Verify scan findings from an endpoint agent's host inventory.

The PwnBroker agent (app/static/agent/pwnbroker_agent.py) periodically sends a
read-only inventory of its host: OS, IP addresses, which package owns each
listening port, installed package versions, the CVE entries in those
packages' vendor changelogs, and Apache/nginx modules. Nothing flows the other
way except "please send a fresh inventory" and the list of packages whose
changelogs are wanted — PwnBroker never runs commands on the host.

AgentHostFacts exposes that inventory through the same interface as the SSH
HostFacts in ssh_verify.py, so evaluate_host() applies exactly the same
rule-out / confirm logic whichever way the facts were gathered.

Trust: an inventory can rule findings out, so only registered agents (which
needed the registration token) are used, an IP claimed by more than one agent
is ignored, and inventories older than AGENT_INVENTORY_MAX_AGE_DAYS are not
used.
"""
import ipaddress
import json
import logging
import re
import threading
from datetime import datetime, timedelta, timezone

log = logging.getLogger(__name__)

INVENTORY_SCHEMA = 1
INVENTORY_INTERVAL_HOURS = 6          # agent sends this often, plus on request
_MAX_PACKAGES = 30000
_MAX_ENTRIES = 5000                   # CVE changelog lines per package
_MAX_LISTENERS = 2000
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_:~-]{0,199}$")
_MAX_PROGRAMS = 5000
_WIN_BUILD_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+$")
_KB_RE = re.compile(r"^KB\d{4,9}$", re.I)
_FILE_KEYS = ("product", "company", "description", "product_version", "file_version")


def max_age_days():
    try:
        from flask import current_app
        return int(current_app.config.get("AGENT_INVENTORY_MAX_AGE_DAYS", 7))
    except Exception:
        return 7


def wanted_changelog_packages():
    """Server packages whose changelogs the agent should send even when the
    package doesn't own a listener (the SSH checks' product fallbacks)."""
    from .ssh_verify import _PRODUCT_PACKAGES
    return sorted({p for _, pkgs in _PRODUCT_PACKAGES for p in pkgs})


# ── ingest ───────────────────────────────────────────────────────────────────

def _s(v, n=256):
    return str(v)[:n] if v is not None else ""


def _ip(v):
    try:
        a = ipaddress.ip_address(str(v).split("%", 1)[0])
    except ValueError:
        return None
    if a.is_loopback or a.is_unspecified or a.is_link_local or a.is_multicast:
        return None
    return str(a)


def normalize_inventory(data):
    """Validate and trim an inventory payload → dict safe to store, or raise
    ValueError. Agent input is untrusted: everything is type-checked, length
    capped, and package names must look like package names."""
    if not isinstance(data, dict):
        raise ValueError("inventory must be a JSON object")
    osd = data.get("os") if isinstance(data.get("os"), dict) else {}
    pm = data.get("package_manager")
    pm = pm if pm in ("deb", "rpm") else None

    ips = []
    for v in (data.get("ips") or [])[:64]:
        ip = _ip(v)
        if ip and ip not in ips:
            ips.append(ip)

    listeners = []
    for l in (data.get("listeners") or [])[:_MAX_LISTENERS]:
        if not isinstance(l, dict):
            continue
        try:
            port = int(l.get("port"))
        except (TypeError, ValueError):
            continue
        if not 0 < port < 65536:
            continue
        pkg = l.get("package")
        item = {"port": port, "proto": "udp" if l.get("proto") == "udp" else "tcp",
                "exe": _s(l.get("exe"), 512) or None,
                "package": pkg if isinstance(pkg, str) and _NAME_RE.match(pkg) else None}
        fi = l.get("file")
        if isinstance(fi, dict):
            fi = {k: _s(fi.get(k), 160).strip() for k in _FILE_KEYS if fi.get(k)}
            if fi:
                item["file"] = fi
        listeners.append(item)

    packages = {}
    raw = data.get("packages") if isinstance(data.get("packages"), dict) else {}
    for name, val in list(raw.items())[:_MAX_PACKAGES]:
        if not (isinstance(name, str) and _NAME_RE.match(name)):
            continue
        if not (isinstance(val, (list, tuple)) and val and isinstance(val[0], str)):
            continue
        src = val[1] if len(val) > 1 and isinstance(val[1], str) and _NAME_RE.match(val[1]) else name
        packages[name] = [val[0][:128], src]

    changelogs = {}
    raw = data.get("changelogs") if isinstance(data.get("changelogs"), dict) else {}
    for name, val in list(raw.items())[:500]:
        if not (isinstance(name, str) and _NAME_RE.match(name) and isinstance(val, dict)):
            continue
        entries = []
        for e in (val.get("entries") or [])[:_MAX_ENTRIES]:
            if isinstance(e, (list, tuple)) and len(e) == 2:
                entries.append([_s(e[0], 200), _s(e[1], 300)])
        changelogs[name] = {"found": bool(val.get("found")), "trimmed": bool(val.get("trimmed")),
                            "entries": entries}

    windows = None
    win = data.get("windows")
    if isinstance(win, dict):
        build = _s(win.get("build"), 40).strip()
        windows = {
            "build": build if _WIN_BUILD_RE.match(build) else "",
            "product": _s(win.get("product"), 120),
            "display_version": _s(win.get("display_version"), 20),
            "edition": _s(win.get("edition"), 60),
            "installation_type": _s(win.get("installation_type"), 30),
            "hotfixes": sorted({h.upper() for h in (win.get("hotfixes") or [])[:5000]
                                if isinstance(h, str) and _KB_RE.match(h)}),
        }

    programs = []
    for p in (data.get("programs") or [])[:_MAX_PROGRAMS]:
        if isinstance(p, dict) and isinstance(p.get("name"), str) and p["name"].strip():
            programs.append({"name": _s(p["name"], 200).strip(),
                             "version": _s(p.get("version"), 64).strip(),
                             "publisher": _s(p.get("publisher"), 120).strip(),
                             "location": _s(p.get("location"), 400).strip()})

    mods = data.get("apache_modules")
    mods = sorted({m for m in mods if isinstance(m, str) and re.match(r"^[a-z0-9_]{1,64}$", m)}
                  )[:500] if isinstance(mods, list) else None
    nginx = data.get("nginx_build")
    nginx = _s(nginx, 20000) if isinstance(nginx, str) and nginx.strip() else None

    return {
        "schema": INVENTORY_SCHEMA,
        "collected_at": _s(data.get("collected_at"), 40),
        "os": {"kernel": _s(osd.get("kernel"), 40), "id": _s(osd.get("id"), 40).lower(),
               "pretty": _s(osd.get("pretty"), 120)},
        "package_manager": pm,
        "ips": ips,
        "listeners": listeners,
        "packages": packages,
        "changelogs": changelogs,
        "apache_modules": mods,
        "nginx_build": nginx,
        "windows": windows,
        "programs": programs,
        "errors": [_s(e, 300) for e in (data.get("errors") or [])[:20]],
    }


def store_inventory(agent, data):
    inv = normalize_inventory(data)
    agent.inventory = json.dumps(inv, separators=(",", ":"))
    agent.inventory_at = datetime.now(timezone.utc)
    agent.inventory_ips = " " + " ".join(inv["ips"]) + " " if inv["ips"] else None
    agent.inventory_requested = False
    return inv


def inventory_due(agent):
    if agent.inventory_requested or not agent.inventory_at:
        return True
    at = agent.inventory_at if agent.inventory_at.tzinfo else agent.inventory_at.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) - at > timedelta(hours=INVENTORY_INTERVAL_HOURS)


# ── facts ────────────────────────────────────────────────────────────────────

class AgentHostFacts:
    """Same interface as ssh_verify.HostFacts, backed by a stored inventory."""

    def __init__(self, agent, inv):
        self.agent = agent
        self.inv = inv
        self.pm = inv.get("package_manager")
        osd = inv.get("os") or {}
        self.kernel = osd.get("kernel") or ""
        self.os_id = osd.get("id") or ""
        self.os = osd.get("pretty") or "this host"
        self.windows = inv.get("windows") or None      # set → windows_verify applies
        self.programs = inv.get("programs") or []
        at = agent.inventory_at
        self.label = f"agent on {agent.hostname or 'host'}" + (
            f", inventory {at.strftime('%Y-%m-%d %H:%M')} UTC" if at else "")

    def listener(self, port):
        """The listener record on `port` (TCP preferred), or None."""
        best = None
        for l in self.inv.get("listeners") or []:
            if l["port"] == int(port):
                if l["proto"] == "tcp" or best is None:
                    best = l
        return best

    def listener_package(self, port):
        best = self.listener(port)
        if not best:
            return None, None
        return best.get("package"), best.get("exe")

    def package_owning(self, path):
        for l in self.inv.get("listeners") or []:
            if l.get("exe") == path:
                return l.get("package")
        return None

    def installed(self, pkg):
        v = (self.inv.get("packages") or {}).get(pkg)
        return (v[0], v[1]) if v else None

    def changelog(self, pkg, source, version):
        cl = (self.inv.get("changelogs") or {}).get(pkg)
        if cl is None and source:
            cl = (self.inv.get("changelogs") or {}).get(source)
        text = ""
        if cl and cl.get("found"):
            text = "\n".join(f"{h}\n  {line}" if h else line for h, line in cl["entries"])
            if not cl.get("trimmed"):
                return text, True
        if self.pm == "deb":
            # Missing or trimmed on disk (Ubuntu ships only recent entries):
            # fetch the full one for this exact version — sends only the
            # package name and version, never anything about the host.
            from .ssh_verify import vendor_changelog
            full = vendor_changelog(self.os_id, source or pkg, version)
            if full:
                return full, True
        return text, False

    def apache_modules(self):
        mods = self.inv.get("apache_modules")
        return set(mods) if mods else False

    def nginx_build(self):
        b = self.inv.get("nginx_build")
        return b if b and "configure arguments" in b else False


def _fresh(agent):
    if not agent.inventory_at:
        return False
    at = agent.inventory_at if agent.inventory_at.tzinfo else agent.inventory_at.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) - at <= timedelta(days=max_age_days())


def agents_for_host(host):
    from ..models import EndpointAgent
    ip = _ip(host)
    if not ip:
        return []
    return [a for a in EndpointAgent.query.filter(
                EndpointAgent.inventory_ips.like(f"% {ip} %")).all() if _fresh(a)]


def facts_for_host(host):
    """AgentHostFacts for the one agent reporting `host` as its address, or None."""
    agents = agents_for_host(host)
    if len(agents) != 1:
        if len(agents) > 1:
            log.warning("%d agents claim %s — not using agent inventory for it", len(agents), host)
        return None
    a = agents[0]
    try:
        inv = json.loads(a.inventory)
    except (TypeError, ValueError):
        return None
    return AgentHostFacts(a, inv)


# ── re-verify a host's open findings when a new inventory arrives ────────────

def reverify_host_findings(agent_db_id):
    """Run the credentialed checks for every open, still-unproven (or
    agent-confirmed) finding on the agent's addresses. Returns a summary."""
    from ..extensions import db
    from ..models import EndpointAgent, ScanResult, VulnTicket
    from ..routes.vulns import _apply_newer_evidence
    from .ssh_verify import verify_credentialed
    from .verify import UNCONFIRMED, NOT_EXPLOITABLE, INSTALLED

    agent = db.session.get(EndpointAgent, agent_db_id)
    if not agent or not agent.inventory_ips:
        return {}
    ips = set(agent.inventory_ips.split())
    rows, prev = [], {}
    for t in VulnTicket.query.filter(VulnTicket.status.in_(("open", "in_progress"))).all():
        r = t.scan_result
        if (r is not None and r.host in ips and r.cve_id and r.is_inferred
                and r.verification_status in (UNCONFIRMED, INSTALLED)):
            prev[r.id] = (r.verification_status, r.verification_evidence)
            r.verification_status = UNCONFIRMED
            rows.append((t, r))
    if not rows:
        return {"checked": 0}
    hints = {}
    for scan_id in {r.scan_id for _, r in rows}:
        for p in ScanResult.query.filter_by(scan_id=scan_id, result_type="port").all():
            hints[(p.host, p.port)] = p.service or ""
    summary = {UNCONFIRMED: len(rows), NOT_EXPLOITABLE: 0, INSTALLED: 0}
    verify_credentialed([r for _, r in rows], None, summary, hints)
    now = datetime.now(timezone.utc)
    from .verify import classify
    for t, r in rows:
        if r.verification_status == UNCONFIRMED and prev[r.id][0] == INSTALLED:
            # This pass couldn't settle it (e.g. vendor changelog unreachable):
            # keep the earlier Confirmed verdict rather than downgrading it.
            r.verification_status, r.verification_evidence = prev[r.id]
        classify(r)
        _apply_newer_evidence(t, r, now)
    db.session.commit()
    summary["checked"] = len(rows)
    log.info("agent %s inventory: checked %d findings — %d confirmed, %d ruled out",
             agent.hostname, len(rows), summary[INSTALLED], summary[NOT_EXPLOITABLE])
    return summary


def reverify_in_background(app, agent_db_id):
    def _run():
        with app.app_context():
            try:
                reverify_host_findings(agent_db_id)
            except Exception as e:
                log.warning("agent re-verification failed: %s", e)
                from ..extensions import db
                db.session.rollback()
    threading.Thread(target=_run, daemon=True, name="agent-reverify").start()
