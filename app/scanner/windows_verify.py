"""Verify scan findings on Windows hosts from the PwnBroker agent's inventory.

Windows has no package manager or vendor changelogs, so the Linux checks in
ssh_verify.py don't apply. Two things settle a finding instead:

Windows itself (SMB, RDP, HTTP.sys, IIS, ...)
    Microsoft publishes, per CVE and per Windows version, the build that
    contains the fix (cve_mirror/msrc.py). Windows updates are cumulative, so
    the host's build number — 10.0.19045.5131 — says whether it has the fix.

Other software (Apache, Tomcat, OpenSSL, MySQL, ...)
    Windows builds of these aren't patched by a distribution, so the version
    that's installed is the version that runs. The agent reports which
    program owns each listening port, that file's version resource, and the
    installed programs list (Apps & Features). When the program serving the
    finding's port is identified, its version is checked against the CVE's
    affected range from the CVE mirror.

A rule-out is only made from software tied to the listening process — the
executable itself, or an installed program whose folder it lives in. An
installed program that merely shares the product's name might be a different
copy from the one serving the port, so it only produces a note.
"""
import ntpath
import re

from ..cve_mirror.versions import compare_versions, version_in_range

_BUILD_RE = re.compile(r"^(\d+\.\d+\.\d+)\.(\d+)$")
_VER_RE = re.compile(r"\d+(?:\.\d+)+(?:[a-z]+\d*)?|\d+", re.I)
_GENERIC = {"server", "http", "https", "service", "services", "web", "the", "for", "and",
            "daemon", "client", "windows", "microsoft", "project", "software", "foundation",
            "edition", "community", "enterprise", "x64", "x86", "64", "32", "bit"}


def _ver(s):
    # Old-style version resources write "2, 4, 58, 0".
    s = re.sub(r"(\d)\s*,\s*(?=\d)", r"\1.", str(s or ""))
    m = _VER_RE.search(s)
    return m.group(0) if m else ""


def _cpe_parts(cpe):
    bits = (cpe or "").split(":")
    if cpe.startswith("cpe:2.3") and len(bits) > 5:
        return bits[3], bits[4], bits[5]
    if cpe.startswith("cpe:/") and len(bits) > 3:
        return bits[2], bits[3], bits[4] if len(bits) > 4 else ""
    return "", "", ""


def _words(s):
    return set(re.findall(r"[a-z0-9]+", (s or "").lower()))


def names_product(vendor, product, text):
    """Does `text` (a program's name/publisher/description) name this CPE
    product? Every word of the product must appear; if those are all generic
    ("http_server"), the vendor must appear too."""
    words = _words(text)
    ptoks = [t for t in re.split(r"[_\-.]+", (product or "").lower()) if t]
    if not ptoks or not all(t in words for t in ptoks):
        return False
    vtoks = [t for t in re.split(r"[_\-.]+", (vendor or "").lower()) if t]
    return (any(t in words for t in vtoks)
            or any(t not in _GENERIC and len(t) >= 4 for t in ptoks))


def _same_version(installed, cpe_ver):
    if not cpe_ver or cpe_ver in ("*", "-"):
        return False
    a, b = installed.lower(), cpe_ver.lower()
    return compare_versions(a, b) == 0 or a.startswith(b + ".") or b.startswith(a + ".")


def _norm_path(p):
    return (p or "").replace("/", "\\").rstrip("\\").lower()


def _owning_program(facts, exe):
    """The installed program whose install folder contains `exe`."""
    e, best, best_len = _norm_path(exe), None, 0
    for p in facts.programs:
        loc = _norm_path(p.get("location"))
        if len(loc) > 3 and e.startswith(loc + "\\") and len(loc) > best_len:
            best, best_len = p, len(loc)
    return best


def identify(facts, port, vendor, product):
    """(name, version, tied_to_listener, exe) for the software behind a
    finding, or None."""
    l = facts.listener(port) if port else None
    exe = (l or {}).get("exe")
    if exe:
        prog = _owning_program(facts, exe)
        if prog and _ver(prog.get("version")) and names_product(
                vendor, product, f"{prog.get('name')} {prog.get('publisher')}"):
            return prog["name"], _ver(prog["version"]), True, exe
        fi = (l or {}).get("file") or {}
        v = _ver(fi.get("product_version")) or _ver(fi.get("file_version"))
        text = " ".join([fi.get("product") or "", fi.get("company") or "",
                         fi.get("description") or "", ntpath.basename(exe)])
        if v and names_product(vendor, product, text):
            return (fi.get("product") or ntpath.basename(exe)), v, True, exe
    cands = [p for p in facts.programs if _ver(p.get("version")) and names_product(
             vendor, product, f"{p.get('name')} {p.get('publisher')}")]
    if cands:
        p = cands[0]
        return p["name"], _ver(p["version"]), False, exe
    return None


def _os_verdict(facts, r, cve):
    """(status, detail, extra) for a Windows OS CVE, or None if Microsoft has
    no Windows build data for this CVE."""
    from ..cve_mirror import msrc
    rows = msrc.fixes_for(cve)
    if not rows:
        return None
    win = facts.windows or {}
    build = win.get("build") or ""
    m = _BUILD_RE.match(build)
    if not m:
        return None, "the agent didn't report this host's Windows build number", {}
    line, ubr = m.group(1), int(m.group(2))
    mine = [x for x in rows if x["build_line"] == line]
    if not mine:
        return None, (f"Microsoft lists fixes for {cve} on other Windows versions but not for "
                      f"build {line} ({facts.os}) — this version may be out of support"), {}
    normal = sorted((x for x in mine if not x["hotpatch"]), key=lambda x: x["fixed_ubr"])
    hot = sorted((x for x in mine if x["hotpatch"]), key=lambda x: x["fixed_ubr"])
    pkg = f"Windows {build}"
    if normal and ubr >= normal[-1]["fixed_ubr"]:
        x = normal[-1]
        return "not_exploitable", (
            f"Patched: this host runs Windows build {build} ({facts.os}). Microsoft fixed {cve} "
            f"for this Windows version in build {line}.{x['fixed_ubr']} ({x['kb']}), and Windows "
            f"updates are cumulative."), {"package": pkg, "proof": f"{x['product']}: fixed in "
                                          f"{line}.{x['fixed_ubr']} by {x['kb']}"}
    installed_kbs = set(win.get("hotfixes") or [])
    hit = [x for x in mine if x["kb"] in installed_kbs]
    if hit:
        x = hit[0]
        return "not_exploitable", (
            f"Patched: update {x['kb']}, which Microsoft lists as the fix for {cve} on this "
            f"Windows version, is installed."), {"package": pkg}
    if hot and ubr >= hot[0]["fixed_ubr"]:
        return None, (f"Windows build {build} may be a hotpatch build — Microsoft's hotpatch fix "
                      f"for {cve} is {line}.{hot[0]['fixed_ubr']} ({hot[0]['kb']})"), {}
    if normal and ubr < normal[0]["fixed_ubr"]:
        x = normal[0]
        return "installed", (
            f"Confirmed on the host: it runs Windows build {build} ({facts.os}), older than build "
            f"{line}.{x['fixed_ubr']}, where Microsoft fixed {cve} for this Windows version "
            f"({x['kb']} isn't installed)."), {"package": pkg, "proof": f"{x['product']}: fixed in "
                                               f"{line}.{x['fixed_ubr']} by {x['kb']}"}
    return None, (f"Windows build {build} falls between the builds Microsoft lists as fixing {cve}"), {}


def _app_verdict(facts, r, cve):
    from ..cve_mirror import query
    vendor, product, cpe_ver = _cpe_parts(getattr(r, "cpe", "") or "")
    if not product:
        return None, "the finding names no product to look for on the host", {}
    ident = identify(facts, r.port, vendor, product)
    nice = product.replace("_", " ")
    if not ident:
        return None, f"couldn't find {nice} among the programs installed on this host", {}
    name, ver, tied, exe = ident
    extra = {"package": f"{name} {ver}", "executable": exe if tied else None}
    where = (f"owns the process listening on port {r.port}" if tied else
             "is installed, but isn't tied to the process listening on this port")
    ranges = query.affected_ranges(cve, vendor, product) if cve else None
    affected = (any(version_in_range(ver, *rg) for rg in ranges) if ranges else None)
    same = _same_version(ver, cpe_ver)
    if tied and affected is False and not same:
        return "not_exploitable", (
            f"Not affected: {name} {ver} {where}, and version {ver} is outside the range "
            f"affected by {cve} (the scan's banner suggested {cpe_ver})."), extra
    if tied and (affected or (affected is None and same)):
        return "installed", (
            f"Confirmed on the host: {name} {ver} {where}, and that version is affected by {cve}. "
            f"Windows builds of this software get no distribution backports, so the installed "
            f"version is what runs."), extra
    note = f"{name} {ver} {where}"
    if tied and affected is None:
        note += f"; the CVE database has no affected-version range for {cve} to compare it to"
    return None, note, {}


def evaluate_windows(facts, findings, hints=None):
    """Same contract as ssh_verify.evaluate_host: [(r, status, detail, extra)]."""
    out = []
    for r in findings:
        cve = (r.cve_id or "").upper()
        v = _os_verdict(facts, r, cve) if cve else None
        if v is None:
            v = _app_verdict(facts, r, cve)
        status, detail, extra = v
        if status is None:
            detail = f"Credentialed check: {detail}."
        out.append((r, status, detail, extra))
    return out
