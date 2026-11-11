"""Credentialed (SSH) checks for version-matched CVEs.

A service banner says "Apache 2.4.52", but Linux distributions fix CVEs by
backporting patches without changing the upstream version, and many CVEs only
matter if a specific module is loaded. When a scan has SSH credentials (saved
on the target, or entered for the scan) this module logs in and looks:

  * which package owns the process listening on the finding's port, its exact
    installed version, and that package's changelog. If the vendor changelog
    lists the CVE, the installed build carries the fix → not exploitable.
  * for Apache httpd / nginx: which modules are actually loaded / compiled in.
    If the CVE is in a module this server doesn't load → not exploitable.

Credentialed checks only ever *rule findings out* (or add context). They never
prove a finding exploitable — that still needs a live check (verify.py) — so
a finding they can't rule out stays Unverified, now with what was learned.

Everything run on the host is read-only (dpkg-query/rpm, reading files under
/usr/share/doc, `ss`, `apachectl -M`, `nginx -V`). `sudo -n` is tried as a
fallback only where root is needed to see another user's process, and only
if passwordless sudo is already configured; it never prompts.
"""
import io
import json
import logging
import re
import shlex
from dataclasses import dataclass

log = logging.getLogger(__name__)

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
_APACHE_MOD_RE = re.compile(r"\bmod_([a-z0-9_]+)", re.I)
_NGINX_MOD_RE = re.compile(r"\bngx_(http|mail|stream)_([a-z0-9_]+?)_module\b", re.I)
_DEB_HEADER = re.compile(r"^[a-z0-9][a-z0-9.+-]* \([^)]+\) ")
_MAX_CHANGELOG = 4 * 1024 * 1024

# nginx modules that are NOT built unless explicitly enabled with --with-…;
# only these can be ruled out by their absence from `nginx -V`.
_NGINX_OPTIONAL_HTTP = {
    "addition", "auth_request", "dav", "degradation", "flv", "geoip", "gunzip",
    "gzip_static", "image_filter", "mp4", "perl", "random_index", "realip",
    "secure_link", "slice", "ssl", "stub_status", "sub", "v2", "v3", "xslt",
}

# Fallback product → package names when the listening process can't be seen
# (e.g. no root). Keys are matched against the CPE product / service banner.
_PRODUCT_PACKAGES = [
    (("http_server", "apache httpd", "apache"), ("apache2-bin", "apache2", "httpd", "httpd-core")),
    (("nginx",), ("nginx-core", "nginx-full", "nginx-light", "nginx-extras", "nginx")),
    (("openssh",), ("openssh-server", "openssh")),
    (("vsftpd",), ("vsftpd",)),
    (("proftpd",), ("proftpd-core", "proftpd-basic", "proftpd")),
    (("postfix",), ("postfix",)),
    (("exim",), ("exim4-daemon-light", "exim4-daemon-heavy", "exim")),
    (("dovecot",), ("dovecot-core", "dovecot")),
    (("mariadb",), ("mariadb-server-core", "mariadb-server")),
    (("mysql",), ("mysql-server-core-8.0", "mysql-server", "mariadb-server-core")),
    (("samba", "smbd"), ("samba",)),
    (("bind", "named"), ("bind9", "bind")),
    (("lighttpd",), ("lighttpd",)),
    (("squid",), ("squid",)),
    (("redis",), ("redis-server", "redis")),
    (("memcached",), ("memcached",)),
    (("haproxy",), ("haproxy",)),
    (("tomcat",), ("tomcat10", "tomcat9", "tomcat")),
    (("openssl",), ("openssl", "libssl3", "libssl1.1")),
]


_TRIMMED_RE = re.compile(r"older changelog entries|changelog has been trimmed", re.I)
_vendor_cache = {}


def _pool_prefix(source):
    return source[:4] if source.startswith("lib") and len(source) > 3 else source[:1]


def vendor_changelog(os_id, source, version):
    """Full Debian/Ubuntu changelog for one source package version, or ''."""
    if os_id not in ("ubuntu", "debian") or not source or not version:
        return ""
    ver = version.split(":", 1)[-1]
    key = (os_id, source, ver)
    if key in _vendor_cache:
        return _vendor_cache[key]
    if not re.fullmatch(r"[a-z0-9][a-z0-9.+-]*", source) or not re.fullmatch(r"[A-Za-z0-9.+~-]+", ver):
        return ""
    import requests
    pre = _pool_prefix(source)
    if os_id == "ubuntu":
        urls = [f"https://changelogs.ubuntu.com/changelogs/pool/{c}/{pre}/{source}/{source}_{ver}/changelog"
                for c in ("main", "universe", "restricted", "multiverse")]
    else:
        urls = [f"https://metadata.ftp-master.debian.org/changelogs//{c}/{pre}/{source}/{source}_{ver}_changelog"
                for c in ("main", "contrib", "non-free")]
    text = ""
    for url in urls:
        try:
            r = requests.get(url, timeout=20, headers={"User-Agent": "PWNBroker"})
        except requests.RequestException as e:
            log.info("vendor changelog fetch failed (%s): %s", url, e)
            break
        if r.status_code == 200 and f"{source} (" in r.text[:2000]:
            text = r.text[:_MAX_CHANGELOG]
            break
    if text:  # don't remember failures — the next scan retries
        _vendor_cache[key] = text
    return text


@dataclass
class Creds:
    """SSH login for one host. Attribute names match Target's so the
    existing SSH helpers (EOL scan, dependency fetch) accept it as-is."""
    host: str
    ssh_username: str
    ssh_port: int = 22
    ssh_auth_type: str = "password"
    ssh_password: str = None
    ssh_private_key: str = None
    ssh_key_passphrase: str = None
    source: str = "target"     # target | scan

    @property
    def label(self):
        return f"{self.ssh_username}@{self.host}:{self.ssh_port}"


def _creds_from(obj, host, source):
    if not obj or not getattr(obj, "ssh_username", None):
        return None
    if not (obj.ssh_password or obj.ssh_private_key):
        return None
    return Creds(host=host, ssh_username=obj.ssh_username, ssh_port=int(obj.ssh_port or 22),
                 ssh_auth_type=obj.ssh_auth_type or "password",
                 ssh_password=obj.ssh_password, ssh_private_key=obj.ssh_private_key,
                 ssh_key_passphrase=obj.ssh_key_passphrase, source=source)


def creds_for(scan, host):
    """The SSH login to use for `host` in `scan`, or None.

    cred_mode "off"    → never log in.
    cred_mode "scan"   → the credentials entered on the scan, for every host.
    cred_mode "target" (default) → a target saved for exactly this host wins,
                         else the scan's target's saved credentials (which, for
                         a subnet target, apply to every host in it)."""
    if scan is None:
        return None
    mode = getattr(scan, "cred_mode", None) or "target"
    if mode == "off":
        return None
    if mode == "scan":
        return _creds_from(scan, host, "scan")
    from ..models import Target
    exact = Target.query.filter(Target.host == host, Target.ssh_username.isnot(None)).first()
    c = _creds_from(exact, host, "target")
    if c:
        return c
    return _creds_from(getattr(scan, "target", None), host, "target")


def scan_has_creds(scan):
    mode = getattr(scan, "cred_mode", None) or "target"
    if mode == "off":
        return False
    if mode == "scan":
        return bool(_creds_from(scan, "", "scan"))
    return bool(_creds_from(getattr(scan, "target", None), "", "target"))


# ── SSH session ──────────────────────────────────────────────────────────────

def load_private_key(key_str, passphrase=None):
    """Load an OpenSSH/PEM private key of any type paramiko supports."""
    import paramiko
    last = None
    for name in ("Ed25519Key", "ECDSAKey", "RSAKey", "DSSKey"):
        cls = getattr(paramiko, name, None)
        if cls is None:
            continue
        try:
            return cls.from_private_key(io.StringIO(key_str.strip() + "\n"), password=passphrase or None)
        except paramiko.PasswordRequiredException:
            raise ValueError("The private key is encrypted — enter its passphrase.")
        except (paramiko.SSHException, ValueError, TypeError) as e:
            last = e
    raise ValueError(f"Unsupported private key type or wrong passphrase ({last}).")


class Session:
    def __init__(self, creds, timeout=15):
        import paramiko
        self.creds = creds
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kw = dict(hostname=creds.host, port=int(creds.ssh_port or 22), username=creds.ssh_username,
                  timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
                  look_for_keys=False, allow_agent=False)
        if creds.ssh_auth_type == "key" and creds.ssh_private_key:
            kw["pkey"] = load_private_key(creds.ssh_private_key, creds.ssh_key_passphrase)
        else:
            kw["password"] = creds.ssh_password
        self.client.connect(**kw)
        self._sudo = None

    def run(self, cmd, timeout=25):
        """Run a read-only shell command → (exit_status, stdout)."""
        _, stdout, _ = self.client.exec_command(cmd, timeout=timeout)
        out = stdout.read(_MAX_CHANGELOG + 1).decode("utf-8", errors="replace")
        return stdout.channel.recv_exit_status(), out

    def has_sudo(self):
        if self._sudo is None:
            rc, _ = self.run("sudo -n true 2>/dev/null", timeout=10)
            self._sudo = rc == 0
        return self._sudo

    def run_priv(self, cmd, timeout=25):
        """Run as the login user; retry with passwordless sudo if that's
        available and the unprivileged attempt saw nothing."""
        rc, out = self.run(cmd, timeout)
        if (rc != 0 or not out.strip()) and self.has_sudo():
            rc, out = self.run(f"sudo -n sh -c {shlex.quote(cmd)}", timeout)
        return rc, out

    def close(self):
        try:
            self.client.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


def test_login(creds):
    """Log in and report who we are and what the checks can see."""
    try:
        with Session(creds) as s:
            _, who = s.run("id -un; uname -sr; . /etc/os-release 2>/dev/null && echo \"$PRETTY_NAME\"")
            lines = [l.strip() for l in who.splitlines() if l.strip()]
            pm = _package_manager(s)
            return {"ok": True, "user": lines[0] if lines else creds.ssh_username,
                    "os": lines[2] if len(lines) > 2 else (lines[1] if len(lines) > 1 else ""),
                    "package_manager": pm or "none found",
                    "sudo": s.has_sudo()}
    except Exception as e:
        return {"ok": False, "error": str(e) or e.__class__.__name__}


# ── host facts ───────────────────────────────────────────────────────────────

def _package_manager(s):
    _, out = s.run("command -v dpkg-query >/dev/null && echo deb; "
                   "command -v rpm >/dev/null && echo rpm; true", timeout=10)
    kinds = out.split()
    return kinds[0] if kinds else None


class HostFacts:
    """Lazily-gathered, cached facts about one logged-in host."""

    def __init__(self, session):
        self.s = session
        self.pm = _package_manager(session)
        _, kern = session.run("uname -s", timeout=10)
        self.kernel = kern.strip()            # Linux, FreeBSD, Darwin, ...
        _, osr = session.run(". /etc/os-release 2>/dev/null && echo \"$ID|$PRETTY_NAME\"", timeout=10)
        os_id, _, pretty = osr.strip().partition("|")
        self.os_id = os_id.lower()
        self.os = pretty or "this host"
        self._listener = {}
        self._pkg = {}
        self._apache = self._nginx = None

    # Which package owns the process listening on `port`?
    def listener_package(self, port):
        if port in self._listener:
            return self._listener[port]
        pkg = exe = None
        _, out = self.s.run_priv(f"ss -Hltnp 'sport = :{int(port)}' 2>/dev/null")
        m = re.search(r"pid=(\d+)", out)
        if m:
            _, exe = self.s.run_priv(f"readlink -f /proc/{m.group(1)}/exe")
            exe = exe.strip() or None
        if exe:
            pkg = self.package_owning(exe)
        self._listener[port] = (pkg, exe)
        return pkg, exe

    def package_owning(self, path):
        candidates = [path]
        if path.startswith("/usr/"):
            candidates.append(path[4:])          # merged-/usr: dpkg may know /sbin/…
        for p in candidates:
            q = shlex.quote(p)
            if self.pm == "deb":
                rc, out = self.s.run(f"dpkg -S {q} 2>/dev/null")
                if rc == 0 and ":" in out:
                    return out.split(":", 1)[0].split(",")[0].strip()
            elif self.pm == "rpm":
                rc, out = self.s.run(f"rpm -qf --qf '%{{NAME}}\\n' {q} 2>/dev/null")
                if rc == 0 and out.strip() and "not owned" not in out:
                    return out.split()[0]
        return None

    def installed(self, pkg):
        """(version, source_package) if installed, else None."""
        if pkg in self._pkg:
            return self._pkg[pkg]
        q = shlex.quote(pkg)
        info = None
        if self.pm == "deb":
            rc, out = self.s.run(
                f"dpkg-query -W -f='${{db:Status-Status}}|${{Version}}|${{source:Package}}' {q} 2>/dev/null")
            parts = out.strip().split("|")
            if rc == 0 and len(parts) == 3 and parts[0] == "installed":
                info = (parts[1], parts[2] or pkg)
        elif self.pm == "rpm":
            rc, out = self.s.run(f"rpm -q --qf '%{{VERSION}}-%{{RELEASE}}|%{{SOURCERPM}}' {q} 2>/dev/null")
            if rc == 0 and "|" in out and "not installed" not in out:
                ver, srpm = out.strip().split("|", 1)
                info = (ver, re.sub(r"-[^-]+-[^-]+\.src\.rpm$", "", srpm) or pkg)
        self._pkg[pkg] = info
        return info

    def changelog(self, pkg, source, version):
        """Vendor changelog for an installed package → (text, complete).

        Ubuntu trims the copy installed on disk to recent entries; when the
        trim marker is there, the full changelog for this exact source version
        is fetched from the vendor (only the package name and version are
        sent — nothing about the host)."""
        text = ""
        if self.pm == "deb":
            for d in dict.fromkeys([pkg, source]):
                path = shlex.quote(f"/usr/share/doc/{d}")
                _, out = self.s.run(
                    f"for f in {path}/changelog.Debian.gz {path}/changelog.Debian; do "
                    f"[ -r \"$f\" ] && {{ zcat -f \"$f\" | head -c {_MAX_CHANGELOG}; exit 0; }}; done; true")
                if out.strip():
                    text = out
                    break
            if not text or _TRIMMED_RE.search(text):
                full = vendor_changelog(self.os_id, source, version)
                if full:
                    return full, True
                return text, False
            return text, True
        if self.pm == "rpm":
            _, out = self.s.run(f"rpm -q --changelog {shlex.quote(pkg)} 2>/dev/null | head -c {_MAX_CHANGELOG}")
            return out, bool(out.strip())
        return "", False

    def apache_modules(self):
        if self._apache is None:
            _, out = self.s.run_priv("for c in apache2ctl apachectl httpd; do "
                                     "command -v $c >/dev/null && { $c -M 2>/dev/null; break; }; done")
            mods = set(re.findall(r"^\s*([a-z0-9_]+)_module\b", out, re.M))
            self._apache = mods or False   # False = couldn't list (don't rule anything out)
        return self._apache

    def nginx_build(self):
        if self._nginx is None:
            _, out = self.s.run_priv("command -v nginx >/dev/null && nginx -V 2>&1; "
                                     "grep -rhs '^[[:space:]]*load_module' /etc/nginx 2>/dev/null; true")
            self._nginx = out if "configure arguments" in out else False
        return self._nginx


# ── evaluating one finding ───────────────────────────────────────────────────

def _changelog_index(text):
    """CVE id → (version header, the changelog line naming it)."""
    found = {}
    header = ""
    for line in text.splitlines():
        if _DEB_HEADER.match(line) or line.startswith("* "):
            header = line.strip()[:200]
        for cve in _CVE_RE.findall(line):
            found.setdefault(cve.upper(), (header, line.strip()[:300]))
    return found


def _product_hint(r, hints):
    parts = []
    cpe = getattr(r, "cpe", "") or ""
    if cpe.startswith("cpe:"):
        bits = cpe.split(":")
        parts += bits[3:5] if cpe.startswith("cpe:2.3") else bits[2:4]
    parts.append(hints.get((r.host, r.port), ""))
    parts.append(getattr(r, "service", "") or "")
    return " ".join(p for p in parts if p).lower()


def _fallback_packages(facts, hint):
    for keys, pkgs in _PRODUCT_PACKAGES:
        if any(k in hint for k in keys):
            for p in pkgs:
                if facts.installed(p):
                    return p
    return None


def _module_verdict(facts, r, hint):
    """(ruled_out, note) from the modules this server actually loads."""
    desc = getattr(r, "description", "") or ""
    if "apache" in hint or "http_server" in hint or "httpd" in hint:
        wanted = {m.lower() for m in _APACHE_MOD_RE.findall(desc)}
        if not wanted:
            return False, None
        loaded = facts.apache_modules()
        if loaded is False:
            return False, "couldn't list loaded Apache modules"
        present = sorted(m for m in wanted if m in loaded)
        if present:
            return False, f"mod_{', mod_'.join(present)} is loaded"
        return True, (f"The vulnerable module (mod_{', mod_'.join(sorted(wanted))}) is not loaded by "
                      f"Apache on this server (checked with apachectl -M).")
    if "nginx" in hint:
        wanted = {(k.lower(), n.lower()) for k, n in _NGINX_MOD_RE.findall(desc)}
        wanted = {w for w in wanted if w[0] == "http" and w[1] in _NGINX_OPTIONAL_HTTP}
        if not wanted:
            return False, None
        build = facts.nginx_build()
        if build is False:
            return False, "couldn't read the nginx build configuration"
        present = sorted(n for _, n in wanted
                         if f"--with-http_{n}_module" in build or f"ngx_http_{n}_module" in build)
        if present:
            return False, f"ngx_http_{present[0]}_module is built in"
        names = ", ".join(f"ngx_http_{n}_module" for _, n in sorted(wanted))
        return True, (f"The vulnerable module ({names}) isn't compiled into or loaded by nginx "
                      f"on this server (checked with nginx -V).")
    return False, None


_ON_WINDOWS_RE = re.compile(r"\b(?:on|for|running on) (?:Microsoft )?Windows\b", re.I)
_OTHER_OS_RE = re.compile(r"\b(?:Linux|Unix|BSD|mac ?OS|OS X|Solaris|AIX|all platforms|other platforms)\b", re.I)


def _windows_only(desc):
    """True if the CVE text scopes it to Windows and names no other OS."""
    desc = " ".join((desc or "").split())
    return bool(_ON_WINDOWS_RE.search(desc)) and not _OTHER_OS_RE.search(desc)


def evaluate_host(facts, findings, hints):
    """Apply credentialed checks to one host's findings → [(r, status, detail, extra)]."""
    out = []
    pkg_cache = {}
    for r in findings:
        hint = _product_hint(r, hints)
        key = (r.port, hint)
        if key not in pkg_cache:
            pkg, exe = facts.listener_package(r.port) if r.port else (None, None)
            how = "owns the process listening on this port" if pkg else None
            if not pkg:
                pkg = _fallback_packages(facts, hint)
                how = "matches the detected product" if pkg else None
            inst = facts.installed(pkg) if pkg else None
            log_text, complete = facts.changelog(pkg, inst[1], inst[0]) if inst else ("", False)
            pkg_cache[key] = (pkg, exe, how, inst, _changelog_index(log_text), complete)
        pkg, exe, how, inst, fixed, complete = pkg_cache[key]

        cve = (r.cve_id or "").upper()
        if inst and cve in fixed:
            header, line = fixed[cve]
            out.append((r, "not_exploitable",
                        f"Patched by the vendor: the installed package {pkg} {inst[0]} on {facts.os} "
                        f"lists the fix for {cve} in its changelog (a backported fix — the service "
                        f"banner still shows the upstream version).",
                        {"proof": f"{header}\n  …\n  {line}" if header else line,
                         "package": f"{pkg} {inst[0]}"}))
            continue

        if facts.kernel and _windows_only(getattr(r, "description", "")):
            out.append((r, "not_exploitable",
                        f"This CVE only affects the product on Windows; this host runs "
                        f"{facts.kernel} ({facts.os}).", {"package": f"{pkg} {inst[0]}" if inst else None}))
            continue

        ruled_out, mod_note = _module_verdict(facts, r, hint)
        if ruled_out:
            out.append((r, "not_exploitable", mod_note, {"package": f"{pkg} {inst[0]}" if inst else None}))
            continue

        if inst:
            note = (f"{pkg} {inst[0]} ({how}) has no vendor fix listed for {cve}"
                    if complete else
                    f"{pkg} {inst[0]} is installed but its full changelog wasn't available, "
                    f"so a backported fix couldn't be checked")
        else:
            note = "couldn't identify which installed package provides this service"
        if mod_note:
            note += f"; {mod_note}"
        out.append((r, None, f"Credentialed check: {note}.", {}))
    return out


def verify_with_ssh(todo, creds_of, summary, hints=None):
    """Second pass for findings the live checks couldn't settle. Mutates
    each ScanResult's verdict/evidence; returns a per-host status list."""
    from .verify import UNCONFIRMED, NOT_EXPLOITABLE, evidence
    hints = hints or {}
    by_host = {}
    for r in todo:
        if r.verification_status != UNCONFIRMED or not r.host:
            continue
        c = creds_of(r)
        if c:
            by_host.setdefault((r.host, c.label), (c, []))[1].append(r)

    report = []
    for (host, _), (creds, findings) in by_host.items():
        try:
            with Session(creds) as s:
                facts = HostFacts(s)
                verdicts = evaluate_host(facts, findings, hints)
        except Exception as e:
            msg = str(e) or e.__class__.__name__
            log.warning("credentialed check of %s failed: %s", host, msg)
            report.append({"host": host, "ok": False, "error": msg, "user": creds.ssh_username,
                           "ruled_out": 0, "checked": len(findings)})
            for r in findings:
                _add_note(r, f"Credentialed check couldn't log in as {creds.ssh_username}: {msg}.")
            continue

        ruled = 0
        for r, status, detail, extra in verdicts:
            if status == NOT_EXPLOITABLE:
                ruled += 1
                r.verification_status = NOT_EXPLOITABLE
                r.verification_evidence = evidence("ssh", "credentialed check", NOT_EXPLOITABLE,
                                                   detail, target=creds.label, **extra)
                summary[UNCONFIRMED] -= 1
                summary[NOT_EXPLOITABLE] += 1
            else:
                _add_note(r, detail)
        report.append({"host": host, "ok": True, "user": creds.ssh_username, "os": facts.os,
                       "ruled_out": ruled, "checked": len(findings)})
    return report


def _add_note(r, note):
    try:
        ev = json.loads(r.verification_evidence) if r.verification_evidence else {}
    except ValueError:
        ev = {}
    if not ev:
        from .verify import evidence
        r.verification_evidence = evidence("none", None, "unconfirmed", "Not verified.", credentialed=note)
        return
    ev["credentialed"] = note
    r.verification_evidence = json.dumps(ev)


# ── form helpers (targets / scans / scheduled scans) ─────────────────────────

SSH_FIELDS = ("ssh_port", "ssh_username", "ssh_auth_type", "ssh_password",
              "ssh_private_key", "ssh_key_passphrase")


def apply_ssh_form(obj, form, keep_secrets=False):
    """Copy SSH login fields from a submitted form onto `obj`.

    With keep_secrets, a blank password/key/passphrase leaves the stored one
    in place (edit forms never echo secrets back). Returns an error message
    or None."""
    user = (form.get("ssh_username") or "").strip() or None
    try:
        port = int(form.get("ssh_port") or 22)
    except ValueError:
        return "SSH port must be a number."
    if not 1 <= port <= 65535:
        return "SSH port must be between 1 and 65535."
    auth = form.get("ssh_auth_type") if form.get("ssh_auth_type") in ("password", "key") else "password"
    pw = (form.get("ssh_password") or "").strip() or None
    key = (form.get("ssh_private_key") or "").strip() or None
    pp = (form.get("ssh_key_passphrase") or "").strip() or None

    if keep_secrets and user:
        pw = pw or (obj.ssh_password if auth == "password" else None)
        key = key or (obj.ssh_private_key if auth == "key" else None)
        pp = pp or (obj.ssh_key_passphrase if auth == "key" and key == obj.ssh_private_key else None)
    if user:
        if auth == "password" and not pw:
            return "Enter the SSH password."
        if auth == "key":
            if not key:
                return "Paste the SSH private key."
            try:
                load_private_key(key, pp)
            except ValueError as e:
                return str(e)
    obj.ssh_username = user
    obj.ssh_port = port
    obj.ssh_auth_type = auth
    obj.ssh_password = pw if user and auth == "password" else None
    obj.ssh_private_key = key if user and auth == "key" else None
    obj.ssh_key_passphrase = pp if user and auth == "key" else None
    return None


def apply_scan_cred_form(obj, form):
    """Set cred_mode (+ per-scan login when mode is "scan"). Returns error or None."""
    mode = form.get("cred_mode") or "target"
    if mode not in ("target", "scan", "off"):
        mode = "target"
    obj.cred_mode = mode
    if mode != "scan":
        for f in SSH_FIELDS:
            setattr(obj, f, None)
        obj.ssh_port, obj.ssh_auth_type = 22, "password"
        return None
    if not (form.get("ssh_username") or "").strip():
        return "Enter the SSH username for this scan's credentialed checks."
    return apply_ssh_form(obj, form)


def copy_scan_creds(src, dst):
    dst.cred_mode = getattr(src, "cred_mode", None) or "target"
    for f in SSH_FIELDS:
        setattr(dst, f, getattr(src, f, None))
