"""
OSV dependency scanner.
Supports local path scanning and remote SSH-based lockfile fetching.
Tries the `osv-scanner` CLI binary first; falls back to the OSV REST API
with built-in lockfile parsers when the binary is not installed.
"""
import io
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import requests

OSV_API = "https://api.osv.dev/v1"

# ── Severity mapping ───────────────────────────────────────────────────────────

def _cvss_to_severity(score):
    if score is None:
        return "medium"
    score = float(score)
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _osv_severity(vuln):
    """Extract the highest CVSS score from an OSV vuln record."""
    best = None
    for sev in vuln.get("severity", []):
        raw = sev.get("score", "")
        # CVSS v3 vector or numeric
        m = re.search(r"(\d+\.\d+)", raw)
        if m:
            val = float(m.group(1))
            if best is None or val > best:
                best = val
    return best


def _fixed_version(vuln):
    """Return the first 'fixed' version from the vuln's affected ranges."""
    for affected in vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            events = rng.get("events", [])
            for ev in events:
                if "fixed" in ev:
                    return ev["fixed"]
    return None


def _aliases(vuln):
    """Return CVE IDs from aliases list."""
    return [a for a in vuln.get("aliases", []) if a.startswith("CVE-")]


# ── Remediation command builder ────────────────────────────────────────────────

REMEDIATION_TEMPLATES = {
    "PyPI":       "pip install \"{name}>={fixed}\"",
    "npm":        "npm install {name}@{fixed}",
    "Go":         "go get {name}@v{fixed}",
    "crates.io":  "# Update {name} to {fixed} in Cargo.toml, then run: cargo update",
    "RubyGems":   "gem install {name} -v {fixed}",
    "Packagist":  "composer require {name}:{fixed}",
    "Maven":      "# Update {name} to {fixed} in pom.xml / build.gradle",
    "NuGet":      "dotnet add package {name} --version {fixed}",
}


def _remediation_cmd(ecosystem, name, fixed):
    if not fixed:
        return f"Upgrade {name} to the latest patched version."
    tpl = REMEDIATION_TEMPLATES.get(ecosystem, "Upgrade {name} to {fixed} or later.")
    return tpl.format(name=name, fixed=fixed)


# ── Lockfile parsers ───────────────────────────────────────────────────────────

def _parse_requirements_txt(path):
    """Parse requirements.txt → list of (name, version, ecosystem)."""
    pkgs = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            m = re.match(r"^([A-Za-z0-9_\-\.]+)==([^\s;]+)", line)
            if m:
                pkgs.append((m.group(1), m.group(2), "PyPI"))
    return pkgs


def _parse_package_json(path):
    """Parse package.json → list of (name, version, ecosystem).
    Reads exact versions from package-lock.json if present."""
    pkgs = []
    lock_path = os.path.join(os.path.dirname(path), "package-lock.json")
    if os.path.exists(lock_path):
        with open(lock_path) as f:
            lock = json.load(f)
        for name, info in lock.get("dependencies", {}).items():
            ver = info.get("version", "").lstrip("^~>=")
            if ver:
                pkgs.append((name, ver, "npm"))
    else:
        with open(path) as f:
            data = json.load(f)
        for section in ("dependencies", "devDependencies"):
            for name, ver_spec in data.get(section, {}).items():
                ver = ver_spec.lstrip("^~>=")
                if ver and re.match(r"^\d+\.\d+", ver):
                    pkgs.append((name, ver, "npm"))
    return pkgs


def _parse_pipfile_lock(path):
    pkgs = []
    with open(path) as f:
        lock = json.load(f)
    for section in ("default", "develop"):
        for name, info in lock.get(section, {}).items():
            ver = info.get("version", "").lstrip("=")
            if ver:
                pkgs.append((name, ver, "PyPI"))
    return pkgs


def _parse_poetry_lock(path):
    pkgs = []
    with open(path) as f:
        content = f.read()
    for m in re.finditer(r'\[\[package\]\].*?name\s*=\s*"([^"]+)".*?version\s*=\s*"([^"]+)"', content, re.DOTALL):
        pkgs.append((m.group(1), m.group(2), "PyPI"))
    return pkgs


def _parse_cargo_lock(path):
    pkgs = []
    with open(path) as f:
        content = f.read()
    for m in re.finditer(r'\[\[package\]\].*?name\s*=\s*"([^"]+)".*?version\s*=\s*"([^"]+)"', content, re.DOTALL):
        pkgs.append((m.group(1), m.group(2), "crates.io"))
    return pkgs


def _parse_go_mod(path):
    pkgs = []
    with open(path) as f:
        in_require = False
        for line in f:
            line = line.strip()
            if line.startswith("require ("):
                in_require = True
                continue
            if in_require:
                if line == ")":
                    in_require = False
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    pkgs.append((parts[0], parts[1].lstrip("v"), "Go"))
            elif line.startswith("require "):
                parts = line[8:].split()
                if len(parts) >= 2:
                    pkgs.append((parts[0], parts[1].lstrip("v"), "Go"))
    return pkgs


def _parse_gemfile_lock(path):
    pkgs = []
    with open(path) as f:
        in_gems = False
        for line in f:
            stripped = line.strip()
            if stripped == "GEM":
                in_gems = True
                continue
            if in_gems:
                if stripped in ("", "PLATFORMS", "DEPENDENCIES", "BUNDLED WITH"):
                    in_gems = False
                    continue
                m = re.match(r"^\s{4}(\S+)\s+\(([^\)]+)\)", line)
                if m:
                    pkgs.append((m.group(1), m.group(2), "RubyGems"))
    return pkgs


def _parse_composer_lock(path):
    """Parse composer.lock → list of (name, version, ecosystem)."""
    pkgs = []
    with open(path) as f:
        data = json.load(f)
    for section in ("packages", "packages-dev"):
        for pkg in data.get(section, []):
            name = pkg.get("name", "").strip()
            ver  = pkg.get("version", "").lstrip("v").strip()
            if name and ver and re.match(r"^\d+\.\d+", ver):
                pkgs.append((name, ver, "Packagist"))
    return pkgs


def _parse_composer_json(path):
    """
    Parse composer.json — only includes packages with exact/tilde versions
    that resolve to a concrete semver (e.g. "1.2.3" or "~1.2.3").
    Prefer composer.lock when available; this is a fallback.
    """
    # If composer.lock exists alongside, the lock parser is preferred — skip here
    lock_path = os.path.join(os.path.dirname(path), "composer.lock")
    if os.path.exists(lock_path):
        return []
    pkgs = []
    with open(path) as f:
        data = json.load(f)
    for section in ("require", "require-dev"):
        for name, ver_spec in data.get(section, {}).items():
            if name in ("php", "ext-*") or name.startswith("ext-"):
                continue
            ver = ver_spec.lstrip("^~>=v").strip()
            if ver and re.match(r"^\d+\.\d+", ver):
                pkgs.append((name, ver, "Packagist"))
    return pkgs


LOCKFILE_PARSERS = {
    "requirements.txt": _parse_requirements_txt,
    "package.json":     _parse_package_json,
    "Pipfile.lock":     _parse_pipfile_lock,
    "poetry.lock":      _parse_poetry_lock,
    "Cargo.lock":       _parse_cargo_lock,
    "go.mod":           _parse_go_mod,
    "Gemfile.lock":     _parse_gemfile_lock,
    "composer.lock":    _parse_composer_lock,
    "composer.json":    _parse_composer_json,
}


def _collect_packages(scan_path):
    """Walk scan_path and collect packages from all recognised lockfiles."""
    pkgs = []
    seen_files = []
    for root, dirs, files in os.walk(scan_path):
        dirs[:] = [d for d in dirs if d not in ("node_modules", ".git", "__pycache__", ".venv", "venv")]
        for fname in files:
            if fname in LOCKFILE_PARSERS:
                fpath = os.path.join(root, fname)
                try:
                    found = LOCKFILE_PARSERS[fname](fpath)
                    pkgs.extend(found)
                    seen_files.append(os.path.relpath(fpath, scan_path))
                except Exception:
                    pass
    return pkgs, seen_files


# ── OSV API query ──────────────────────────────────────────────────────────────

def _query_osv_api(packages):
    """
    Query OSV batch API for a list of (name, version, ecosystem) tuples.
    Returns a list of (pkg_tuple, [vuln_dict, ...]).
    """
    BATCH = 1000
    all_results = []
    for i in range(0, len(packages), BATCH):
        batch = packages[i:i + BATCH]
        queries = [
            {"package": {"name": name, "ecosystem": eco}, "version": ver}
            for name, ver, eco in batch
        ]
        try:
            resp = requests.post(
                f"{OSV_API}/querybatch",
                json={"queries": queries},
                timeout=60,
            )
            if resp.ok:
                for pkg, result in zip(batch, resp.json().get("results", [])):
                    vulns = result.get("vulns", [])
                    if vulns:
                        all_results.append((pkg, vulns))
        except requests.RequestException:
            pass
    return all_results


# ── CLI mode ───────────────────────────────────────────────────────────────────

def _run_cli(scan_path):
    """
    Run osv-scanner binary, return parsed findings list or None if binary absent.
    Each finding: {"package": name, "version": ver, "ecosystem": eco,
                   "vuln": vuln_dict}
    """
    binary = shutil.which("osv-scanner")
    if not binary:
        return None

    try:
        proc = subprocess.run(
            [binary, "--format", "json", scan_path],
            capture_output=True, text=True, timeout=300,
        )
        output = proc.stdout or proc.stderr
        data = json.loads(output)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
        return None

    findings = []
    for res in data.get("results", []):
        for pkg_info in res.get("packages", []):
            pkg = pkg_info.get("package", {})
            for vuln in pkg_info.get("vulnerabilities", []):
                findings.append({
                    "package": pkg.get("name", ""),
                    "version": pkg.get("version", ""),
                    "ecosystem": pkg.get("ecosystem", ""),
                    "vuln": vuln,
                    "source": res.get("source", {}).get("path", scan_path),
                })
    return findings


# ── SSH remote lockfile fetch ──────────────────────────────────────────────────

SUPPORTED_LOCKFILES = set(LOCKFILE_PARSERS.keys())


def _load_private_key(key_str: str, passphrase):
    """Load a PEM private key trying RSA, Ed25519, ECDSA, and DSS in order."""
    import paramiko
    for cls in (paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.DSSKey):
        try:
            return cls.from_private_key(io.StringIO(key_str), password=passphrase)
        except (paramiko.SSHException, ValueError):
            continue
    raise ValueError("Unsupported private key type or incorrect passphrase.")


def fetch_lockfiles_via_ssh(target, remote_path) -> tuple[str, list[str]]:
    """
    SSH into target, find lockfiles under remote_path, download them into a
    temp directory. Returns (local_tmp_dir, [relative_paths_found]).
    Raises on connection failure.
    """
    import paramiko

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connect_kw = {
        "hostname": target.host,
        "port": int(target.ssh_port or 22),
        "username": target.ssh_username,
        "timeout": 30,
    }

    if target.ssh_auth_type == "key" and target.ssh_private_key:
        passphrase = target.ssh_key_passphrase or None
        pkey = _load_private_key(target.ssh_private_key, passphrase)
        connect_kw["pkey"] = pkey
        connect_kw["look_for_keys"] = False
    else:
        connect_kw["password"] = target.ssh_password
        connect_kw["look_for_keys"] = False

    ssh.connect(**connect_kw)

    # Find all recognised lockfiles under remote_path
    names_pattern = " -o ".join(f"-name '{n}'" for n in SUPPORTED_LOCKFILES)
    find_cmd = (
        f"find {shlex.quote(remote_path)} \\( {names_pattern} \\) "
        f"-not -path '*/node_modules/*' -not -path '*/.git/*' "
        f"-not -path '*/__pycache__/*' -not -path '*/.venv/*' -not -path '*/venv/*' "
        f"2>/dev/null"
    )
    _, stdout, _ = ssh.exec_command(find_cmd)
    remote_files = [l.strip() for l in stdout.read().decode().splitlines() if l.strip()]

    tmp_dir = tempfile.mkdtemp(prefix="pwnbroker_osv_")
    sftp = ssh.open_sftp()
    fetched = []

    for remote_file in remote_files:
        rel = os.path.relpath(remote_file, remote_path)
        local_path = os.path.join(tmp_dir, rel.replace("/", "_"))
        try:
            sftp.get(remote_file, local_path)
            # Rename to the base lockfile name so parsers recognise it
            base = os.path.basename(remote_file)
            dest = os.path.join(tmp_dir, base) if not os.path.exists(os.path.join(tmp_dir, base)) else local_path
            if local_path != dest:
                os.rename(local_path, dest)
            fetched.append(rel)
        except Exception:
            pass

    sftp.close()
    ssh.close()
    return tmp_dir, fetched


def test_ssh_connection(target) -> dict:
    """Quick connectivity check. Returns {"ok": bool, "message": str}."""
    try:
        tmp, _ = fetch_lockfiles_via_ssh(target, "/tmp")
        shutil.rmtree(tmp, ignore_errors=True)
        return {"ok": True, "message": "Connection successful."}
    except Exception as e:
        return {"ok": False, "message": str(e)}


# ── Public entry point ─────────────────────────────────────────────────────────

def run_osv_scan(scan, scan_path, target=None, github_token=None):
    """
    Scan for dependency vulnerabilities.

    Runs OSV (via CLI binary or REST API) and, when *github_token* is set,
    also queries the GitHub Advisory Database for additional coverage.
    Results from both sources are de-duplicated before returning.
    """
    results = []
    scanned_files = []
    tmp_dir = None
    effective_path = scan_path
    host = target.host if target else scan_path

    # SSH fetch if path doesn't exist locally and target has SSH creds
    if not os.path.isdir(scan_path) and target and target.ssh_username:
        try:
            tmp_dir, scanned_files = fetch_lockfiles_via_ssh(target, scan_path)
            effective_path = tmp_dir
        except Exception as e:
            return [{
                "result_type": "info",
                "host": host,
                "severity": "info",
                "title": "SSH Connection Failed",
                "description": f"Could not connect to {target.host}: {e}",
            }]

    cli_findings = _run_cli(effective_path)
    packages = []   # accumulated for GHSA enrichment

    try:
        if cli_findings is not None:
            for f in cli_findings:
                vuln = f["vuln"]
                cvss = _osv_severity(vuln)
                severity = _cvss_to_severity(cvss)
                fixed = _fixed_version(vuln)
                cves = _aliases(vuln)
                name, ver, eco = f["package"], f["version"], f["ecosystem"]
                packages.append((name, ver, eco))
                results.append({
                    "result_type": "vulnerability",
                    "host": host,
                    "severity": severity,
                    "title": f"{name} — {vuln.get('id', 'Unknown')}",
                    "description": vuln.get("summary", vuln.get("details", ""))[:1000],
                    "cve_id": cves[0] if cves else None,
                    "cvss_score": cvss,
                    "remediation": _remediation_cmd(eco, name, fixed),
                    "package_name": name,
                    "package_version": ver,
                    "ecosystem": eco,
                    "fixed_version": fixed,
                    "raw_data": json.dumps({
                        "source": "osv",
                        "osv_id": vuln.get("id"),
                        "aliases": vuln.get("aliases", []),
                    }),
                })
        else:
            packages, local_files = _collect_packages(effective_path)
            if not scanned_files:
                scanned_files = local_files
            if not packages:
                return [{
                    "result_type": "info",
                    "host": host,
                    "severity": "info",
                    "title": "No lockfiles found",
                    "description": (
                        f"No supported lockfiles found in {scan_path}. "
                        "Supported: requirements.txt, package.json, Pipfile.lock, "
                        "poetry.lock, Cargo.lock, go.mod, Gemfile.lock, "
                        "composer.lock, composer.json"
                    ),
                }]

            api_results = _query_osv_api(packages)
            for (name, ver, eco), vulns in api_results:
                for vuln in vulns:
                    cvss = _osv_severity(vuln)
                    severity = _cvss_to_severity(cvss)
                    fixed = _fixed_version(vuln)
                    cves = _aliases(vuln)
                    results.append({
                        "result_type": "vulnerability",
                        "host": host,
                        "severity": severity,
                        "title": f"{name} — {vuln.get('id', 'Unknown')}",
                        "description": vuln.get("summary", vuln.get("details", ""))[:1000],
                        "cve_id": cves[0] if cves else None,
                        "cvss_score": cvss,
                        "remediation": _remediation_cmd(eco, name, fixed),
                        "package_name": name,
                        "package_version": ver,
                        "ecosystem": eco,
                        "fixed_version": fixed,
                        "raw_data": json.dumps({
                            "source": "osv",
                            "osv_id": vuln.get("id"),
                            "aliases": vuln.get("aliases", []),
                        }),
                    })

        # ── GitHub Advisory Database enrichment ───────────────────────────────
        ghsa_added = 0
        if github_token and packages:
            try:
                from .github_advisory import query_ghsa, dedupe_key
                # Build de-dup set from OSV findings
                seen = {dedupe_key(r) for r in results if r["result_type"] == "vulnerability"}
                ghsa_findings = query_ghsa(
                    list({(n, v, e) for n, v, e in packages}),  # unique packages
                    github_token,
                    host=host,
                )
                for gf in ghsa_findings:
                    k = dedupe_key(gf)
                    if k not in seen:
                        seen.add(k)
                        results.append(gf)
                        ghsa_added += 1
            except Exception:
                pass  # GHSA enrichment is best-effort; never fail the whole scan

        binary_mode = cli_findings is not None
        ssh_mode    = tmp_dir is not None
        vuln_count  = sum(1 for r in results if r["result_type"] == "vulnerability")

        source_note = "osv-scanner CLI" if binary_mode else "OSV API (lockfile parser)"
        if github_token:
            source_note += f" + GitHub Advisory DB ({ghsa_added} additional findings)"

        results.insert(0, {
            "result_type": "info",
            "host": host,
            "severity": "info",
            "title": f"Dependency Scan Complete — {vuln_count} vulnerabilities found",
            "description": (
                f"Scanner: {source_note}\n"
                f"{'Remote path (SSH): ' if ssh_mode else 'Path: '}{scan_path}\n"
                + (f"Files scanned: {', '.join(scanned_files)}" if scanned_files else "")
            ),
        })
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    return results
