"""
GitHub repository dependency scanner with Dependabot-style PR remediation.

Fetches lockfiles from a GitHub repo via the REST API, runs OSV + GHSA checks,
and can open fix PRs for vulnerable packages.
"""
import base64
import json
import os
import re
import shutil
import tempfile

import requests

GITHUB_API = "https://api.github.com"

ECO_MANIFESTS = {
    "PyPI":      "requirements.txt",
    "npm":       "package.json",
    "Packagist": "composer.json",
    "Go":        "go.mod",
    "RubyGems":  "Gemfile",
    "crates.io": "Cargo.toml",
}

_SKIP_DIRS = {
    "vendor", "node_modules", ".git", "venv", "__pycache__",
    ".venv", "dist", "build", ".tox", "eggs",
}


def _headers(token: str) -> dict:
    return {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


# ── Repo traversal ────────────────────────────────────────────────────────────

def _get_lockfile_paths(owner: str, repo: str, token: str, subpath: str = "") -> list:
    """Return list of lockfile/manifest paths in the repo matching supported parsers."""
    from .osv_scanner import LOCKFILE_PARSERS
    supported = set(LOCKFILE_PARSERS.keys())

    resp = requests.get(
        f"{GITHUB_API}/repos/{owner}/{repo}/git/trees/HEAD?recursive=1",
        headers=_headers(token), timeout=30,
    )
    if not resp.ok:
        raise RuntimeError(f"GitHub API {resp.status_code}: {resp.text[:300]}")

    data    = resp.json()
    subpath = subpath.strip("/")

    # For very large repos where tree is truncated, fall back to root listing
    if data.get("truncated"):
        root = requests.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/contents/",
            headers=_headers(token), timeout=15,
        )
        items = root.json() if root.ok else []
        return [
            i["path"] for i in items
            if isinstance(i, dict) and i.get("type") == "file"
            and i.get("name") in supported
        ]

    # Track which filenames appear in each directory for precedence checks
    dir_files: dict = {}
    all_paths = []

    for item in data.get("tree", []):
        if item.get("type") != "blob":
            continue
        path  = item["path"]
        parts = path.split("/")
        if any(p in _SKIP_DIRS for p in parts[:-1]):
            continue
        if subpath and not path.startswith(subpath + "/") and path != subpath:
            continue
        fname = parts[-1]
        if fname in supported:
            dirpart = "/".join(parts[:-1])
            dir_files.setdefault(dirpart, set()).add(fname)
            all_paths.append(path)

    # Prefer composer.lock over composer.json in the same directory
    final = []
    for path in all_paths:
        parts   = path.split("/")
        dirpart = "/".join(parts[:-1])
        fname   = parts[-1]
        if fname == "composer.json" and "composer.lock" in dir_files.get(dirpart, set()):
            continue
        final.append(path)

    return final


def _fetch_file(owner: str, repo: str, path: str, token: str) -> tuple:
    """Fetch a file from GitHub. Returns (text_content, blob_sha)."""
    resp = requests.get(
        f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}",
        headers=_headers(token), timeout=20,
    )
    if not resp.ok:
        raise RuntimeError(f"Cannot fetch {path}: {resp.status_code}")
    data    = resp.json()
    content = base64.b64decode(
        data["content"].replace("\n", "")
    ).decode("utf-8", errors="replace")
    return content, data["sha"]


# ── Manifest patching ─────────────────────────────────────────────────────────

def _patch_requirements_txt(content: str, package: str, new_version: str):
    new_lines = []
    found     = False
    for line in content.splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            new_lines.append(line)
            continue
        pkg_name = re.split(r"[=<>!;\[#\s]", stripped)[0]
        if pkg_name.lower() == package.lower():
            new_lines.append(f"{package}=={new_version}\n")
            found = True
        else:
            new_lines.append(line)
    return "".join(new_lines) if found else None


def _patch_json_manifest(content: str, package: str, new_version: str,
                          sections: list, prefix: str = "^"):
    try:
        data = json.loads(content)
    except Exception:
        return None
    patched = False
    for section in sections:
        if package in (data.get(section) or {}):
            data[section][package] = f"{prefix}{new_version}"
            patched = True
    return (json.dumps(data, indent=2) + "\n") if patched else None


def _patch_go_mod(content: str, package: str, new_version: str):
    new_lines = []
    found     = False
    for line in content.splitlines(keepends=True):
        m = re.match(r"(\s*)" + re.escape(package) + r"\s+v?[\d.]+\S*", line)
        if m:
            new_lines.append(f"{m.group(1)}{package} v{new_version}\n")
            found = True
        else:
            new_lines.append(line)
    return "".join(new_lines) if found else None


def _patch_gemfile(content: str, package: str, new_version: str):
    new_lines = []
    found     = False
    for line in content.splitlines(keepends=True):
        m = re.match(r"(\s*gem\s+['\"]" + re.escape(package) + r"['\"])(.*)", line)
        if m:
            new_lines.append(f"{m.group(1)}, \"~> {new_version}\"\n")
            found = True
        else:
            new_lines.append(line)
    return "".join(new_lines) if found else None


def _patch_cargo_toml(content: str, package: str, new_version: str):
    new_lines = []
    found     = False
    for line in content.splitlines(keepends=True):
        m = re.match(r'(' + re.escape(package) + r'\s*=\s*["\'])[\d.]+(["\'])', line)
        if m:
            new_lines.append(f'{m.group(1)}{new_version}{m.group(2)}\n')
            found = True
        else:
            new_lines.append(line)
    return "".join(new_lines) if found else None


def patch_manifest(filename: str, content: str, package: str, new_version: str):
    """Return patched manifest content, or None if the package wasn't found."""
    if filename == "requirements.txt":
        return _patch_requirements_txt(content, package, new_version)
    if filename == "package.json":
        return _patch_json_manifest(
            content, package, new_version,
            ["dependencies", "devDependencies", "peerDependencies"], "^",
        )
    if filename == "composer.json":
        return _patch_json_manifest(
            content, package, new_version, ["require", "require-dev"], "^",
        )
    if filename == "go.mod":
        return _patch_go_mod(content, package, new_version)
    if filename == "Gemfile":
        return _patch_gemfile(content, package, new_version)
    if filename == "Cargo.toml":
        return _patch_cargo_toml(content, package, new_version)
    return None


# ── PR creation ───────────────────────────────────────────────────────────────

def create_fix_pr(owner: str, repo: str, result_data: dict, token: str) -> dict:
    """
    Open a GitHub PR bumping the vulnerable package to its fixed version.
    Returns {"ok": bool, "pr_url": str|None, "error": str|None}.
    """
    package   = result_data.get("package_name", "")
    old_ver   = result_data.get("package_version", "unknown")
    fixed     = result_data.get("fixed_version", "")
    eco       = result_data.get("ecosystem", "")
    vuln_id   = result_data.get("title", "").split(" — ")[-1]
    severity  = result_data.get("severity", "unknown").upper()

    if not package or not fixed:
        return {"ok": False, "pr_url": None,
                "error": "No fixed version available for this finding."}

    target_manifest = ECO_MANIFESTS.get(eco)
    if not target_manifest:
        return {"ok": False, "pr_url": None,
                "error": f"Automated PR not supported for ecosystem: {eco}"}

    hdrs = _headers(token)

    # Get default branch + HEAD SHA
    try:
        repo_info = requests.get(
            f"{GITHUB_API}/repos/{owner}/{repo}", headers=hdrs, timeout=15
        ).json()
        default_branch = repo_info.get("default_branch", "main")
        ref_data = requests.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/git/ref/heads/{default_branch}",
            headers=hdrs, timeout=15,
        ).json()
        base_sha = ref_data["object"]["sha"]
    except Exception as e:
        return {"ok": False, "pr_url": None, "error": f"Cannot read repo: {e}"}

    # Find manifest candidates in the tree
    try:
        tree = requests.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/git/trees/HEAD?recursive=1",
            headers=hdrs, timeout=30,
        ).json().get("tree", [])
        candidates = [
            item["path"] for item in tree
            if item.get("type") == "blob"
            and os.path.basename(item["path"]) == target_manifest
            and not any(p in _SKIP_DIRS for p in item["path"].split("/")[:-1])
        ]
    except Exception as e:
        return {"ok": False, "pr_url": None, "error": f"Cannot list repo files: {e}"}

    if not candidates:
        return {"ok": False, "pr_url": None,
                "error": f"No {target_manifest} found in {owner}/{repo}"}

    # Find the first manifest that actually contains the package
    patched_path = patched_content = file_sha = None
    for file_path in candidates:
        try:
            content, sha = _fetch_file(owner, repo, file_path, token)
            new_content  = patch_manifest(target_manifest, content, package, fixed)
            if new_content:
                patched_path    = file_path
                patched_content = new_content
                file_sha        = sha
                break
        except Exception:
            continue

    if not patched_path:
        return {"ok": False, "pr_url": None,
                "error": f"Could not locate {package} in any {target_manifest} to patch"}

    # Create branch
    safe_pkg = re.sub(r"[^a-zA-Z0-9._-]", "-", package)
    branch   = f"pwnbroker/security/{safe_pkg}-{fixed}"
    try:
        br = requests.post(
            f"{GITHUB_API}/repos/{owner}/{repo}/git/refs",
            headers=hdrs,
            json={"ref": f"refs/heads/{branch}", "sha": base_sha},
            timeout=15,
        )
        if not br.ok and "already exists" not in (br.text or ""):
            return {"ok": False, "pr_url": None,
                    "error": f"Branch creation failed: {br.status_code}"}
    except Exception as e:
        return {"ok": False, "pr_url": None, "error": f"Cannot create branch: {e}"}

    # Commit the patched file
    try:
        commit = requests.put(
            f"{GITHUB_API}/repos/{owner}/{repo}/contents/{patched_path}",
            headers=hdrs,
            json={
                "message": (
                    f"fix: bump {package} from {old_ver} to {fixed}\n\n"
                    f"Resolves {vuln_id}. Automated security fix by PwnBroker."
                ),
                "content": base64.b64encode(patched_content.encode()).decode(),
                "sha":     file_sha,
                "branch":  branch,
            },
            timeout=15,
        )
        if not commit.ok:
            return {"ok": False, "pr_url": None,
                    "error": f"Commit failed: {commit.status_code} {commit.text[:200]}"}
    except Exception as e:
        return {"ok": False, "pr_url": None, "error": f"Cannot commit: {e}"}

    # Open the PR
    pr_body = (
        f"## Security Fix — {severity} Severity\n\n"
        f"| Field | Value |\n|---|---|\n"
        f"| Package | `{package}` |\n"
        f"| From | `{old_ver}` |\n"
        f"| To | `{fixed}` |\n"
        f"| Advisory | {vuln_id} |\n"
        f"| Ecosystem | {eco} |\n\n"
        f"### Description\n{(result_data.get('description') or '')[:500]}\n\n"
        f"---\n*Automated security PR by PwnBroker. Review and test before merging.*"
    )
    try:
        pr = requests.post(
            f"{GITHUB_API}/repos/{owner}/{repo}/pulls",
            headers=hdrs,
            json={
                "title": f"fix({package}): {old_ver} → {fixed} [{vuln_id}]",
                "body":  pr_body,
                "head":  branch,
                "base":  default_branch,
            },
            timeout=15,
        )
        if pr.ok:
            return {"ok": True, "pr_url": pr.json().get("html_url"), "error": None}
        # PR already exists
        if pr.status_code == 422:
            existing = requests.get(
                f"{GITHUB_API}/repos/{owner}/{repo}/pulls",
                headers=hdrs,
                params={"head": f"{owner}:{branch}", "state": "open"},
                timeout=15,
            ).json()
            if existing and isinstance(existing, list):
                return {"ok": True, "pr_url": existing[0].get("html_url"), "error": None}
        return {"ok": False, "pr_url": None,
                "error": f"PR failed: {pr.status_code} {pr.text[:200]}"}
    except Exception as e:
        return {"ok": False, "pr_url": None, "error": f"Cannot open PR: {e}"}


# ── Main scan ─────────────────────────────────────────────────────────────────

def run_github_dep_scan(scan, owner: str, repo: str, token: str, subpath: str = "") -> list:
    """
    Fetch lockfiles from a GitHub repo and return ScanResult-ready dicts.
    Uses OSV API + GHSA for vulnerability data (same sources as Dependabot).
    """
    host = f"github.com/{owner}/{repo}"

    if not token:
        return [{
            "result_type": "info", "host": host, "severity": "info",
            "title": "GitHub Token Required",
            "description": "Configure a GitHub token in Settings → Threat Intel APIs.",
        }]

    try:
        lockfile_paths = _get_lockfile_paths(owner, repo, token, subpath)
    except Exception as e:
        return [{
            "result_type": "info", "host": host, "severity": "info",
            "title": "GitHub API Error", "description": str(e),
        }]

    if not lockfile_paths:
        return [{
            "result_type": "info", "host": host, "severity": "info",
            "title": "No dependency files found",
            "description": (
                f"No supported lockfiles found in {owner}/{repo}"
                + (f" under /{subpath}" if subpath else "") + "."
            ),
        }]

    from .osv_scanner import (
        LOCKFILE_PARSERS, _query_osv_api, _osv_severity,
        _cvss_to_severity, _fixed_version, _aliases, _remediation_cmd,
    )
    from .github_advisory import query_ghsa, dedupe_key

    tmp_dir       = tempfile.mkdtemp(prefix="pwnbroker_ghrepo_")
    packages      = []
    scanned_files = []

    try:
        for file_path in lockfile_paths:
            filename = os.path.basename(file_path)
            parser   = LOCKFILE_PARSERS.get(filename)
            if not parser:
                continue
            try:
                content, _ = _fetch_file(owner, repo, file_path, token)
            except Exception:
                continue

            # Preserve directory structure so intra-dir checks work (e.g. composer)
            local_path = os.path.join(tmp_dir, file_path)
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            with open(local_path, "w", encoding="utf-8") as f:
                f.write(content)

            try:
                pkgs = parser(local_path)
                if pkgs:
                    packages.extend(pkgs)
                    scanned_files.append(file_path)
            except Exception:
                pass
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    if not packages:
        return [{
            "result_type": "info", "host": host, "severity": "info",
            "title": "No packages found",
            "description": (
                f"Lockfiles found but no package versions could be extracted from {owner}/{repo}."
            ),
        }]

    results     = []
    api_results = _query_osv_api(packages)
    for (name, ver, eco), vulns in api_results:
        for vuln in vulns:
            cvss     = _osv_severity(vuln)
            severity = _cvss_to_severity(cvss)
            fixed    = _fixed_version(vuln)
            cves     = _aliases(vuln)
            results.append({
                "result_type":     "vulnerability",
                "host":            host,
                "severity":        severity,
                "title":           f"{name} — {vuln.get('id', 'Unknown')}",
                "description":     vuln.get("summary", vuln.get("details", ""))[:1000],
                "cve_id":          cves[0] if cves else None,
                "cvss_score":      cvss,
                "remediation":     _remediation_cmd(eco, name, fixed),
                "package_name":    name,
                "package_version": ver,
                "ecosystem":       eco,
                "fixed_version":   fixed,
                "raw_data": json.dumps({
                    "source":  "osv",
                    "osv_id":  vuln.get("id"),
                    "aliases": vuln.get("aliases", []),
                }),
            })

    ghsa_added = 0
    try:
        seen = {dedupe_key(r) for r in results if r["result_type"] == "vulnerability"}
        for gf in query_ghsa(
            list({(n, v, e) for n, v, e in packages}), token, host=host
        ):
            k = dedupe_key(gf)
            if k not in seen:
                seen.add(k)
                results.append(gf)
                ghsa_added += 1
    except Exception:
        pass

    vuln_count = sum(1 for r in results if r["result_type"] == "vulnerability")
    results.insert(0, {
        "result_type": "info", "host": host, "severity": "info",
        "title": f"GitHub Repo Scan — {vuln_count} vulnerabilities found",
        "description": (
            f"Repository: github.com/{owner}/{repo}\n"
            f"Scanner: OSV API + GitHub Advisory DB ({ghsa_added} additional findings)\n"
            f"Files scanned: {', '.join(scanned_files)}"
        ),
    })
    return results
