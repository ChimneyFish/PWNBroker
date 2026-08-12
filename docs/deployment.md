# Deployment & Production Hardening

This covers what's specific to running PwnBroker in production — for installation and feature usage see [guide.md](guide.md). See `.env.example` at the repo root for every environment variable mentioned here.

## First boot

1. Copy `.env.example` to `.env` and adjust if needed (every value has a working default).
2. Start the app (`python run.py`, or your process manager of choice — see [Process model](#process-model)).
3. Log in as `admin` / `admin`. **You'll be forced to set a new password immediately** — this is enforced by `must_change_password` on the seeded admin account and can't be skipped by navigating elsewhere.
4. Generate a TLS certificate (see guide.md's install section) — `run.py` serves plain HTTP with a startup warning if `data/ssl/cert.pem`/`key.pem` aren't present. Don't run a real deployment without TLS.

## Process model

`run.py` launches gunicorn with **one worker process** and multiple threads (`WEB_THREADS`, default 8), not multiple workers. This is deliberate, not a resource constraint:

- APScheduler's background jobs (scan-due checks, report sends, domain monitoring, CVE enrichment, the Palo Alto firewall poller) run in-process. With more than one worker, every scheduled job fires once per worker — duplicate scans, duplicate report emails, duplicate firewall polls.
- The login rate limiter (Flask-Limiter) uses in-memory storage, which is only accurate within a single process.

Threads still give real request concurrency for this app's workload (DB queries, subprocess calls to `nmap` that release the GIL while blocked). If you need more raw throughput than one process can give, the actual jobs to move are the APScheduler-driven ones (into their own process with a shared lock or external scheduler) and the rate limiter (into a shared backend like Redis) — don't just bump `--workers` without doing that first.

## Secrets

Three things are auto-generated on first boot and persisted to `data/` (all already gitignored):

| File | Purpose | If lost |
|---|---|---|
| `data/secret_key.txt` | Flask session-signing key | Everyone gets logged out; no data loss |
| `data/encryption_key.txt` | Fernet key encrypting API keys / SSH credentials at rest | **Every stored secret becomes permanently unrecoverable** — must be re-entered manually |
| `data/scanner.db` | The application database (SQLite) | Full data loss |

Back up all three together. There's currently no automated backup job — this is a known gap, not an oversight (see the project's production-readiness punch list).

API keys (`ThreatConfig`), Palo Alto firewall credentials, and `Target` SSH credentials are encrypted at rest (Fernet, via `app/crypto.py`). Any pre-existing plaintext values are encrypted in place automatically on the first boot after upgrading — this migration is idempotent and safe to leave running on every boot.

**`.env` ownership** (setup.sh installs only): the app runs as a dedicated unprivileged `pwnbroker` system user, but `.env` is deliberately `640 root:pwnbroker` rather than world-readable, since it holds `SECRET_KEY` and SMTP credentials. `setup.sh` re-asserts this ownership/permission on every run (not just first install) — it has to, because the same script's own directory setup step does a blanket `chown -R root:root` over the whole install directory on every run, which would otherwise silently flip `.env` back to `root:root` and break the service with `[Errno 13] Permission denied` on next restart. If you ever manually `sudo`-edit `.env` directly (bypassing `setup.sh`), re-run `sudo bash setup.sh` afterward (or manually `chown root:pwnbroker .env && chmod 640 .env`) to restore the correct ownership before restarting the service.

## Database

SQLite, tuned for concurrent access: WAL journal mode, `synchronous=NORMAL`, and a 30s busy-timeout (`app/__init__.py`'s `_tune_sqlite`). This assumes single-instance deployment — there's no clustering story for SQLite, and none is planned; a real multi-instance deployment would need a networked database instead.

Schema changes ship as additive columns picked up by `_migrate_columns()` in `app/__init__.py` (no Alembic) — they run automatically on every boot.

## Logging & health

- Application logs: `data/logs/app.log`, rotating at 10MB × 5 backups. Level via `LOG_LEVEL` (default `INFO`). gunicorn's own access/error logs go to stdout as before — capture both if you're shipping logs somewhere.
- `GET /healthz` — unauthenticated, pings the database, returns `{"status": "ok"}`/200 or `{"status": "error"}`/503. Point your load balancer / orchestrator health check at this.

## MFA and SSO

**MFA (TOTP)** needs no external setup — any user can enable it from their profile page, and admins can mark specific accounts `mfa_required` (**Users** table → shield icon) to force enrollment on next login. Backup codes are shown once at enrollment time and never stored in recoverable form; if someone loses both their device and their codes, an admin resets MFA for that account from the same table (clears enrollment, doesn't affect the `mfa_required` policy flag).

**SSO (Google / Microsoft)** requires registering PwnBroker as an OAuth app with each provider first — this can't be done from inside PwnBroker itself:

- **Google** — [Google Cloud Console](https://console.cloud.google.com/) → APIs & Services → Credentials → Create OAuth client ID (type: Web application). Authorized redirect URI: `https://<your-domain>:<port>/login/sso/google/callback`. Copy the Client ID/Secret into **Settings → Single Sign-On**.
- **Microsoft** — [Entra admin center](https://entra.microsoft.com/) → App registrations → New registration. Redirect URI (type: Web): `https://<your-domain>:<port>/login/sso/microsoft/callback`. Under "Supported account types," pick single-tenant unless you intend `common`. Create a client secret under Certificates & secrets. Copy the Application (client) ID, the secret, and (if single-tenant) the Directory (tenant) ID into Settings.
- Either way, set **Allowed Email Domains** in Settings before enabling — an empty allowlist never permits sign-in or auto-provisioning, by design, regardless of the auto-provision toggle.
- SSO credential changes require a restart to take effect (providers are registered with Authlib at boot from the DB-stored config, same reasoning as the TLS-cert-upload flow).
- SSO logins bypass the local MFA step — the identity provider is trusted to have handled its own factors. Local username/password login keeps working for every account regardless of SSO configuration; SSO is additive, not a replacement.

**SAML 2.0** (for IdPs set up as a SAML Enterprise App rather than an OAuth registration — e.g. Microsoft Entra's **Enterprise Applications → SAML-based sign-on**, or Okta/OneLogin equivalents) is a separate mechanism from the OIDC providers above, with its own setup flow:

- In the IdP's SAML app config, paste in the **Reply URL / Assertion Consumer Service URL** and **Identifier / Entity ID** shown on PwnBroker's **Settings → SAML** section (these are generated from PwnBroker's own external URL, no need to invent them).
- Download the IdP's **Federation Metadata XML** and upload it back into **Settings → SAML** (or paste its metadata URL instead) — this single import auto-fills the IdP's SSO URL, Entity ID, and signing certificate. No client secret is involved in SAML; trust comes from the IdP's signed assertions plus that certificate.
- The IdP must emit the user's email — Entra's default `.../claims/emailaddress` claim works out of the box; if the NameID isn't itself an email address (commonly it's the UPN), PwnBroker falls back to that claim automatically.
- SAML shares the same **Allowed Email Domains** / auto-provisioning policy as the OIDC providers above — there's no separate copy of that setting to keep in sync.
- Both SP-initiated (starting from PwnBroker's login page) and IdP-initiated (starting from the IdP's own app portal, e.g. Entra's "My Apps") sign-in work without extra configuration.
- Same as OIDC: changes require a restart to take effect.
- Not implemented: SAML Single Logout (SLO) and SP-initiated request signing — local `/logout` just ends the PwnBroker session, and Entra accepts unsigned AuthnRequests by default, so neither adds meaningful security here today.

## Scan engines

**PEN** (the `pen` scan type — "PEN — Operational Web/API Pentest (Run All)") wraps an external Go CLI, [ekomsSavior/PEN](https://github.com/ekomsSavior/PEN), which runs 11 web/API pentest modules against a target URL: IDOR enumeration, file upload testing, SQL injection, lateral movement, exploitation (hash cracking + privilege escalation), GraphQL/WebSocket testing, git repository exposure, server fingerprinting, and misconfiguration checks.

- **Build**: `setup.sh` clones and builds it automatically (step 5) to `<install dir>/tools/pen/pen`, requiring `golang-go` (added to the package list). It has no releases to `go install` directly — building from source is the only option, matching the upstream README's own instructions. Re-running `setup.sh` skips the build if the binary already exists; delete `tools/pen/` to force a rebuild.
- **Manual dev setup** (not using `setup.sh`): `git clone https://github.com/ekomsSavior/PEN.git tools/pen && cd tools/pen && go mod init pen && go mod tidy && go build -o pen main.go`. Override the binary location with the `PEN_BINARY` env var if you build it elsewhere.
- **Optional sub-tools**: `john` (hash cracking, installed by `setup.sh`), `websocat` (WebSocket connection testing), `git-dumper` (`pip install git-dumper`, repository dumping). PEN itself detects when these are missing and skips those specific checks gracefully — PwnBroker doesn't gate the scan on their presence.
- **What it actually finds against a real target**: PEN's own README describes 11 generic-sounding modules, but reading its source shows options 1-5 (IDOR, file upload, SQLi, lateral movement, exploitation) probe endpoints hardcoded to PEN's own reference vulnerable app (`/api/users/{id}`, `/api/upload/csv`, `/api/networks`, and a privilege-escalation attempt hardcoded to `PUT /api/users/6`) — against an arbitrary real target these simply 404 and contribute nothing. Options 6-10 (GraphQL, WebSocket, git exposure, fingerprinting, misconfigurations) are genuine generic checks and are where real signal comes from on ordinary targets. "Run All Scans" still runs all 11, same as the tool itself does.
- **No structured output**: PEN prints free text with `[+]`/`[-]`/`[*]`/`[!]` prefixes, not JSON — `app/scanner/pen_scanner.py` parses this heuristically (`[!]` → high-severity finding, `[+]` → low-severity info, `[-]`/`[*]` dropped from individual results). The complete unfiltered transcript is always kept as one additional info-severity result, so nothing the tool printed is ever silently lost even where the structured parse is imprecise.
- **Driving the interactive CLI**: PEN has no command-line flags — it's stdin-prompt-driven only. `pen_scanner.py` uses `pexpect` (expect/sendline) rather than piping a fixed script upfront, because PEN's own prompt-reading code (`bufio.NewReader` re-created on every prompt) can silently drop buffered-ahead input if multiple lines are written to stdin before it's ready to read them.
- **Isolation**: PEN persists its target/token to `~/.pen_config.json`. Each scan run gets its own temporary `HOME` directory so concurrent PEN scans (or scans against different targets) never share or clobber each other's config; the directory is deleted when the scan finishes.
- **Timeout**: capped at 40 minutes total (`PEN_TIMEOUT_SECONDS` in `pen_scanner.py`) — hash cracking against a wordlist has no natural end, so the whole run is killed at the cap and whatever output was captured up to that point is still parsed and kept, with a note that the results are partial.
- **Authorization**: this scan type performs active exploitation (password hash cracking, a privilege-escalation attempt, git secret extraction), not passive scanning. Only run it against targets you're authorized to test — the same rule that applies to running PEN directly.

**REAPER** (the **Secrets** section, its own top-level nav item — not a `Scan` type on the generic New Scan form, same as `osv`) wraps [ekomsSavior/REAPER](https://github.com/ekomsSavior/REAPER), an external Go CLI that scans a GitHub repository's code, commit messages, pull requests, and issues for exposed secrets (API keys, tokens, credentials, private keys, database URLs). Unlike PEN, it has real CLI flags and structured JSONL output — much simpler to drive.

- **Build**: `setup.sh` clones and builds it automatically (step 6) to `<install dir>/tools/reaper/reaper`. **Build command is `go build -o reaper .`, not `go build -o reaper reaper.go`** — `reaper.go` depends on symbols defined in `detector.go` (`Detector`, `loadPatternFile`, etc.), and Go's single-file build mode excludes sibling files in the package, so building just `reaper.go` fails with `undefined: Detector`. REAPER ships its own `go.mod`/`go.sum`, so (unlike PEN) no `go mod init` step is needed. Re-running `setup.sh` skips the build if the binary already exists; delete `tools/reaper/` to force a rebuild.
- **Manual dev setup** (not using `setup.sh`): `git clone https://github.com/ekomsSavior/REAPER.git tools/reaper && cd tools/reaper && go mod tidy && go build -o reaper .`. Override the binary location with the `REAPER_BINARY` env var if you build it elsewhere.
- **GitHub token**: shares the same token as OSV's GitHub Advisory lookups (`ThreatConfig.github_advisory_token`, **Settings → Threat Intel APIs**) rather than a separate field — but REAPER needs broader scopes than that field originally required: `repo` and `public_repo`, so it can read a repository's commit/PR/issue history via the authenticated API. Without a token, scans return a "token required" result rather than failing outright. The token must reach REAPER via the `GITHUB_TOKEN` environment variable specifically, not just its `-token` flag — one of its code paths (GitHub Security Advisories lookup) reads `os.Getenv("GITHUB_TOKEN")` directly, bypassing the flag entirely, so `reaper_scanner.py` always sets the env var.
- **Structured output**: REAPER writes `reaper_findings.jsonl` (one JSON object per finding: secret type, file path, line number, masked value, branch, GitHub permalink, severity) directly into the output directory PwnBroker passes via `-repo`/`-output` — much more reliable to parse than PEN's free-text markers. REAPER masks secret values itself (`maskSecret()`) before writing them out, so an unmasked live credential never ends up stored in PwnBroker's database.
- **Silent-failure handling**: if REAPER can't authenticate or can't read the target repo, it logs the error to stderr and still exits 0 with an empty findings file — indistinguishable from "scanned cleanly, found nothing" unless stderr is checked. `reaper_scanner.py` captures stderr and surfaces it as an explicit "REAPER scan error" result whenever it's non-empty (REAPER never writes ordinary progress there, only real errors), so a bad or under-scoped token shows up clearly instead of looking like a clean scan.
- **One-shot, not continuous**: REAPER's own default is `-continuous=true` (run forever, re-scanning all of public GitHub on a sleep cycle) — PwnBroker always passes `-repo <url> -continuous=false`, which forces single-repository, single-run mode regardless of that default (confirmed in REAPER's own `main()`). "Monitoring a repo over time" is done by re-running or scheduling scans through PwnBroker itself, not by leaving a REAPER process running in the background — consistent with the single-worker process model above.
- **Timeout**: capped at 20 minutes (`REAPER_TIMEOUT_SECONDS` in `reaper_scanner.py`) — REAPER self-throttles its GitHub API calls (`-api-rps 1` by default) to respect rate limits, so a large or long-lived repository's full history can take a while. On timeout, the process is killed and whatever findings were already flushed to `reaper_findings.jsonl` (written incrementally, not buffered until the end) are still parsed and returned, with a note that the results are partial.
- **Advisory scanning is off**: REAPER's `-scan-advisories` flag (GitHub Security Advisories / GHSA) is left at its default `false`. GHSA/CVE coverage for GitHub repos is already handled by OSV's GitHub Advisory integration in the Dependency Scanner — enabling it here too would produce a second, overlapping copy of that data under a different heading.

**Backdoor Detector** (the **Backdoor Scan** section) wraps [ekomsSavior/backdoor_detector](https://github.com/ekomsSavior/backdoor_detector), a Python tool that statically analyzes a directory for backdoor indicators: YARA signature matching, hardcoded-secret patterns, and dependency vulnerabilities (Safety/Trivy/pip-audit/npm audit). Unlike PEN or REAPER, it targets a **local filesystem path already on this server** (`Target.target_type == "local_path"`), not a remote address or GitHub repo — a genuinely different target shape from every other scan type here.

- **The runtime-analysis phase is never run.** Reading the tool's source (not just its README) shows `run_full_analysis()` — the only entry point its own CLI mode calls — unconditionally includes a "runtime analysis" phase that auto-detects a project's entry point (`main.py`, `package.json` → `npm start`, a `Makefile`, `run.sh`, or *any executable file at all* in the top-level directory) and executes it via `subprocess.Popen(cmd, shell=True, ...)` with no sandboxing, to observe its network behavior. There is no flag to disable this. PwnBroker never calls `run_full_analysis()` or `analyze_network_behavior()` — `app/scanner/_backdoor_detector_runner.py` calls only the specific safe phases (`scan_with_yara()`, `scan_hardcoded_secrets()`, `scan_for_vulnerabilities()`, `generate_manual_review_checklist()`) directly. Nothing in the scanned directory is ever executed.
- **Build**: `setup.sh` clones it automatically (step 7) to `<install dir>/tools/backdoor_detector/` — pure Python, no build step. Re-running `setup.sh` skips the clone if `backdoor_detector.py` already exists; delete `tools/backdoor_detector/` to force a re-clone. Override the location with the `BACKDOOR_DETECTOR_DIR` env var.
- **Subprocess isolation, not in-process import**: although `BackdoorDetector` is just a Python class that could be imported directly into the Flask process, its file-walking phases (`rglob("*")` over the whole target) have no size/count cap of their own, and an in-process Python call can't be forcibly killed on timeout the way a subprocess can. `_backdoor_detector_runner.py` is invoked as a subprocess via `subprocess.run(..., timeout=...)` — same isolation principle as PEN/REAPER, applied to a tool with no CLI worth shelling out to directly.
- **Fresh YARA rules dir per scan**: `BackdoorDetector.__init__` deletes every `.yar`/`.yara` file in whatever `yara_rules_dir` it's given and regenerates its own hardcoded default rules from scratch, on *every* instantiation. `backdoor_scanner.py` passes a fresh `tempfile.mkdtemp()` per run so this destructive side effect never touches a shared directory or races under concurrent scans.
- **`pip-audit` is neutered, not fixed**: as shipped, `_run_pip_audit()` calls bare `pip-audit --format json` with no `-r`/project-path argument — verified directly, this makes `pip-audit` audit whichever Python environment it's invoked from (PwnBroker's own venv), not the scanned directory. `_backdoor_detector_runner.py` overrides `BackdoorDetector._run_pip_audit` to a no-op at the class level before instantiation, rather than patching it to audit the target correctly — that would just duplicate PwnBroker's existing OSV-based Dependency Scanner.
- **Safety's JSON output is degraded**: `_run_safety_scan()` calls `safety check -r <file> --json`, but current `safety` (3.x) prints a deprecation banner directly into stdout around the JSON payload, so `json.loads()` always raises and the tool silently falls back to a much lower-fidelity text-grep (`"CVE" in line`). Left as-is (upstream issue, not something to patch around here) — Trivy and pip-audit's own dependency-file scanning cover the same ground with better fidelity.
- **Three bundled YARA rules had to be patched to compile at all**: the tool's own default rules (regenerated fresh every run, see above) failed YARA compilation for three independent, verified reasons — an unreferenced `$packet_send` string in `suspicious_network_activity`, an unreferenced `$shell` string in `backdoor_indicator`, and (once referenced) an invalid regex on `$shell` itself. YARA rejects the *whole file* on the first such error, so out of the box this phase was silently a no-op regardless of target content. `_backdoor_detector_runner.py` patches these three narrowly rather than reproducing the tool's full rule set from scratch.
- **Trivy and npm audit are optional**: `setup.sh` installs Trivy (step 7, pinned to `v0.68.2` via Aqua Security's own documented installer, not the `main`-branch "latest") to `/usr/local/bin`. npm/Node.js is **not** auto-installed — this project's stack doesn't otherwise need Node, and `_run_npm_audit()` already degrades gracefully (skipped when `package.json` is absent, or npm itself is missing). Safety and pip-audit are installed via `requirements.txt` (`yara-python`, `safety`, `pip-audit`) so those two sub-scanners always run.
- **Timeout**: capped at 10 minutes (`BACKDOOR_TIMEOUT_SECONDS` in `backdoor_scanner.py`) — `scan_for_vulnerabilities()` alone can take up to ~8 minutes worst-case across its sequential sub-scanners, plus unbounded file-walk time for a large directory. Unlike PEN/REAPER, the runner only prints its JSON output at the very end — nothing is written incrementally — so a timeout genuinely has no partial results to recover; the result set says so explicitly rather than implying partial findings exist.
- **Authorization**: this reads the full contents of whatever directory a `local_path` target points at, including any secrets or credentials present in source files. Only point it at directories you have the right to analyze on this server.

## Running tests

```
pip install -r requirements.txt
pytest
```

CI runs the same suite on every push/PR via `.github/workflows/tests.yml`.

## What's intentionally not done here

- **No automated backups** — no offsite/cloud destination is assumed; wire `data/` (db + both key files) into whatever backup tooling your infrastructure already uses.
- **No multi-instance / off-disk file storage** — `evidence_uploads/` and the SQLite DB are local-disk only. Fine for one instance on persistent storage; breaks on ephemeral container filesystems or if you ever need more than one instance.
- **No third-party APM/error-tracking** (Sentry etc.) — wire one up if you have a DSN; the 500 handler already logs full tracebacks locally in the meantime.
- **Input validation** is targeted (target host/port-range, Palo Alto firewall hostname — the fields that reach a subprocess or an outbound network call), not a blanket framework across every form.
