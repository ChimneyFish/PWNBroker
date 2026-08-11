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
