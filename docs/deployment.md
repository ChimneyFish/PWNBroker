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
