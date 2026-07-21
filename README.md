<div align="center">

<img src="PWNBroker.png" alt="PwnBroker Logo" width="480"/>

# PwnBroker

**Self-hosted security operations platform for small and mid-sized security teams.**

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0-black?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Ubuntu%2022.04%2B-orange?logo=ubuntu&logoColor=white)](https://ubuntu.com/)

</div>

---

PwnBroker combines network scanning, vulnerability management, dependency auditing, threat intelligence, endpoint monitoring, and GRC compliance into a single web interface. All data stays on your own infrastructure — no cloud accounts, no telemetry, no subscriptions.

---

## Table of Contents

- [Features](#features)
- [Screenshots](#screenshots)
- [Requirements](#requirements)
- [Quick Install](#quick-install)
- [Manual Setup](#manual-setup)
- [Configuration](#configuration)
- [Usage](#usage)
- [Agent Deployment](#agent-deployment)
- [API](#api)
- [Upgrading](#upgrading)
- [Tech Stack](#tech-stack)
- [License](#license)

---

## Features

| Module | Capabilities |
|---|---|
| **Network Scanning** | nmap-powered port, service, OS, and CVE scans with CIDR and asset-group targeting |
| **Vulnerability Management** | Ticket-based remediation workflow with SLA tracking, assignees, and auto-dedup |
| **Dependency Scanner** | SSH into hosts (password, RSA, Ed25519, or ECDSA key auth), pull package manifests, cross-reference OSV — Python, npm, Go, Rust, Ruby, Java, PHP, and more |
| **Threat Intelligence** | Multi-source IOC lookups (OTX, VirusTotal, AbuseIPDB, GreyNoise), SOC triage queue, OTX pulse feed |
| **Endpoint Agents** | Lightweight Python agent watches outbound connections in real time and fires alerts to the SOC queue |
| **CVE Enrichment** | EPSS scores, NVD CVSS v3 vectors, CWE IDs, and MITRE ATT&CK technique mapping — refreshed nightly |
| **GRC** | Risk register (5×5 heat-map), NIST CSF 2.0 / CIS Controls v8 / ISO 27001:2022 compliance tracking, policy library, evidence file uploads, audit-ready PDF exports |
| **Reports** | PDF and HTML scan reports, scheduled email delivery, Confluence publish, Jira ticket creation, Cloud API push |
| **Asset Inventory** | Auto-discovered from scan results; tagging, grouping, per-asset quick scan, hostname and OS enrichment |
| **Domain Monitoring** | crt.sh + DNSDumpster DNS enumeration, continuous change detection (new / changed / removed records) |
| **Scheduled Jobs** | Cron-based recurring scans and reports with asset-group expansion at fire time |
| **Audit Log** | Tamper-evident, filterable log of every admin and user action |
| **HTTPS** | Self-signed cert generated at install; upload a CA-signed cert in the UI with zero downtime |

---

## Screenshots

> Screenshots coming soon — the interface is a dark-themed Bootstrap 5 dashboard. See `docs/guide.md` for detailed feature walkthroughs.

---

## Requirements

- **OS**: Ubuntu 22.04 LTS or 24.04 LTS (Debian 11/12 also works)
- **RAM**: 2 GB minimum, 4 GB recommended
- **Disk**: 10 GB free
- **Access**: root / sudo for initial setup
- **Network**: outbound HTTPS for threat intel API calls and NVD CVE lookups
- **Python**: 3.11+ (3.13 tested)

Optional API keys (all free tiers available):

| Service | Key env / setting |
|---|---|
| [NVD](https://nvd.nist.gov/developers/request-an-api-key) | `NVD_API_KEY` — 10× higher rate limit |
| [AlienVault OTX](https://otx.alienvault.com) | IOC lookups, threat feed |
| [VirusTotal](https://www.virustotal.com) | File, URL, domain, IP reputation |
| [AbuseIPDB](https://www.abuseipdb.com) | IP abuse confidence scores |
| [GreyNoise](https://www.greynoise.io) | Internet noise / mass-scanner classification |
| [DNSDumpster](https://dnsdumpster.com) | Subdomain enumeration |

---

## Quick Install

`setup.sh` manages its own checkout — you don't need to clone the repo yourself first, just grab the script and run it:

```bash
curl -fsSL https://raw.githubusercontent.com/ChimneyFish/PWNBroker/main/setup.sh -o setup.sh
sudo bash setup.sh
```

That's it. The script clones the project to `/opt/PWNBroker`, installs everything, generates TLS certificates, creates a systemd service, and starts the server. When it finishes:

```
  Access URL:       https://<server-ip>:5000
  Default login:    admin / admin
```

> **You'll be forced to set a new password on first login** — the default `admin`/`admin` account can't be used to navigate anywhere else until you do.

### Custom port or install path

```bash
sudo PORT=8443 INSTALL_DIR=/srv/pwnbroker bash setup.sh
```

### Updating

`/opt/PWNBroker` (or your custom `INSTALL_DIR`) is a live git checkout, not a one-time copy — updating is a normal git pull:

```bash
cd /opt/PWNBroker && sudo git pull && sudo systemctl restart pwnbroker
```

Re-running `setup.sh` does the same fetch-and-reset plus everything else (dependency updates, service file, etc.) in one step, and is always safe to re-run — it never touches your data, logs, or `.env`.

---

## Manual Setup

For development or non-Ubuntu hosts:

```bash
# 1 — Clone
git clone https://github.com/ChimneyFish/PWNBroker.git
cd PWNBroker

# 2 — Virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt   # includes gunicorn

# 3 — Environment
cp .env.example .env          # or create from scratch (see Configuration)
$EDITOR .env

# 4 — Run (dev)
python run.py

# 4 — Run (production)
# One worker, several threads — see docs/deployment.md for why this isn't
# scaled up like a typical stateless web app (in-process scheduler + rate limiter).
gunicorn --bind 0.0.0.0:5000 --workers 1 --threads 8 "app:create_app()"
```

The database (`data/scanner.db`) and all required directories are created automatically on first start.

---

## Configuration

All runtime configuration lives in `.env` at the project root (or the install directory). The setup script generates this file automatically with a random secret key.

```ini
# ── Required ──────────────────────────────────────────────────────────────────
SECRET_KEY=<randomly generated 64-char hex string>
DATABASE_URL=sqlite:////opt/PWNBroker/data/scanner.db

# ── Optional: CVE lookups ─────────────────────────────────────────────────────
# Free key at https://nvd.nist.gov/developers/request-an-api-key
# Without key: 5 req/30s   With key: 50 req/30s
NVD_API_KEY=

# ── Optional: Email (can also be set in the web UI) ──────────────────────────
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USERNAME=
MAIL_PASSWORD=
MAIL_DEFAULT_SENDER=

# ── Optional: PostgreSQL (SQLite is default) ──────────────────────────────────
# DATABASE_URL=postgresql://pwnbroker:password@localhost/pwnbroker
```

All threat intel API keys (OTX, VirusTotal, AbuseIPDB, GreyNoise, DNSDumpster) are entered through the web UI under **Settings → Threat Intelligence APIs** and stored in the database.

### PostgreSQL (recommended for production)

```bash
sudo -u postgres createuser pwnbroker
sudo -u postgres createdb -O pwnbroker pwnbroker
sudo -u postgres psql -c "ALTER USER pwnbroker WITH PASSWORD 'yourpassword';"

/opt/PWNBroker/venv/bin/pip install psycopg2-binary
# Update DATABASE_URL in .env, then restart
sudo systemctl restart pwnbroker
```

---

## Usage

### Service management

```bash
sudo systemctl start   pwnbroker
sudo systemctl stop    pwnbroker
sudo systemctl restart pwnbroker
sudo systemctl reload  pwnbroker   # zero-downtime worker reload
sudo systemctl status  pwnbroker

journalctl -u pwnbroker -f         # live log stream
```

Application logs: `/opt/PWNBroker/logs/` (rotated daily, 14-day retention).

### First-time setup checklist

1. Log in at `https://<server>:5000` with `admin` / `admin`
2. **Profile** → change your password
3. **Settings → Time & NTP** → set your timezone
4. **Settings → Threat Intelligence APIs** → add API keys
5. **Targets → New Target** → add your first host or domain
6. **Scans → New Scan** → run your first scan

### Scan types

| Type | What it does |
|---|---|
| **Full** | Port scan + service detection + OS fingerprinting + CVE lookup + web checks + SOC triage |
| **Port** | Port and service detection only |
| **Web** | HTTP/HTTPS security header and misconfiguration checks |
| **OSV** | SSH dependency scan against OSV database |
| **Subdomain** | DNS enumeration via crt.sh + DNSDumpster |

### TLS certificate

The installer generates a self-signed 4096-bit RSA certificate (10-year validity). Your browser will show a security warning — click **Advanced → Proceed**.

To replace with a CA-signed certificate: **Settings → HTTPS / TLS** → upload cert + key (PEM format). The pair is validated before being written to disk. Restart the service to activate:

```bash
sudo systemctl restart pwnbroker
```

---

## Agent Deployment

PwnBroker includes a lightweight Python agent that monitors outbound network connections on endpoints and reports suspicious activity to the SOC queue in real time.

### Install on a Linux endpoint

```bash
curl -k https://<pwnbroker-server>:5000/threat/download/script/linux | sudo bash
```

### Install on macOS

```bash
curl -k https://<pwnbroker-server>:5000/threat/download/script/mac | sudo bash
```

### Install on Windows (PowerShell as Administrator)

```powershell
iwr https://<pwnbroker-server>:5000/threat/download/script/windows -UseBasicParsing | iex
```

Each installer embeds the correct server URL and registration token automatically. The agent appears in **Threat Intel → Agents** within one minute of first startup.

Agent config file locations:
- **Linux / macOS**: `~/.pwnbroker_agent.json`
- **Windows**: `%APPDATA%\pwnbroker_agent.json`

---

## API

All endpoints require an authenticated browser session (cookie). The built-in API is intended for dashboard polling and agent communication — not a general-purpose REST API.

### `GET /api/dashboard/stats`

```json
{
  "total_scans": 42,
  "running_scans": 1,
  "total_targets": 8,
  "total_vulns": 137,
  "critical_vulns": 5
}
```

### `GET /api/scans/<id>/status`

```json
{
  "id": 9,
  "status": "done",
  "vuln_count": 12,
  "critical_count": 2,
  "duration": 47
}
```

`status` values: `pending` · `running` · `done` · `failed`

### `POST /threat/api/register` — Agent registration (no session required)

```json
// Request
{ "reg_token": "<token>", "hostname": "host01", "os": "linux", "os_version": "Ubuntu 22.04", "ip_address": "10.0.0.5" }

// Response 200
{ "agent_id": "abc123", "token": "<session-token>" }
```

### `POST /threat/api/heartbeat` — Agent heartbeat

Headers: `X-Agent-ID: <agent_id>`, `X-Agent-Token: <token>`

```json
// Request body
{ "ip_address": "10.0.0.5", "connections": [{ "remote_ip": "1.2.3.4", "status": "ESTABLISHED", "pid": 1234 }] }

// Response 200
{ "status": "ok", "alerts": [], "new_alerts": 0 }
```

Full API reference: [`docs/guide.md → Section 16`](docs/guide.md#16-api-reference)

---

## Upgrading

`/opt/PWNBroker` is a live git checkout, so upgrading is a plain git pull + restart:

```bash
cd /opt/PWNBroker
sudo git pull
sudo systemctl restart pwnbroker
```

Or just re-run `sudo bash setup.sh` — it's fully idempotent: it fetches and resets to the latest commit, upgrades Python dependencies, and restarts the service, without touching `data/`, `logs/`, `evidence_uploads/`, or `.env`. Database schema changes are applied automatically at startup — no manual migrations.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Web framework | Flask 3.0 + Werkzeug |
| ORM | SQLAlchemy 2.0 + Flask-SQLAlchemy |
| Auth | Flask-Login + Werkzeug password hashing (scrypt) |
| WSGI server | Gunicorn (gthread workers) |
| Scheduler | APScheduler 3 (background thread) |
| Database | SQLite (default) / PostgreSQL |
| Scanning | python-nmap, paramiko (SSH — RSA / Ed25519 / ECDSA), requests |
| HTML parsing | BeautifulSoup4 (subdomain enumeration scrape fallback) |
| PDF reports | ReportLab |
| Frontend | Bootstrap 5, Chart.js, vanilla JS |

---

## Troubleshooting

**Service won't start**
```bash
journalctl -u pwnbroker -n 50
# Port in use?      ss -tlnp | grep 5000
# Bad TLS cert?     openssl x509 -in /opt/PWNBroker/data/ssl/cert.pem -noout -text
# Python error?     /opt/PWNBroker/venv/bin/python -c "from app import create_app; create_app()"
```

**`Permission denied` on service start / WorkingDirectory**

The service user (`pwnbroker`) needs execute permission on the install directory to enter it. If the directory mode is `750` instead of `755` the service fails immediately before gunicorn launches. Re-run setup.sh to fix it, or apply manually:
```bash
sudo chmod 755 /opt/PWNBroker
sudo systemctl restart pwnbroker
```

**Scans stuck in "running"**
```bash
sudo systemctl restart pwnbroker
# Reset stuck scans:
sqlite3 /opt/PWNBroker/data/scanner.db "UPDATE scans SET status='failed' WHERE status='running';"
```

**OS detection not working**
```bash
sudo setcap cap_net_raw+eip,cap_net_admin+eip $(which nmap)
getcap $(which nmap)
# Expected: /usr/bin/nmap cap_net_admin,cap_net_raw+eip
```

For the full troubleshooting guide see [`docs/guide.md → Section 18`](docs/guide.md#18-troubleshooting).

---

## License

PwnBroker is released under the [GNU General Public License v3.0](LICENSE).

---

<div align="center">
Built for security teams that prefer owning their own data.
</div>
