# PwnBroker — Complete User Guide

PwnBroker is a self-hosted security operations platform that combines network scanning, vulnerability management, dependency auditing, threat intelligence, GRC compliance, and endpoint monitoring into a single web UI. All data stays on your infrastructure.

---

## Table of Contents

1. [Installation](#1-installation)
2. [First Login & Initial Setup](#2-first-login--initial-setup)
3. [Dashboard](#3-dashboard)
4. [Targets](#4-targets)
5. [Assets](#5-assets)
6. [Scans](#6-scans)
7. [Vulnerability Management](#7-vulnerability-management)
8. [Dependency Scanner](#8-dependency-scanner)
9. [Reports](#9-reports)
10. [Threat Intelligence](#10-threat-intelligence)
11. [Endpoint Agents](#11-endpoint-agents)
12. [GRC — Governance, Risk & Compliance](#12-grc--governance-risk--compliance)
13. [Settings](#13-settings)
14. [User Management](#14-user-management)
15. [Activity Log](#15-activity-log)
16. [API Reference](#16-api-reference)
17. [Upgrading](#17-upgrading)
18. [Troubleshooting](#18-troubleshooting)

---

## 1. Installation

### Requirements

- Ubuntu 22.04 LTS or 24.04 LTS (Debian-based distros also work)
- 2 GB RAM minimum, 4 GB recommended
- 10 GB disk space
- Root / sudo access
- Outbound internet access (for threat intel API calls and NVD CVE lookups)

### Quick Install

```bash
git clone https://github.com/your-org/pwnbroker.git /opt/pwnbroker-src
cd /opt/pwnbroker-src
sudo bash setup.sh
```

The script will:

1. Install system packages: `python3`, `nmap`, `openssl`, `ufw`, and build tools
2. Create a `pwnbroker` system user (no shell, no home directory)
3. Copy the application to `/opt/pwnbroker`
4. Build a Python virtual environment and install all dependencies
5. Grant `nmap` raw-socket capabilities (`cap_net_raw`) so OS fingerprinting works without root
6. Generate a self-signed TLS certificate (4096-bit RSA, 10-year validity)
7. Create `/opt/pwnbroker/.env` with a randomly generated `SECRET_KEY`
8. Install and enable a `systemd` service (`pwnbroker.service`) that starts automatically on boot
9. Configure `logrotate` for daily log rotation with 14-day retention
10. Open the HTTPS port in `ufw` if the firewall is active

After the script completes you will see:

```
  Access URL:       https://<server-ip>:5000
  Default login:    admin / admin
```

### Custom Port or Install Directory

```bash
sudo PORT=8443 INSTALL_DIR=/srv/pwnbroker bash setup.sh
```

### Service Management

```bash
sudo systemctl start   pwnbroker     # start
sudo systemctl stop    pwnbroker     # stop
sudo systemctl restart pwnbroker     # full restart
sudo systemctl reload  pwnbroker     # graceful zero-downtime worker reload
sudo systemctl status  pwnbroker     # health check

journalctl -u pwnbroker -f           # live log stream
journalctl -u pwnbroker -n 100       # last 100 log lines
```

Application logs are also written to `/opt/pwnbroker/logs/`.

### TLS Certificate

The installer generates a self-signed certificate. Your browser will show a security warning — click **Advanced → Proceed** to continue.

For production, upload a CA-signed certificate through **Settings → HTTPS / TLS**. Both the certificate (PEM) and private key (PEM) files are required. The service must be restarted after uploading.

---

## 2. First Login & Initial Setup

1. Navigate to `https://<your-server-ip>:5000`
2. Log in with `admin` / `admin`
3. Go to **Profile** (bottom of the sidebar) and change your password immediately
4. Go to **Settings → Time & NTP** and set your timezone — all timestamps across the platform will display in this zone
5. Add your API keys under **Settings → Threat Intelligence APIs** to unlock IOC lookups, OTX feeds, and SOC triage

### Recommended First Steps

| Step | Where |
|------|-------|
| Change admin password | Sidebar → Profile |
| Set timezone | Settings → Time & NTP |
| Add threat intel API keys | Settings → Threat Intelligence APIs |
| Add your first target | Targets → New Target |
| Run your first scan | Scans → New Scan |

---

## 3. Dashboard

The dashboard is fully customizable. All widgets pull live data from the API and refresh every 30 seconds.

### Customizing the Layout

Click **Customize** in the top-right corner to open the widget picker panel. From there you can:

- **Add** any widget by clicking the `+` button next to it
- **Remove** any widget by clicking the `−` button (or hover over a widget and click the `×` in the top-right corner)
- **Reorder** widgets by dragging them to a new position (grab the `⠿` handle that appears on hover)
- **Reset** to the default layout with the "Reset defaults" button

Your layout is saved in the browser's `localStorage` and persists across page refreshes.

### Available Widgets

**Stat cards** (small, shows a single number with a link):

| Widget | Shows | Links to |
|--------|-------|----------|
| Total Scans | All scans ever run | Scans |
| Running Now | Active scans | Scans |
| Targets | Configured scan targets | Targets |
| Critical Vulns | Unresolved critical findings | Vuln Management |
| High Vulns | High severity findings | Vuln Management |
| Online Agents | Endpoint agents with recent heartbeat | Threat Intel → Agents |
| Assets | Total discovered assets | Assets |
| Open SOC Cases | Pending SOC triage cases | Threat Intel → SOC Triage |

**Charts** (medium width):

| Widget | Chart type | Shows |
|--------|-----------|-------|
| Severity Breakdown | Doughnut | Distribution of all findings by severity |
| Scan Trend (14d) | Line | Number of scans launched per day |
| Vulns by Target | Horizontal bar | Top 5 targets ranked by vulnerability count |
| Agent Health | Status list | Online / Offline / Unknown agent counts |

**Tables & Tools** (full or half width):

| Widget | Shows |
|--------|-------|
| Recent Scans | Last 8 scans with status, vuln count, and date |
| Recent Findings | Last 10 vulnerabilities with severity, CVSS, and CVE |
| Quick Actions | One-click shortcuts to New Scan, SOC Triage, Add Target, IOC Lookup |

---

## 4. Targets

Targets are the hosts, IP addresses, IP ranges, or domains that PwnBroker scans and monitors.

### Target Types

| Type | Example | Notes |
|------|---------|-------|
| Host | `192.168.1.100` | Single IP or hostname |
| IP Range | `192.168.1.0/24` | CIDR range, scanned as one job |
| Domain | `example.com` | Enables DNS/subdomain enumeration |

### Adding a Target

1. Go to **Targets → New Target**
2. Enter a name, the host/IP/domain, and an optional description
3. Click **Create Target**

### Target Detail Page

Clicking a target shows:

- **Scan history** for that target
- **Domain records** (for domain targets) — A, AAAA, CNAME, MX, NS records discovered via crt.sh and DNSDumpster
- **DNS enumeration** — click **Re-Enumerate** to refresh DNS records
- Subdomain changes are tracked: new records show as `new`, changed values as `changed`, removed entries as `removed`

### SSH Credentials (for Dependency Scanning)

To enable dependency scanning on a remote host, add SSH credentials on the target detail page. Supported auth types:

- **Password** — username + password
- **Key** — upload a PEM private key (with optional passphrase)

Test the connection with the **Test SSH** button before running a scan.

### Deleting a Target

Deleting a target also deletes all associated scans, results, assets, and reports. This action cannot be undone.

---

## 5. Assets

Assets are individual network devices discovered during scans. They are tracked automatically — every completed scan populates the asset inventory.

### Asset Inventory (`/assets`)

The inventory table shows every known device with its:

- IP address and hostname (editable inline)
- Operating system
- Last seen timestamp
- Status (Active / Inactive)
- Tags
- Open vulnerability count
- Parent target

### Tags

Tags let you group and filter assets. Examples: `production`, `dmz`, `windows`, `critical`.

- Create a tag with a name and hex color
- Assign tags to assets from the inventory or asset row
- Filter the inventory by tag using the tag buttons at the top

### Asset Groups

Groups are collections of assets that can be scanned together as a single job. Three group types:

| Type | How assets are collected |
|------|--------------------------|
| Manual | You add assets individually |
| By Tag | All assets with a chosen tag |
| By Network | All assets belonging to a target |

**Creating a group**: Assets → Asset Groups → New Group

**Scanning a group**: On the group detail page, click **Scan Group** to launch a full scan against all member assets simultaneously.

### Quick Scan

From the asset inventory, click **Quick Scan** on any row to immediately launch a full scan of that single asset without going through the scan wizard.

---

## 6. Scans

Scans run `nmap` against targets or asset groups and enrich results with CVE data from NVD.

### Scan Types

| Type | What it does |
|------|-------------|
| Full | Port scan + service detection + OS fingerprinting + CVE lookup |
| Port | Port scan and service detection only |
| Web | HTTP/HTTPS service checks |
| CVE | CVE lookup against already-discovered services (no new port scan) |
| OSV | Dependency vulnerability scan via SSH (see Dependency Scanner) |

### Running a Scan

1. Go to **Scans → New Scan**
2. Select a target or asset group
3. Choose scan type and port range (default: 1–1024)
4. Give it a name and click **Launch Scan**

The scan runs in the background. The scan detail page polls every 2.5 seconds and updates automatically when complete.

### Scan Results

Each scan result falls into one of these categories:

- **Port** — open port with service, version, and protocol
- **Vulnerability** — CVE-matched finding with severity, CVSS score, and remediation
- **Web Check** — HTTP header findings (missing security headers, etc.)
- **Info** — general host/OS information

Findings are color-coded by severity: **Critical** (red) · **High** (orange) · **Medium** (yellow) · **Low** (blue) · **Info** (gray)

### Marking Findings as Remediated

On the scan detail page, click **Remediate** next to any finding to mark it resolved. Remediated findings are excluded from future vulnerability ticket counts.

### Scheduled Scans

Set up recurring scans using cron expressions:

1. Go to **Scans → Schedule New**
2. Pick a target or asset group, scan type, and port range
3. Enter a cron expression (e.g., `0 2 * * *` for 2 AM daily)
4. Click **Create Schedule**

Active schedules can be paused/resumed with the toggle on the Scans index page. Scheduled scans appear in the activity log when they run.

---

## 7. Vulnerability Management

The Vuln Management module tracks findings as tickets through their remediation lifecycle.

### Vuln Tickets (`/vulns/tickets`)

A ticket is automatically created for each unique vulnerability the first time it is found on a host. If the same CVE reappears on the same host in a later scan, the existing ticket is updated rather than duplicated.

**Ticket statuses:**

| Status | Meaning |
|--------|---------|
| Open | Newly found, not yet being worked |
| In Progress | Someone is actively remediating |
| Patched | Fix confirmed |
| Accepted Risk | Risk accepted by the team |
| False Positive | Finding is not actually exploitable |

**SLA tracking**: Each severity level has a default SLA (Critical: 1 day, High: 7 days, Medium: 30 days, Low: 90 days). Overdue tickets are highlighted in red.

### Device View (`/vulns/device/<target>`)

Shows all open tickets grouped by target with a risk heat-map. Use this view to get a per-host risk summary.

### Updating a Ticket

Click any ticket to open the detail panel and:

- Change status
- Assign to a user
- Add notes
- Record the patch date

---

## 8. Dependency Scanner

The dependency scanner connects to a target over SSH, reads the installed package manifest, and cross-references it against the [OSV (Open Source Vulnerabilities)](https://osv.dev) database.

### Supported Ecosystems

Python (pip), Node.js (npm), Go modules, Rust (Cargo), Ruby (Bundler), Java (Maven/Gradle), PHP (Composer), and others supported by OSV.

### Prerequisites

- The target must have SSH enabled and credentials configured on the Target detail page
- Test the connection with **Test SSH** before running a scan

### Running a Dependency Scan

1. Go to **Dependency Scanner → New Scan**
2. Select a target that has SSH credentials configured
3. Optionally specify a path on the remote host to scan (defaults to home directory)
4. Click **Launch**

### Results

Results list each vulnerable package with:

- Package name and installed version
- First fixed version
- CVE ID and CVSS score
- Severity badge

Click **Remediate** on any row to mark it resolved.

---

## 9. Reports

Reports generate PDF or HTML summaries of scan results.

### Generating a Report

1. Go to **Reports**
2. Find a completed scan in the table
3. Click **Generate** and choose PDF or HTML format

The report includes: executive summary, severity breakdown chart, full findings table with CVSS scores and remediation advice, and scan metadata.

### Downloading Reports

Generated reports appear in the **Saved Reports** table. Click **Download** to save the file locally.

### Pushing Reports to a Cloud API

If you have configured a Cloud API endpoint under **Settings → Cloud API Integration**, click **Push** next to any saved report to POST it to the endpoint. The payload includes scan metadata and optionally a base64-encoded copy of the report file.

### Scheduled Reports

Schedule automatic report delivery by email:

1. Go to **Reports → Schedule New**
2. Select a target, cron schedule, recipients, and format
3. Click **Create Schedule**

Recipients will receive an email with the report attached each time the schedule fires. SMTP must be configured under **Settings → Email / SMTP**.

### Atlassian Integration

If Confluence and/or Jira are configured under **Settings → Atlassian**:

- **Publish to Confluence**: From the scan detail page, click **Publish to Confluence** to create a formatted wiki page in your configured space
- **Create Jira Tickets**: From the scan detail page, click **Create Jira Tickets** to open issues for findings at or above your configured severity threshold

---

## 10. Threat Intelligence

The Threat Intelligence module provides IOC lookups, threat feed monitoring, SOC triage workflows, subdomain enumeration, and domain-change tracking.

### Required API Keys

Configure all keys under **Settings → Threat Intelligence APIs**.

| Service | Used for |
|---------|---------|
| OTX (AlienVault) | IOC reputation, threat feed pulses |
| VirusTotal | File hash / URL / domain / IP reputation |
| AbuseIPDB | IP abuse reports and confidence scores |
| GreyNoise | Internet noise classification (RIOT / mass-scanner detection) |
| DNSDumpster | Subdomain enumeration |
| NVD | CVE lookup and CVSS enrichment |

Click **Test All Keys** on the Settings page to validate each key without leaving the page.

### IOC Lookup (`/threat/lookup`)

Enter any of the following and get a multi-source reputation report:

- IPv4 / IPv6 address
- Domain name
- File hash (MD5, SHA-1, SHA-256)
- URL

Results are cached for 24 hours to avoid burning API quota.

### OTX Feed (`/threat/feed`)

Displays the latest threat pulses from your AlienVault OTX subscriptions. Each pulse shows indicator counts, tags, and adversary attribution. Requires an OTX API key.

### SOC Triage (`/threat/triage`)

The triage queue collects IOCs that need analyst review. IOCs reach the queue either:

- Manually submitted via the Lookup page when the threat score exceeds the threshold
- Automatically when an endpoint agent reports a network connection to a known-malicious IP and GreyNoise or VT confirm it

**Triage actions:**

| Action | Meaning |
|--------|---------|
| Alert | Flag as confirmed threat, add analyst notes |
| Dismiss | Mark as benign / false positive |

Alerted cases can be exported. Dismissed cases are removed from the active queue but retained in history.

### Subdomain Enumeration (`/threat/subdomains`)

Enter a domain to enumerate subdomains using crt.sh certificate transparency logs and DNSDumpster. Results show IP addresses, record types, and first/last seen dates.

---

## 11. Endpoint Agents

Endpoint agents are lightweight Python scripts that run on monitored hosts. They send heartbeats and report suspicious network connections back to PwnBroker.

### How Agents Work

1. The agent runs as a background process (service/daemon) on the endpoint
2. Every 60 seconds it sends a heartbeat with the host's IP, OS, and hostname
3. It monitors active network connections and cross-checks destination IPs against your IOC database
4. If a connection to a known-malicious IP is detected, an alert is created in PwnBroker
5. Agents that have not sent a heartbeat in 5 minutes are marked **Offline**

### Deploying an Agent

#### Step 1 — Download the agent script

Go to **Threat Intel → Agents → Download Agent**. The download page shows three options:

| Platform | File | Method |
|----------|------|--------|
| Linux | `install_linux.sh` | Bash one-liner |
| macOS | `install_mac.sh` | Bash one-liner |
| Windows | `install_windows.ps1` | PowerShell script |

Each installer downloads the Python agent, sets the server URL and registration token automatically, and installs it as a system service.

#### Step 2 — Set the registration token

Under **Settings → Threat Intelligence APIs**, set a **Registration Token** (a pre-shared secret). All agents must present this token when registering for the first time.

#### Step 3 — Install on the endpoint

**Linux / macOS:**
```bash
curl -k https://<pwnbroker-server>:5000/threat/download/script/linux | sudo bash
```

**Windows (PowerShell as Administrator):**
```powershell
iwr https://<pwnbroker-server>:5000/threat/download/script/windows -UseBasicParsing | iex
```

#### Step 4 — Verify registration

The agent appears in **Threat Intel → Agents** within a minute of first startup. Status shows **Online** when heartbeats are received.

### Agent Alerts

When an agent detects a suspicious connection, the alert appears on:

- The agent's detail page
- The **Threat Intel** overview page
- The **SOC Triage** queue (if the threat score exceeds the threshold)

Acknowledge alerts from the agent detail page to clear them from the active list.

### Manual Registration (advanced)

```bash
python3 pwnbroker_agent.py --register --no-verify-ssl
```

This prompts for server URL and registration token, saves the config, then exits. Subsequent runs without `--register` operate in normal heartbeat mode.

---

## 12. GRC — Governance, Risk & Compliance

The GRC module manages risk registers, compliance frameworks, and security policies.

### Risk Register (`/grc/risks`)

Track risks across five categories: Technical, Operational, Compliance, Strategic, Financial.

**Risk scoring**: likelihood (1–5) × impact (1–5) = risk score (1–25)

| Score | Level |
|-------|-------|
| 1–5 | Low |
| 6–11 | Medium |
| 12–19 | High |
| 20–25 | Critical |

**Risk statuses**: Open · In Treatment · Mitigated · Accepted · Transferred · Closed

Each risk can have a mitigation plan, target date, assigned owner, and optionally be linked to a specific asset. Residual likelihood and impact can be recorded after controls are applied to show risk reduction.

### Compliance (`/grc/compliance`)

PwnBroker ships with seeded compliance frameworks:

- **NIST CSF 2.0** — Govern, Identify, Protect, Detect, Respond, Recover
- **CIS Controls v8** — 18 control groups
- **ISO 27001:2022** — Annex A controls

**Assessing a control**: Click any framework to see its controls. Click **Assess** on any control to record:

- Status: Compliant · Partial · Non-Compliant · Not Applicable · Not Assessed
- Evidence notes
- Next review date

**Auto-assessment**: Click **Run Auto-Assessment** to have PwnBroker automatically evaluate controls it can infer from scan data (e.g., patch status, open ports, missing headers).

**Evidence files**: Upload supporting evidence documents (PDFs, screenshots, configs) directly to a control.

**Compliance report**: Generate a PDF compliance report for any framework showing pass/fail counts and a gap summary. Useful for auditors.

### Policies (`/grc/policies`)

Maintain a library of security policies with version tracking.

**Policy categories**: Access Control · Data Classification · Incident Response · Vulnerability Management · Change Management · Acceptable Use · General

**Policy statuses**: Draft · Active · Under Review · Retired

Each policy tracks the owner, approver, approval date, and next review date. Overdue review dates are highlighted in red.

---

## 13. Settings

### Time & NTP

**Timezone**: Select any IANA timezone from the dropdown. All timestamps across the entire platform — scans, findings, activity logs, SOC cases — display in this timezone. The preview updates live as you change the selection.

**NTP Server**: Enter the hostname of your NTP server (e.g., `pool.ntp.org`, `time.cloudflare.com`). PwnBroker writes this to `/etc/systemd/timesyncd.conf` and restarts the sync service. This requires the process to run as root or have `sudo` access — if it fails, the timezone is still saved and the error message shows the exact command to run manually.

### Email / SMTP

Configure outbound email for scheduled reports and alerts.

| Field | Example |
|-------|---------|
| SMTP Server | `smtp.gmail.com` |
| Port | `587` |
| Use STARTTLS | Checked |
| Username | `alerts@company.com` |
| Password | App password (not your login password) |
| From Address | `pwnbroker@company.com` |

Use the **Send Test Email** button to verify the configuration before saving.

### Threat Intelligence APIs

All API keys are stored encrypted in the database. Entering a key and saving replaces the existing value; leaving a field blank keeps the current key. Click **Test All Keys** to verify connectivity for each configured service.

### Atlassian Integration

Connect to Confluence and Jira for automated report publishing and ticket creation.

| Field | Notes |
|-------|-------|
| Base URL | `https://yourorg.atlassian.net` |
| Email | Your Atlassian account email |
| API Token | Generate at id.atlassian.com → Security → API tokens |
| Confluence Space Key | e.g., `SEC` |
| Parent Page ID | Optional — found in the page URL |
| Jira Project Key | e.g., `SEC` |
| Issue Type | Usually `Bug` or `Security` |
| Minimum Severity | Only findings at or above this level create Jira tickets |

### Cloud API Integration

Forward scan reports to an external API endpoint (e.g., a SIEM, ticketing system, or custom webhook).

PwnBroker POSTs a JSON payload containing scan metadata, all findings, and optionally a base64-encoded report file. Authentication options: None, Bearer Token, or API Key header.

### HTTPS / TLS

Upload a CA-signed certificate to replace the self-signed one. Provide both the certificate file (PEM/CRT/CER) and the matching private key file (PEM/KEY). The pair is validated before being written to disk. Restart the service after uploading:

```bash
sudo systemctl restart pwnbroker
```

---

## 14. User Management

Users are managed under **Settings → User Management** (admin only).

### Roles

| Role | Permissions |
|------|-------------|
| Admin | Full access: create/delete targets, run scans, manage users and settings, generate reports |
| User | Read-only: view dashboard, scans, targets, and reports; update own profile |

### Adding a User

Fill in username, email, temporary password, and role, then click **Add User**. The user can change their password under **Profile**.

### Managing Existing Users

- **Change role**: Select from the dropdown in the role column — takes effect immediately
- **Disable/Enable**: Prevent login without deleting the account
- **Delete**: Permanently removes the account (cannot be undone)

You cannot change your own role or delete your own account.

### Profile

Each user can update their own username, email, and password under **Sidebar → Profile**. Admins do not need to be involved for password changes.

---

## 15. Activity Log

The Activity Log (`/activity`) is an immutable audit trail of every significant action taken in PwnBroker. It is only visible to admin users.

Each entry records:

- Timestamp (in the configured timezone)
- Actor (username or "System" for automated actions)
- Action type (e.g., `scan.created`, `user.login`, `settings.threat_save`)
- Entity name (e.g., the scan name or target)
- Detail string
- Source IP address

The log is grouped by date. Hover over a timestamp to see the full date/time with seconds.

Admins can clear the entire log with the **Clear Log** button. This is irreversible.

---

## 16. API Reference

PwnBroker exposes a small JSON API for programmatic access. All endpoints require an authenticated session (cookie-based).

### `GET /api/dashboard/stats`

Returns basic dashboard counts.

```json
{
  "total_scans": 42,
  "running_scans": 1,
  "total_targets": 8,
  "total_vulns": 137,
  "critical_vulns": 5
}
```

### `GET /api/dashboard/widgets`

Returns all dashboard widget data in one call. Used by the dashboard widget system.

```json
{
  "stats": {
    "total_scans": 42,
    "running_scans": 1,
    "total_targets": 8,
    "total_assets": 64,
    "online_agents": 3,
    "open_soc": 2,
    "critical_vulns": 5,
    "high_vulns": 18,
    "medium_vulns": 61,
    "low_vulns": 48,
    "info_vulns": 5
  },
  "severity_map": { "critical": 5, "high": 18, "medium": 61, "low": 48, "info": 5 },
  "trend": {
    "labels": ["Jun 04", "Jun 05", "..."],
    "data":   [2, 0, 1, 3, "..."]
  },
  "vuln_by_target": {
    "labels": ["web-server", "db-host"],
    "data":   [42, 19]
  },
  "agent_stats": { "online": 3, "offline": 1, "unknown": 0 },
  "recent_scans": [ { "id": 9, "name": "...", "status": "done", "..." } ],
  "recent_vulns": [ { "severity": "critical", "title": "...", "cve_id": "CVE-2024-..." } ]
}
```

### `GET /api/scans/<scan_id>/status`

Poll the live status of a running scan. Used by the scan view page.

```json
{
  "id": 9,
  "status": "running",
  "vuln_count": 12,
  "critical_count": 2,
  "duration": null
}
```

`status` values: `pending` · `running` · `done` · `failed`

### Endpoint Agent API

These endpoints are used exclusively by the agent script.

#### `POST /threat/api/register`

Register a new agent. Requires the pre-shared registration token.

```json
// Request
{
  "token": "<registration-token>",
  "hostname": "workstation-01",
  "os_type": "linux",
  "os_version": "Ubuntu 22.04",
  "ip_address": "10.0.0.45"
}

// Response 200
{
  "agent_id": "abc123...",
  "token": "<agent-session-token>"
}
```

#### `POST /threat/api/heartbeat`

Send a periodic heartbeat with current network connections. Requires the agent's session token in the `X-Agent-Token` header.

```json
// Request
{
  "agent_id": "abc123...",
  "ip_address": "10.0.0.45",
  "connections": [
    { "raddr": "185.220.101.5", "status": "ESTABLISHED", "pid": 1234 }
  ]
}

// Response 200
{ "ok": true }
```

---

## 17. Upgrading

Re-running `setup.sh` is safe and idempotent. It syncs new application files without touching `data/`, `logs/`, or `evidence_uploads/`, and preserves your existing `.env` and TLS certificates.

```bash
# Pull latest code
cd /path/to/pwnbroker-src
git pull

# Re-run setup (syncs files, updates Python deps, reloads service)
sudo bash setup.sh
```

New database columns (added by migrations) are applied automatically on startup by `_migrate_columns()` in `app/__init__.py`. No manual schema changes are needed.

---

## 18. Troubleshooting

### Service won't start

```bash
# Check the last 50 log lines
journalctl -u pwnbroker -n 50

# Common causes:
# - Port already in use:     ss -tlnp | grep 5000
# - Missing .env file:       ls /opt/pwnbroker/.env
# - Bad TLS cert:            openssl x509 -in /opt/pwnbroker/data/ssl/cert.pem -noout -text
# - Python import error:     /opt/pwnbroker/venv/bin/python -c "from app import create_app; create_app()"
```

### Scans stuck in "running" state

The scan background thread may have died. Restart the service:

```bash
sudo systemctl restart pwnbroker
```

Scans that were running when the service stopped are left in `running` status. Reset them manually in the database if needed:

```bash
sqlite3 /opt/pwnbroker/data/scanner.db \
  "UPDATE scans SET status='failed' WHERE status='running';"
```

### OS detection not working

nmap needs `CAP_NET_RAW` for `-O` (OS fingerprinting). Re-run the capability grant:

```bash
sudo setcap cap_net_raw+eip,cap_net_admin+eip $(which nmap)
```

Verify it worked:
```bash
getcap $(which nmap)
# Expected: /usr/bin/nmap cap_net_admin,cap_net_raw+eip
```

### API keys "INVALID" even though they are correct

- Ensure there are no leading/trailing spaces in the key fields
- Some services (VirusTotal, NVD) have rate limits — a 429 response is treated as "key accepted"
- Network issues (DNS, firewall) to the external APIs will show as "Network error"

### Timezone not applying to old timestamps

The `localdt` Jinja2 filter converts UTC datetimes at render time. All timestamps stored in the database are always UTC — only the display changes. If a page is still showing UTC, hard-refresh the browser (`Ctrl+Shift+R`) to clear cached template responses.

### Agents showing as Offline immediately

The agent is considered Offline if no heartbeat is received within 5 minutes. Common causes:

- The agent process is not running — check the service status on the endpoint
- The server URL in the agent config is wrong or not reachable from the endpoint
- TLS verification is failing — re-run the agent with `--no-verify-ssl` if using a self-signed cert

Agent config file location:
- Linux/macOS: `~/.pwnbroker_agent.json`
- Windows: `%APPDATA%\pwnbroker_agent.json`

### "Permission denied" when setting NTP server

PwnBroker writes to `/etc/systemd/timesyncd.conf`. If the service runs as the `pwnbroker` user (not root), this will fail. The timezone setting is always saved regardless. To apply the NTP server change manually:

```bash
sudo nano /etc/systemd/timesyncd.conf
# Set: NTP=your.ntp.server

sudo systemctl restart systemd-timesyncd
sudo timedatectl set-ntp true
```

### Database locked errors

SQLite allows only one writer at a time. If you see "database is locked" errors under heavy load, consider switching to PostgreSQL:

```bash
# Install psycopg2
/opt/pwnbroker/venv/bin/pip install psycopg2-binary

# Update DATABASE_URL in /opt/pwnbroker/.env
DATABASE_URL=postgresql://pwnbroker:password@localhost/pwnbroker

# Create the database
sudo -u postgres createuser pwnbroker
sudo -u postgres createdb -O pwnbroker pwnbroker
sudo -u postgres psql -c "ALTER USER pwnbroker WITH PASSWORD 'password';"

# Restart to apply
sudo systemctl restart pwnbroker
```

---

*PwnBroker — built for security teams that prefer owning their own data.*
