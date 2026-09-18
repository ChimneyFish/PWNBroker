#!/usr/bin/env bash
# =============================================================================
#  PwnBroker — Ubuntu Server Setup
#  Usage:  sudo bash setup.sh
#  Re-run at any time to upgrade/repair an existing installation.
# =============================================================================
set -euo pipefail

# ── Tunables (override via env vars) ─────────────────────────────────────────
# Install dir matches the project's actual name/casing (PWNBroker) — this is
# also the directory that "git pull" gets run in to update, see step 3.
INSTALL_DIR="${INSTALL_DIR:-/opt/PWNBroker}"
REPO_URL="${REPO_URL:-https://github.com/ChimneyFish/PWNBroker.git}"
BRANCH="${BRANCH:-main}"
PORT="${PORT:-443}"
WEB_THREADS="${WEB_THREADS:-8}"
SERVICE_USER=pwnbroker
SERVICE_FILE=/etc/systemd/system/pwnbroker.service

# ── Colours ───────────────────────────────────────────────────────────────────
R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m' C='\033[0;36m' B='\033[1m' N='\033[0m'
info() { printf "${C}[*]${N} %s\n"  "$*"; }
ok()   { printf "${G}[✓]${N} %s\n"  "$*"; }
warn() { printf "${Y}[!]${N} %s\n"  "$*"; }
die()  { printf "${R}[✗]${N} %s\n"  "$*" >&2; exit 1; }
step() { echo ""; printf "${B}──── %s${N}\n" "$*"; }

# ── Root check ────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && die "Must run as root:  sudo bash $0"

# Optional: warn if not Ubuntu (still usually works on Debian)
if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    [[ "${ID:-}" != "ubuntu" ]] && warn "Designed for Ubuntu — may work on other Debian-based distros"
fi

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${C}${B}"
cat << 'BANNER'
  ██████╗ ██╗    ██╗███╗   ██╗██████╗ ██████╗  ██████╗ ██╗  ██╗███████╗██████╗
  ██╔══██╗██║    ██║████╗  ██║██╔══██╗██╔══██╗██╔═══██╗██║ ██╔╝██╔════╝██╔══██╗
  ██████╔╝██║ █╗ ██║██╔██╗ ██║██████╔╝██████╔╝██║   ██║█████╔╝ █████╗  ██████╔╝
  ██╔═══╝ ██║███╗██║██║╚██╗██║██╔══██╗██╔══██╗██║   ██║██╔═██╗ ██╔══╝  ██╔══██╗
  ██║     ╚███╔███╔╝██║ ╚████║██████╔╝██║  ██║╚██████╔╝██║  ██╗███████╗██║  ██║
  ╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
BANNER
echo -e "${N}"
echo -e "  ${B}Security Operations Platform${N}  —  Ubuntu Server Setup"
echo ""
info "Install dir : $INSTALL_DIR"
info "Bind port   : $PORT (all interfaces)"
info "Service user: $SERVICE_USER"
echo ""

# =============================================================================
step "1 / 14 — System Packages"
# =============================================================================
info "Updating package lists..."
apt-get update -qq

PKGS=(
    python3 python3-pip python3-venv python3-dev
    nmap openssl libcap2-bin
    curl git ufw
    build-essential libssl-dev libffi-dev
    pkg-config libxml2-dev libxmlsec1-dev
    golang-go john
)
info "Installing: ${PKGS[*]}"
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${PKGS[@]}" -qq
ok "System packages installed"

# =============================================================================
step "2 / 14 — Service User"
# =============================================================================
if ! id "$SERVICE_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /bin/false \
            --comment "PwnBroker service account" "$SERVICE_USER"
    ok "System user '$SERVICE_USER' created"
else
    ok "User '$SERVICE_USER' already exists"
fi

# =============================================================================
step "3 / 14 — Application Files"
# =============================================================================
# $INSTALL_DIR is a live git checkout, not a one-time copy — updating the
# deployed app from here on is just: cd $INSTALL_DIR && git pull (as root,
# since that's who owns the checkout) && sudo systemctl restart pwnbroker.
# Re-running this whole script does the same fetch+reset plus everything else
# (deps, service file, etc.) in one step.
if [[ -d "$INSTALL_DIR/.git" ]]; then
    info "Existing git checkout found — updating to latest $BRANCH..."
    BEFORE=$(git -C "$INSTALL_DIR" rev-parse --short HEAD 2>/dev/null || echo "unknown")
    git -C "$INSTALL_DIR" fetch --quiet origin "$BRANCH"
    git -C "$INSTALL_DIR" reset --hard --quiet "origin/$BRANCH"
    AFTER=$(git -C "$INSTALL_DIR" rev-parse --short HEAD)
    ok "Updated $BEFORE → $AFTER"
elif [[ -e "$INSTALL_DIR" && -n "$(ls -A "$INSTALL_DIR" 2>/dev/null)" ]]; then
    die "$INSTALL_DIR exists and isn't a git checkout of this project — move it aside (or set INSTALL_DIR to a different path) before re-running."
else
    info "Cloning $REPO_URL ($BRANCH) → $INSTALL_DIR ..."
    mkdir -p "$(dirname "$INSTALL_DIR")"
    git clone --quiet --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
    ok "Cloned"
fi

# Persistent runtime directories
mkdir -p \
    "$INSTALL_DIR/data/ssl" \
    "$INSTALL_DIR/logs" \
    "$INSTALL_DIR/evidence_uploads"

# Fix ownership; keep code root-owned, only runtime dirs writable by service user.
# 755 on the root dir lets the pwnbroker service user traverse into it;
# sensitive files inside carry their own tighter permissions.
chown -R root:root "$INSTALL_DIR"
chown -R "$SERVICE_USER":"$SERVICE_USER" \
    "$INSTALL_DIR/data" \
    "$INSTALL_DIR/logs" \
    "$INSTALL_DIR/evidence_uploads"
chmod 755 "$INSTALL_DIR"
ok "Directory permissions set"

# =============================================================================
step "4 / 14 — Python Virtual Environment"
# =============================================================================
PY_VER=$(python3 --version 2>&1)
info "Using $PY_VER"

if [[ ! -d "$INSTALL_DIR/venv" ]]; then
    info "Creating virtual environment..."
    python3 -m venv "$INSTALL_DIR/venv"
fi

info "Installing Python dependencies (this may take a minute)..."
# python -m pip, not pip's own executable directly — pip's own recommended way
# to upgrade itself.
VENV_PY="$INSTALL_DIR/venv/bin/python3"
"$VENV_PY" -m pip install --upgrade pip setuptools wheel -q
"$VENV_PY" -m pip install gunicorn -q
"$VENV_PY" -m pip install -r "$INSTALL_DIR/requirements.txt" -q
chown -R "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR/venv"
ok "Virtual environment ready  ($("$INSTALL_DIR/venv/bin/python3" --version))"

# =============================================================================
step "5 / 14 — PEN Operational Scanner"
# =============================================================================
# PEN (github.com/ekomsSavior/PEN) has no releases/module path to `go install`
# directly — it has to be cloned and built from source, per its own README.
# Skip if already built so re-running setup.sh doesn't rebuild every time (same
# idempotency pattern as the venv/.env steps above).
PEN_DIR="$INSTALL_DIR/tools/pen"
if [[ -x "$PEN_DIR/pen" ]]; then
    ok "PEN already built at $PEN_DIR/pen"
else
    info "Cloning and building PEN..."
    mkdir -p "$(dirname "$PEN_DIR")"
    if [[ -d "$PEN_DIR" ]]; then
        rm -rf "$PEN_DIR"  # partial/failed build from a previous run
    fi
    if git clone --quiet https://github.com/ekomsSavior/PEN.git "$PEN_DIR" \
        && ( cd "$PEN_DIR" && { go mod init pen >/dev/null 2>&1 || true; } && go mod tidy && go build -o pen main.go ); then
        chmod 755 "$PEN_DIR/pen"
        ok "PEN built at $PEN_DIR/pen"
    else
        warn "PEN build failed — the 'pen' scan type will report itself unavailable until this is fixed"
        warn "Retry manually: cd $PEN_DIR && go mod tidy && go build -o pen main.go"
    fi
fi
warn "PEN's exploitation module can optionally crack hashes with john (installed above) and dump exposed git repos with git-dumper (pip install git-dumper, not installed automatically) — both are optional, PEN skips them gracefully if missing"

# =============================================================================
step "6 / 14 — REAPER Secret Scanner"
# =============================================================================
# REAPER (github.com/ekomsSavior/REAPER) ships its own go.mod/go.sum, so no
# `go mod init` step is needed here (unlike PEN). Note the build command is
# `go build -o reaper .` (the whole package) — reaper.go depends on symbols
# defined in detector.go, so `go build -o reaper reaper.go` (building only
# that one file) fails with "undefined: Detector" and similar errors.
REAPER_DIR="$INSTALL_DIR/tools/reaper"
if [[ -x "$REAPER_DIR/reaper" ]]; then
    ok "REAPER already built at $REAPER_DIR/reaper"
else
    info "Cloning and building REAPER..."
    mkdir -p "$(dirname "$REAPER_DIR")"
    if [[ -d "$REAPER_DIR" ]]; then
        rm -rf "$REAPER_DIR"  # partial/failed build from a previous run
    fi
    if git clone --quiet https://github.com/ekomsSavior/REAPER.git "$REAPER_DIR" \
        && ( cd "$REAPER_DIR" && go mod tidy && go build -o reaper . ); then
        chmod 755 "$REAPER_DIR/reaper"
        ok "REAPER built at $REAPER_DIR/reaper"
    else
        warn "REAPER build failed — the Secrets section will report itself unavailable until this is fixed"
        warn "Retry manually: cd $REAPER_DIR && go mod tidy && go build -o reaper ."
    fi
fi
warn "REAPER requires a GitHub token (Settings → Threat Intel APIs, repo + public_repo scopes) — scans return a 'token required' result until one is configured"

# =============================================================================
step "7 / 14 — Backdoor Detector"
# =============================================================================
# Backdoor Detector (github.com/ekomsSavior/backdoor_detector) is pure Python
# — no build step, just a clone-if-missing like PEN/REAPER's source checkout,
# minus the `go build`.
BACKDOOR_DIR="$INSTALL_DIR/tools/backdoor_detector"
if [[ -f "$BACKDOOR_DIR/backdoor_detector.py" ]]; then
    ok "Backdoor Detector already present at $BACKDOOR_DIR"
else
    info "Cloning Backdoor Detector..."
    mkdir -p "$(dirname "$BACKDOOR_DIR")"
    if [[ -d "$BACKDOOR_DIR" ]]; then
        rm -rf "$BACKDOOR_DIR"  # partial/failed clone from a previous run
    fi
    if git clone --quiet https://github.com/ekomsSavior/backdoor_detector.git "$BACKDOOR_DIR"; then
        ok "Backdoor Detector cloned to $BACKDOOR_DIR"
    else
        warn "Backdoor Detector clone failed — the 'backdoor' scan type will report itself unavailable until this is fixed"
        warn "Retry manually: git clone https://github.com/ekomsSavior/backdoor_detector.git $BACKDOOR_DIR"
    fi
fi

# Trivy (dependency-vulnerability sub-scanner used by Backdoor Detector's
# scan_for_vulnerabilities() phase) — pinned release, not the `main`-branch
# "latest" installer some docs suggest. Installed to /usr/local/bin, no sudo
# needed since this script already runs as root.
TRIVY_VERSION="v0.68.2"
if command -v trivy &>/dev/null; then
    ok "Trivy already installed ($(trivy --version 2>/dev/null | head -1))"
else
    info "Installing Trivy $TRIVY_VERSION..."
    if curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
        | sh -s -- -b /usr/local/bin "$TRIVY_VERSION" >/dev/null 2>&1; then
        ok "Trivy $TRIVY_VERSION installed to /usr/local/bin"
    else
        warn "Trivy install failed — Backdoor Detector's Trivy sub-scan will be skipped gracefully until this is fixed"
        warn "Retry manually: curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin $TRIVY_VERSION"
    fi
fi
warn "Backdoor Detector's npm-audit sub-scan needs Node.js/npm — not installed automatically (this project's stack doesn't otherwise need Node); install from nodejs.org if you want that sub-scan to run. Safety and pip-audit are already installed via requirements.txt."

# =============================================================================
step "8 / 14 — BloodHound CE (Active Directory attack-path analysis)"
# =============================================================================
# BloodHound CE's only supported self-hosted deployment is Docker Compose
# (Postgres + Neo4j + its own API/UI binary) — this is the first Docker
# dependency in an otherwise bare-metal/systemd app. Deliberately NOT adding
# the service user to the docker group: Docker group membership is
# root-equivalent, and PwnBroker's own backend only ever needs plain HTTP to
# localhost:8080 for its API calls, never the Docker socket. Docker's own
# daemon/restart-policy owns this stack's lifecycle independently of the
# pwnbroker systemd unit.
#
# PwnBroker itself is meant to run on a VM reached remotely, not on localhost
# — so BloodHound's own web UI (which an admin needs to reach at least once,
# to create the API token PwnBroker's backend uses) has to be reachable the
# same way, not just from the host it runs on. The official compose file
# ships BLOODHOUND_HOST=127.0.0.1 by default specifically to prevent
# "accidental" exposure (its own comment says so) — overridden below via the
# supported .env mechanism, deliberately for *only* the bloodhound app
# service. Neo4j's bolt/web ports (7687/7474) stay bound to 127.0.0.1 (hard-
# coded in the compose file, not something .env can override) and Postgres
# isn't published at all — neither has any auth boundary of its own besides
# "not reachable from the network," unlike the bloodhound app itself (own
# login + the HMAC-signed API token), so those two are deliberately left as
# loopback-only rather than opened up alongside it.
DOCKER_AVAILABLE=false
if command -v docker &>/dev/null; then
    ok "Docker already installed"
    DOCKER_AVAILABLE=true
else
    info "Installing Docker..."
    if apt-get install -y -qq docker.io docker-compose-plugin && systemctl enable --now docker; then
        ok "Docker installed and started"
        DOCKER_AVAILABLE=true
    else
        warn "Docker install failed — BloodHound CE won't be set up; the 'bloodhound' scan type"
        warn "will report itself unconfigured until this is fixed. Retry manually:"
        warn "  apt-get install -y docker.io docker-compose-plugin && systemctl enable --now docker"
    fi
fi

if [[ "$DOCKER_AVAILABLE" == true ]]; then
    BLOODHOUND_DIR="$INSTALL_DIR/docker/bloodhound"
    mkdir -p "$BLOODHOUND_DIR"
    if [[ -f "$BLOODHOUND_DIR/docker-compose.yml" ]]; then
        ok "BloodHound CE docker-compose.yml already present"
    else
        # Fetched fresh from SpecterOps rather than vendored in this repo — a
        # hand-copied version here would silently drift from whatever
        # image tags/env vars a future BloodHound CE release actually needs.
        # This is the same file their own quickstart's one-liner
        # (curl -L https://ghst.ly/getbhce | docker compose -f - up) uses.
        info "Fetching BloodHound CE's official docker-compose.yml..."
        if curl -sfL -o "$BLOODHOUND_DIR/docker-compose.yml" \
            https://raw.githubusercontent.com/SpecterOps/BloodHound/main/examples/docker-compose/docker-compose.yml; then
            ok "Saved to $BLOODHOUND_DIR/docker-compose.yml"
        else
            warn "Could not fetch BloodHound CE's docker-compose.yml — the 'bloodhound' scan type"
            warn "will report itself unconfigured until this is set up manually. See docs/deployment.md."
        fi
    fi

    if [[ ! -f "$BLOODHOUND_DIR/.env" ]]; then
        info "Generating BloodHound CE .env (binds its UI to all interfaces, randomizes DB passwords)..."
        PG_PASS=$("$INSTALL_DIR/venv/bin/python3" -c "import secrets; print(secrets.token_hex(32))")
        NEO4J_PASS=$("$INSTALL_DIR/venv/bin/python3" -c "import secrets; print(secrets.token_hex(32))")
        cat > "$BLOODHOUND_DIR/.env" << EOF
# Binds the bloodhound app's UI/API to all interfaces — PwnBroker itself runs
# remotely (not on localhost), and an admin needs to reach this at least once
# to create the API token PwnBroker's backend uses. Neo4j/Postgres are
# deliberately NOT overridden here — see the comment above this block in
# setup.sh for why they stay loopback-only.
BLOODHOUND_HOST=0.0.0.0
POSTGRES_PASSWORD=$PG_PASS
NEO4J_SECRET=$NEO4J_PASS
EOF
        ok "$BLOODHOUND_DIR/.env created"
    else
        ok "BloodHound CE .env already exists — existing config preserved"
    fi
    # root:root 600, not the app's own root:pwnbroker 640 convention — this
    # .env is only ever read by `docker compose` (run as root, here and by
    # hand), never by the pwnbroker service user's own process, which has no
    # reason to see these DB passwords.
    chmod 600 "$BLOODHOUND_DIR/.env"
    chown root:root "$BLOODHOUND_DIR/.env"

    if [[ -f "$BLOODHOUND_DIR/docker-compose.yml" ]]; then
        info "Starting BloodHound CE (Postgres + Neo4j + API/UI)..."
        if (cd "$BLOODHOUND_DIR" && docker compose pull -q && docker compose up -d); then
            ok "BloodHound CE containers started — UI/API on port 8080 on all interfaces"
            warn "One-time manual step required: BloodHound prints a randomly-generated"
            warn "initial admin password to its logs on first boot. Run:"
            warn "  cd $BLOODHOUND_DIR && docker compose logs bloodhound | grep -i 'initial password'"
            warn "Log into http://<this-host>:8080, change that password, then go to"
            warn "My Profile -> API Tokens -> Create Token and paste the Token ID/Key into"
            warn "PwnBroker's Settings -> BloodHound CE. This can't be scripted — it needs"
            warn "an authenticated UI session. See docs/deployment.md for details."
        else
            warn "BloodHound CE containers failed to start — check 'docker compose logs' in $BLOODHOUND_DIR"
        fi
    fi
fi

# =============================================================================
step "9 / 14 — nmap Raw-Socket Capability"
# =============================================================================
# nmap needs CAP_NET_RAW for OS fingerprinting (-O) and CAP_NET_ADMIN for some
# scan types.  setcap grants these to the nmap binary so the service user
# can run OS-detection scans without running the whole process as root.
NMAP_BIN=$(command -v nmap)
info "nmap binary: $NMAP_BIN"
if setcap cap_net_raw+eip,cap_net_admin+eip "$NMAP_BIN" 2>/dev/null; then
    ok "Capabilities set on nmap — OS detection works as '$SERVICE_USER'"
else
    warn "setcap failed — OS detection scans (-O) may not work"
    warn "Fix later: sudo setcap cap_net_raw+eip,cap_net_admin+eip $NMAP_BIN"
fi

# =============================================================================
step "10 / 14 — TLS Certificate"
# =============================================================================
CERT="$INSTALL_DIR/data/ssl/cert.pem"
KEY="$INSTALL_DIR/data/ssl/key.pem"
if [[ ! -f "$CERT" || ! -f "$KEY" ]]; then
    FQDN=$(hostname -f 2>/dev/null || hostname)
    LOCAL_IP=$(hostname -I | awk '{print $1}')
    info "Generating self-signed TLS certificate..."
    info "  CN=$FQDN  SAN=DNS:$FQDN,DNS:localhost,IP:$LOCAL_IP,IP:127.0.0.1"
    openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
        -keyout "$KEY" -out "$CERT" \
        -subj "/CN=$FQDN/O=PwnBroker/C=US" \
        -addext "subjectAltName=DNS:$FQDN,DNS:localhost,IP:$LOCAL_IP,IP:127.0.0.1" \
        2>/dev/null
    chmod 600 "$KEY"
    chown "$SERVICE_USER":"$SERVICE_USER" "$CERT" "$KEY"
    ok "Self-signed certificate created (valid 10 years)"
    warn "Replace with a CA-signed cert via Settings → HTTPS / TLS for production"
else
    ok "TLS certificate already present — skipping generation"
fi

# =============================================================================
step "11 / 14 — Environment File"
# =============================================================================
ENV_FILE="$INSTALL_DIR/.env"
if [[ ! -f "$ENV_FILE" ]]; then
    info "Generating .env with random secret key..."
    SECRET=$("$INSTALL_DIR/venv/bin/python3" \
        -c "import secrets; print(secrets.token_hex(32))")
    cat > "$ENV_FILE" << EOF
SECRET_KEY=$SECRET
DATABASE_URL=sqlite:///$INSTALL_DIR/data/scanner.db

# NVD API key — optional, speeds up CVE lookups (5 req/30s without, 50 with)
# Get one free at https://nvd.nist.gov/developers/request-an-api-key
NVD_API_KEY=

# SMTP — can also be configured in the web UI under Settings → Email
MAIL_SERVER=
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USERNAME=
MAIL_PASSWORD=
MAIL_DEFAULT_SENDER=
EOF
    ok ".env created with random SECRET_KEY"
else
    # Ensure DATABASE_URL uses an absolute path (not relative to CWD)
    if grep -q "sqlite:///data/" "$ENV_FILE" 2>/dev/null; then
        sed -i "s|sqlite:///data/|sqlite:///$INSTALL_DIR/data/|g" "$ENV_FILE"
        info "Updated DATABASE_URL to absolute path"
    fi
    ok ".env already exists — existing config preserved"
fi
# Re-assert ownership/permissions every run, not just at creation — step 3's
# blanket "chown -R root:root $INSTALL_DIR" resets .env to root:root on every
# re-run (it lives outside data/, the only root-level dir chown'd to the
# service user), which otherwise silently breaks the service on next restart
# with "[Errno 13] Permission denied: '.env'". This is what makes re-running
# setup.sh to "repair an existing installation" actually idempotent for it.
chmod 640 "$ENV_FILE"
chown root:"$SERVICE_USER" "$ENV_FILE"

# =============================================================================
step "12 / 14 — Systemd Service"
# =============================================================================
# One worker, multiple threads — not scaled by CPU count. APScheduler's
# background jobs (scan checks, report sends, the Palo Alto poller) and the
# login rate limiter both run in-process / in-memory; more than one worker
# means every scheduled job fires once per worker (duplicate scans, duplicate
# report emails) and the rate limiter under-counts. See docs/deployment.md.
info "Workers: 1  ·  Threads: $WEB_THREADS  ·  Binding: 0.0.0.0:$PORT"

cat > "$SERVICE_FILE" << EOF
[Unit]
Description=PwnBroker Security Operations Platform
Documentation=https://github.com/ChimneyFish/PWNBroker
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$ENV_FILE

# Binding port 443 (or any port < 1024) as the unprivileged $SERVICE_USER
# needs this — it's the systemd equivalent of the setcap grant already used
# for nmap below, scoped to exactly the one capability needed instead of
# running the whole service as root.
#
# CAP_NET_RAW/CAP_NET_ADMIN are also listed in the bounding set (but not
# granted ambiently) so the nmap subprocess spawned by this service can
# actually use the file capabilities step 5 sets on the nmap binary itself.
# CapabilityBoundingSet is a ceiling, not a grant — without these two here,
# nmap's setcap capabilities get silently stripped at exec time no matter
# what step 5 does, and -O (OS detection) fails under systemd even though
# `setcap` reported success and manual runs outside the service work fine.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN

ExecStart=$INSTALL_DIR/venv/bin/gunicorn \\
    --bind 0.0.0.0:$PORT \\
    --workers 1 \\
    --threads $WEB_THREADS \\
    --worker-class gthread \\
    --timeout 120 \\
    --keep-alive 5 \\
    --certfile  $INSTALL_DIR/data/ssl/cert.pem \\
    --keyfile   $INSTALL_DIR/data/ssl/key.pem \\
    --access-logfile $INSTALL_DIR/logs/access.log \\
    --error-logfile  $INSTALL_DIR/logs/error.log \\
    --log-level info \\
    "app:create_app()"

# Graceful reload on SIGHUP (zero-downtime worker restart)
ExecReload=/bin/kill -s HUP \$MAINPID

Restart=on-failure
RestartSec=5
StartLimitIntervalSec=60
StartLimitBurst=3

# ── Sandboxing ────────────────────────────────────────────────────────────────
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=$INSTALL_DIR/data $INSTALL_DIR/logs $INSTALL_DIR/evidence_uploads /tmp
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable pwnbroker
ok "Unit file written: $SERVICE_FILE"
ok "Service enabled for autostart on boot"

# =============================================================================
step "13 / 14 — Log Rotation"
# =============================================================================
cat > /etc/logrotate.d/pwnbroker << EOF
$INSTALL_DIR/logs/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 640 $SERVICE_USER $SERVICE_USER
    postrotate
        systemctl reload pwnbroker 2>/dev/null || true
    endscript
}
EOF
ok "Logrotate config installed (/etc/logrotate.d/pwnbroker)"

# =============================================================================
step "14 / 14 — Firewall & Service Start"
# =============================================================================
# Firewall
if command -v ufw &>/dev/null; then
    ufw allow "$PORT/tcp" comment "PwnBroker HTTPS" > /dev/null 2>&1 || true
    if ufw status 2>/dev/null | grep -q "Status: active"; then
        ok "ufw: port $PORT/tcp rule active"
    else
        warn "ufw is installed but inactive"
        warn "To enable: sudo ufw allow ssh && sudo ufw allow $PORT/tcp && sudo ufw enable"
    fi
else
    warn "ufw not found — open port $PORT/tcp in your firewall or cloud security group"
fi

# Start / restart service
info "Starting PwnBroker..."
systemctl restart pwnbroker
sleep 4

if systemctl is-active --quiet pwnbroker; then
    PID=$(systemctl show -p MainPID --value pwnbroker)
    ok "PwnBroker is running  (PID $PID)"
else
    echo ""
    warn "Service failed to start. Last 30 log lines:"
    journalctl -u pwnbroker -n 30 --no-pager
    die "Fix the error above, then: sudo systemctl start pwnbroker"
fi

# =============================================================================
# Done
# =============================================================================
LOCAL_IP=$(hostname -I | awk '{print $1}')
echo ""
echo -e "${G}${B}╔══════════════════════════════════════════════════════╗${N}"
echo -e "${G}${B}║             PwnBroker is ready!                      ║${N}"
echo -e "${G}${B}╚══════════════════════════════════════════════════════╝${N}"
echo ""
printf "  ${B}%-18s${N}%s\n"  "Access URL:"      "https://$LOCAL_IP:$PORT"
printf "  ${B}%-18s${N}%s\n"  "Default login:"   "admin / admin"
printf "  ${B}%-18s${N}%s\n"  "Install dir:"     "$INSTALL_DIR"
printf "  ${B}%-18s${N}%s\n"  "Environment:"     "$ENV_FILE"
printf "  ${B}%-18s${N}%s\n"  "App logs:"        "$INSTALL_DIR/logs/"
printf "  ${B}%-18s${N}%s\n"  "System logs:"     "journalctl -u pwnbroker -f"
echo ""
echo -e "  ${B}Service management:${N}"
echo "    sudo systemctl start   pwnbroker"
echo "    sudo systemctl stop    pwnbroker"
echo "    sudo systemctl restart pwnbroker"
echo "    sudo systemctl reload  pwnbroker   # zero-downtime worker reload"
echo "    sudo systemctl status  pwnbroker"
echo ""
echo -e "  ${B}To update to the latest code:${N}"
echo "    sudo bash setup.sh                          # re-run this script, or"
echo "    cd $INSTALL_DIR && sudo git pull && sudo systemctl restart pwnbroker"
echo ""
echo -e "  ${Y}${B}Action required:${N}"
echo -e "  ${Y}►${N} Change the default admin password immediately after first login"
echo -e "  ${Y}►${N} TLS cert is self-signed — browser will show a security warning"
echo -e "  ${Y}►${N} Upload a CA-signed cert:  Settings → HTTPS / TLS"
echo -e "  ${Y}►${N} Set your timezone:        Settings → Time & NTP"
echo ""
