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
PORT="${PORT:-5000}"
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
step "1 / 10 — System Packages"
# =============================================================================
info "Updating package lists..."
apt-get update -qq

PKGS=(
    python3 python3-pip python3-venv python3-dev
    nmap openssl libcap2-bin
    curl git ufw
    build-essential libssl-dev libffi-dev
)
info "Installing: ${PKGS[*]}"
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${PKGS[@]}" -qq
ok "System packages installed"

# =============================================================================
step "2 / 10 — Service User"
# =============================================================================
if ! id "$SERVICE_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /bin/false \
            --comment "PwnBroker service account" "$SERVICE_USER"
    ok "System user '$SERVICE_USER' created"
else
    ok "User '$SERVICE_USER' already exists"
fi

# =============================================================================
step "3 / 10 — Application Files"
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
step "4 / 10 — Python Virtual Environment"
# =============================================================================
PY_VER=$(python3 --version 2>&1)
info "Using $PY_VER"

if [[ ! -d "$INSTALL_DIR/venv" ]]; then
    info "Creating virtual environment..."
    python3 -m venv "$INSTALL_DIR/venv"
fi

info "Installing Python dependencies (this may take a minute)..."
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip setuptools wheel -q
"$INSTALL_DIR/venv/bin/pip" install gunicorn -q
"$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt" -q
chown -R "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR/venv"
ok "Virtual environment ready  ($("$INSTALL_DIR/venv/bin/python3" --version))"

# =============================================================================
step "5 / 10 — nmap Raw-Socket Capability"
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
step "6 / 10 — TLS Certificate"
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
step "7 / 10 — Environment File"
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
    chmod 640 "$ENV_FILE"
    chown root:"$SERVICE_USER" "$ENV_FILE"
    ok ".env created with random SECRET_KEY"
else
    # Ensure DATABASE_URL uses an absolute path (not relative to CWD)
    if grep -q "sqlite:///data/" "$ENV_FILE" 2>/dev/null; then
        sed -i "s|sqlite:///data/|sqlite:///$INSTALL_DIR/data/|g" "$ENV_FILE"
        info "Updated DATABASE_URL to absolute path"
    fi
    ok ".env already exists — existing config preserved"
fi

# =============================================================================
step "8 / 10 — Systemd Service"
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
step "9 / 10 — Log Rotation"
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
step "10 / 10 — Firewall & Service Start"
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
