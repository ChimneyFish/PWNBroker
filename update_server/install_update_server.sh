#!/usr/bin/env bash
# PWNBroker update server installer. Run this ON the update server, as root.
#
# From your dev machine, copy this folder and your license PUBLIC key over:
#   scp -r update_server ~/.pwnbroker-license/public_key.pem root@pwnbroker.space:/root/
# Then on the server:
#   sudo bash /root/update_server/install_update_server.sh --email you@example.com
#
# Options:
#   --domain NAME     hostname customers use              (default pwnbroker.space)
#   --port N          HTTPS port                          (default 7585)
#   --email ADDR      Let's Encrypt account email         (recommended)
#   --pubkey PATH     license public key                  (default: public_key.pem next to
#                     this folder, or already-installed one)
#   --self-signed     skip Let's Encrypt (testing only; customers then need PWNBROKER_UPDATE_CA)
#   --no-firewall     don't touch ufw/firewalld
#
# Safe to re-run: it updates the server code and restarts the service, and
# keeps releases, check-ins, yanked/revoked lists and the token secret.
set -euo pipefail

DOMAIN="pwnbroker.space"
PORT=7585
PREFIX="/updates"
EMAIL=""
PUBKEY=""
SELF_SIGNED=0
FIREWALL=1

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="/opt/pwnbroker-update-server"
DATA_DIR="/srv/pwnbroker-updates"
SVC_USER="pwnupdates"
SERVICE="pwnbroker-update-server"

info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m ✓\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m !\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m ✗ %s\033[0m\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain)      DOMAIN="$2"; shift 2 ;;
        --port)        PORT="$2"; shift 2 ;;
        --email)       EMAIL="$2"; shift 2 ;;
        --pubkey)      PUBKEY="$2"; shift 2 ;;
        --self-signed) SELF_SIGNED=1; shift ;;
        --no-firewall) FIREWALL=0; shift ;;
        -h|--help)     sed -n '2,19p' "$0"; exit 0 ;;
        *) die "Unknown option: $1 (see --help)" ;;
    esac
done

[[ $EUID -eq 0 ]] || die "Run as root (sudo bash $0)"
[[ -f "$SRC_DIR/server.py" && -f "$SRC_DIR/requirements.txt" ]] \
    || die "server.py / requirements.txt not found next to this script ($SRC_DIR)"
[[ "$PORT" =~ ^[0-9]+$ ]] || die "Bad --port: $PORT"

# ── 1. packages ──────────────────────────────────────────────────────────────
info "Installing system packages"
if command -v apt-get >/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq python3 python3-venv python3-pip rsync curl sqlite3 openssl certbot >/dev/null
elif command -v dnf >/dev/null; then
    dnf install -y -q python3 python3-pip rsync curl sqlite openssl >/dev/null
    dnf install -y -q certbot >/dev/null 2>&1 || { dnf install -y -q epel-release >/dev/null && dnf install -y -q certbot >/dev/null; }
else
    die "Unsupported distro (need apt or dnf)"
fi
ok "Packages installed"

# ── 2. user and folders ──────────────────────────────────────────────────────
info "Creating service user and folders"
id "$SVC_USER" >/dev/null 2>&1 || useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin "$SVC_USER"
mkdir -p "$DATA_DIR/releases" "$DATA_DIR/ssl" "$APP_DIR"
touch "$DATA_DIR/yanked.txt" "$DATA_DIR/revoked.txt"
ok "$DATA_DIR"

# ── 3. server code + venv ────────────────────────────────────────────────────
info "Installing server code to $APP_DIR"
install -m 644 "$SRC_DIR/server.py" "$SRC_DIR/requirements.txt" "$APP_DIR/"
[[ -x "$APP_DIR/venv/bin/python" ]] || python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install -q --upgrade pip
"$APP_DIR/venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"
ok "Python environment ready"

# ── 4. license public key ────────────────────────────────────────────────────
info "Installing license public key"
if [[ -z "$PUBKEY" ]]; then
    for c in "$SRC_DIR/../public_key.pem" "$SRC_DIR/public_key.pem" "$SRC_DIR/license_public_key.pem"; do
        [[ -f "$c" ]] && { PUBKEY="$c"; break; }
    done
fi
if [[ -n "$PUBKEY" ]]; then
    grep -q "PRIVATE KEY" "$PUBKEY" && die "$PUBKEY is a PRIVATE key — never put that on the update server. Use public_key.pem."
    "$APP_DIR/venv/bin/python" - "$PUBKEY" <<'PY' || die "$PUBKEY is not a valid Ed25519 public key"
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
k = serialization.load_pem_public_key(open(sys.argv[1], "rb").read())
sys.exit(0 if isinstance(k, Ed25519PublicKey) else 1)
PY
    install -m 644 "$PUBKEY" "$DATA_DIR/license_public_key.pem"
    ok "Using $PUBKEY"
elif [[ -f "$DATA_DIR/license_public_key.pem" ]]; then
    ok "Keeping existing $DATA_DIR/license_public_key.pem"
else
    die "No license public key. Copy ~/.pwnbroker-license/public_key.pem here and pass --pubkey PATH."
fi

# ── 5. TLS certificate ───────────────────────────────────────────────────────
HOOK=/etc/letsencrypt/renewal-hooks/deploy/pwnbroker-updates.sh
if [[ $SELF_SIGNED -eq 1 ]]; then
    info "Creating a self-signed certificate (testing only)"
    if [[ ! -f "$DATA_DIR/ssl/cert.pem" ]]; then
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 825 -subj "/CN=$DOMAIN" \
            -addext "subjectAltName=DNS:$DOMAIN" \
            -keyout "$DATA_DIR/ssl/key.pem" -out "$DATA_DIR/ssl/cert.pem" 2>/dev/null
    fi
    ok "$DATA_DIR/ssl/cert.pem — customers must set PWNBROKER_UPDATE_CA to a copy of it"
else
    info "Getting a Let's Encrypt certificate for $DOMAIN"
    ip=$(getent ahostsv4 "$DOMAIN" | awk 'NR==1{print $1}')
    [[ -n "$ip" ]] || die "$DOMAIN doesn't resolve yet. Point its A record at this server and re-run (or use --self-signed to test)."
    ok "$DOMAIN resolves to $ip"

    # Copies the cert where the service user can read it, then restarts.
    mkdir -p "$(dirname "$HOOK")"
    cat > "$HOOK" <<EOF
#!/bin/sh
# Installed by install_update_server.sh — copies the renewed cert for the update server.
set -e
LIVE=/etc/letsencrypt/live/$DOMAIN
[ -d "\$LIVE" ] || exit 0
install -m 644 -o $SVC_USER -g $SVC_USER "\$LIVE/fullchain.pem" $DATA_DIR/ssl/cert.pem
install -m 600 -o $SVC_USER -g $SVC_USER "\$LIVE/privkey.pem"   $DATA_DIR/ssl/key.pem
systemctl try-restart $SERVICE || true
EOF
    chmod 755 "$HOOK"

    if [[ ! -d "/etc/letsencrypt/live/$DOMAIN" ]]; then
        if ss -ltn 'sport = :80' | grep -q LISTEN; then
            die "Something is already listening on port 80, so certbot can't verify $DOMAIN.
   Stop it and re-run, or get the cert yourself and put fullchain/privkey at
   $DATA_DIR/ssl/cert.pem and key.pem, then re-run with --self-signed (it keeps existing certs)."
        fi
        [[ $FIREWALL -eq 1 ]] && command -v ufw >/dev/null && ufw status | grep -q "Status: active" && ufw allow 80/tcp >/dev/null
        if [[ $FIREWALL -eq 1 ]] && command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
            firewall-cmd --permanent --add-service=http >/dev/null; firewall-cmd --reload >/dev/null
        fi
        email_args=(--register-unsafely-without-email)
        [[ -n "$EMAIL" ]] && email_args=(-m "$EMAIL")
        certbot certonly --standalone --non-interactive --agree-tos "${email_args[@]}" \
            -d "$DOMAIN" --deploy-hook "$HOOK" \
            || die "certbot failed. Check that $DOMAIN points here and port 80 is reachable from the internet."
    fi
    sh "$HOOK"
    systemctl enable --now certbot.timer >/dev/null 2>&1 || true
    ok "Certificate installed; it renews automatically (port 80 must stay reachable for renewals)"
fi

chown -R "$SVC_USER:$SVC_USER" "$DATA_DIR"
chmod 750 "$DATA_DIR"
chmod 600 "$DATA_DIR/ssl/key.pem"
# Releases are uploaded as root by build_release.py publish; the service only reads them.
chmod 755 "$DATA_DIR/releases"

# ── 6. systemd service ───────────────────────────────────────────────────────
info "Installing systemd service"
cat > "/etc/systemd/system/$SERVICE.service" <<EOF
[Unit]
Description=PWNBroker update server (https://$DOMAIN:$PORT$PREFIX)
After=network-online.target
Wants=network-online.target

[Service]
User=$SVC_USER
Group=$SVC_USER
WorkingDirectory=$APP_DIR
Environment=PWNUPD_ROOT=$DATA_DIR
Environment=PWNUPD_LICENSE_PUBKEY=$DATA_DIR/license_public_key.pem
Environment=PWNUPD_PREFIX=$PREFIX
ExecStart=$APP_DIR/venv/bin/gunicorn \\
    --bind 0.0.0.0:$PORT --workers 2 --threads 4 --timeout 300 \\
    --certfile $DATA_DIR/ssl/cert.pem --keyfile $DATA_DIR/ssl/key.pem \\
    --access-logfile - "server:create_app()"
Restart=on-failure
RestartSec=3

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA_DIR

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null 2>&1
systemctl restart "$SERVICE"
ok "$SERVICE running"

# ── 7. firewall ──────────────────────────────────────────────────────────────
if [[ $FIREWALL -eq 1 ]]; then
    if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
        ufw allow "$PORT/tcp" >/dev/null; ok "ufw: opened $PORT/tcp"
    elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port="$PORT/tcp" >/dev/null; firewall-cmd --reload >/dev/null
        ok "firewalld: opened $PORT/tcp"
    else
        warn "No active ufw/firewalld — make sure $PORT/tcp is open in any cloud firewall."
    fi
fi

# ── 8. health check ──────────────────────────────────────────────────────────
info "Checking the server"
curl_tls=()
[[ $SELF_SIGNED -eq 1 ]] && curl_tls=(-k)
healthy=0
for _ in $(seq 1 15); do
    if curl -fsS "${curl_tls[@]}" --resolve "$DOMAIN:$PORT:127.0.0.1" \
            "https://$DOMAIN:$PORT$PREFIX/v1/health" 2>/dev/null | grep -q '"ok"'; then
        healthy=1; break
    fi
    sleep 1
done
[[ $healthy -eq 1 ]] || die "Health check failed — see: journalctl -u $SERVICE -n 50"
ok "https://$DOMAIN:$PORT$PREFIX/v1/health is answering"

n=$(find "$DATA_DIR/releases" -mindepth 2 -maxdepth 2 -name manifest.sig 2>/dev/null | wc -l)
cat <<EOF

$(printf '\033[1;32m')PWNBroker update server is ready.$(printf '\033[0m')

  Customer update URL   https://$DOMAIN:$PORT$PREFIX
  Published releases    $n  (in $DATA_DIR/releases/)

  Publish a release (from your dev machine):
    python tools/release/build_release.py build --bump minor --notes "..."
    python tools/release/build_release.py publish X.Y.Z root@$DOMAIN:$DATA_DIR/releases/

  Pull a bad release:    echo X.Y.Z >> $DATA_DIR/yanked.txt
  Cut off a license:     echo <license id> >> $DATA_DIR/revoked.txt
  Who's on what:         sqlite3 $DATA_DIR/checkins.db "select customer, version, last_seen from checkins"
  Logs:                  journalctl -u $SERVICE -f
  Update server code:    copy the new update_server/ folder over and re-run this script
EOF
