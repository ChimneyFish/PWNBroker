#!/usr/bin/env bash
# PWNBroker update server installer. Run this ON the update server, as root.
#
# From your dev machine, copy this folder and your license PUBLIC key over:
#   scp -r update_server ~/.pwnbroker-license/public_key.pem root@pwnbroker.space:/root/
# Then run it (interactive — it asks for your SSL Manager token, so keep -t):
#   ssh -t root@pwnbroker.space bash /root/update_server/install_update_server.sh
#
# Options:
#   --domain NAME      hostname customers use                 (default pwnbroker.space)
#   --port N           HTTPS port customers connect to        (default 7585)
#   --ssl MODE         spaceship    Spaceship SSL Manager — your signed cert (default)
#                      letsencrypt  free Let's Encrypt cert via certbot
#                      self-signed  testing only; customers then need PWNBROKER_UPDATE_CA
#   --email ADDR       Let's Encrypt account email (letsencrypt mode)
#   --pubkey PATH      license public key (default: public_key.pem next to this
#                      folder, or the one already installed)
#   --no-firewall      don't touch ufw/firewalld
#
# Layout:  customers ──https :PORT──▶ nginx ──http 127.0.0.1:APP_PORT──▶ gunicorn
#          nginx also serves :80 for certificate domain validation.
#
# Safe to re-run: it updates the server code and restarts the service, and
# keeps releases, check-ins, yanked/revoked lists, the token secret and certs.
set -euo pipefail

DOMAIN="pwnbroker.space"
PORT=7585
APP_PORT=7586
PREFIX="/updates"
SSL_MODE="spaceship"
EMAIL=""
PUBKEY=""
FIREWALL=1

SSL_MANAGER_INSTALLER="https://ssl-manager.s3.amazonaws.com/external/sh/installer.sh"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="/opt/pwnbroker-update-server"
DATA_DIR="/srv/pwnbroker-updates"
WEBROOT="/var/www/pwnbroker-updates"
SVC_USER="pwnupdates"
SERVICE="pwnbroker-update-server"
CERTSYNC="/usr/local/sbin/pwnbroker-updates-certsync"
SNIPPET="/etc/nginx/pwnbroker-updates-cert.conf"
SITE_HTTP="/etc/nginx/conf.d/pwnbroker-updates-http.conf"
SITE_TLS="/etc/nginx/conf.d/pwnbroker-updates-tls.conf"

info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m ✓\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m !\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m ✗ %s\033[0m\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain)      DOMAIN="$2"; shift 2 ;;
        --port)        PORT="$2"; shift 2 ;;
        --ssl)         SSL_MODE="$2"; shift 2 ;;
        --self-signed) SSL_MODE="self-signed"; shift ;;
        --email)       EMAIL="$2"; shift 2 ;;
        --pubkey)      PUBKEY="$2"; shift 2 ;;
        --no-firewall) FIREWALL=0; shift ;;
        -h|--help)     sed -n '2,24p' "$0"; exit 0 ;;
        *) die "Unknown option: $1 (see --help)" ;;
    esac
done

[[ $EUID -eq 0 ]] || die "Run as root (sudo bash $0)"
[[ -f "$SRC_DIR/server.py" && -f "$SRC_DIR/requirements.txt" ]] \
    || die "server.py / requirements.txt not found next to this script ($SRC_DIR)"
[[ "$PORT" =~ ^[0-9]+$ && "$PORT" != "$APP_PORT" && "$PORT" != 80 ]] || die "Bad --port: $PORT"
[[ "$DOMAIN" =~ ^[A-Za-z0-9.-]+$ ]] || die "Bad --domain: $DOMAIN"
case "$SSL_MODE" in spaceship|letsencrypt|self-signed) ;; *) die "Bad --ssl: $SSL_MODE" ;; esac

open_port() {   # open_port 80
    [[ $FIREWALL -eq 1 ]] || return 0
    if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
        ufw allow "$1/tcp" >/dev/null && ok "ufw: opened $1/tcp"
    elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port="$1/tcp" >/dev/null && firewall-cmd --reload >/dev/null \
            && ok "firewalld: opened $1/tcp"
    fi
}

# ── 1. packages ──────────────────────────────────────────────────────────────
info "Installing system packages"
pkgs_apt=(python3 python3-venv python3-pip rsync curl sqlite3 openssl nginx)
pkgs_dnf=(python3 python3-pip rsync curl sqlite openssl nginx)
[[ $SSL_MODE == letsencrypt ]] && { pkgs_apt+=(certbot); pkgs_dnf+=(certbot); }
if command -v apt-get >/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq "${pkgs_apt[@]}" >/dev/null
elif command -v dnf >/dev/null; then
    dnf install -y -q "${pkgs_dnf[@]}" >/dev/null 2>&1 \
        || { dnf install -y -q epel-release >/dev/null && dnf install -y -q "${pkgs_dnf[@]}" >/dev/null; }
else
    die "Unsupported distro (need apt or dnf)"
fi
if command -v apache2 >/dev/null || command -v httpd >/dev/null; then
    warn "Apache is installed too. Make sure it isn't using port 80 — nginx needs it."
fi
ok "Packages installed"

# ── 2. user and folders ──────────────────────────────────────────────────────
info "Creating service user and folders"
id "$SVC_USER" >/dev/null 2>&1 || useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin "$SVC_USER"
mkdir -p "$DATA_DIR/releases" "$DATA_DIR/ssl" "$APP_DIR" "$WEBROOT/.well-known"
touch "$DATA_DIR/yanked.txt" "$DATA_DIR/revoked.txt"
chown -R "$SVC_USER:$SVC_USER" "$DATA_DIR"
chmod 750 "$DATA_DIR"; chmod 700 "$DATA_DIR/ssl"
chmod 755 "$DATA_DIR/releases"   # publish uploads as root; the service only reads
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
    install -m 644 -o "$SVC_USER" -g "$SVC_USER" "$PUBKEY" "$DATA_DIR/license_public_key.pem"
    ok "Using $PUBKEY"
elif [[ -f "$DATA_DIR/license_public_key.pem" ]]; then
    ok "Keeping existing $DATA_DIR/license_public_key.pem"
else
    die "No license public key. Copy ~/.pwnbroker-license/public_key.pem here and pass --pubkey PATH."
fi

# ── 5. app service (localhost only; nginx terminates TLS) ────────────────────
info "Installing $SERVICE service"
cat > "/etc/systemd/system/$SERVICE.service" <<EOF
[Unit]
Description=PWNBroker update server (https://$DOMAIN:$PORT$PREFIX via nginx)
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
    --bind 127.0.0.1:$APP_PORT --workers 2 --threads 4 --timeout 300 \\
    --forwarded-allow-ips 127.0.0.1 --access-logfile - "server:create_app()"
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
ok "$SERVICE listening on 127.0.0.1:$APP_PORT"

# ── 6. nginx: port 80 for domain validation ──────────────────────────────────
info "Configuring nginx"
# Debian's default site also claims port 80 as default_server; ours must win for $DOMAIN.
cat > "$SITE_HTTP" <<EOF
# PWNBroker update server — HTTP, used only for certificate domain validation.
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    root $WEBROOT;
    location /.well-known/ { try_files \$uri =404; }
    location / { return 404; }
}
EOF
# Port $PORT block is written by the cert sync once a certificate exists.
cat > "$CERTSYNC" <<EOF
#!/usr/bin/env python3
"""Point nginx's port-$PORT site at the current certificate for $DOMAIN.
Installed by install_update_server.sh; runs daily and after cert changes.
Looks for the cert in this order:
  1. a server block for $DOMAIN that has ssl_certificate (Spaceship SSL Manager
     installs the cert into nginx this way)
  2. /etc/letsencrypt/live/$DOMAIN/
  3. $DATA_DIR/ssl/{cert,key}.pem  (self-signed, or a cert you placed by hand)
"""
import os, re, subprocess, sys
DOMAIN, PORT, APP_PORT, PREFIX = "$DOMAIN", "$PORT", "$APP_PORT", "$PREFIX"
SNIPPET, SITE_TLS, DATA_DIR = "$SNIPPET", "$SITE_TLS", "$DATA_DIR"

def server_blocks(text):
    i = 0
    while True:
        m = re.search(r"(^|[\s;}])server\s*\{", text[i:])
        if not m:
            return
        start = i + m.end(); depth = 1; j = start
        while j < len(text) and depth:
            depth += {"{": 1, "}": -1}.get(text[j], 0); j += 1
        yield text[start:j - 1]; i = j

def from_nginx():
    try:
        conf = subprocess.run(["nginx", "-T"], capture_output=True, text=True).stdout
    except FileNotFoundError:
        return None
    conf = re.sub(r"#[^\n]*", "", conf)
    for b in server_blocks(conf):
        names = re.findall(r"server_name\s+([^;]+);", b)
        if not any(DOMAIN in n.split() for n in names):
            continue
        c = re.search(r"\bssl_certificate\s+([^;\s]+)\s*;", b)
        k = re.search(r"\bssl_certificate_key\s+([^;\s]+)\s*;", b)
        if c and k and c.group(1) != SNIPPET:
            return c.group(1).strip("'\""), k.group(1).strip("'\"")
    return None

def find_cert():
    for cand in (from_nginx(),
                 (f"/etc/letsencrypt/live/{DOMAIN}/fullchain.pem", f"/etc/letsencrypt/live/{DOMAIN}/privkey.pem"),
                 (f"{DATA_DIR}/ssl/cert.pem", f"{DATA_DIR}/ssl/key.pem")):
        if cand and all(os.path.exists(p) for p in cand):
            return cand
    return None

def write_if_changed(path, text):
    old = open(path).read() if os.path.exists(path) else None
    if old != text:
        open(path, "w").write(text)
    return old != text

cert = find_cert()
if not cert:
    print(f"No certificate for {DOMAIN} yet — port {PORT} stays closed.")
    sys.exit(2)
changed = write_if_changed(SNIPPET, f"ssl_certificate {cert[0]};\nssl_certificate_key {cert[1]};\n")
changed |= write_if_changed(SITE_TLS, f"""# PWNBroker update server — HTTPS on {PORT}. Generated by {sys.argv[0]}.
# server_name is deliberately '_' so SSL managers don't edit this block.
server {{
    listen {PORT} ssl;
    listen [::]:{PORT} ssl;
    server_name _;
    include {SNIPPET};
    ssl_protocols TLSv1.2 TLSv1.3;
    client_max_body_size 1m;
    location = / {{ return 404; }}
    location {PREFIX}/ {{
        proxy_pass http://127.0.0.1:{APP_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 300s;
    }}
}}
""")
if changed:
    if subprocess.run(["nginx", "-t", "-q"]).returncode != 0:
        sys.exit("nginx config test failed — not reloading")
    subprocess.run(["systemctl", "reload-or-restart", "nginx"], check=True)
print(f"Port {PORT} uses {cert[0]}" + (" (updated)" if changed else ""))
EOF
chmod 755 "$CERTSYNC"

cat > /etc/systemd/system/pwnbroker-updates-certsync.service <<EOF
[Unit]
Description=Point the PWNBroker update server at the current TLS certificate
After=nginx.service
[Service]
Type=oneshot
ExecStart=$CERTSYNC
SuccessExitStatus=2
EOF
cat > /etc/systemd/system/pwnbroker-updates-certsync.timer <<EOF
[Unit]
Description=Re-check the PWNBroker update server certificate (catches renewals)
[Timer]
OnBootSec=2min
OnUnitActiveSec=6h
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now pwnbroker-updates-certsync.timer >/dev/null 2>&1
nginx -t -q || die "nginx config test failed (nginx -t)"
systemctl enable nginx >/dev/null 2>&1
systemctl reload-or-restart nginx
open_port 80
ok "nginx serving http://$DOMAIN/.well-known/ for domain validation"

# ── 7. certificate ───────────────────────────────────────────────────────────
case "$SSL_MODE" in
spaceship)
    info "Spaceship SSL Manager"
    ip=$(getent ahostsv4 "$DOMAIN" | awk 'NR==1{print $1}')
    [[ -n "$ip" ]] || warn "$DOMAIN doesn't resolve yet — validation will fail until DNS points here."
    if command -v ssl-manager >/dev/null && ssl-manager info 2>/dev/null | grep -q "Manager is ready"; then
        ok "SSL Manager already registered"
    else
        tmp=$(mktemp -d)
        curl -fsSL -o "$tmp/installer.sh" "$SSL_MANAGER_INSTALLER" || die "Couldn't download $SSL_MANAGER_INSTALLER"
        head -1 "$tmp/installer.sh" | grep -q '^#!/bin/sh' || die "SSL Manager installer doesn't look like a shell script — not running it."
        echo "   Paste the SSL Manager token from your Spaceship dashboard when asked."
        sh "$tmp/installer.sh" </dev/tty || die "SSL Manager registration failed. Re-run this script to try again."
        rm -rf "$tmp"
    fi
    # Installs SSL Manager's own cron job, which issues/renews the cert into nginx.
    ssl-manager cron </dev/tty || warn "'ssl-manager cron' reported a problem — check 'ssl-manager info'."
    info "Waiting for the certificate (up to 10 minutes)"
    for _ in $(seq 1 60); do
        "$CERTSYNC" >/dev/null 2>&1 && break
        sleep 10
    done
    if [[ ! -f "$SITE_TLS" ]]; then
        warn "No certificate yet. Spaceship may still be validating $DOMAIN."
        warn "Port $PORT turns on by itself once it arrives (checked every 6 hours,"
        warn "or run: sudo $CERTSYNC)."
    fi
    ;;
letsencrypt)
    info "Getting a Let's Encrypt certificate for $DOMAIN"
    [[ -n "$(getent ahostsv4 "$DOMAIN")" ]] || die "$DOMAIN doesn't resolve yet. Point its A record here and re-run."
    if [[ ! -d "/etc/letsencrypt/live/$DOMAIN" ]]; then
        email_args=(--register-unsafely-without-email)
        [[ -n "$EMAIL" ]] && email_args=(-m "$EMAIL")
        certbot certonly --webroot -w "$WEBROOT" --non-interactive --agree-tos "${email_args[@]}" -d "$DOMAIN" \
            || die "certbot failed. Check that $DOMAIN points here and port 80 is reachable from the internet."
    fi
    mkdir -p /etc/letsencrypt/renewal-hooks/deploy
    printf '#!/bin/sh\nsystemctl reload nginx\n' > /etc/letsencrypt/renewal-hooks/deploy/pwnbroker-updates.sh
    chmod 755 /etc/letsencrypt/renewal-hooks/deploy/pwnbroker-updates.sh
    systemctl enable --now certbot.timer >/dev/null 2>&1 || true
    "$CERTSYNC"
    ;;
self-signed)
    info "Creating a self-signed certificate (testing only)"
    if [[ ! -f "$DATA_DIR/ssl/cert.pem" ]]; then
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 825 \
            -subj "/CN=$DOMAIN" -addext "subjectAltName=DNS:$DOMAIN" \
            -keyout "$DATA_DIR/ssl/key.pem" -out "$DATA_DIR/ssl/cert.pem" 2>/dev/null
        chmod 600 "$DATA_DIR/ssl/key.pem"
    fi
    "$CERTSYNC"
    warn "Customers must set PWNBROKER_UPDATE_CA to a copy of $DATA_DIR/ssl/cert.pem"
    ;;
esac
open_port "$PORT"
[[ $FIREWALL -eq 1 ]] && warn "Also open ports 80 and $PORT in any cloud-provider firewall."

# ── 8. health check ──────────────────────────────────────────────────────────
info "Checking the server"
app_ok=0
for _ in $(seq 1 15); do
    curl -fsS "http://127.0.0.1:$APP_PORT$PREFIX/v1/health" 2>/dev/null | grep -q '"ok"' && { app_ok=1; break; }
    sleep 1
done
[[ $app_ok -eq 1 ]] || die "Update server isn't answering — see: journalctl -u $SERVICE -n 50"
ok "Update server app is running"
TLS_UP=0
if [[ -f "$SITE_TLS" ]]; then
    k=(); [[ $SSL_MODE == self-signed ]] && k=(-k)
    if curl -fsS "${k[@]}" --resolve "$DOMAIN:$PORT:127.0.0.1" "https://$DOMAIN:$PORT$PREFIX/v1/health" \
            2>/dev/null | grep -q '"ok"'; then
        TLS_UP=1; ok "https://$DOMAIN:$PORT$PREFIX/v1/health is answering"
    else
        warn "HTTPS on $PORT isn't answering yet. Check: nginx -t; journalctl -u nginx -n 30"
    fi
fi

n=$(find "$DATA_DIR/releases" -mindepth 2 -maxdepth 2 -name manifest.sig 2>/dev/null | wc -l)
if [[ $TLS_UP -eq 1 ]]; then
    printf '\n\033[1;32mPWNBroker update server is ready.\033[0m\n'
else
    printf '\n\033[1;33mPWNBroker update server is installed; HTTPS turns on once the certificate is in place.\033[0m\n'
fi
cat <<EOF

  Customer update URL   https://$DOMAIN:$PORT$PREFIX
  Certificate           $SSL_MODE  (sync: sudo $CERTSYNC)
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
