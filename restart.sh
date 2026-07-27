#!/bin/bash
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
PORT="${PORT:-443}"

# If this box has the systemd service (from setup.sh), always defer to it —
# managing gunicorn directly here as well is exactly what caused a port-5000
# conflict/crash-loop between this script and the systemd unit.
if systemctl list-unit-files pwnbroker.service &>/dev/null; then
    echo "[*] pwnbroker.service is systemd-managed — restarting via systemctl"
    exec sudo systemctl restart pwnbroker
fi

echo "[*] No systemd unit found — falling back to a standalone gunicorn daemon (dev/non-systemd use only)"
echo "[*] Stopping existing gunicorn (tracked via /tmp/pwnbroker.pid only, not a blanket pkill)..."
if [[ -f /tmp/pwnbroker.pid ]] && kill -0 "$(cat /tmp/pwnbroker.pid)" 2>/dev/null; then
    kill "$(cat /tmp/pwnbroker.pid)"
    sleep 2
fi

echo "[*] Starting PwnBroker..."
if [[ "$PORT" -lt 1024 && "$EUID" -ne 0 ]]; then
    echo "[!] Port $PORT requires root (or CAP_NET_BIND_SERVICE) — run this via sudo,"
    echo "    or set PORT=5000 (or another port >1024) to run unprivileged."
    exit 1
fi
cd "$DIR"
venv/bin/gunicorn \
  -w 1 \
  --threads 8 \
  --certfile=data/ssl/cert.pem \
  --keyfile=data/ssl/key.pem \
  -b 0.0.0.0:$PORT \
  "app:create_app()" \
  --daemon \
  --pid /tmp/pwnbroker.pid \
  --error-logfile logs/gunicorn-error.log \
  --access-logfile logs/gunicorn-access.log

sleep 2
if kill -0 "$(cat /tmp/pwnbroker.pid 2>/dev/null)" 2>/dev/null; then
  echo "[+] PwnBroker running (PID $(cat /tmp/pwnbroker.pid))"
  echo "[+] https://localhost:$PORT"
else
  echo "[!] Failed to start — check logs/gunicorn-error.log"
  exit 1
fi
