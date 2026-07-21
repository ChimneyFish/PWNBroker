#!/bin/bash
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"

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
cd "$DIR"
venv/bin/gunicorn \
  -w 1 \
  --threads 8 \
  --certfile=data/ssl/cert.pem \
  --keyfile=data/ssl/key.pem \
  -b 0.0.0.0:5000 \
  "app:create_app()" \
  --daemon \
  --pid /tmp/pwnbroker.pid \
  --error-logfile logs/gunicorn-error.log \
  --access-logfile logs/gunicorn-access.log

sleep 2
if kill -0 "$(cat /tmp/pwnbroker.pid 2>/dev/null)" 2>/dev/null; then
  echo "[+] PwnBroker running (PID $(cat /tmp/pwnbroker.pid))"
  echo "[+] https://localhost:5000"
else
  echo "[!] Failed to start — check logs/gunicorn-error.log"
  exit 1
fi
