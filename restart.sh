#!/bin/bash
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"

echo "[*] Stopping existing gunicorn..."
pkill -f "gunicorn" || true
sleep 2

echo "[*] Starting PwnBroker..."
cd "$DIR"
venv/bin/gunicorn \
  -w 2 \
  --threads 4 \
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
