#!/usr/bin/env bash
# PwnBroker Agent Installer — Linux (systemd)
# Usage: sudo ./install_linux.sh [--no-verify-ssl]
set -e

SERVER="__PWNBROKER_SERVER__"
REG_TOKEN="__REG_TOKEN__"
NO_VERIFY="${1:-}"
AGENT_DIR="/opt/pwnbroker-agent"
VENV_DIR="$AGENT_DIR/venv"
PYTHON="python3"
SERVICE_NAME="pwnbroker-agent"

echo "=== PwnBroker Agent Installer (Linux) ==="
echo "Server : $SERVER"
echo ""

# Check Python
if ! command -v "$PYTHON" &>/dev/null; then
  echo "ERROR: python3 not found. Install it: apt install python3 python3-venv"
  exit 1
fi

# Ensure venv support is available
if ! "$PYTHON" -m venv --help &>/dev/null 2>&1; then
  echo "Installing python3-venv..."
  apt-get install -y python3-venv python3-full 2>/dev/null || true
fi

# Create agent directory and venv
echo "[1/4] Setting up virtual environment at $VENV_DIR..."
mkdir -p "$AGENT_DIR"
"$PYTHON" -m venv "$VENV_DIR"
VENV_PY="$VENV_DIR/bin/python3"
VENV_PIP="$VENV_DIR/bin/pip"

# Install deps inside the venv (no system-package conflict)
"$VENV_PIP" install --quiet --upgrade pip
"$VENV_PIP" install --quiet requests psutil
echo "    requests + psutil installed."

# Write agent script (embedded — no separate download required)
echo "[2/4] Writing agent to $AGENT_DIR/agent.py..."
cat > "$AGENT_DIR/agent.py" << 'PWNBROKER_AGENT_HEREDOC_END'
__AGENT_CONTENT__
PWNBROKER_AGENT_HEREDOC_END
chmod 700 "$AGENT_DIR/agent.py"

# Register with the PwnBroker server
echo "[3/4] Registering agent with $SERVER..."
EXTRA=""
[ "$NO_VERIFY" = "--no-verify-ssl" ] && EXTRA="--no-verify-ssl"
"$VENV_PY" "$AGENT_DIR/agent.py" \
  --server "$SERVER" \
  --reg-token "$REG_TOKEN" \
  --register \
  $EXTRA

# Create systemd service
echo "[4/4] Creating systemd service '$SERVICE_NAME'..."
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=PwnBroker Endpoint Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${VENV_PY} ${AGENT_DIR}/agent.py ${EXTRA}
Restart=on-failure
RestartSec=30
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

echo ""
echo "=== Done! Agent running as systemd service '$SERVICE_NAME' ==="
echo "Status : systemctl status $SERVICE_NAME"
echo "Logs   : journalctl -u $SERVICE_NAME -f"
