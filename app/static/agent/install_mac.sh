#!/usr/bin/env bash
# PwnBroker Agent Installer — macOS (LaunchAgent)
# Usage: ./install_mac.sh [--no-verify-ssl]
set -e

SERVER="__PWNBROKER_SERVER__"
REG_TOKEN="__REG_TOKEN__"
NO_VERIFY="${1:-}"
AGENT_DIR="$HOME/Library/PwnBroker"
VENV_DIR="$AGENT_DIR/venv"
PLIST_DIR="$HOME/Library/LaunchAgents"
PLIST="$PLIST_DIR/com.pwnbroker.agent.plist"
LABEL="com.pwnbroker.agent"

echo "=== PwnBroker Agent Installer (macOS) ==="
echo "Server : $SERVER"
echo ""

# Find Python
PYTHON=""
for candidate in python3 /usr/local/bin/python3 /opt/homebrew/bin/python3; do
  if command -v "$candidate" &>/dev/null; then
    PYTHON="$candidate"
    break
  fi
done
if [ -z "$PYTHON" ]; then
  echo "ERROR: python3 not found. Install via Homebrew: brew install python"
  exit 1
fi
echo "Using: $PYTHON ($($PYTHON --version))"

# Create venv
echo "[1/4] Setting up virtual environment at $VENV_DIR..."
mkdir -p "$AGENT_DIR"
"$PYTHON" -m venv "$VENV_DIR"
VENV_PY="$VENV_DIR/bin/python3"
VENV_PIP="$VENV_DIR/bin/pip"
"$VENV_PIP" install --quiet --upgrade pip
"$VENV_PIP" install --quiet requests psutil
echo "    requests + psutil installed."

# Write agent script (embedded — no separate download required)
echo "[2/4] Writing agent to $AGENT_DIR/agent.py..."
cat > "$AGENT_DIR/agent.py" << 'PWNBROKER_AGENT_HEREDOC_END'
__AGENT_CONTENT__
PWNBROKER_AGENT_HEREDOC_END
chmod 700 "$AGENT_DIR/agent.py"

# Register
echo "[3/4] Registering agent with $SERVER..."
EXTRA=""
[ "$NO_VERIFY" = "--no-verify-ssl" ] && EXTRA="--no-verify-ssl"
"$VENV_PY" "$AGENT_DIR/agent.py" \
  --server "$SERVER" \
  --reg-token "$REG_TOKEN" \
  --register \
  $EXTRA

# Create LaunchAgent
echo "[4/4] Installing LaunchAgent..."
mkdir -p "$PLIST_DIR"
EXTRA_ARG_XML=""
[ -n "$EXTRA" ] && EXTRA_ARG_XML="    <string>$EXTRA</string>"

cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${VENV_PY}</string>
    <string>${AGENT_DIR}/agent.py</string>
${EXTRA_ARG_XML}
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>30</integer>
  <key>StandardOutPath</key>
  <string>${HOME}/Library/Logs/pwnbroker-agent.log</string>
  <key>StandardErrorPath</key>
  <string>${HOME}/Library/Logs/pwnbroker-agent.log</string>
</dict>
</plist>
EOF

launchctl unload "$PLIST" 2>/dev/null || true
launchctl load "$PLIST"

echo ""
echo "=== Done! Agent running as LaunchAgent ==="
echo "Logs   : tail -f ~/Library/Logs/pwnbroker-agent.log"
echo "Stop   : launchctl unload $PLIST"
echo "Start  : launchctl load $PLIST"
