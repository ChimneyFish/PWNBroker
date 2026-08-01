#!/usr/bin/env bash
# Rebuilds app/static/css/app.css from the Tailwind source at
# app/static/css/src/main.css. No Node/npm needed — uses Tailwind's
# standalone CLI binary (downloaded once, gitignored).
set -euo pipefail
cd "$(dirname "$0")/../.."

BIN=scripts/build/tailwindcss
if [[ ! -x "$BIN" ]]; then
  echo "[*] Downloading Tailwind standalone CLI..."
  curl -sL https://github.com/tailwindlabs/tailwindcss/releases/latest/download/tailwindcss-linux-x64 -o "$BIN"
  chmod +x "$BIN"
fi

"$BIN" -i app/static/css/src/main.css -o app/static/css/app.css --minify
echo "[+] Built app/static/css/app.css"
