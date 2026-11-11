#!/usr/bin/env bash
# =============================================================================
#  PWNBroker @VERSION@ — single-file installer
#
#    sudo bash pwnbroker-@VERSION@-install.run [options]
#
#  Everything needed is inside this file: the signed PWNBroker release and the
#  setup that installs it (system packages, Python environment, nmap, nuclei
#  exploit checks, TLS certificate, systemd service, firewall rule). The server
#  needs internet access for OS and Python packages. Re-running it on an
#  existing install upgrades/repairs it and keeps all data.
#
#  Options:
#    --license FILE     install this license key (otherwise upload it in the UI)
#    --port N           HTTPS port (default 443)
#    --dir PATH         install directory (default /opt/PWNBroker)
#    --update-url URL   update server (default https://pwnbroker.space:7585/updates)
#    --check            only verify this file's integrity and signature, then exit
#    --extract DIR      only verify and unpack the release into DIR, then exit
#    -h, --help         show this help
# =============================================================================
set -euo pipefail

VERSION="@VERSION@"
PAYLOAD_SHA256="@PAYLOAD_SHA256@"
RELEASE_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----
@RELEASE_PUBKEY@
-----END PUBLIC KEY-----"

R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m' C='\033[0;36m' B='\033[1m' N='\033[0m'
info() { printf "${C}[*]${N} %s\n" "$*"; }
ok()   { printf "${G}[✓]${N} %s\n" "$*"; }
warn() { printf "${Y}[!]${N} %s\n" "$*"; }
die()  { printf "${R}[✗]${N} %s\n" "$*" >&2; exit 1; }

usage() { sed -n '3,20p' "$0" | sed 's/^# \{0,2\}//'; exit "${1:-0}"; }

LICENSE_FILE="" PORT_ARG="" DIR_ARG="" UPDATE_URL_ARG="" MODE=install EXTRACT_DIR=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --license)    LICENSE_FILE="${2:?--license needs a file}"; shift 2 ;;
        --port)       PORT_ARG="${2:?--port needs a number}"; shift 2 ;;
        --dir)        DIR_ARG="${2:?--dir needs a path}"; shift 2 ;;
        --update-url) UPDATE_URL_ARG="${2:?--update-url needs a URL}"; shift 2 ;;
        --check)      MODE=check; shift ;;
        --extract)    MODE=extract; EXTRACT_DIR="${2:?--extract needs a directory}"; shift 2 ;;
        -h|--help)    usage 0 ;;
        *)            warn "Unknown option: $1"; usage 1 ;;
    esac
done

SELF="$(readlink -f "$0")"

# ── Root (re-run through sudo when possible, so one command is enough) ──────
if [[ $MODE == install && $EUID -ne 0 ]]; then
    if command -v sudo >/dev/null; then
        info "Root is required — re-running with sudo..."
        exec sudo bash "$SELF" ${LICENSE_FILE:+--license "$(readlink -f "$LICENSE_FILE")"} \
            ${PORT_ARG:+--port "$PORT_ARG"} ${DIR_ARG:+--dir "$DIR_ARG"} \
            ${UPDATE_URL_ARG:+--update-url "$UPDATE_URL_ARG"}
    fi
    die "Run as root:  sudo bash $0"
fi

# ── Validate options early (before any work) ────────────────────────────────
if [[ -n $PORT_ARG ]] && ! [[ $PORT_ARG =~ ^[0-9]+$ && $PORT_ARG -ge 1 && $PORT_ARG -le 65535 ]]; then
    die "--port must be a number between 1 and 65535"
fi
if [[ -n $DIR_ARG && $DIR_ARG != /* ]]; then
    die "--dir must be an absolute path"
fi
if [[ -n $LICENSE_FILE ]]; then
    [[ -r $LICENSE_FILE ]] || die "Can't read license file: $LICENSE_FILE"
    grep -Eq 'BEGIN PWNBROKER LICENSE|^[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+$' "$LICENSE_FILE" \
        || die "$LICENSE_FILE doesn't look like a PWNBroker license key"
fi

# ── Unpack and verify ───────────────────────────────────────────────────────
for tool in tar sha256sum awk tail openssl base64; do
    if [[ $tool == openssl ]] && ! command -v openssl >/dev/null && [[ $EUID -eq 0 ]] \
            && command -v apt-get >/dev/null; then
        info "Installing openssl (needed to verify the release signature)..."
        { apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssl; } >/dev/null \
            || die "Couldn't install openssl — check this server's internet/apt access."
    fi
    command -v "$tool" >/dev/null || die "Missing required tool: $tool"
done
OPENSSL_MAJOR=$(openssl version | awk '{split($2, v, "."); print v[1]}')
[[ ${OPENSSL_MAJOR:-0} -ge 3 ]] || die "OpenSSL 3 or newer is required (Ubuntu 22.04+ / Debian 12+). Found: $(openssl version)"

WORK="$(mktemp -d /tmp/pwnbroker-install.XXXXXX)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

info "PWNBroker $VERSION installer — verifying..."
LINE=$(awk '/^__PWNBROKER_PAYLOAD_BELOW__$/ { print NR + 1; exit }' "$SELF")
[[ -n $LINE ]] || die "This file is damaged (payload marker missing) — download it again."
tail -n +"$LINE" "$SELF" > "$WORK/payload.tar"
GOT=$(sha256sum "$WORK/payload.tar" | awk '{print $1}')
[[ $GOT == "$PAYLOAD_SHA256" ]] || die "This file is damaged or incomplete (checksum mismatch) — download it again."

tar -xf "$WORK/payload.tar" -C "$WORK" manifest.json manifest.sig "pwnbroker-$VERSION.tar.gz" \
    || die "This file is damaged (can't unpack the release)."

# The release is signed with PWNBroker's release key — the same check the
# auto-updater does before installing any update.
printf '%s\n' "$RELEASE_PUBLIC_KEY" > "$WORK/release_pub.pem"
base64 -d "$WORK/manifest.sig" > "$WORK/manifest.sig.bin" 2>/dev/null || die "Release signature is malformed."
if ! openssl pkeyutl -verify -pubin -inkey "$WORK/release_pub.pem" -rawin \
        -in "$WORK/manifest.json" -sigfile "$WORK/manifest.sig.bin" >/dev/null 2>&1; then
    die "Release signature is INVALID — this file was not produced by PWNBroker. Do not install it."
fi
WANT_TAR=$(sed -n 's/^  "sha256": "\([0-9a-f]\{64\}\)",\{0,1\}$/\1/p' "$WORK/manifest.json")
GOT_TAR=$(sha256sum "$WORK/pwnbroker-$VERSION.tar.gz" | awk '{print $1}')
[[ -n $WANT_TAR && $WANT_TAR == "$GOT_TAR" ]] || die "Release archive doesn't match its signed manifest."
grep -q "\"version\": \"$VERSION\"" "$WORK/manifest.json" || die "Signed manifest is for a different version."
ok "Signature valid — genuine PWNBroker $VERSION release"

if [[ $MODE == check ]]; then
    ok "Integrity check passed. Install with:  sudo bash $0"
    exit 0
fi

mkdir -p "$WORK/app"
tar -xzf "$WORK/pwnbroker-$VERSION.tar.gz" -C "$WORK/app"
[[ -f "$WORK/app/setup.sh" && -f "$WORK/app/app/version.py" ]] || die "Release is missing setup files."

if [[ $MODE == extract ]]; then
    mkdir -p "$EXTRACT_DIR"
    cp -a "$WORK/app/." "$EXTRACT_DIR/"
    ok "Release unpacked to $EXTRACT_DIR (install from there with: sudo bash $EXTRACT_DIR/setup.sh)"
    exit 0
fi

# ── Pre-flight ──────────────────────────────────────────────────────────────
# Read os-release in a subshell: it defines VERSION, which would clobber ours.
read -r OS_ID OS_LIKE OS_NAME < <( [[ -f /etc/os-release ]] && . /etc/os-release
    printf '%s %s %s\n' "${ID:-unknown}" "${ID_LIKE:-none}" "${PRETTY_NAME:-unknown}" | tr -d '"' )
case "$OS_ID" in
    ubuntu|debian) ;;
    *) case " ${OS_LIKE//,/ } " in
           *" debian "*|*" ubuntu "*) warn "$OS_NAME isn't Ubuntu/Debian — trying anyway (Debian-based)." ;;
           *) die "PWNBroker installs on Ubuntu Server (22.04 or newer) or Debian 12+. Detected: $OS_NAME." ;;
       esac ;;
esac
command -v apt-get >/dev/null || die "apt-get not found — Ubuntu/Debian is required."
command -v systemctl >/dev/null && [[ -d /run/systemd/system ]] \
    || die "systemd isn't running — PWNBroker installs as a systemd service (containers without systemd aren't supported)."
case "$(uname -m)" in
    x86_64|amd64|aarch64|arm64) ;;
    *) die "Unsupported CPU architecture $(uname -m) — x86_64 or arm64 is required." ;;
esac
AVAIL_MB=$(df -Pm "$(dirname "${DIR_ARG:-/opt/PWNBroker}")" 2>/dev/null | awk 'NR==2 {print $4}')
if [[ -n ${AVAIL_MB:-} && $AVAIL_MB -lt 3072 ]]; then
    die "Only ${AVAIL_MB} MB free — at least 3 GB is needed for PWNBroker and its scanners."
fi

TARGET_DIR="${DIR_ARG:-${INSTALL_DIR:-/opt/PWNBroker}}"
if [[ -f "$TARGET_DIR/app/version.py" ]]; then
    CUR=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$TARGET_DIR/app/version.py")
    if [[ -n $CUR && $CUR != "$VERSION" && $(printf '%s\n%s\n' "$CUR" "$VERSION" | sort -V | tail -1) == "$CUR" ]]; then
        die "PWNBroker $CUR is already installed in $TARGET_DIR — this installer is older ($VERSION). Use the newest installer, or roll back with the updater."
    fi
    [[ -d "$TARGET_DIR/.git" ]] && die "$TARGET_DIR is a git checkout — update it with setup.sh/git, or install the release elsewhere with --dir."
    info "Existing PWNBroker ${CUR:-install} found in $TARGET_DIR — upgrading to $VERSION (data is kept)."
fi

if [[ -n $LICENSE_FILE ]]; then
    mkdir -p "$WORK/app/data"
    install -m 0640 "$LICENSE_FILE" "$WORK/app/data/license.key"
    ok "License key will be installed"
fi

# ── Install ─────────────────────────────────────────────────────────────────
LOG=/var/log/pwnbroker-install.log
info "Installing — this takes a few minutes. Full log: $LOG"
export INSTALL_DIR="${DIR_ARG:-${INSTALL_DIR:-/opt/PWNBroker}}"
[[ -n $PORT_ARG ]] && export PORT="$PORT_ARG"
[[ -n $UPDATE_URL_ARG ]] && export UPDATE_URL="$UPDATE_URL_ARG"
set +e
bash "$WORK/app/setup.sh" 2>&1 | tee -a "$LOG"
RC=${PIPESTATUS[0]}
set -e
if [[ $RC -ne 0 ]]; then
    die "Setup failed (exit $RC). See $LOG — fix the reported problem and run this installer again; it's safe to re-run."
fi
[[ -z $LICENSE_FILE ]] && warn "No license installed yet — sign in and upload it under the user menu → License (or re-run with --license FILE)."
ok "PWNBroker $VERSION installed."
exit 0
__PWNBROKER_PAYLOAD_BELOW__
