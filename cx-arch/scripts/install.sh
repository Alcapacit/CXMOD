#!/bin/sh
# CXMOD install script
# Usage: sudo ./scripts/install.sh [PREFIX]
#
# Builds and installs CXMOD on the local system.
# Supports: Debian/Ubuntu, RHEL/CentOS/Fedora, Arch, Alpine, Gentoo

set -e

PREFIX="${1:-/usr/local}"
SBIN="$PREFIX/sbin"
MANDIR="$PREFIX/share/man/man8"

# ── Colour output ───────────────────────────────────────────────────────────
RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; BOLD='\033[1m'; RESET='\033[0m'
ok()   { printf "${GREEN}  [ OK ]${RESET}  %s\n" "$*"; }
warn() { printf "${YELLOW}  [WARN]${RESET}  %s\n" "$*"; }
die()  { printf "${RED}  [FAIL]${RESET}  %s\n" "$*" >&2; exit 1; }

# ── Check root ──────────────────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    die "This script must be run as root. Re-run: sudo $0 $*"
fi

printf "\n${BOLD}CXMOD Install Script${RESET}\n"
printf "  Prefix: %s\n\n" "$PREFIX"

# ── Check compiler ──────────────────────────────────────────────────────────
CC="${CC:-gcc}"
if ! command -v "$CC" >/dev/null 2>&1; then
    warn "gcc not found — attempting to install..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get install -y --quiet gcc make
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y gcc make
    elif command -v yum >/dev/null 2>&1; then
        yum install -y gcc make
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Sy --noconfirm gcc make
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache gcc musl-dev make
    else
        die "Cannot find or install gcc. Install build-essential (Debian) or gcc/make (RHEL/Arch) and re-run."
    fi
fi

ok "Compiler: $(${CC} --version | head -1)"

# ── Build ───────────────────────────────────────────────────────────────────
printf "\n  Building CXMOD...\n"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$SCRIPT_DIR"

make clean >/dev/null 2>&1 || true
if make CC="$CC" PREFIX="$PREFIX"; then
    ok "Build complete"
else
    die "Build failed. Check compiler output above."
fi

# ── Install binary ──────────────────────────────────────────────────────────
mkdir -p "$SBIN"
install -m 755 cxmod "$SBIN/cx"
ok "Installed binary: $SBIN/cx"

# ── Install man page ────────────────────────────────────────────────────────
mkdir -p "$MANDIR"
install -m 644 man/cxmod.8 "$MANDIR/cxmod.8"
gzip -f "$MANDIR/cxmod.8" 2>/dev/null || true
ok "Installed man page: $MANDIR/cxmod.8.gz"

# ── Install systemd unit ────────────────────────────────────────────────────
SYSTEMD_DIR="/etc/systemd/system"
if [ -d "$SYSTEMD_DIR" ]; then
    install -m 644 scripts/cxmod.service "$SYSTEMD_DIR/cxmod.service"
    systemctl daemon-reload 2>/dev/null || true
    ok "Installed systemd unit: $SYSTEMD_DIR/cxmod.service"
    printf "\n  To enable CXMOD at boot:\n"
    printf "    systemctl enable --now cxmod\n"
else
    warn "systemd not detected — skipping service installation"
fi

# ── Verify install ──────────────────────────────────────────────────────────
printf "\n"
if "$SBIN/cx" version >/dev/null 2>&1; then
    ok "Verification: cx --version OK"
else
    warn "Binary installed but 'cx version' failed — check PATH"
fi

printf "\n${BOLD}  CXMOD installed successfully.${RESET}\n"
printf "\n  Quick start:\n"
printf "    sudo cx diagnose                      # full health check\n"
printf "    sudo cx tune --profile=balanced       # apply safe defaults\n"
printf "    sudo cx tune --profile=high_throughput # maximize throughput\n"
printf "    sudo cx conntrack --fix               # fix conntrack overflow\n"
printf "    sudo cx irq --balance                 # balance NIC IRQs\n"
printf "    sudo cx irq --rps                     # enable RPS/XPS\n"
printf "    cx monitor                            # live traffic monitor\n"
printf "    man cx                                # full documentation\n\n"
