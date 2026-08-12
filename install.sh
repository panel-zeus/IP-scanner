#!/usr/bin/env bash
# Zeus Scanner — one-line installer for Termux & Linux
#   curl -fsSL https://raw.githubusercontent.com/panel-zeus/IP-scanner/main/install.sh | bash
set -euo pipefail

# ─── config ────────────────────────────────────────────────────────────────────
REPO="${ZEUS_REPO:-panel-zeus/IP-scanner}"
BRANCH="${ZEUS_BRANCH:-main}"
RAW="${ZEUS_RAW_BASE:-https://raw.githubusercontent.com/$REPO/$BRANCH}"
XRAY_TAG="${ZEUS_XRAY_TAG:-latest}"
PORT="${ZEUS_PORT:-8000}"

if [ -n "${PREFIX:-}" ] && [ -d "${PREFIX:-}/bin" ]; then
    TERMUX=1
    HOME_DIR="${HOME:-/data/data/com.termux/files/home}"
    BIN_DIR="$PREFIX/bin"
else
    TERMUX=0
    HOME_DIR="${HOME:-$PWD}"
    BIN_DIR="$HOME_DIR/.local/bin"
fi
DEST="${ZEUS_DIR:-$HOME_DIR/zeus-scanner}"

# ─── colors & styles ───────────────────────────────────────────────────────────
R=$'\033[91m'   # red
G=$'\033[92m'   # green
Y=$'\033[93m'   # yellow
B=$'\033[94m'   # blue
M=$'\033[95m'   # magenta
C=$'\033[96m'   # cyan
W=$'\033[97m'   # white
D=$'\033[90m'   # dark/grey
N=$'\033[0m'    # reset
BOLD=$'\033[1m'
DIM=$'\033[2m'

# ─── spinner ───────────────────────────────────────────────────────────────────
_spin_pid=""
_spin_msg=""
spin_start() {
    _spin_msg="$1"
    local frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
    (
        local i=0
        while true; do
            printf "\r  ${C}${frames[$((i % 10))]}${N}  ${DIM}%s${N}   " "$_spin_msg"
            sleep 0.08
            i=$((i+1))
        done
    ) &
    _spin_pid=$!
    disown "$_spin_pid" 2>/dev/null || true
}
spin_stop() {
    if [ -n "$_spin_pid" ]; then
        kill "$_spin_pid" 2>/dev/null || true
        wait "$_spin_pid" 2>/dev/null || true
        _spin_pid=""
    fi
    printf "\r\033[2K"
}
spin_ok()   { spin_stop; printf "  ${G}${BOLD}✓${N}  %s\n" "$1"; }
spin_fail() { spin_stop; printf "  ${R}${BOLD}✗${N}  %s\n" "$1" >&2; exit 1; }

step()  { printf "\n${B}${BOLD}▸${N}  ${W}${BOLD}%s${N}\n" "$1"; }
info()  { printf "     ${D}%s${N}\n" "$1"; }
warn()  { printf "\n  ${Y}${BOLD}!${N}  ${Y}%s${N}\n" "$1"; }
die()   { spin_stop; printf "\n  ${R}${BOLD}✗  FATAL:${N}  ${R}%s${N}\n\n" "$1" >&2; exit 1; }

# ─── banner ────────────────────────────────────────────────────────────────────
clear 2>/dev/null || true
printf "\n"
printf "${C}${BOLD}"
printf "  ╔══════════════════════════════════════════════╗\n"
printf "  ║                                              ║\n"
printf "  ║    ⚡  Z E U S   S C A N N E R               ║\n"
printf "  ║    Clean Cloudflare IP Finder + Xray Core    ║\n"
printf "  ║                                              ║\n"
printf "  ╚══════════════════════════════════════════════╝\n"
printf "${N}"
printf "${D}              Developed by MO  •  v1.5${N}\n"
printf "\n"
sleep 0.4

# ─── platform detect ───────────────────────────────────────────────────────────
if [ "$TERMUX" = 1 ]; then
    printf "  ${M}▪${N}  Platform   ${W}Termux / Android${N}\n"
else
    printf "  ${M}▪${N}  Platform   ${W}Linux Desktop${N}\n"
fi
printf "  ${M}▪${N}  Install    ${W}%s${N}\n" "$DEST"
printf "  ${M}▪${N}  Port       ${W}%s${N}\n" "$PORT"
printf "\n"
sleep 0.3

# ─── step 1: dependencies ──────────────────────────────────────────────────────
step "Checking dependencies"

NEED=""
for tool in curl unzip python3; do
    if command -v "$tool" >/dev/null 2>&1; then
        printf "  ${G}✓${N}  %-10s  ${D}%s${N}\n" "$tool" "$(command -v $tool)"
    else
        printf "  ${Y}—${N}  %-10s  ${D}not found${N}\n" "$tool"
        NEED="$NEED $tool"
    fi
done

if [ -n "$NEED" ]; then
    NEED="${NEED// python3/ python}"
    step "Installing missing packages:${Y}$NEED${N}"
    if [ "$TERMUX" = 1 ]; then
        spin_start "pkg install$NEED ..."
        # shellcheck disable=SC2086
        pkg install -y $NEED >/dev/null 2>&1 || pkg install -y $NEED >/dev/null 2>&1 || spin_fail "pkg install failed"
        spin_ok "packages installed"
    elif command -v apt-get >/dev/null 2>&1; then
        spin_start "apt-get install$NEED ..."
        # shellcheck disable=SC2086
        sudo apt-get update -qq && sudo apt-get install -y $NEED >/dev/null 2>&1 || spin_fail "apt-get failed"
        spin_ok "packages installed"
    else
        die "missing tools:$NEED — install them and re-run"
    fi
fi

command -v python3 >/dev/null 2>&1 || die "python3 not on PATH after install"
PY_VER="$(python3 --version 2>&1)"
printf "  ${G}✓${N}  python3    ${D}%s${N}\n" "$PY_VER"

# ─── step 2: detect CPU ────────────────────────────────────────────────────────
step "Detecting architecture"

ARCH="$(uname -m)"
case "$ARCH" in
    aarch64|arm64)
        [ "$TERMUX" = 1 ] && ZIP="Xray-android-arm64-v8a.zip" || ZIP="Xray-linux-arm64-v8a.zip" ;;
    armv7l|armv8l)
        ZIP="Xray-linux-arm32-v7a.zip" ;;
    x86_64|amd64)
        [ "$TERMUX" = 1 ] && ZIP="Xray-android-amd64.zip" || ZIP="Xray-linux-64.zip" ;;
    i686|i386)
        ZIP="Xray-linux-32.zip" ;;
    *)
        die "Unsupported CPU: $ARCH" ;;
esac

printf "  ${G}✓${N}  CPU        ${D}%s${N}\n" "$ARCH"
printf "  ${G}✓${N}  Package    ${D}%s${N}\n" "$ZIP"

# ─── step 3: xray core ─────────────────────────────────────────────────────────
step "Downloading Xray core"

if [ "$XRAY_TAG" = latest ]; then
    XRAY_URL="https://github.com/XTLS/Xray-core/releases/latest/download/$ZIP"
else
    XRAY_URL="https://github.com/XTLS/Xray-core/releases/download/$XRAY_TAG/$ZIP"
fi

mkdir -p "$DEST/bin"
cd "$DEST"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

spin_start "Downloading $ZIP ..."
curl -fsSL --retry 3 --retry-delay 2 -o "$TMP/xray.zip" "$XRAY_URL" \
    || spin_fail "Could not download Xray from $XRAY_URL"
spin_ok "Downloaded $ZIP"

spin_start "Extracting ..."
unzip -oq "$TMP/xray.zip" -d "$TMP/x" || spin_fail "Xray archive is corrupt"
[ -f "$TMP/x/xray" ] || spin_fail "No xray binary inside the archive"
install -m 755 "$TMP/x/xray" "$DEST/bin/xray" 2>/dev/null \
    || { cp -f "$TMP/x/xray" "$DEST/bin/xray" && chmod 755 "$DEST/bin/xray"; }
for extra in geoip.dat geosite.dat; do
    [ -f "$TMP/x/$extra" ] && cp -f "$TMP/x/$extra" "$DEST/bin/$extra"
done
spin_ok "Xray installed"

XRAY_VER="$("$DEST/bin/xray" version 2>/dev/null | head -n1 || echo 'unknown')"
printf "  ${G}✓${N}  Version    ${D}%s${N}\n" "$XRAY_VER"

# ─── step 4: scanner files ─────────────────────────────────────────────────────
step "Downloading scanner files"

FILES="index.html server.py xray.py"
COUNT=0
TOTAL=3
for f in $FILES; do
    spin_start "[$((COUNT+1))/$TOTAL] $f ..."
    curl -fsSL --retry 3 --retry-delay 2 -o "$DEST/$f.part" "$RAW/$f" \
        || spin_fail "Could not download $f"
    [ -s "$DEST/$f.part" ] || spin_fail "$f came back empty"
    mv -f "$DEST/$f.part" "$DEST/$f"
    COUNT=$((COUNT+1))
    spin_ok "$f"
done

spin_start "Validating Python files ..."
python3 -c "import ast,sys; [ast.parse(open(f,encoding='utf-8').read(),f) for f in sys.argv[1:]]" \
    "$DEST/server.py" "$DEST/xray.py" \
    || spin_fail "Downloaded Python files failed validation"
spin_ok "All files valid"

# ─── step 5: launcher ──────────────────────────────────────────────────────────
step "Creating zeus command"

mkdir -p "$BIN_DIR"
cat > "$BIN_DIR/zeus" <<LAUNCHER
#!/usr/bin/env bash
# Zeus Scanner launcher — generated by install.sh
set -euo pipefail
DEST="$DEST"
export XRAY_BIN="\${XRAY_BIN:-\$DEST/bin/xray}"
export XRAY_LOCATION_ASSET="\${XRAY_LOCATION_ASSET:-\$DEST/bin}"
export ZEUS_PORT="\${ZEUS_PORT:-$PORT}"
cd "\$DEST"
URL="http://127.0.0.1:\$ZEUS_PORT/"
if command -v termux-open-url >/dev/null 2>&1; then
    ( sleep 2; termux-open-url "\$URL" >/dev/null 2>&1 || true ) &
fi
exec python3 server.py
LAUNCHER
chmod 755 "$BIN_DIR/zeus"

case ":$PATH:" in
    *":$BIN_DIR:"*) spin_ok "zeus command ready" ;;
    *) warn "$BIN_DIR is not on PATH — add it or run: $BIN_DIR/zeus" ;;
esac

# ─── done ──────────────────────────────────────────────────────────────────────
printf "\n"
printf "${G}${BOLD}"
printf "  ╔══════════════════════════════════════════════╗\n"
printf "  ║                                              ║\n"
printf "  ║    ✅  Installation Complete!                ║\n"
printf "  ║                                              ║\n"
printf "  ╚══════════════════════════════════════════════╝\n"
printf "${N}\n"

printf "  ${W}${BOLD}How to start:${N}\n\n"
printf "  ${G}${BOLD}  zeus${N}                 ${D}start the scanner${N}\n"
printf "  ${D}  then open in browser:${N}\n"
printf "  ${C}${BOLD}  http://127.0.0.1:%s/${N}\n" "$PORT"
printf "\n"
printf "  ${D}  Update anytime:${N}\n"
printf "  ${DIM}  curl -fsSL %s/install.sh | bash${N}\n" "$RAW"
printf "\n"
printf "${D}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}\n"
printf "${D}               Developed by MO  •  Zeus v1.5${N}\n"
printf "${D}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}\n\n"
