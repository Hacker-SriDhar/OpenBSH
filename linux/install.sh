#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# BSH Linux — Installation Script
# Installs BSH as a systemd service on Debian/Ubuntu/Fedora/RHEL/Arch Linux.
#
# Usage:
#   sudo bash install.sh
#   sudo bash install.sh --uninstall
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

BSH_USER="root"
INSTALL_DIR="/opt/bsh"
DATA_DIR="/var/lib/bsh"
LOG_DIR="/var/log/bsh"
RUN_DIR="/run/bsh"
CONFIG_DIR="/etc/bsh"
SYSTEMD_UNIT="/etc/systemd/system/bsh.service"
PYTHON="python3"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'  # No Colour

ok()   { echo -e "  ${GREEN}✓${NC} $*"; }
warn() { echo -e "  ${YELLOW}⚠${NC} $*"; }
err()  { echo -e "  ${RED}✗${NC} $*"; }

# ─────────────────────────────────────────────────────────────────────────────
# Privilege check
# ─────────────────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root."
    echo "  Run:  sudo bash install.sh"
    exit 1
fi

# ─────────────────────────────────────────────────────────────────────────────
# Uninstall
# ─────────────────────────────────────────────────────────────────────────────
if [[ "${1:-}" == "--uninstall" ]]; then
    echo
    echo "=== BSH Uninstall ==="
    echo
    systemctl stop bsh 2>/dev/null && ok "Service stopped" || warn "Service was not running"
    systemctl disable bsh 2>/dev/null && ok "Service disabled" || true
    rm -f "$SYSTEMD_UNIT"
    systemctl daemon-reload
    ok "Systemd unit removed"
    rm -rf "$INSTALL_DIR"
    ok "Install directory removed: $INSTALL_DIR"
    echo
    warn "Data directories kept: $DATA_DIR  $LOG_DIR"
    warn "To fully remove:  rm -rf $DATA_DIR $LOG_DIR $CONFIG_DIR"
    echo
    echo "=== BSH uninstalled ==="
    exit 0
fi

# ─────────────────────────────────────────────────────────────────────────────
# Install
# ─────────────────────────────────────────────────────────────────────────────
echo
echo "=== BSH Linux Installation ==="
echo

# 1. Check Python
echo "[1/7] Checking Python …"
if ! command -v "$PYTHON" &>/dev/null; then
    err "python3 not found — install with your package manager"
    exit 1
fi
PYVER=$("$PYTHON" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
ok "Found Python $PYVER"

# 2. Detect Linux Bluetooth stack
echo
echo "[2/7] Checking Bluetooth stack …"
if systemctl is-active --quiet bluetooth; then
    ok "BlueZ daemon (bluetoothd) is running"
else
    warn "BlueZ daemon is not running — starting it …"
    systemctl enable --now bluetooth || warn "Could not start bluetooth service"
fi

if ! command -v hciconfig &>/dev/null && ! command -v bluetoothctl &>/dev/null; then
    warn "BlueZ tools not found.  Install with:"
    echo "       Debian/Ubuntu:  sudo apt install bluez"
    echo "       Fedora/RHEL:    sudo dnf install bluez"
    echo "       Arch:           sudo pacman -S bluez bluez-utils"
fi

# 3. System dependencies
echo
echo "[3/7] Installing system dependencies …"
if command -v apt-get &>/dev/null; then
    apt-get install -y libbluetooth-dev libpam0g-dev python3-pip 2>/dev/null | grep -E "^(Get:|Inst)" | head -20 || true
    ok "apt packages ready"
elif command -v dnf &>/dev/null; then
    dnf install -y bluez-libs-devel pam-devel python3-pip 2>/dev/null | tail -3 || true
    ok "dnf packages ready"
elif command -v pacman &>/dev/null; then
    pacman -S --noconfirm --needed bluez-libs pam python-pip 2>/dev/null | tail -3 || true
    ok "pacman packages ready"
else
    warn "Unknown package manager — install libbluetooth-dev and libpam0g-dev manually"
fi

# 4. Python packages
echo
echo "[4/7] Installing Python packages …"
"$PYTHON" -m pip install --quiet cryptography
ok "cryptography installed"

"$PYTHON" -m pip install --quiet python-pam && ok "python-pam installed" \
    || warn "python-pam install failed — PAM auth may be limited"

"$PYTHON" -m pip install --quiet 'git+https://github.com/pybluez/pybluez.git' \
    && ok "PyBluez installed" \
    || {
        "$PYTHON" -m pip install --quiet PyBluez && ok "PyBluez installed (PyPI)" \
        || warn "PyBluez install failed — SDP advertisement disabled (clients must use channel directly)"
    }

# 5. Copy files
echo
echo "[5/7] Copying BSH files to $INSTALL_DIR …"
mkdir -p "$INSTALL_DIR"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for f in bsh_crypto.py bsh_protocol.py bsh_server_service.py bsh_service.py; do
    cp "$SOURCE_DIR/$f" "$INSTALL_DIR/"
    ok "Copied $f"
done
chmod 750 "$INSTALL_DIR/bsh_service.py"

# 6. Create directories and config
echo
echo "[6/7] Creating directories and config …"
mkdir -p "$DATA_DIR" "$LOG_DIR" "$RUN_DIR" "$CONFIG_DIR"
chmod 750 "$DATA_DIR" "$LOG_DIR"
chmod 755 "$RUN_DIR"
ok "Directories created"

CONFIG_FILE="$CONFIG_DIR/config.json"
if [[ ! -f "$CONFIG_FILE" ]]; then
    cat > "$CONFIG_FILE" <<EOF
{
  "channel": 1,
  "log_level": "DEBUG",
  "log_file": "$LOG_DIR/bsh_service.log"
}
EOF
    ok "Default config written: $CONFIG_FILE"
else
    warn "Config already exists: $CONFIG_FILE"
fi

# 7. Install and enable systemd unit
echo
echo "[7/7] Installing systemd unit …"
cat > "$SYSTEMD_UNIT" <<EOF
[Unit]
Description=BSH Bluetooth Shell Service
After=network.target bluetooth.target
Wants=bluetooth.target

[Service]
Type=simple
ExecStart=$PYTHON $INSTALL_DIR/bsh_service.py _run
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=bsh
User=root
Group=root
PrivateTmp=yes
ProtectSystem=full
ReadWritePaths=$DATA_DIR $LOG_DIR $RUN_DIR

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
ok "Systemd unit installed: $SYSTEMD_UNIT"

systemctl enable bsh
ok "BSH enabled on boot"

echo
echo "=================================================="
echo "  BSH installation complete!"
echo "=================================================="
echo
echo "  Start the service:"
echo "    sudo systemctl start bsh"
echo "     — or —"
echo "    sudo $PYTHON $INSTALL_DIR/bsh_service.py start"
echo
echo "  Check status:"
echo "    sudo $PYTHON $INSTALL_DIR/bsh_service.py status"
echo "     — or —"
echo "    systemctl status bsh"
echo
echo "  View logs:"
echo "    $PYTHON $INSTALL_DIR/bsh_service.py logs --follow"
echo "     — or —"
echo "    journalctl -u bsh -f"
echo
echo "  Bluetooth adapter info:"
echo "    hciconfig -a"
echo "    bluetoothctl show"
echo "=================================================="
