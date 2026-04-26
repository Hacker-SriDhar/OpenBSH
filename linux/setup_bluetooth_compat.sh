#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# BSH: Enable bluetoothd --compat mode (required for SDP advertisement)
#
# BlueZ 5+ disables legacy SDP server access by default. Both PyBluez's
# advertise_service() and sdptool need bluetoothd to be started with --compat.
#
# Run once (requires root):
#   sudo bash setup_bluetooth_compat.sh
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: This script must be run as root (use sudo)."
    exit 1
fi

DROPIN_DIR="/etc/systemd/system/bluetooth.service.d"
DROPIN_FILE="${DROPIN_DIR}/compat.conf"

# Detect actual bluetoothd binary path
BTDAEMON="$(systemctl show bluetooth -p ExecStart --value 2>/dev/null | awk '{print $2}' | tr -d '{')"
if [[ -z "${BTDAEMON}" ]]; then
    # Fallback: try common locations
    for p in /usr/libexec/bluetooth/bluetoothd /usr/lib/bluetooth/bluetoothd /usr/sbin/bluetoothd; do
        if [[ -x "${p}" ]]; then BTDAEMON="${p}"; break; fi
    done
fi

if [[ -z "${BTDAEMON}" ]]; then
    echo "ERROR: Could not find bluetoothd binary. Is BlueZ installed?"
    exit 1
fi

echo "  bluetoothd binary : ${BTDAEMON}"
echo "  Drop-in file      : ${DROPIN_FILE}"

mkdir -p "${DROPIN_DIR}"

cat > "${DROPIN_FILE}" << EOF
[Service]
# Clear the upstream ExecStart so we can override it completely
ExecStart=
# Re-add with --compat to allow legacy SDP registration (required for PyBluez
# advertise_service() and sdptool add SP)
ExecStart=${BTDAEMON} --compat
EOF

echo ""
echo "  Drop-in written. Reloading systemd and restarting bluetooth..."
systemctl daemon-reload
systemctl restart bluetooth

echo ""
echo "  Waiting for bluetoothd to settle..."
sleep 1

# Verify --compat is active
if systemctl show bluetooth -p ExecStart --value | grep -q '\-\-compat'; then
    echo "  ✓ bluetoothd is running with --compat"
else
    echo "  ⚠  Could not verify --compat flag — check: systemctl status bluetooth"
fi

# Test sdptool works now
if sdptool add --channel 1 SP 2>/dev/null; then
    echo "  ✓ sdptool SDP registration works"
else
    echo "  ⚠  sdptool still failing — check bluetoothd logs: journalctl -u bluetooth -n 20"
fi

echo ""
echo "Done. The BSH server will now advertise via SDP automatically."
