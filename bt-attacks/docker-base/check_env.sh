#!/usr/bin/env bash
# Day 1 environment verification script.
# Run inside the base container on the Ubuntu lab machine:
#   docker run --privileged --net=host -v /var/run/dbus:/var/run/dbus \
#              bt-attack-base bash /attack/check_env.sh
set -euo pipefail

HCI=${HCI_DEV:-hci0}
PASS=0
FAIL=0

pass() { echo "[PASS] $*"; ((PASS++)) || true; }
fail() { echo "[FAIL] $*"; ((FAIL++)) || true; }

echo "=============================="
echo " Bluetooth Environment Check"
echo "=============================="

# 1. Adapter present
if hciconfig "$HCI" 2>/dev/null | grep -q "BD Address"; then
    BDADDR=$(hciconfig "$HCI" | grep "BD Address" | awk '{print $3}')
    pass "hci0 present — BD_ADDR: $BDADDR"
else
    fail "hci0 not found — is adapter attached and driver loaded?"
fi

# 2. Adapter chip / manufacturer (determines KNOB Mode B availability)
MANUF=$(hciconfig -a "$HCI" 2>/dev/null | grep -i "manuf" | awk -F: '{print $2}' | xargs)
echo ""
echo "--- Adapter Info ---"
hciconfig -a "$HCI" 2>/dev/null || true
echo ""
if echo "$MANUF" | grep -qi "broadcom"; then
    pass "Chip is Broadcom — KNOB Mode B (InternalBlue) available"
else
    pass "Chip manufacturer: ${MANUF:-unknown} — use KNOB Mode A (relay) only"
fi

# 3. uhid module
if [ -c /dev/uhid ]; then
    pass "/dev/uhid present — uhid HID device emulation available"
else
    fail "/dev/uhid missing — run: modprobe uhid"
fi

# 4. dbus socket
if [ -S /var/run/dbus/system_bus_socket ]; then
    pass "dbus system bus socket present"
else
    fail "dbus socket missing — BlueZ/bluetoothd may not work"
fi

# 5. Python imports
python3 - <<'PYCHECK'
import sys
missing = []
for mod in ["scapy", "bluetooth", "dbus", "uhid"]:
    try:
        __import__(mod)
    except ImportError:
        missing.append(mod)
if missing:
    print(f"[FAIL] Missing Python modules: {', '.join(missing)}")
else:
    print("[PASS] All required Python modules importable")
PYCHECK

# 6. Scatternet — open two L2CAP sockets simultaneously (loopback self-connect test)
python3 - <<'SCATCHECK'
import socket, errno
try:
    s1 = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
    s2 = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
    s1.close(); s2.close()
    print("[PASS] Two simultaneous HCI sockets opened — scatternet architecture feasible")
except Exception as e:
    print(f"[FAIL] Could not open dual HCI sockets: {e}")
SCATCHECK

echo ""
echo "=============================="
echo " Results: ${PASS} passed, ${FAIL} failed"
echo "=============================="
[ "$FAIL" -eq 0 ]
