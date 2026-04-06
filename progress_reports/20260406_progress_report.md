# Method Confusion MITM — Implementation & PoC Analysis — 2026-04-06

## Environment

- **Host machine**: Lenovo V15 G4 IRU, Ubuntu 22.04
- **Bluetooth adapter**: Intel (manufacturer ID 2), `hci0`, BD_ADDR `E8:62:BE:42:BE:12`
- **Target device**: 지클릭커 오피스프로 WK90B (BLE-only, address `F3:E1:40:21:5A:47`, static random)
- **Working directory**: `~/bt-hid-attack-research-master/bt-attacks/method-confusion/`

---

## Summary

Two major tasks completed today:

1. **Python MITM skeleton (`method_confusion_mitm.py`)**: implemented all empty function bodies, identified and corrected 13 bugs across SMP protocol logic, missing symbols, and architecture
2. **BThack-master PoC analysis**: fully read and understood the original authors' C+BTstack implementation; assessed hardware requirements and feasibility on current lab machine

---

## Part 1 — method_confusion_mitm.py Implementation

### Starting Point

A skeleton file existed (`custom_mitm.py`, later renamed `method_confusion_mitm.py`) with constants and function signatures but no bodies. Nine functions needed implementation, and the file had multiple correctness issues.

### Functions Implemented

#### `open_hci_user(hci_index)`
Opens an `AF_BLUETOOTH / SOCK_RAW / BTPROTO_HCI` socket bound to `HCI_CHANNEL_USER=1`. This gives exclusive raw HCI access, bypassing BlueZ entirely. The fix here was simply adding the missing `return sock` line.

#### `hci_cmd(sock, opcode, param)`
Sends an HCI command packet (type `0x01`, opcode 2 LE bytes, plen 1 byte, params) and loops on `sock.recv(260)` until a Command Complete event (`0x0E`) for the matching opcode is received. Used by the advertising and connection functions.

#### `setup_advertise_as_keyboard(sock, keyboard_name, keyboard_addr)`
Builds a 31-byte BLE AD payload containing:
- Flags `0x02 0x01 0x06` (LE General Discoverable, BR/EDR Not Supported)
- Appearance `0x03C1` (keyboard)
- Complete UUID list `0x1812` (HID over GATT)
- Complete Local Name

Sends via `HCI LE Set Advertising Data` (opcode `0x2008`) then enables with `HCI LE Set Advertise Enable` (opcode `0x200A`).

#### `connect_to_keyboard(sock, keyboard_addr, addr_type)`
Converts the colon-separated MAC string to 6-byte little-endian, sends `HCI LE Create Connection` (opcode `0x200D`) with 25-byte parameter block, then polls for the `LE Meta` event (`0x3E`, subevent `0x01`) — LE Connection Complete. Returns the 12-bit ACL connection handle. Fixed: `RANDOM` undefined → replaced with `BLE_ADDR_RANDOM`.

#### `accept_pc_connection(sock)`
Waits for the same LE Connection Complete event but filters for `role=0x01` (peripheral/slave), meaning the PC initiated the connection to us. Correctly skips role=master events (those are the keyboard leg). Returns the PC connection handle.

#### `smp_run_leg_a(sock, kb_handle)` — Leg A toward keyboard (NC as initiator)

**Protocol flow (corrected):**
1. Send `SMP_PAIRING_REQUEST` with `IO_DISPLAY_YESNO`
2. Receive `SMP_PAIRING_RESPONSE`
3. Generate ECDH P-256 keypair (Session A)
4. Send `SMP_PUBLIC_KEY`
5. Receive keyboard's `SMP_PUBLIC_KEY`
6. Compute `dh_key_a = ECDH(priv_a, kb_pub)`
7. Generate `Na`, send `Ca = f4(PKa_x, PKb_x, Na, 0)` — **this step was missing in the original**
8. Receive keyboard's `Cb`
9. Send `Na` (reveal nonce)
10. Receive keyboard's `Nb`
11. Verify `Cb == f4(PKb_x, PKa_x, Nb, 0)`
12. Compute `passkey = g2(PKa_x, PKb_x, Na, Nb) % 10^6` — **replaced broken brute-force loop**
13. DHKey check exchange (calls `compute_dhkey_check_a/b`)

Key bug fixed: the original code tried to brute-force all 10^6 passkey candidates against a single `f4` commit value. This is wrong for NC mode — the passkey is directly `g2() % 10^6`, computed in one call after nonces are exchanged.

#### `smp_run_leg_b(sock, pc_handle, passkey_queue)` — Leg B toward PC (NC as responder)

**Protocol flow (corrected):**
1. Receive `SMP_PAIRING_REQUEST` from PC
2. Send `SMP_PAIRING_RESPONSE` with `IO_DISPLAY_YESNO`
3. Generate ECDH P-256 keypair (Session B — independent of Session A)
4. Receive PC's `SMP_PUBLIC_KEY`
5. Send our `SMP_PUBLIC_KEY`
6. Compute `dh_key_b = ECDH(priv_b, pc_pub)`
7. Receive PC's Confirm `Ca_pc` — **this step was missing in the original**
8. Generate `Nb_b`, send `Cb = f4(PKb_x, PKa_x, Nb_b, 0)` — **must commit before seeing Na**
9. Receive PC's `Na_pc`
10. Verify `Ca_pc == f4(PKa_x, PKb_x, Na_pc, 0)`
11. Send `Nb_b` (reveal nonce)
12. Compute `nc_value_b = g2(PKa_x, PKb_x, Na_pc, Nb_b) % 10^6`
13. Read passkey from `passkey_queue` (from Leg A); log whether values match
14. DHKey check exchange

Key bugs fixed:
- Original received `Na` (SMP_PAIRING_RANDOM) before sending Confirm — backwards per spec
- Completely missing receipt of PC's Confirm (Ca_pc)
- Nonce grinding loop removed: attacker must commit to `Nb_b` before `Na_pc` is known, so grinding post-Na is protocol-invalid

#### `gatt_setup_keyboard(sock, kb_handle)`
Sends ATT `Find By Type Value` (opcode `0x06`) for UUID `0x1812` (HID Service) to get service handle range, then `Read By Type` (opcode `0x08`) for UUID `0x2A4D` (HID Report) to find the value handle. Writes `0x0001` to the CCCD (handle+1) to enable notifications. Returns the HID Report handle.

#### `gatt_relay_loop(sock, kb_handle, pc_handle, stop)`
Replaces pseudo-code with real Python:
- `sock.recv(4096)` with `socket.timeout` handling on each iteration
- Checks HCI packet type (`0x02`) and ACL handle against `kb_handle`
- Checks L2CAP CID `0x0004` (ATT)
- Checks ATT opcode `0x1B` (Handle Value Notification)
- Calls `decode_hid_report()` and prints `[RELAY] KEY: x`
- Re-packs and sends notification to `pc_handle`

#### `gatt_inject(sock, pc_handle, text)`
Replaces pseudo-code with real Python:
- `_ASCII_TO_HID.get(ch)` guard against unmapped characters
- Packs ATT notification with correct header and `pc_handle`
- `time.sleep(0.02)` between press and release
- Sends `RELEASE_REPORT` between characters

#### `main()`
Full argument parser (`--target`, `--hci`, `--addr-type`, `--inject`). Flow:
1. `open_hci_user` → `sock.settimeout(2.0)`
2. `setup_advertise_as_keyboard`
3. `_accept_pc` thread → `pc_conn_q`
4. `connect_to_keyboard` → `kb_handle`
5. `pc_conn_q.get(timeout=120)` → `pc_handle`
6. Concurrent SMP threads (`_leg_a`, `_leg_b`) with `passkey_q`, `leg_a_q`, `leg_b_q`
7. `gatt_setup_keyboard` → `hid_handle`
8. `gatt_relay_loop` relay thread with `threading.Event` stop
9. Optional `gatt_inject`
10. `KeyboardInterrupt` → `stop.set()` → cleanup

### Remaining Issues After Today

| # | Location | Issue |
|---|----------|-------|
| 1 | File-wide | `decode_hid_report`, `make_hid_report`, `_ASCII_TO_HID`, `RELEASE_REPORT` not defined — copy from `nino_mitm.py` |
| 2 | Lines 269, 274, 351 | `compute_dhkey_check_a/b` not defined — requires f5 + f6 (AES-CMAC chain) implementation |
| 3 | SMP threads | Both `smp_run_leg_a` and `smp_run_leg_b` call `sock.recv()` on the same socket from separate threads — need a single dispatcher thread routing packets by `conn_handle` to per-leg queues |
| 4 | `gatt_inject` line 442 | Hardcoded HID handle `0x0012` — should accept `hid_handle` as parameter |
| 5 | Several functions | 6-space body indentation (non-standard but valid Python) |

---

## Part 2 — BThack-master PoC Analysis

### What BThack Is

`BThack-master/` is the original proof-of-concept released alongside the Method Confusion paper (Tschirschnitz, Peukert et al., IEEE S&P 2021). It is a C implementation using a forked version of the BTstack BLE stack.

### Directory Structure

```
BThack-master/
├── attack.py               # Python UI orchestrator with optional micro:bit jamming
├── full_mitm/full_mitm.c   # Complete bidirectional MITM relay (the key file)
├── discovery/discovery.c   # BLE scanner for locating target keyboard
├── NumericOnPasskey/       # NC→PE variant
├── PasskeyOnNumeric/       # PE→NC variant
└── performance_test/       # Pre-compiled test binaries
```

### How full_mitm.c Works

`full_mitm.c` runs two parallel BTstack state machines on two separate USB Bluetooth adapters:

- **Initiator role** (connects to real keyboard): scans by MAC, connects as central, runs LESC SMP pairing as initiator, opens L2CAP LE Data Channel on PSM `0x25`
- **Responder role** (advertises fake keyboard to PC): waits for PC to connect, runs LESC SMP pairing as responder, opens L2CAP LE Data Channel on PSM `0x25`

The two roles communicate via IPC pipes (`initiator_tx/rx`, `responder_tx/rx`). Once both L2CAP channels are established, HID data is forwarded bidirectionally. The Method Confusion is embedded in the IO capability negotiation: the forked BTstack allows mismatched IO caps that standard SM would reject.

### Two Critical Modifications in the BTstack Fork

The fork (`lupinglui/btstack`, branch `bthack_mods`) contains two patches that make the attack possible:

1. **DHKey validation disabled on responder** (`turnoff_dhkey_validation = 1`): the standard SM verifies the peer's DHKey check (f6) and aborts if it fails. Disabling this allows the attacker to complete pairing even when the two sessions have different ECDH keys.
2. **Arbitrary IO capability pairs allowed**: standard SM rejects pairing when the negotiated association model creates a contradiction (e.g., both sides claiming NC but the commit values don't match due to different session keys). The fork removes this check.

Without these two patches, `full_mitm.c` would fail at the DHKey check exchange — which is exactly where the Python implementation also needs `compute_dhkey_check_a/b`.

### Hardware Requirements

| Component | Requirement |
|-----------|-------------|
| Bluetooth adapters | **2 × USB** (one per role; cannot share) |
| Chipset | CSR 8510 (`lsusb: 0a12:0001`) or BTstack-supported equivalent |
| Intel hci0 (lab machine) | **Not compatible** — BTstack uses libusb directly; Intel firmware does not expose required HCI vendor commands |
| Jamming (optional) | 3 × BBC micro:bit with BTleJack firmware |

### Confirmed-Compatible Dongle

**ASUS USB-BT400** (`lsusb: 0b05:17cb`, CSR 8510 A10) — explicitly listed in BTstack's supported hardware list and referenced in BThack's own documentation.

Any dongle showing `0a12:0001` on `lsusb` is also acceptable. "CSR 4.0" printed on the dongle label is **not** a reliable indicator — many cheap dongles use clone chipsets with non-CSR USB IDs.

### Execution Flow (once hardware available)

```bash
# Build
cd ~/bt-hid-attack-research-master/BThack-master
git clone https://github.com/lupinglui/btstack && cd btstack && git checkout bthack_mods
# Set BTSTACK_ROOT in full_mitm/Makefile
make -C full_mitm

# Scan for keyboard
./discovery/discovery <initiator_usb_device_id>

# Run MITM
./full_mitm/full_mitm.bin <initiator_id> <responder_id> "WK90B" F3:E1:40:21:5A:47
```

Expected output:
```
INIT: Connection complete
RESP: Connection complete
INIT: Confirming numeric comparison: 123456
RESP: Confirming numeric comparison: 123456
INIT: Pairing complete
RESP: Pairing complete
INIT: L2CAP LE Data Channel successfully opened — relay active
```

### BThack Completeness Assessment

| Capability | Status |
|---|---|
| Full MITM relay (keyboard ↔ attacker ↔ PC) | ✅ Complete |
| LESC SMP pairing both sides | ✅ Complete |
| IO capability confusion (NC + PE variants) | ✅ Complete |
| Keystroke relay (HID notifications forwarded) | ✅ Complete |
| Keystroke logging | ✅ stdout output |
| Keystroke injection | ⚠️ Code present, not formally tested |
| Single-adapter operation | ❌ Requires 2 adapters |

---

## Hardware Decision

The current lab machine (Intel hci0 only) cannot run `full_mitm.c`. Two options going forward:

1. **Buy 2 × CSR 8510 USB dongles** → use `full_mitm.c` directly for the MITM demo
2. **Complete the Python implementation** → finish the 5 remaining items in `method_confusion_mitm.py` (HID codec copy + f5/f6 + dispatcher thread)

Both options can be pursued in parallel. The Python version is valuable for the poster even if BThack is used for the live demo, because it shows the attack architecture in readable code without a BTstack dependency.

---

## Files Changed

| File | Change |
|------|--------|
| `bt-attacks/method-confusion/method_confusion_mitm.py` | All empty functions implemented; SMP leg bugs fixed; main() written |
| `PROGRESS.md` | Day 5 marked in-progress; session log added |
| `CLAUDE.md` | BThack hardware requirements and Python missing symbols documented |
