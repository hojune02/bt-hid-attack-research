# NiNo MITM — Testing & Architecture Upgrade — 2026-04-02

## Environment

- **Host machine**: Lenovo V15 G4 IRU, Ubuntu 22.04
- **Bluetooth adapter**: Intel (manufacturer ID 2), `hci0`, BD_ADDR `E8:62:BE:42:BE:12`
- **KNOB Mode B eligibility**: Not applicable — Intel chip, Broadcom-only
- **Target devices available today**: None (BR/EDR keyboard deferred)
- **Working directory**: `~/bt-hid-attack-research-master/bt-attacks/nino/`

---

## Summary

Two major tasks completed today:

1. **Offline + kernel correctness testing** of the existing `nino_mitm.py` without hardware
2. **Architecture upgrade**: replaced the uhid PC-side with a true two-leg over-the-air MITM relay

---

## Part 1 — Offline & Kernel Testing (No Hardware)

### Motivation

The NiNo code was written on 2026-04-01 but had never been run. Before getting hardware, it was important to verify correctness of every function that could be tested without a keyboard or PC target.

### What Was Tested

#### 1. Pure function unit tests (25 tests)

Written in `test_nino_offline.py`, covering:

| Function | Tests | What was checked |
|---|---|---|
| `decode_hid_report` | 12 | Lowercase, uppercase via Left/Right Shift, digits, punctuation, Enter, arrows, all-zero (release), short report, multi-key, unknown keycode |
| `make_hid_report` | 3 | Modifier byte, keycode position, RELEASE_REPORT is all zeros |
| `_ASCII_TO_HID` round-trip | 4 | Every printable char in the map survives char → keycode → report → decode → same char; all lowercase, digits, common punctuation present |
| `relay_loop` via socketpair | 4 | 0xA1 header stripped, raw report passed without header, short report zero-padded to 8 bytes, keystroke printed to stdout |
| uhid struct sizes | 2 | CREATE2 fmt = 4376 bytes, INPUT2 fmt = 4102 bytes (matches kernel `linux/uhid.h`) |

All 25 passed.

#### 2. uhid kernel smoke test (root, no Bluetooth)

Opened `/dev/uhid`, sent a CREATE2 event, verified kernel accepted it, then sent DESTROY.

```
dmesg output:
input: NiNo-MITM-Keyboard as /devices/virtual/misc/uhid/0005:046D:C52B.0008/input/input28
hid-generic 0005:046D:C52B.0008: input,hidraw1: BLUETOOTH HID v0.01 Keyboard [NiNo-MITM-Keyboard] on 0:0:0:0
```

The kernel registered a virtual Bluetooth HID keyboard and assigned it an input node. The uhid path from userspace Python to OS input subsystem is fully functional.

#### 3. btmgmt io-cap verification (hci0, no target device)

```bash
sudo btmgmt -i hci0 power off
sudo btmgmt -i hci0 io-cap 3
sudo btmgmt -i hci0 power on
sudo btmgmt -i hci0 info
```

Output confirmed:
- `IO Capabilities successfully set`
- `settings: powered ssp br/edr le secure-conn`

The adapter will correctly advertise NoInputNoOutput before any pairing attempt — the core precondition for the NiNo Just Works force.

---

## Part 2 — Architecture Upgrade: True Two-Leg MITM

### Problem with the Original Design

The original `nino_mitm.py` used `uhid` on the PC-facing side:

```
[Keyboard] --BT L2CAP--> [Ubuntu attacker] --uhid--> [Ubuntu input subsystem]
```

This is not a true MITM. The MacBook is completely displaced — keystrokes arrive at the attacker's own OS, not at the MacBook. The attacker *replaces* the PC rather than sitting *between* the keyboard and the MacBook.

### True MITM Architecture

```
[Keyboard] --BT L2CAP--> [Ubuntu attacker / hci0] --BT L2CAP--> [MacBook]
                                      |
                                [keystroke log]
                                [injection]
```

The attacker holds two simultaneous ACL connections on a single `hci0` (BlueZ scatternet):
- **Keyboard leg**: attacker as HID Host, L2CAP client to keyboard on PSM 0x11/0x13
- **MacBook leg**: attacker as HID Device, L2CAP server accepting MacBook's inbound connection on PSM 0x11/0x13

Both sides believe they are in a direct HID session. The attacker is transparent.

### Why a Single hci0 Is Sufficient

- BlueZ scatternet allows one adapter to hold multiple simultaneous ACL connections — one as master (toward keyboard) and one as slave (toward MacBook)
- No BD_ADDR spoofing needed for NiNo because it targets **initial pairing**: the MacBook has never seen the keyboard before. The MacBook pairs with whatever device advertises as a keyboard — which is the attacker.
- Spoofing would only be needed for reconnection attacks (MacBook already bonded to the keyboard). NiNo is an initial-pairing attack.

### Changes Made to nino_mitm.py

#### New function: `bt_advertise_as_keyboard(hci)`

Sets Class of Device to `0x002540` (Peripheral/Keyboard), enables discoverable + connectable, and registers an HID SDP service record via `sdptool`. Without the SDP record, macOS refuses to complete the HID connection even after pairing succeeds.

#### New function: `accept_pc_connection(timeout=60.0)`

L2CAP server. Binds and listens on PSM 0x11 (Control) then PSM 0x13 (Interrupt), accepts one connection each, closes the server sockets, and returns `(pc_ctrl_sock, pc_intr_sock, pc_addr)`.

macOS always connects Control before Interrupt — the sequential accept order is intentional and required.

#### New function: `relay_kb_to_pc(kb_intr_sock, pc_intr_sock, stop)`

The true MITM forward path. Per packet:
1. `recv` from keyboard interrupt socket (1s timeout for stop-event responsiveness)
2. Strip `0xA1` HID-over-L2CAP transaction header if present
3. Zero-pad to 8 bytes if short
4. Decode with `decode_hid_report` and print `[RELAY] KEY: x`
5. **Re-add `0xA1` header** and send to MacBook interrupt socket

The re-add in step 5 is required — macOS HID stack expects the HID-over-L2CAP framing on inbound interrupt channel packets.

#### New function: `relay_pc_to_kb(pc_ctrl_sock, kb_ctrl_sock, stop)`

Reverse direction relay on the control channel. Forwards LED state (Caps Lock, Num Lock), HID feature requests, and SET_PROTOCOL commands from MacBook to keyboard verbatim. Without this, the keyboard's LED state diverges from what macOS thinks it is.

#### New function: `inject_to_pc(pc_intr_sock, text, delay=0.02)`

Injects arbitrary keystrokes directly into the MacBook's input stream over L2CAP. For each character: look up `(keycode, shift)` in `_ASCII_TO_HID`, send `0xA1 + make_hid_report(keycode, shift)`, sleep, send `0xA1 + RELEASE_REPORT`, sleep. Unmapped characters are skipped with a warning.

#### Updated `main()` flow

```
1. bt_setup_nino()            — NoInputNoOutput, SSP on, BR/EDR on
2. bt_advertise_as_keyboard() — CoD 0x002540, SDP HID record, discoverable
3. Start accept_pc_connection in thread (queue.Queue for result return)
4. bt_connect(keyboard)       — pairing + ACL
5. open_l2cap(keyboard, 0x11) — kb_ctrl_sock
6. open_l2cap(keyboard, 0x13) — kb_intr_sock
7. pc_queue.get(timeout=60)   — block until MacBook connects
8. Start relay_kb_to_pc thread
9. Start relay_pc_to_kb thread
10. Optional inject_to_pc()
11. Wait for Ctrl-C, stop threads, close all 4 sockets
```

`queue.Queue` is used to pass `(pc_ctrl_sock, pc_intr_sock, pc_addr)` from the accept thread back to main, since Python threads do not return values directly.

uhid code (`uhid_create`, `uhid_send_report`, `uhid_destroy`) is retained in the file — it is reused by the KNOB and WhisperPair attack scripts.

### Known Remaining Issues

| Location | Issue | Impact |
|---|---|---|
| `relay_kb_to_pc` line 393 | `pc_intr_sock.send()` outside try block | Silent crash if MacBook disconnects mid-relay |
| `relay_pc_to_kb` line 405 | `kb_ctrl_sock.send()` no OSError handler | Silent crash if keyboard disconnects mid-relay |
| `main()` line 471 | `pc_queue.get(timeout=60)` raises unhandled `queue.Empty` | Unclean exit if MacBook never connects |
| Module docstring line 8 | Still says `--uhid--> [Local OS input]` | Misleading only |
| `relay_loop`, `inject_string` | Dead code | Misleading only |

All three crash-path issues are disconnect edge cases — they do not affect the happy path.

---

## Part 3 — Extended Offline Test Suite (37 tests)

Added 12 new tests covering the two new relay functions:

### `TestRelayKbToPc` (5 tests) — dual socketpair harness

Used two `socket.socketpair(AF_UNIX, SOCK_SEQPACKET)` pairs to simulate both L2CAP legs:

| Test | What it verifies |
|---|---|
| `test_forwards_with_a1_header_to_pc` | Keyboard packet arrives at MacBook with 0xA1 header intact |
| `test_raw_report_gets_a1_header_added` | Even if keyboard omits 0xA1, MacBook receives it with 0xA1 added |
| `test_short_report_padded_before_forwarding` | Short reports are padded to 8 bytes before forwarding |
| `test_multiple_packets_all_forwarded` | Multiple packets forwarded in order |
| `test_relay_logs_keystrokes` | `[RELAY] KEY: x` appears in stdout |

### `TestInjectToPc` (7 tests) — socketpair as mock MacBook

| Test | What it verifies |
|---|---|
| `test_single_char_produces_press_and_release` | Each char → exactly 2 packets (press + release) |
| `test_press_has_a1_header` | Both press and release packets start with 0xA1 |
| `test_press_encodes_correct_keycode` | `'a'` → keycode 0x04, no modifier |
| `test_uppercase_sets_shift_modifier` | `'A'` → keycode 0x04, modifier 0x02 (Left Shift) |
| `test_release_is_all_zeros` | Release payload is 8 zero bytes |
| `test_multi_char_string` | `'ab'` → 4 packets in correct keycode order |
| `test_unmapped_char_skipped` | `'é'` skipped without crash |

**Final result: 37/37 tests pass.**

---

## Files Changed

| File | Change |
|---|---|
| `bt-attacks/nino/nino_mitm.py` | Upgraded to true two-leg MITM: added `bt_advertise_as_keyboard`, `accept_pc_connection`, `relay_kb_to_pc`, `relay_pc_to_kb`, `inject_to_pc`; updated `main()` to use L2CAP server for PC side |
| `bt-attacks/nino/test_nino_offline.py` | Extended from 25 to 37 tests; added `TestRelayKbToPc` and `TestInjectToPc` |
| `bt-attacks/nino/TESTING.md` | Fully rewritten for true MITM architecture; updated offline (37 tests) and online (steps 4–9 with MacBook) sections |
| `PROGRESS.md` | Added 2026-04-02 session rows |
| `PLAN.md` | Updated Day 2 and Linux APIs section to reflect L2CAP server (not uhid) |
| `CLAUDE.md` | Updated key technical decisions: NiNo PC-side uses L2CAP server; uhid retained for other scripts |

---

## What Remains for NiNo

| Item | Blocker |
|---|---|
| End-to-end relay test (keyboard + MacBook) | Need BR/EDR HID keyboard |
| Verify macOS SDP HID record acceptance | Need MacBook + keyboard |
| Test `relay_pc_to_kb` LED passthrough | Need MacBook + keyboard |
| Fix 3 remaining disconnect-edge-case bugs | Can do anytime (no hardware needed) |

---

## Key Technical Decisions Made Today

1. **uhid is not a MITM** — it delivers keystrokes to the attacker's own OS. A true MITM requires a second Bluetooth leg to the PC using an L2CAP server socket.
2. **Single hci0 is sufficient for NiNo** — BlueZ scatternet handles two simultaneous ACL connections. No BD_ADDR spoofing needed because NiNo targets initial pairing, not reconnection.
3. **0xA1 must be stripped inbound and re-added outbound** — the HID-over-L2CAP transaction header is present in raw L2CAP packets from the keyboard and expected by macOS on inbound packets, so both directions require explicit header handling.
4. **SDP registration is required** — macOS will pair successfully but refuse to open the HID L2CAP channels if no HID SDP service record is present on the attacker.
5. **`queue.Queue` is the correct pattern for returning values from accept threads** — Python threads do not have return values; storing results in a Queue and calling `queue.get()` in main is idiomatic.
