#!/usr/bin/env python3
"""
test_nino_offline.py — offline correctness tests for nino_mitm.py

Tests that require NO hardware:
  1. decode_hid_report — known inputs / edge cases
  2. _ASCII_TO_HID round-trip (char → keycode → decode → same char)
  3. make_hid_report encoding
  4. relay_loop logic via socketpair + a fake uhid write buffer (legacy)
  5. uhid struct sizes vs kernel uhid.h
  6. relay_kb_to_pc — true MITM forward path via dual socketpairs
  7. inject_to_pc — keystroke injection into PC-side L2CAP socket

Run as any user:
  python3 test_nino_offline.py
"""

import os
import socket
import struct
import sys
import threading
import time
import unittest

# ---------------------------------------------------------------------------
# Import the module under test (without executing main())
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(__file__))
import nino_mitm as N


# ---------------------------------------------------------------------------
# 1. decode_hid_report
# ---------------------------------------------------------------------------
class TestDecodeHidReport(unittest.TestCase):

    def _report(self, modifier, *keycodes):
        """Build an 8-byte boot-keyboard report."""
        keys = list(keycodes) + [0] * (6 - len(keycodes))
        return bytes([modifier, 0x00] + keys[:6])

    def test_single_lowercase(self):
        self.assertEqual(N.decode_hid_report(self._report(0x00, 0x04)), 'a')

    def test_single_uppercase_via_shift(self):
        self.assertEqual(N.decode_hid_report(self._report(0x02, 0x04)), 'A')

    def test_right_shift_also_uppercase(self):
        self.assertEqual(N.decode_hid_report(self._report(0x20, 0x04)), 'A')

    def test_digit(self):
        self.assertEqual(N.decode_hid_report(self._report(0x00, 0x1E)), '1')

    def test_digit_shifted_to_bang(self):
        self.assertEqual(N.decode_hid_report(self._report(0x02, 0x1E)), '!')

    def test_space(self):
        self.assertEqual(N.decode_hid_report(self._report(0x00, 0x2C)), ' ')

    def test_enter(self):
        self.assertEqual(N.decode_hid_report(self._report(0x00, 0x28)), '[ENTER]')

    def test_all_zeros_empty_string(self):
        self.assertEqual(N.decode_hid_report(bytes(8)), '')

    def test_short_report_empty_string(self):
        self.assertEqual(N.decode_hid_report(b'\x00\x00\x04'), '')

    def test_multiple_keys(self):
        # 'a' + 'b' simultaneously (unusual but valid)
        self.assertEqual(N.decode_hid_report(self._report(0x00, 0x04, 0x05)), 'ab')

    def test_unknown_keycode_hex_label(self):
        result = N.decode_hid_report(self._report(0x00, 0xFF))
        self.assertIn('0xff', result.lower())

    def test_arrow_right(self):
        self.assertEqual(N.decode_hid_report(self._report(0x00, 0x4F)), '[RIGHT]')


# ---------------------------------------------------------------------------
# 2. make_hid_report
# ---------------------------------------------------------------------------
class TestMakeHidReport(unittest.TestCase):

    def test_no_shift(self):
        r = N.make_hid_report(0x04, shift=False)
        self.assertEqual(len(r), 8)
        self.assertEqual(r[0], 0x00)   # no modifier
        self.assertEqual(r[2], 0x04)   # keycode

    def test_shift(self):
        r = N.make_hid_report(0x04, shift=True)
        self.assertEqual(r[0], 0x02)   # Left Shift
        self.assertEqual(r[2], 0x04)

    def test_release_report(self):
        self.assertEqual(N.RELEASE_REPORT, bytes(8))


# ---------------------------------------------------------------------------
# 3. _ASCII_TO_HID round-trip
# ---------------------------------------------------------------------------
class TestAsciiToHidRoundTrip(unittest.TestCase):
    """Every entry in _ASCII_TO_HID must survive the round-trip:
       char → (keycode, shift) → make_hid_report → decode_hid_report → char
    """

    def test_full_round_trip(self):
        failed = []
        for ch, (kc, shift) in N._ASCII_TO_HID.items():
            if ch.startswith('['):   # skip control-label strings like '[ENTER]'
                continue
            report = N.make_hid_report(kc, shift)
            decoded = N.decode_hid_report(report)
            if decoded != ch:
                failed.append(f'{repr(ch)} → kc=0x{kc:02x} shift={shift} → decoded {repr(decoded)}')
        self.assertFalse(failed, 'Round-trip failures:\n' + '\n'.join(failed))

    def test_lowercase_letters_present(self):
        for c in 'abcdefghijklmnopqrstuvwxyz':
            self.assertIn(c, N._ASCII_TO_HID, f'{repr(c)} missing from _ASCII_TO_HID')

    def test_digits_present(self):
        for c in '0123456789':
            self.assertIn(c, N._ASCII_TO_HID)

    def test_common_punctuation(self):
        for c in ' -=[];\'`,./':
            self.assertIn(c, N._ASCII_TO_HID, f'{repr(c)} missing')


# ---------------------------------------------------------------------------
# 4. relay_loop logic via socketpair + fake uhid buffer
# ---------------------------------------------------------------------------
class FakeUhidFd:
    """Mimics an os.write-able fd by capturing written bytes."""
    def __init__(self):
        self.written = []
        self._r, self._w = os.pipe()
        self.fd = self._w

    def read_events(self):
        """Drain the pipe and decode INPUT2 events → list of 8-byte reports."""
        os.set_blocking(self._r, False)
        buf = b''
        try:
            while True:
                buf += os.read(self._r, 65536)
        except BlockingIOError:
            pass
        events = []
        offset = 0
        fmt_size = struct.calcsize(N._INPUT2_FMT)
        while offset + fmt_size <= len(buf):
            chunk = buf[offset:offset + fmt_size]
            ev_type, size, data = struct.unpack(N._INPUT2_FMT, chunk)
            if ev_type == N.UHID_INPUT2:
                events.append(data[:size])
            offset += fmt_size
        return events

    def close(self):
        os.close(self._r)
        os.close(self._w)


class TestRelayLoop(unittest.TestCase):

    def _run_relay(self, packets, timeout=2.0):
        """Feed packets into relay_loop via socketpair, return uhid events."""
        srv, cli = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        fake_uhid = FakeUhidFd()
        stop = threading.Event()

        t = threading.Thread(
            target=N.relay_loop,
            args=(cli, fake_uhid.fd, stop),
            daemon=True,
        )
        t.start()

        for pkt in packets:
            srv.send(pkt)
            time.sleep(0.05)

        time.sleep(0.1)
        stop.set()
        t.join(timeout=timeout)
        srv.close()
        cli.close()

        events = fake_uhid.read_events()
        fake_uhid.close()
        return events

    def test_relay_strips_a1_header(self):
        """0xA1 header byte must be stripped before forwarding to uhid."""
        # 'a' keypress with 0xA1 prefix (as real keyboard sends it)
        report = bytes([0x04, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00])
        events = self._run_relay([b'\xA1' + report])
        self.assertTrue(len(events) >= 1)
        self.assertEqual(events[0][:8], report)

    def test_relay_passes_raw_report_without_header(self):
        """If no 0xA1 prefix, raw bytes are forwarded as-is."""
        report = bytes([0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00])
        events = self._run_relay([report])
        self.assertTrue(len(events) >= 1)
        self.assertEqual(events[0][:8], report)

    def test_relay_pads_short_report(self):
        """Reports shorter than 8 bytes must be zero-padded to 8 bytes."""
        # 4-byte short report for 'a'
        short = b'\xA1\x00\x00\x04'
        events = self._run_relay([short])
        self.assertTrue(len(events) >= 1)
        self.assertEqual(len(events[0]), 8)
        self.assertEqual(events[0][2], 0x04)   # keycode in position 2

    def test_relay_logs_keystroke(self, capsys=None):
        """decode_hid_report output should be printed (smoke test)."""
        import io, contextlib
        report = bytes([0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00])  # 'a'
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self._run_relay([b'\xA1' + report])
        self.assertIn('[RELAY]', buf.getvalue())
        self.assertIn('a', buf.getvalue())


# ---------------------------------------------------------------------------
# 5. uhid struct sizes vs kernel uhid.h
# ---------------------------------------------------------------------------
class TestUhidStructSizes(unittest.TestCase):
    """
    From linux/uhid.h (kernel 5.x+):
      struct uhid_event { u32 type; union { ... } u; }

    CREATE2 payload = name(128) + phys(64) + uniq(64) + rd_size(2) + bus(2)
                    + vendor(4) + product(4) + version(4) + country(4) + rd_data(4096)
                    = 4372 bytes → total event = 4 + 4372 = 4376

    INPUT2  payload = size(2) + data(4096) = 4098 bytes
                    → total event = 4 + 4098 = 4102
    """

    def test_create2_size(self):
        self.assertEqual(struct.calcsize(N._CREATE2_FMT), 4376)

    def test_input2_size(self):
        self.assertEqual(struct.calcsize(N._INPUT2_FMT), 4102)


# ---------------------------------------------------------------------------
# 6. relay_kb_to_pc — true MITM forward path (keyboard → PC)
# ---------------------------------------------------------------------------
class TestRelayKbToPc(unittest.TestCase):
    """
    Uses two Unix socketpairs to simulate the two L2CAP legs:
      kb_srv  →  kb_cli   (test feeds keyboard packets into kb_cli)
      pc_srv  →  pc_cli   (relay sends to pc_srv; test reads from pc_cli)

    relay_kb_to_pc(kb_cli, pc_srv, stop)
    """

    def _run_relay_kb_to_pc(self, packets, timeout=2.0):
        kb_srv, kb_cli = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        pc_srv, pc_cli = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        stop = threading.Event()

        t = threading.Thread(
            target=N.relay_kb_to_pc,
            args=(kb_cli, pc_srv, stop),
            daemon=True,
        )
        t.start()

        for pkt in packets:
            kb_srv.send(pkt)
            time.sleep(0.05)

        time.sleep(0.1)
        stop.set()
        t.join(timeout=timeout)

        # Drain everything pc_cli received
        pc_cli.setblocking(False)
        received = []
        try:
            while True:
                received.append(pc_cli.recv(64))
        except BlockingIOError:
            pass

        for s in (kb_srv, kb_cli, pc_srv, pc_cli):
            s.close()
        return received

    def test_forwards_with_a1_header_to_pc(self):
        """Packet received from keyboard must arrive at PC with 0xA1 header."""
        report = bytes([0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00])  # 'a'
        received = self._run_relay_kb_to_pc([b'\xA1' + report])
        self.assertTrue(len(received) >= 1)
        self.assertEqual(received[0], b'\xA1' + report)

    def test_raw_report_gets_a1_header_added(self):
        """Even if keyboard sends without 0xA1, PC must receive with 0xA1."""
        report = bytes([0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00])
        received = self._run_relay_kb_to_pc([report])
        self.assertTrue(len(received) >= 1)
        self.assertEqual(received[0][0:1], b'\xA1')

    def test_short_report_padded_before_forwarding(self):
        """Short report padded to 8 bytes; PC receives 0xA1 + 8 bytes."""
        short = b'\xA1\x00\x00\x04'   # only 3 payload bytes
        received = self._run_relay_kb_to_pc([short])
        self.assertTrue(len(received) >= 1)
        # total = 1 (0xA1) + 8 (padded report)
        self.assertEqual(len(received[0]), 9)
        self.assertEqual(received[0][0:1], b'\xA1')
        self.assertEqual(received[0][3], 0x04)   # keycode at offset 3 (1 header + 2 report bytes)

    def test_multiple_packets_all_forwarded(self):
        """All packets sent by keyboard arrive at PC in order."""
        reports = [
            b'\xA1' + bytes([0x00, 0x00, kc, 0, 0, 0, 0, 0])
            for kc in [0x04, 0x05, 0x06]   # a, b, c
        ]
        received = self._run_relay_kb_to_pc(reports)
        self.assertEqual(len(received), 3)
        self.assertEqual(received[0][3], 0x04)
        self.assertEqual(received[1][3], 0x05)
        self.assertEqual(received[2][3], 0x06)

    def test_relay_logs_keystrokes(self):
        """Keystrokes must be printed to stdout during relay."""
        import io, contextlib
        report = bytes([0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00])
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self._run_relay_kb_to_pc([b'\xA1' + report])
        self.assertIn('[RELAY]', buf.getvalue())
        self.assertIn('a', buf.getvalue())


# ---------------------------------------------------------------------------
# 7. inject_to_pc — keystroke injection into PC-side L2CAP socket
# ---------------------------------------------------------------------------
class TestInjectToPc(unittest.TestCase):
    """
    Uses a Unix socketpair to simulate the PC interrupt channel.
    inject_to_pc sends to pc_srv; test reads from pc_cli.
    """

    def _inject_and_capture(self, text, delay=0.001):
        pc_srv, pc_cli = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        # run injection in a thread so we can read concurrently
        t = threading.Thread(
            target=N.inject_to_pc,
            args=(pc_srv, text, delay),
            daemon=True,
        )
        t.start()
        t.join(timeout=5.0)

        pc_cli.setblocking(False)
        packets = []
        try:
            while True:
                packets.append(pc_cli.recv(64))
        except BlockingIOError:
            pass
        pc_srv.close()
        pc_cli.close()
        return packets

    def test_single_char_produces_press_and_release(self):
        """Each character must generate exactly one press + one release packet."""
        packets = self._inject_and_capture('a')
        self.assertEqual(len(packets), 2)

    def test_press_has_a1_header(self):
        packets = self._inject_and_capture('a')
        self.assertEqual(packets[0][0:1], b'\xA1')
        self.assertEqual(packets[1][0:1], b'\xA1')

    def test_press_encodes_correct_keycode(self):
        """'a' → keycode 0x04, no shift."""
        packets = self._inject_and_capture('a')
        press = packets[0][1:]   # strip 0xA1
        self.assertEqual(press[0], 0x00)   # no modifier
        self.assertEqual(press[2], 0x04)   # keycode 'a'

    def test_uppercase_sets_shift_modifier(self):
        """'A' → keycode 0x04 with Left Shift modifier (0x02)."""
        packets = self._inject_and_capture('A')
        press = packets[0][1:]
        self.assertEqual(press[0], 0x02)   # Left Shift
        self.assertEqual(press[2], 0x04)

    def test_release_is_all_zeros(self):
        """Release packet payload must be 8 zero bytes."""
        packets = self._inject_and_capture('a')
        release = packets[1][1:]   # strip 0xA1
        self.assertEqual(release, bytes(8))

    def test_multi_char_string(self):
        """'ab' → 4 packets: press a, release, press b, release."""
        packets = self._inject_and_capture('ab')
        self.assertEqual(len(packets), 4)
        self.assertEqual(packets[0][3], 0x04)   # 'a' keycode (offset 1+2)
        self.assertEqual(packets[2][3], 0x05)   # 'b' keycode

    def test_unmapped_char_skipped(self):
        """Characters not in _ASCII_TO_HID must be skipped, not crash."""
        # U+00E9 é is not in the map
        packets = self._inject_and_capture('\u00e9')
        self.assertEqual(len(packets), 0)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    unittest.main(verbosity=2)
