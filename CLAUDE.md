# Claude Context — Bluetooth HID Attack Research

## Project Summary

This is an active research project (CyPhy Lab, Georgia Tech, 4th year) implementing Dockerized full MITM attack tools for known Bluetooth vulnerabilities targeting keyboards and mice, plus discovering new Bluetooth vulnerabilities for a research poster.

**Lab machine:** Ubuntu 22.04, single `hci0` Bluetooth adapter. No jammers, no extra hardware.

## Active Plan

See [PLAN.md](PLAN.md) for the complete 14-day plan. See [PROGRESS.md](PROGRESS.md) for current status.

**At the start of every session: read PROGRESS.md first, then continue from where we left off.**

## Research Context

The student previously ran BlueToolkit on this machine and tested these 5 vulnerabilities on real devices:

1. **NiNo** — SSP MITM via NoInputNoOutput capability (Samsung Note10+, Note10, Galaxy S7, iPhone 13 Pro)
2. **KNOB** (CVE-2019-9506) — 1-byte entropy key negotiation on BR/EDR
3. **BLUR** — Cross-Transport Key Derivation (CTKD) exploitation
4. **Method Confusion** — LESC NC vs PE association confusion (Soundcore Motion X600 vulnerable)
5. **WhisperPair** (CVE-2025-36911) — Google Fast Pair unauthorized pairing

Reference papers are in `literature/`: `sec19-antonioli.pdf` (KNOB), `2009.11776v2.pdf` (BLUR), `2021-SP-Tschirschnitz_Peukert.pdf` (Method Confusion), `Nino_man-in-the-middle_attack_on_bluetooth_secure_simple_pairing.pdf` (NiNo). BlueToolkit slides and device inventory are also in `literature/`. Progress reports are in `progress_reports/`.

## Key Technical Decisions Already Made

- **Full MITM required** (not just PoC): each attack must relay all traffic between keyboard and PC, log keystrokes in real-time, and inject arbitrary keystrokes
- **Single hci0 relay architecture:** BlueZ scatternet allows one adapter to hold two ACL connections — HID Host to keyboard (L2CAP client) + HID Device to PC (L2CAP server, **true over-the-air relay**)
- **NiNo PC-side uses L2CAP server, not uhid:** attacker sets CoD=0x002540, registers HID SDP record via sdptool, listens on PSM 0x11/0x13 for PC inbound connection. uhid is kept only for attacks that need local OS injection (WhisperPair, KNOB).
- **No jamming needed:** attacks are performed at pairing stage when device is in pairing mode; lab controls the pairing window by turning off PC Bluetooth temporarily
- **KNOB Mode A** (relay-based, no firmware): attacker as MITM relay proposes `Lmin=1` to both sides. KNOB **Mode B** (InternalBlue, Broadcom-only) is optional. Lab chip is Intel — Mode B not applicable.
- **Docker:** `docker run --privileged --net=host -v /var/run/dbus:/var/run/dbus -v /dev/uhid:/dev/uhid`

## Target Directory Structure

```text
bt-attacks/
├── docker-base/Dockerfile
├── docker-compose.yml
├── knob/Dockerfile + knob_mitm.py
├── nino/Dockerfile + nino_mitm.py        ← Core relay architecture (built first, reused)
├── method-confusion/Dockerfile + confusion_mitm.py
├── blur/Dockerfile + blur_mitm.py
├── whisperpair/Dockerfile + whisperpair_mitm.py
└── vuln-research/
    ├── hogp_audit.py
    ├── ble_downgrade.py
    ├── irk_tracker.py
    └── l2cap_hid_fuzzer.py
```

## New Vulnerability Targets (Week 2)

Three most promising areas (in priority order):

1. **HOGP Unauthenticated HID Write** (Day 8): BLE keyboards that accept ATT writes to HID Report characteristics without bonding/encryption. Test: `gatttool` write to UUID `0x2A4D` without pairing. Buy cheap BLE keyboards if lab devices are premium.
2. **BLE LE SC Pairing Downgrade** (Day 9-10): Strip `SC` and `MITM` flags from `SMP_Pairing_Request` to force legacy Just Works pairing → derive LTK from TK=0 trivially.
3. **IRK Privacy Leakage** (Day 10): Keyboards that send IRK via `SM_Identity_Information` enable permanent tracking via RPA resolution even with randomized addresses.

## Behavior Instructions for Claude

- When starting a new session: read PROGRESS.md and pick up where we left off
- When completing a task: update PROGRESS.md immediately
- When writing attack code: every script must include working relay loop (read from keyboard side → log → write to PC side) plus injection function
- For BR/EDR HID relay (NiNo, KNOB): use L2CAP server sockets for PC-facing side; use `uhid` only when local OS injection is specifically required
- When in doubt about a design decision, refer to the original paper PDFs in this directory
- If a day's task takes longer than expected, skip Day 4 (KNOB Mode B) or Day 6 (BLUR) first — they are lowest priority
