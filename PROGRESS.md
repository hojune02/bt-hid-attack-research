# Research Progress Tracker

Update this file at the end of every work session. Claude reads this at the start of each session to continue from where we left off.

---

## Current Status

**Week:** Week 1 — in progress
**Last updated:** 2026-04-06
**Next task:** Day 5 continued — complete method_confusion_mitm.py (missing symbols + f5/f6) OR run BThack full_mitm.c once CSR dongles arrive

---

## Week 1: Full MITM Attack Implementation

| Day | Task | Status | Notes |
|-----|------|--------|-------|
| 1 | Environment setup + device inventory | [x] Done (partial) | Device inventory skipped — no devices available. Docker base image + full directory structure created. Chip check deferred to lab machine (run `check_env.sh` inside container). |
| 2 | NiNo Full MITM — core relay architecture | [x] Done | nino/nino_mitm.py — dual-role scatternet relay, keystroke logger, injector via uhid. Needs live test on Ubuntu lab machine with real keyboard. |
| 3 | KNOB Full MITM Mode A — relay + 1-byte entropy | [x] Done | knob/knob_mitm.py — entropy reduction via btmgmt, E0 cipher + 256-key brute force, relay inherited from NiNo, offline --bruteforce mode for pre-captured params. Needs unpatched kernel (< 5.1) for live entropy reduction; patched kernels require Mode B. |
| 4 | KNOB Mode B — InternalBlue passive intercept (optional) | [x] Done | knob/knob_mode_b.py — chip detection, PATCH_TABLE for BCM20702A1/4335C0/4345C0/4358A3/4375B1, InternalBlue writeMem patch, passive HCI sniffer for EN_RAND capture, E0 brute force integration. Functional only on Broadcom; gracefully skips otherwise. |
| 5 | Method Confusion Full MITM | [~] In progress | method_confusion_mitm.py skeleton written; BThack-master PoC analysed; hardware blocker: needs 2× CSR USB dongles |
| 6 | BLUR + WhisperPair Full MITM | [ ] Not started | |
| 7 | Integration + Docker polish | [ ] Not started | |

---

## Week 2: New Vulnerability Discovery

| Day | Task | Status | Notes |
|-----|------|--------|-------|
| 8 | HOGP unauthenticated HID write audit | [ ] Not started | |
| 9 | BLE LE SC pairing downgrade | [ ] Not started | |
| 10 | SC downgrade PoC finish + IRK tracking | [ ] Not started | |
| 11 | L2CAP / LMP fuzzing | [ ] Not started | |
| 12 | BD_ADDR spoofing reconnection bypass | [ ] Not started | |
| 13 | CVE gap analysis + vulnerability triage | [ ] Not started | |
| 14 | Documentation + poster draft | [ ] Not started | |

---

## Completed Attack Containers

- [~] `docker-base/` — Dockerfile written; must `docker build` on Ubuntu lab machine and run `check_env.sh` to confirm
- [~] `nino/` — true two-leg MITM implemented (2026-04-02); 37 offline tests pass; needs live BR/EDR keyboard + MacBook for full end-to-end test
- [~] `knob/` — knob_mitm.py written; needs unpatched kernel for live entropy reduction
- [~] `method-confusion/` — method_confusion_mitm.py skeleton written; BThack-master PoC available as fallback; blocked on CSR USB dongles for live test
- [ ] `blur/` — BLUR full MITM
- [ ] `whisperpair/` — WhisperPair full MITM

---

## Device Inventory

**Status: SKIPPED** — devices not available on Day 1. Fill in when devices are accessible.

To enumerate a device run (inside the base container on Ubuntu):
```bash
hcitool info <BD_ADDR>                         # LMP version, features
sdptool browse <BD_ADDR>                       # SDP / IO capabilities
gatttool -b <BD_ADDR> --primary                # GATT services (BLE)
```

| Device | BD_ADDR | Transport | IO Capability | Applicable Attacks | Chip |
|--------|---------|-----------|--------------|-------------------|------|
| (TBD) | | | | | |

---

## New Vulnerability Findings

*(Fill in during Week 2)*

| # | Vulnerability | Affected Devices | Impact | Novel? | CVE Filed? |
|---|--------------|-----------------|--------|--------|-----------|
| 1 | | | | | |
| 2 | | | | | |
| 3 | | | | | |

---

## Blockers / Issues

- **Device inventory deferred:** no BT devices available on Day 1. Will be filled in when devices are available (ideally before Day 2 testing begins).
- **Docker base image not yet built on lab machine:** transfer repo to Ubuntu and run `docker build -t bt-attack-base ./bt-attacks/docker-base`, then run `check_env.sh` to confirm hci0 + uhid + scatternet all pass.
- **Chip type unknown:** run `hciconfig -a hci0 | grep -i manuf` on Ubuntu to determine KNOB Mode B eligibility.

---

## Session Log

| Date | Work Done | Outcome |
|------|-----------|---------|
| 2026-04-06 | Day 5 — Method Confusion: wrote method_confusion_mitm.py skeleton; analysed BThack-master PoC | method_confusion_mitm.py has full structure (open_hci_user, setup_advertise_as_keyboard, connect_to_keyboard, accept_pc_connection, smp_run_leg_a/b corrected, gatt_setup_keyboard, gatt_relay_loop, gatt_inject, main). 6 bugs fixed in SMP legs (missing Ca send, wrong passkey recovery via g2, NC ordering). 6 missing symbols identified (decode_hid_report, make_hid_report, _ASCII_TO_HID, RELEASE_REPORT, compute_dhkey_check_a/b). BThack-master (Tschirschnitz et al. PoC) fully analysed: full_mitm.c is a complete C+BTstack MITM but requires 2× USB BT dongles (CSR 8510 / 0a12:0001) and forked BTstack (lupinglui/btstack bthack_mods). Current Intel hci0 is incompatible. Hardware decision: order 2× CSR 8510 dongles (ASUS USB-BT400 or confirmed 0a12:0001). |
| 2026-03-31 | Plan created and approved | PLAN.md, CLAUDE.md, PROGRESS.md created |
| 2026-04-01 | Day 1 partial — environment setup without device inventory | Created bt-attacks/ directory tree, docker-base/Dockerfile, all attack Dockerfiles (stubs), docker-compose.yml, check_env.sh. Device inventory and actual Docker build deferred to Ubuntu lab machine. |
| 2026-04-01 | Day 2 — NiNo Full MITM | Wrote nino/nino_mitm.py: NoInputNoOutput adapter setup via btmgmt, dual-role scatternet (L2CAP PSM 0x11+0x13 keyboard side + uhid PC side), relay loop with HID boot keyboard decoder, keystroke injector. |
| 2026-04-01 | Day 3 — KNOB Full MITM Mode A | Wrote knob/knob_mitm.py: entropy reduction via btmgmt set-min-enc-key-size 1, HCI monitor for Encryption_Change events, E0 cipher (4 LFSRs + summation combiner), 256-key brute force with HID validity heuristic, offline --bruteforce mode. |
| 2026-04-01 | Day 4 — KNOB Mode B + polish | Wrote knob/knob_mode_b.py: Broadcom chip detection, PATCH_TABLE (BCM20702A1/4335C0/4345C0/4358A3/4375B1), InternalBlue writeMem patch with pre-write safety check, passive HCI sniffer for EN_RAND/ACL, --sniff + --patch + --unpatch CLI. Updated Dockerfile to pull InternalBlue from git. Syntax-checked all three scripts. |
| 2026-04-02 | NiNo offline + kernel correctness testing (no keyboard) | Wrote test_nino_offline.py (25 tests): decode_hid_report edge cases, _ASCII_TO_HID round-trip, relay_loop via socketpair, uhid struct sizes vs kernel uhid.h. All 25 pass. Live kernel tests: uhid CREATE2 accepted → kernel registered NiNo-MITM-Keyboard virtual device (dmesg confirmed); btmgmt io-cap 3 accepted → adapter confirmed NoInputNoOutput. Chip: Intel (manufacturer 2) — KNOB Mode B not applicable. Created nino/TESTING.md with full offline + online test guide. |
| 2026-04-02 | NiNo — upgraded to true two-leg MITM (keyboard ↔ attacker ↔ MacBook) | Replaced uhid PC-side with real L2CAP server leg: bt_advertise_as_keyboard (CoD 0x002540 + SDP HID + discoverable), accept_pc_connection (L2CAP server PSM 0x11/0x13), relay_kb_to_pc (keyboard→PC with 0xA1 header forwarding + keystroke log), relay_pc_to_kb (LED/control passthrough), inject_to_pc (L2CAP injection to MacBook). Used queue.Queue to pass pc sockets from accept thread to main. Extended test suite to 37 tests covering relay_kb_to_pc (5 tests) and inject_to_pc (7 tests) — all pass. Updated TESTING.md, PLAN.md, CLAUDE.md. |
