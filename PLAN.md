# 2-Week Bluetooth Attack & Vulnerability Research Plan

## Context

After presenting BlueToolkit results to professor, two tasks were assigned:

1. Produce actual Dockerized **full MITM attack code** for each vulnerability — each must: establish MITM position, relay all traffic between keyboard/mouse and host, log keystrokes in real-time, and inject arbitrary keystrokes.
2. Discover 2-3 NEW Bluetooth vulnerabilities against keyboards/mice for a research poster.

**Hardware constraint:** Single laptop with `hci0` only. No jammer, no SDR, no extra BT dongles.

---

## How Full MITM Works on a Single hci0

### Single-Adapter Relay MITM Architecture

BlueZ on Linux supports **scatternet** — one adapter can simultaneously be:

- **HID Host** (master): connected to the keyboard, receiving HID reports
- **HID Device** (slave): connected to the PC, sending HID reports forward

This means a single `hci0` maintains **two ACL connections at once**:

```text
[Keyboard] ---ACL_A---> [hci0 / ATTACKER] ---ACL_B---> [PC Host]
                               |
                         [Keystroke log]
                         [Injection module]
```

The relay loop reads HID reports from ACL_A, optionally modifies them, and writes them to ACL_B — and vice versa for control channel messages. Injection sends frames on ACL_B without receiving from ACL_A.

**Linux APIs used:**

- `socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI)` — raw HCI socket for both connections
- `socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP)` — L2CAP for HID Control + Interrupt channels (both outbound to keyboard and inbound server for PC)
- `btmgmt` — manage pairing modes, IO capability, Class of Device
- `sdptool` — register HID SDP service record so PC discovers attacker as keyboard
- `uhid` kernel module — kept for local injection use cases (WhisperPair, KNOB); **not used in NiNo relay path**

### Why No Jamming Is Needed

All five attacks are performed **at the pairing stage**, when the keyboard/mouse is in pairing mode for the first time (or after a factory reset). In this window, no existing connection exists — the attacker simply responds first. No signal jamming is required:

- The keyboard is advertising/discoverable but not yet connected to anything
- The attacker connects before the legitimate host does (controllable in the lab by simply turning off the PC's Bluetooth for the 10-second window while the attack pairs)
- This is the standard threat model in all five original papers — none of them require RF jamming

---

## Attack Relevance and Single-Adapter Feasibility

| Attack | MITM Mechanism | Single hci0 Feasible? | Notes |
|--------|---------------|----------------------|-------|
| **KNOB** | Reduce entropy during LMP key negotiation, brute force session key | YES — two modes | Mode A: relay proposes Lmin=1; Mode B: InternalBlue (Broadcom only) |
| **NiNo** | Claim NoInputNoOutput → force Just Works on both ends → hold both connections | YES | Scatternet: hci0 = HID host to keyboard + HID device to PC |
| **Method Confusion** | NC with one side, PE with other → separate ECDH keys per session | YES | Two BLE virtual identities on same adapter |
| **BLUR** | CTKD key overwrite across transports | YES | Single adapter initiates BLE pairing to overwrite BT Classic keys |
| **WhisperPair** | Forcible Fast Pair pairing without user consent | YES | Standard BLE connection |

### KNOB — Two Modes

**Mode A — Relay MITM (always works, no chip dependency):**
When already the relay MITM node (via NiNo), the attacker controls both LMP negotiations and simply proposes `Lmin=1` to both keyboard and PC. No firmware patching needed.

**Mode B — Passive Entropy Reduction (chip-dependent):**
InternalBlue intercepts in-flight LMP packets between two other devices. Requires Broadcom BCM4xxx chip.

- Check chip: `hciconfig -a | grep -i manuf`
- If Broadcom → Mode B available; if Intel/Realtek → use Mode A only

---

## Docker Architecture

```text
bt-attacks/
├── docker-base/
│   └── Dockerfile          # Ubuntu 22.04 + BlueZ + Python3 + Scapy + InternalBlue + uhid
├── knob/
│   ├── Dockerfile
│   └── knob_mitm.py        # Mode A: relay + propose Lmin=1 to both; Mode B: InternalBlue intercept
├── nino/
│   ├── Dockerfile
│   └── nino_mitm.py        # Dual ACL scatternet relay (HID host + HID device via uhid)
├── method-confusion/
│   ├── Dockerfile
│   └── confusion_mitm.py   # Dual BLE ECDH sessions + GATT relay + inject
├── blur/
│   ├── Dockerfile
│   └── blur_mitm.py        # BLE CTKD key overwrite + session relay
├── whisperpair/
│   ├── Dockerfile
│   └── whisperpair_mitm.py # Fast Pair GATT provider + HID relay + inject
└── docker-compose.yml
```

**Docker run command:**

```bash
docker run --privileged --net=host \
  -v /var/run/dbus:/var/run/dbus \
  -v /dev/uhid:/dev/uhid \
  bt-attack-<name>
```

**Base image packages:** `bluez`, `bluetooth`, `bluez-tools`, `python3`, `scapy[bluetooth]`, `pybluez`, `internalblue`, `hcitool`, `hciconfig`, `gatttool`, `bluetoothctl`, `btmgmt`, Python `uhid` bindings

---

## 14-Day Plan

### Week 1: Full MITM Attack Implementation

#### Day 1 — Environment Setup & Device Inventory

**Goal:** Verified Docker BT environment + full target device profile

Tasks:

- Build Docker base image; confirm scatternet works (`hciconfig` + connect to two BT devices simultaneously)
- Check adapter chip: `hciconfig -a | grep -i manuf` — determine if KNOB Mode B is available
- Inventory all BT keyboards and mice:
  - `hcitool info <addr>` → firmware, LMP version, features
  - SDP enumeration → HID descriptor, IO capabilities
  - BLE: `gatttool -b <addr> --primary` → GATT services (check for HOGP UUID `0x1812`, Fast Pair UUID `0xFE2C`)
- Classify each device: Just Works? Passkey Entry? NC? BLE or BR/EDR?
- **Output:** `devices.json` mapping each device to its applicable attacks

#### Day 2 — NiNo Full MITM (Core Relay Architecture)

**Goal:** Build the reusable relay architecture used by NiNo (and reused by KNOB Mode A)

This is the most foundational component — all other relay attacks build on it.

Tasks:

- Implement dual-role scatternet on `hci0`:
  - Role 1 (HID Host): connect to keyboard, open L2CAP on PSM 0x0011 + 0x0013
  - Role 2 (HID Device): set CoD to keyboard class (0x002540), register HID SDP record via sdptool, listen on PSM 0x0011 + 0x0013 for PC's inbound L2CAP connection — **true over-the-air relay, no uhid**
- Implement relay loop: read L2CAP frames from keyboard side, write to PC side, and vice versa
- Verify transparent relay: keystrokes typed on keyboard appear on PC without any delay/error
- Implement **keystroke logger**: decode HID boot keyboard reports (8-byte format) to ASCII
- Implement **keystroke injector**: craft HID report for arbitrary keystroke, send on PC-facing L2CAP channel
- **Demo:** Type "password" on keyboard → terminal shows it; inject → "INJECTED" appears on PC
- **NiNo pairing:** both sides use NoInputNoOutput → Just Works

#### Day 3 — KNOB Full MITM (Mode A: Relay + 1-Byte Entropy)

**Goal:** Reduce key entropy during attacker-controlled LMP negotiation

Since the attacker IS the relay MITM node (from Day 2), it controls both LMP key negotiations.

Tasks:

- Implement raw LMP packet construction using HCI VS commands
- Intercept and respond to `LMP_encryption_key_size_req` (opcode 0x0F) on both connections; propose entropy=1
- Verify with `hcidump -X` that session key is 1 byte
- Implement E0 brute force (256 keys): using AU_RAND + EN_RAND from LMP frames + victim BD_ADDR
- Confirm correct key by decrypting a known HID frame
- **Output:** `knob/knob_mitm.py` — relay + entropy reduction + brute force in single script

#### Day 4 — KNOB Mode B (Optional: InternalBlue Passive Intercept)

**Goal:** If Broadcom chip present, implement passive in-flight LMP modification

Tasks:

- Install InternalBlue in Docker with Broadcom firmware patches
- Patch `lmp_encryption_key_size_req` handler to modify packets between two external devices
- If chip is Intel/Realtek → skip and use Day 4 as buffer for Day 2-3 polish

#### Day 5 — Method Confusion Full MITM

**Goal:** NC/PE confusion → dual ECDH sessions → BLE GATT relay

Architecture: hci0 runs two BLE SMP state machines simultaneously.

- Session A (with BLE keyboard): advertise `DisplayOnly` → keyboard uses PE → keyboard displays passkey
- Session B (with PC): advertise `DisplayYesNo` → PC uses NC → confirm same 6-digit value

The 6-digit NC value and PE passkey are cryptographically identical (both derived from `f4(PKa, PKb, Na, 0)`). Attacker reads value from Session A and feeds it into Session B — both sides confirm.

Tasks:

- Use Scapy + raw BLE sockets for two separate SMP state machines on hci0
- Implement ECDH separately per session; manipulate `IOCapability` field in SMP PDUs
- Relay SMP_Confirm values between sessions
- After pairing: hold LTK_A and LTK_B; set up GATT relay for HID notifications
- Injection: fabricated ATT Write to PC's HOGP HID Report characteristic

#### Day 6 — BLUR Full MITM + WhisperPair Full MITM

**BLUR (morning):**

- Identify dual-transport device (smartphone or modern combo keyboard)
- BLE master impersonation using victim's BT Classic BD_ADDR → CTKD derives new BT Classic link key
- Attacker holds new link key → relay MITM loop
- Fallback: demo on smartphone; document keyboard applicability in comments

**WhisperPair (afternoon):**

- Implement GATT Fast Pair provider (UUID `0xFE2C`) → forced pairing without user consent
- Use uhid relay to forward HID between attacker-as-host (keyboard) and attacker-as-keyboard (PC)

#### Day 7 — Integration + Docker Polish

**Goal:** All 5 MITM containers working with clean output

Tasks:

- Test each container against each device from Day 1 inventory
- Fix HCI conflicts: `btmgmt power off` before switching containers
- Standardize output: `[PAIRING]`, `[RELAY] KEY: <ascii>`, `[INJECT] <payload>`, `[MITM] Session established`
- Write `run.sh` per attack; write `docker-compose.yml`

---

### Week 2: New Vulnerability Discovery

#### Day 8 — HOGP Unauthenticated HID Write Audit

**Goal:** Find BLE keyboards/mice accepting HID Report writes without authentication

Theory: HOGP spec §3.11 mandates "Authentication Required" on HID Report characteristics. Many cheap BLE peripherals skip this.

Tasks:

- Connect WITHOUT bonding: `gatttool -b <MAC> -I` → `connect`
- Find HID Report descriptor (UUID `0x2A4D`) handles
- Test Output write (LED toggle): `char-write-req <handle> 01` — if LED changes, security level not enforced
- Test Input write (keystroke injection): `00 00 04 00 00 00 00 00` = key 'a' in HID boot keyboard format
- Search NVD + Google Scholar for existing CVEs to verify novelty
- **Expected yield:** 1-3 budget BLE keyboards vulnerable; if lab devices are all premium, order cheap ones (~$15 each)

#### Day 9 — BLE LE SC Pairing Downgrade

**Goal:** Strip SC flag from SMP → force legacy pairing → derive LTK in seconds

Tasks:

- Craft modified `SMP_Pairing_Request` with `AuthReq.SC=0` and `AuthReq.MITM=0` (Just Works)
- If keyboard responds without reasserting `SC=1` → downgrade accepted
- Complete Just Works legacy pairing: TK=0 → STK = s1(0, Srand, Mrand) (both visible in plaintext SMP PDUs)
- Derive LTK from STK; integrate as relay MITM using derived LTK

#### Day 10 — SC Downgrade PoC Finish + IRK Privacy Tracking

**Goal:** Finalize downgrade PoC + IRK leakage for tracking vulnerability

IRK tracking:

- Initiate bonding as fresh device identity; capture `SM_Identity_Information` PDU containing keyboard's IRK
- Implement RPA resolver: `ah(IRK, prand) == hash` → resolve any BLE advertisement back to device
- Privacy vulnerability: keyboard trackable across all environments even with randomized addresses

#### Day 11 — L2CAP / LMP Fuzzing of BT Classic Keyboards

**Goal:** Find crash or unintended behavior in keyboard firmware

Targets:

- `L2CAP_ConfigReq` on PSM 0x0013 with `MTU=65535` (spec max is 672 for HID)
- Malformed HID Report Descriptor via L2CAP HID Control (truncated, invalid usage pages `0xFFFF`)
- `L2CAP_ConnectionReq` on unregistered PSM values
- `LMP_max_slots_req` with value 0
- Flood HID Interrupt at 1000 packets/second for 30 seconds

Monitor for: device stops responding, spontaneous HID disconnect/reconnect, unexpected pairing prompts.

#### Day 12 — BD_ADDR Spoofing Reconnection Bypass

**Goal:** Test if keyboards authenticate reconnecting hosts or trust BD_ADDR alone

Tasks:

- Get PC's BD_ADDR paired with the keyboard
- Spoof attacker BD_ADDR: `bdaddr -i hci0 <PC_BD_ADDR>`
- Connect to keyboard on PSM 0x0013; observe if `LMP_au_rand` challenge is issued
- If NOT challenged → auth bypass; send keystrokes without pairing
- BLE variant: spoof Identity Address of bonded host → GATT access without re-bonding

#### Day 13 — CVE Gap Analysis + Vulnerability Triage

**Goal:** Assess novelty; prepare technical write-ups

Tasks:

- Compile all findings from Days 8-12 with device + firmware + behavior + HCI capture
- Search NVD, Google Scholar, IEEE/USENIX/CCS, Bluetooth SIG bulletins
- Key terms: `"HOGP unauthenticated"`, `"BLE pairing downgrade keyboard"`, `"IRK leakage"`, `"Bluetooth keyboard BD_ADDR spoof"`
- Select top 2-3 by impact × novelty × reproducibility
- Write 200-300 word technical description per finding (affected devices, prerequisites, steps, impact, mitigation)

#### Day 14 — Documentation + Poster Draft

Tasks:

- Final cleanup of all 5 Docker MITM containers; `README.md` per container
- `VULNERABILITIES.md` with full write-up + PoC scripts
- Poster draft: "MITM Attacks and Novel Vulnerabilities in Bluetooth HID Peripherals"
  - Background → 5 Known Attacks → 2-3 New Findings → Impact → Mitigations
- Consider responsible disclosure for novel CVEs

---

## Guaranteed New Vulnerability Strategy

### 1. HOGP Unauthenticated HID Write — HIGHEST CONFIDENCE (Day 8)

Budget BLE keyboards routinely fail to enforce ATT security levels on HID characteristics. Fast to test, clear impact, under-reported for specific device models. **Buy 2-3 cheap BLE keyboards (~$15 total) if lab devices are all premium.**

### 2. LE SC Pairing Downgrade — HIGH CONFIDENCE (Days 9-10)

SC flag stripping is theoretically known but has no published Dockerized PoC targeting keyboards/mice with specific chipset + firmware documentation. Documenting this on RTL8761B, EFR32BG22, CSR8811 qualifies as a new targeted contribution.

### 3. IRK Leakage / Passive Tracking — HIGH CONFIDENCE (Day 10)

Systematically testing BLE keyboards for IRK exchange + building an RPA resolver is a new privacy measurement study. High reproducibility, clear impact, distinct from authentication attacks.

---

## Risk Mitigation

| Risk | Mitigation |
|------|-----------|
| Scatternet unstable | Test Day 1; if unstable, borrow second laptop for PC-side (attacker uses hci0, PC connects normally) |
| No Broadcom chip for KNOB Mode B | Use KNOB Mode A (relay + entropy negotiation) — same cryptographic result |
| Method Confusion needs two BLE contexts | Time-sliced approach if hci0 can't maintain two simultaneous BLE connections |
| HOGP audit finds nothing on lab devices | Order cheap BLE keyboards (~$15) — budget peripherals highest-risk |
| L2CAP fuzzing yields only disconnects | Reproducible disconnect on malformed L2CAP is still a reportable DoS finding |
| BLUR not applicable to keyboards in inventory | Demo on smartphone; document applicability for dual-transport keyboards in comments |
| Day tasks run over | Days 4 (KNOB Mode B) and 6 (BLUR) are lowest priority — cut first |

---

## Verification Criteria

- **MITM proof per container:** Type on keyboard → terminal prints keystroke; inject from script → character appears on PC
- **New vulns:** Each finding = affected device + firmware + PoC script + HCI capture + CVE search negative
- **Docker portability:** Each container works with `docker run --privileged --net=host` on any machine
