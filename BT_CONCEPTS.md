# Bluetooth Security: A Complete Conceptual Foundation

**Prepared for:** A student with zero Bluetooth background who will implement the attacks described in PLAN.md  
**Written by:** A professor's perspective — 30+ years in systems and wireless security

Read this document from start to finish before writing a single line of code. Every term used in PLAN.md is defined here in the order you will need it.

---

## Part I: What Is Bluetooth, and Why Does It Have Two Personalities?

Bluetooth is a short-range (typically 1–100 meters) wireless communication standard managed by the **Bluetooth Special Interest Group (Bluetooth SIG)**, a consortium of thousands of companies. It operates in the unlicensed **2.4 GHz ISM (Industrial, Scientific, Medical)** radio band — the same band as Wi-Fi and microwave ovens.

### The Two Flavors: BR/EDR and BLE

Here is the single most important distinction to understand before doing anything else:

**Bluetooth Classic** — formally called **BR/EDR** (Basic Rate / Enhanced Data Rate) — is the original Bluetooth protocol introduced in 1999. When your laptop connects to a wireless keyboard or pairs a Bluetooth headphone, it uses BR/EDR. It is optimized for continuous, relatively high-bandwidth connections. Your keyboard uses this.

**Bluetooth Low Energy (BLE)** — introduced in Bluetooth 4.0 (2010) — is a completely different protocol that shares only the brand name and the 2.4 GHz band with BR/EDR. BLE was designed for devices that send tiny bursts of data infrequently and must run for years on a coin cell battery. Modern "smart" keyboards, fitness trackers, and IoT sensors use BLE.

These two protocols have different packet formats, different security mechanisms, different pairing procedures, and different software stacks. A Bluetooth chip that supports both is called **dual-mode** or **dual-transport**. Many modern devices — smartphones, laptops — have dual-mode chips and can speak both protocols simultaneously.

Throughout this document and PLAN.md, when you see "BT Classic" or "BR/EDR" vs "BLE," these refer to two fundamentally different systems that happen to share a radio band.

---

## Part II: The Bluetooth Protocol Stack — Layers From Radio to Application

Both BR/EDR and BLE are built in layers, like a cake. Each layer provides services to the layer above it and uses services from the layer below it. Understanding this layering is essential because each attack operates at a specific layer.

### 2.1 The Physical and Baseband Layers (Radio Layer)

The **Physical Layer (PHY)** is the actual radio hardware — the antenna, the modulator, the receiver. Bluetooth uses **frequency-hopping spread spectrum (FHSS)**: both communicating devices hop between 79 different 1 MHz-wide channels in the 2.4 GHz band, 1600 times per second, following a pseudo-random but synchronized sequence. This is why Bluetooth is resistant to simple jamming — the signal constantly moves.

The **Baseband Layer** sits directly above the PHY. It handles:
- Synchronization between devices (ensuring both devices hop to the same frequency at the same time)
- Defining the **piconet** topology (see Section 3)
- Packet framing and basic error detection (CRC)
- Defining connection types: **ACL** (Asynchronous Connection-oriented Logical) for data, and SCO/eSCO for audio

**ACL** is the connection type you will work with almost exclusively. All data in keyboards and mice flows over ACL links. When PLAN.md says "ACL_A" and "ACL_B," it means two separate data connections, one to the keyboard and one to the PC.

### 2.2 LMP — Link Manager Protocol (BR/EDR Only)

**LMP (Link Manager Protocol)** is a control protocol that runs between two Bluetooth controllers (the hardware chips). It handles:
- **Authentication and encryption negotiation** — including key size negotiation (which KNOB attacks)
- Role switching (who is master, who is slave)
- Power management
- Feature exchange

LMP messages are exchanged directly between chips, completely below the operating system level. The CPU running your OS cannot see or control LMP messages. This is exactly why the KNOB attack was so devastating — it happened in the controller firmware, invisible to the OS.

Key LMP packets you will encounter:
- **`LMP_encryption_key_size_req`** — one device proposes an encryption key size. KNOB attack modifies this.
- **`LMP_au_rand`** — Authentication Random value, used in the challenge-response authentication protocol. If a keyboard sends `LMP_au_rand` when you connect to it, it is requesting authentication. If it doesn't send it, it trusts you based on address alone (the Day 12 attack tests this).
- **`LMP_max_slots_req`** — negotiates how many time slots per packet can be used. Used for fuzzing on Day 11.

### 2.3 HCI — Host Controller Interface

**HCI (Host Controller Interface)** is the standard boundary between the Bluetooth hardware (the "controller") and the operating system software (the "host"). In a laptop, the Bluetooth chip (controller) connects to the CPU (host) via USB or UART. HCI is the language they speak over that cable.

HCI defines:
- **HCI Commands**: the host tells the controller to do something (e.g., "scan for devices," "connect to this address," "start encryption")
- **HCI Events**: the controller tells the host something happened (e.g., "connection established," "pairing complete," "new device found")
- **HCI ACL Data Packets**: actual data being sent/received over Bluetooth connections

In Linux, the HCI interface appears as `hci0` (and `hci1`, `hci2`, ... if you have multiple adapters). Tools like `hciconfig`, `hcitool`, and `btmgmt` communicate with the controller via HCI. When PLAN.md says "raw HCI socket," it means you open `socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI)` in Python/C to interact directly with the HCI layer without going through BlueZ's higher-level abstractions.

**`hciconfig`** — configure the adapter (turn on/off, set class, show info). `hciconfig hci0 up` turns the adapter on; `hciconfig -a` shows detailed info including the manufacturer (which tells you if the chip is Broadcom, Intel, Realtek, etc.).

**`hcitool`** — discover and manage connections. `hcitool scan` finds BR/EDR devices; `hcitool lescan` finds BLE devices; `hcitool info <addr>` retrieves detailed device information. `hcitool cc <addr>` creates a connection.

**`btmgmt`** — higher-level management interface. `btmgmt power off/on` powers the adapter down/up. More reliable than `hciconfig` on modern BlueZ.

**`hcidump`** — captures and displays raw HCI traffic, similar to Wireshark but for the HCI bus. `hcidump -X` shows hex dumps of all HCI packets, which lets you verify LMP negotiation values.

**VS (Vendor Specific) Commands** — HCI commands with opcode group `0x3F` are vendor-specific, meaning they are NOT standardized and each chip manufacturer defines their own. Broadcom's VS commands allow direct firmware interaction, which is what InternalBlue exploits.

### 2.4 L2CAP — Logical Link Control and Adaptation Protocol

**L2CAP (Logical Link Control and Adaptation Protocol)** is the data multiplexing layer sitting above the baseband/HCI. It solves a fundamental problem: many different protocols (HID, A2DP audio, RFCOMM serial, SDP service discovery) all need to send data over the same single physical connection. L2CAP acts like a router inside the connection — it assigns each higher-level protocol its own **channel**, identified by a **CID (Channel Identifier)**.

For our purposes, L2CAP also provides:
- **PDU fragmentation and reassembly**: splits large messages into baseband-sized packets
- **MTU negotiation**: defines maximum packet size for each channel. The normal maximum for HID is 672 bytes. On Day 11, you fuzz by sending `L2CAP_ConfigReq` with MTU=65535 to test if the keyboard handles an out-of-spec value without crashing.

**PSM — Protocol Service Multiplexer**: In BR/EDR, L2CAP uses PSM numbers to identify which higher-level protocol a channel belongs to, similar to TCP port numbers. Standard PSM values relevant to HID:

- **PSM 0x0001** — SDP (Service Discovery Protocol) — for looking up services
- **PSM 0x0011** — **HID Control** — used for out-of-band control messages between keyboard and host (e.g., "set LED state", "get report"). Think of this as the command channel.
- **PSM 0x0013** — **HID Interrupt** — used for the actual keystroke data flowing from keyboard to host (and output reports from host to keyboard). This is the data channel.

When you implement the NiNo relay attack, you must open L2CAP connections on BOTH PSM 0x0011 and 0x0013 to fully relay all keyboard-host communication.

### 2.5 SDP — Service Discovery Protocol (BR/EDR)

**SDP (Service Discovery Protocol)** allows a device to announce what services it provides and allows another device to discover those services. Before a laptop connects to a keyboard, it queries the keyboard's SDP server to find out "what is the PSM for HID? What is your device class? What IO capabilities do you have?"

On Day 1, you run SDP enumeration on each keyboard to get its HID descriptor and IO capabilities. This tells you which attacks apply to each device.

---

## Part III: Bluetooth Low Energy (BLE) — A Different Beast

BLE has its own entirely separate protocol stack. Instead of LMP + L2CAP + SDP, BLE uses a different set of layers.

### 3.1 BLE Advertising — How Devices Announce Themselves

In BLE, devices that want to be found broadcast **advertisement packets** on three fixed channels (37, 38, 39 in the 2.4 GHz band). An advertisement contains at minimum the device's address and optionally its name, supported services, and other data.

Devices listening for these advertisements are called **observers** or **scanners**. When a device wants to connect, it sends a connection request in response to an advertisement.

This is different from BR/EDR, where a device enters "discoverable mode" and responds to inquiry scans. In BLE, the device actively broadcasts its presence.

**This matters for attacks**: several attacks intercept or spoof BLE advertisements. WhisperPair works by broadcasting a fake Fast Pair advertisement. Method Confusion intercepts the keyboard's genuine advertisement and substitutes the attacker's own.

### 3.2 GAP — Generic Access Profile

**GAP (Generic Access Profile)** defines the roles and procedures for device discovery, connection establishment, and security modes. It defines roles like:
- **Central**: initiates connections (your laptop is Central when it connects to a BLE keyboard)
- **Peripheral**: advertises and accepts connections (the BLE keyboard is Peripheral)
- **Broadcaster**: only advertises, never connects
- **Observer**: only scans, never connects

### 3.3 ATT — Attribute Protocol

**ATT (Attribute Protocol)** is BLE's fundamental data exchange protocol. It operates on a simple model: data is organized as **attributes**, each of which has:
- A **handle** (a 16-bit number that identifies the attribute within the device)
- A **type** (identified by a **UUID**)
- A **value** (the actual data)
- **Permissions** (can it be read? written? does it require authentication?)

ATT defines operations: `ATT_Read_Request`, `ATT_Write_Request`, `ATT_Write_Command` (write without response), `ATT_Notification` (server sends unsolicited updates to client), etc.

**UUID (Universally Unique Identifier)** — a 128-bit identifier, though Bluetooth SIG has assigned 16-bit UUIDs for standard attributes to save space. For example:
- `0x2A4D` — HID Report characteristic (the actual keystroke data)
- `0x1812` — HID Service (the container grouping all HID-related attributes)
- `0xFE2C` — Google Fast Pair service
- `0xFE3A` — Google Fast Pair additional service

When PLAN.md says "find HID Report descriptor (UUID `0x2A4D`) handles," it means: query the keyboard's ATT layer to find which attribute handles correspond to HID Report data.

**ATT Security Levels** — every ATT attribute has a required security level for read/write access:
- **No Security**: any connected device can access it
- **Encryption Required**: the BLE connection must be encrypted (requires bonding)
- **Authentication Required**: the connection must be encrypted AND authenticated (requires the pairing to have used MITM protection)
- **Authorization Required**: explicit user authorization needed

The Day 8 vulnerability (HOGP unauthenticated HID write) occurs when a keyboard marks its HID Report characteristics with "No Security" or "Encryption Only" instead of "Authentication Required." This means an attacker who connects to the keyboard WITHOUT going through the pairing process can directly write keystroke data.

### 3.4 GATT — Generic Attribute Profile

**GATT (Generic Attribute Profile)** sits directly on top of ATT and organizes attributes into a structured hierarchy:
- **Services**: logical groupings of related attributes (e.g., the HID Service)
- **Characteristics**: individual data items within a service (e.g., the HID Report characteristic)
- **Descriptors**: metadata about a characteristic (e.g., Client Characteristic Configuration Descriptor, which controls notifications)

When PLAN.md says "GATT relay," it means intercepting and forwarding ATT packets that carry GATT data between the BLE keyboard and the PC. The attacker sits between them and can read all HID notifications (keystrokes from keyboard to PC) and all GATT writes (commands from PC to keyboard).

**`gatttool`** — a Linux command-line tool for interacting with GATT servers. `gatttool -b <MAC> -I` opens an interactive session; `connect` establishes the BLE connection; `primary` lists services; `char-desc` lists characteristics; `char-write-req` writes to a characteristic with a response; `char-write-cmd` writes without a response.

### 3.5 SMP — Security Manager Protocol (BLE Pairing)

**SMP (Security Manager Protocol)** is BLE's entire pairing and security system, implemented over a dedicated L2CAP channel. Understanding SMP in depth is critical for Method Confusion (Day 5), the pairing downgrade (Day 9), and IRK tracking (Day 10).

SMP defines two distinct pairing methods:

**Legacy Pairing** (Bluetooth 4.0/4.1): uses a temporary key called **TK (Temporary Key)** and derives the session key called **STK (Short Term Key)** as:
```
STK = s1(TK, Srand, Mrand)
```
where Srand and Mrand are random values exchanged in plaintext over the air. TK is either 0 (Just Works), a 6-digit number typed by the user (Passkey Entry), or derived from Out-of-Band data. Since Srand and Mrand are visible in unencrypted SMP packets, if you know TK (which is 0 for Just Works), you can compute STK yourself. This is why legacy Just Works pairing is broken — the session key is trivially derivable by any observer.

**LE Secure Connections (LE SC)** (Bluetooth 4.2+): completely redesigned using **ECDH (Elliptic Curve Diffie-Hellman)** key exchange. Both devices generate public/private key pairs and exchange public keys. Neither the public keys nor the resulting shared secret are sufficient alone for an attacker to compute the session key without solving the elliptic curve discrete logarithm problem (computationally infeasible). LE SC is cryptographically strong when used correctly.

**The `SMP_Pairing_Request` PDU** — the first packet sent by the Central (connecting device) to initiate pairing. Contains an **`AuthReq` field** (Authentication Requirements) with bit flags:

- **Bit 0** — Bond: do you want to save keys for future reconnections?
- **Bit 1** — MITM: do you require protection against Man-in-the-Middle attacks?
- **Bit 2** — SC (Secure Connections): do you support LE Secure Connections?
- **Bit 3** — KeyPress: do you want keypress notifications?
- **Bit 4** — CT2: Cross-Transport Key Derivation (for BLUR/CTKD)

**The Day 9 attack (LE SC Pairing Downgrade)** works by clearing bit 2 (SC flag) in the `AuthReq` field and also clearing bit 1 (MITM flag) before sending the `SMP_Pairing_Request` to the keyboard. If the keyboard responds with `SMP_Pairing_Response` without reasserting `SC=1`, it has accepted a downgrade to legacy Just Works pairing (TK=0). Since TK=0 and Srand/Mrand are sent in plaintext, the attacker computes STK immediately and derives the long-term session key **LTK (Long Term Key)** directly.

**SCO (Secure Connections Only) Mode** — a security policy where a BLE device REFUSES to pair with legacy pairing at all. If a device enforces SCO mode, it will respond to a pairing request with `SC=0` by sending `SMP_Pairing_Failed` with error code 0x06 (Authentication Requirements). The Day 9 attack only works on devices that do NOT enforce SCO mode.

---

## Part IV: Bluetooth Addressing — How Devices Are Identified

### 4.1 BD_ADDR — Bluetooth Device Address (BR/EDR)

**BD_ADDR (Bluetooth Device Address)** is a 48-bit (6-byte) globally unique hardware address assigned to every Bluetooth Classic device, analogous to a MAC address in Ethernet. Example: `F4:2B:7D:2F:3E:5B`.

The first 3 bytes (the OUI) identify the manufacturer; the last 3 bytes are unique to the device. This address is burned into the chip at manufacture but can often be spoofed in software.

**BD_ADDR spoofing** (Day 12 attack): `bdaddr -i hci0 <new_address>` changes your adapter's reported BD_ADDR. You can impersonate any device by cloning its BD_ADDR. The Day 12 attack spoofs the PC host's BD_ADDR and connects to the keyboard to test if the keyboard issues an authentication challenge.

### 4.2 BLE Addresses — Privacy and Randomization

BLE devices can use several address types:
- **Public Address**: like BD_ADDR, globally unique, 48 bits. Fixed and never changes.
- **Static Random Address**: randomized at power-on, stays fixed until the device reboots.
- **Resolvable Private Address (RPA)**: changes periodically (typically every 15 minutes) to prevent tracking. But devices that have bonded can resolve each other's RPAs using a shared secret called the **IRK**.

**IRK (Identity Resolving Key)** — a 128-bit secret shared between two bonded BLE devices. Given a device's IRK, you can resolve its RPA to its true identity:

```
ah(IRK, prand) == hash   →   this RPA belongs to the device with this IRK
```

where `prand` is the random part of the RPA address and `hash` is the lower bits of the address.

**The Day 10 vulnerability (IRK leakage)**: during BLE bonding, devices exchange keys including the IRK via the `SM_Identity_Information` PDU. If a keyboard sends its IRK to any device that initiates bonding (without requiring the bonding device to be a known trusted partner), then the attacker obtains the keyboard's IRK and can resolve ALL future RPAs the keyboard generates — effectively tracking the keyboard across all locations forever, defeating the entire purpose of randomized addresses.

This is a serious privacy vulnerability even if the device is cryptographically secure against injection attacks.

---

## Part V: Piconet, Scatternet, and BT Classic Topology

### 5.1 Piconet

In Bluetooth Classic, devices form a **piconet** — a small network with exactly one **master** device (which sets the frequency-hopping schedule) and up to 7 active **slave** devices. The master controls all timing. All slaves synchronize their frequency-hopping to the master's clock.

Typically: your PC (master) connects to your keyboard (slave). The PC initiates the connection and becomes the master.

### 5.2 Scatternet

A **scatternet** is a collection of overlapping piconets. A device can participate in multiple piconets simultaneously — potentially as master in one and slave in another.

This is the foundation of the relay MITM attack in PLAN.md. Your attacking machine's `hci0` adapter joins two piconets:
1. Keyboard's piconet (where your adapter is the master and the keyboard is the slave)
2. PC's piconet (where the PC is the master and your adapter is the slave)

Your adapter relays data between these two piconets. The keyboard thinks it's connected to the PC (via you). The PC thinks it's connected to the keyboard (via you). All data flows through you.

BlueZ (Linux's Bluetooth stack) supports scatternet — one `hci0` adapter can maintain multiple simultaneous ACL connections in both master and slave roles. This is what makes the single-adapter MITM architecture in PLAN.md feasible.

---

## Part VI: Bluetooth Pairing in Depth — Classic (SSP)

### 6.1 Why Pairing Is Necessary

When two Bluetooth devices first connect, they must establish a shared secret key so they can encrypt their communications and verify each other's identity. "Pairing" is the process of establishing this shared secret for the first time. "Bonding" means storing the resulting keys for future use (so you don't have to re-pair every time).

Without pairing and encryption, anyone nearby with a Bluetooth radio could connect to your keyboard and receive all your keystrokes.

### 6.2 SSP — Secure Simple Pairing (Bluetooth Classic)

**SSP (Secure Simple Pairing)** was introduced in Bluetooth 2.1 to replace older, weaker pairing. SSP uses **Elliptic Curve Diffie-Hellman (ECDH)** for the key exchange — both devices generate a public/private key pair and exchange public keys. From the public keys and their own private key, each device independently computes the same shared secret.

**ECDH (Elliptic Curve Diffie-Hellman)**: a key agreement protocol. Two parties can compute the same shared secret by each having a private key (a random number) and exchanging public keys (points on an elliptic curve). An eavesdropper who sees only the public keys cannot compute the shared secret without solving the elliptic curve discrete logarithm problem. This is computationally infeasible with modern elliptic curve parameters.

**The ECDH result guarantees confidentiality but NOT authentication.** An attacker can perform a MITM attack by substituting their own public key for each victim's, establishing separate ECDH sessions with each. Both victims compute shared secrets with the attacker, not with each other. This is exactly what Method Confusion does.

### 6.3 IO Capabilities and Association Methods

After ECDH key exchange, SSP uses **IO Capabilities** to determine an "association method" — a way for users to authenticate the pairing and prevent MITM attacks.

**IO Capability** describes what input/output interfaces a device has:
- **`DisplayOnly`**: device has a display but no keyboard (e.g., a headphone display)
- **`DisplayYesNo`**: device has a display AND a yes/no button (e.g., a smartphone)
- **`KeyboardOnly`**: device has a keyboard but no display (e.g., a PIN pad)
- **`NoInputNoOutput`**: device has neither display nor keyboard (e.g., a simple BT speaker, many headphones)
- **`KeyboardDisplay`**: device has both keyboard and display (e.g., a laptop, tablet)

Based on the IO capabilities of both devices, the Bluetooth specification defines which **association method** to use:

| Device A | Device B | Method |
|----------|----------|--------|
| DisplayOnly | DisplayYesNo | **Passkey Entry** (B displays, A — wait, this depends on version) |
| DisplayYesNo | DisplayYesNo | **Numeric Comparison** |
| KeyboardOnly | DisplayOnly | **Passkey Entry** (A types, B displays) |
| NoInputNoOutput | Anything | **Just Works** |
| KeyboardDisplay | DisplayOnly | **Passkey Entry** |
| KeyboardDisplay | DisplayYesNo | **Numeric Comparison** (in LE SC) |

**Just Works**: no user interaction required. Zero authentication against MITM. Convenient but completely insecure. This is what the NiNo attack forces.

**Passkey Entry**: one device displays a 6-digit number; the user types it on the other device. Prevents MITM as long as the user correctly reads and types the number.

**Numeric Comparison (NC)**: both devices display a 6-digit number; the user verifies they match on both devices and presses "Yes" on both. In LE SC, both numbers are derived from the ECDH shared secret — if a MITM substituted their own key, the numbers would NOT match, and the user would reject the pairing.

**The critical vulnerability exploited by Method Confusion**: the Bluetooth specification does not require both devices to use the SAME association method. The standard says: each device independently declares its IO capabilities, and the method is chosen by looking up the table. If the attacker can force different methods on each side, the MITM is not detected.

In Method Confusion: 
- With the keyboard (which has `DisplayOnly`): the attacker claims `KeyboardOnly` → the table yields **Passkey Entry** (keyboard displays, attacker types). But the attacker doesn't "type" anything — they relay the 6-digit number from the other session.
- With the PC (which has `DisplayYesNo`): the attacker claims `DisplayYesNo` → the table yields **Numeric Comparison** (both display, user confirms).

Both methods produce the same 6-digit check value from the ECDH computation (derived from the function `f4(PKa, PKb, Na, 0)` where PKa and PKb are the public keys and Na is a nonce). The user confirms matching numbers on both sides — but the "matching" is happening across two different ECDH sessions, both of which the attacker controls.

### 6.4 The Classic Bluetooth Key Hierarchy

After SSP, the devices derive a **Link Key** — a 128-bit secret stored by both devices for future reconnection. The Link Key is used to generate session-specific encryption keys.

For **encryption key generation**, BR/EDR uses the **E0 stream cipher**:
- **Session Key (`KC`)**: derived from the link key + random values (**AU_RAND** and **EN_RAND**) using the **E3 key generation function** (based on the **SAFER+** block cipher)
- **AU_RAND**: Authentication Random — used in the challenge-response authentication (`LMP_au_rand`)
- **EN_RAND**: Encryption Random — used in encryption key derivation; transmitted in plaintext in the `LMP_start_encryption` packet

The **KNOB attack** forces the **encryption key size** (`Lmin`) to 1 byte. Normally, the key size is 16 bytes (128 bits), making brute force computationally infeasible. With 1 byte, only 256 possible key values exist. The attacker captures AU_RAND and EN_RAND (visible in LMP packets), computes all 256 candidate KC values, and identifies the correct one by decrypting a known HID frame.

---

## Part VII: Cross-Transport Key Derivation (CTKD) and BLUR

**CTKD (Cross-Transport Key Derivation)** is a feature introduced in Bluetooth 4.2 that allows a device to automatically derive pairing keys for one transport (BR/EDR or BLE) after completing pairing on the other transport. The idea: pair once over BLE, automatically get a BR/EDR link key too, without re-pairing.

This seemingly convenient feature creates a severe security hole: it couples the security of two independent transports. Pairing over BLE (which may use weaker Just Works) can now overwrite a previously established, stronger BR/EDR link key.

The **BLUR attack** exploits this:
1. Alice and Bob have already paired over BR/EDR (Bluetooth Classic) with a strong link key.
2. Charlie initiates a new BLE pairing with Bob, impersonating Alice by using Alice's BD_ADDR.
3. Charlie negotiates **Just Works** BLE pairing (no authentication, no user interaction).
4. Via CTKD, this BLE pairing derives a new BR/EDR link key — and **overwrites** Bob's stored link key for Alice.
5. Now Bob only recognizes Charlie as Alice. Alice cannot reconnect to Bob. Charlie is in complete control.

The vulnerability: CTKD does not track or enforce what association method was used on the original transport. It allows a weaker pairing on one transport to silently overwrite a stronger key on another.

---

## Part VIII: The HID Profile — How Keyboards and Mice Work Over Bluetooth

### 8.1 What HID Means

**HID (Human Interface Device)** is a USB/Bluetooth profile standard that defines how input devices (keyboards, mice, gamepads, touchscreens) communicate with host computers. The key concept is the **HID Report** — a standardized binary packet format describing input state.

A HID keyboard sends a report every time a key is pressed or released. A standard **HID Boot Keyboard Report** is exactly 8 bytes:
```
Byte 0: Modifier keys bitmask (Ctrl, Shift, Alt, Win/Cmd, etc.)
Byte 1: Reserved (always 0x00)
Bytes 2-7: Up to 6 simultaneously pressed key Usage IDs
```

**Usage IDs** are standardized numbers assigned by the USB HID specification. For example:
- `0x04` = key 'a'
- `0x28` = Enter key
- `0x79` = F10 key

So the payload `00 00 04 00 00 00 00 00` in PLAN.md means: no modifier keys, key 'a' pressed, no other keys. Sending this followed by `00 00 00 00 00 00 00 00` (all zeros = all keys released) simulates pressing and releasing 'a'.

This is the payload used on Day 8 to test unauthenticated HID injection.

**HID Report Output** — the host can also send data to the keyboard: typically LED state (caps lock, num lock, scroll lock). Byte 0 is a bitmask: bit 0 = Num Lock LED, bit 1 = Caps Lock LED, bit 2 = Scroll Lock LED. Sending `01` to the Output characteristic turns on the Num Lock LED.

### 8.2 HID over BR/EDR (Classic Bluetooth HID)

In Bluetooth Classic, HID uses L2CAP channels:
- **PSM 0x0011 (HID Control)**: bi-directional control messages. The PC sends SET_REPORT commands here (e.g., to set LED state). The keyboard sends HANDSHAKE responses.
- **PSM 0x0013 (HID Interrupt)**: keyboard → PC direction for keystroke reports. Also carries output reports from PC → keyboard in some implementations.

The keyboard is the **L2CAP server** (it listens). The PC is the **L2CAP client** (it connects). When you implement the NiNo relay, your attacker code must:
1. Act as L2CAP **server** toward the keyboard's side (keyboard connects to you thinking you are the PC)
2. Act as L2CAP **client** toward the PC (you connect to the PC pretending to be the keyboard)

### 8.3 HOGP — HID over GATT Profile (BLE Keyboards/Mice)

**HOGP (HID over GATT Profile)** is the BLE equivalent of HID over BR/EDR. Instead of L2CAP PSMs, it uses GATT characteristics.

Key GATT characteristics in HOGP:
- **HID Service** (UUID `0x1812`): the container service
- **HID Information** (UUID `0x2A4A`): protocol mode, country code
- **Report Map** (UUID `0x2A4B`): the HID Report Descriptor — tells the host how to interpret reports
- **HID Report** (UUID `0x2A4D`): the actual input/output data. There can be multiple instances (one per report type: Input, Output, Feature)
- **HID Control Point** (UUID `0x2A4C`): suspend/exit suspend commands

Keystrokes flow via **ATT Notifications** on the HID Report Input characteristic: the keyboard sends unsolicited notifications whenever a key is pressed. The host subscribes by writing to the characteristic's **CCCD (Client Characteristic Configuration Descriptor)**.

The **HOGP spec §3.11** states that the HID Report characteristic SHALL require at minimum "Authentication Required" for read/write access. This means any access requires a bonded (paired) connection. If an implementation sets the security to "No Security" or even just "Encryption Required" (bonded but not authenticated), the Day 8 attack becomes possible.

---

## Part IX: The Linux Bluetooth Stack

### 9.1 BlueZ

**BlueZ** is the official Bluetooth protocol stack for Linux. It implements virtually all Bluetooth profiles and protocols from the controller interface (HCI) through to application-level APIs (via D-Bus). BlueZ is what controls your `hci0` adapter.

Key BlueZ tools already mentioned: `hciconfig`, `hcitool`, `btmgmt`, `hcidump`, `gatttool`, `bluetoothctl`.

BlueZ exposes Bluetooth functionality to applications in three ways:
1. **D-Bus API**: high-level, used by GUI Bluetooth managers and most applications
2. **Socket API**: `socket(AF_BLUETOOTH, ...)` — raw access to HCI, L2CAP, RFCOMM, etc.
3. **Management API** (`btmgmt`): the modern interface for controller management

### 9.2 uhid — User-Space HID

**`uhid` (User-space HID)** is a Linux kernel feature that allows a user-space program to present itself as a HID device to the rest of the operating system. Normally, HID devices are physical hardware connected via USB or Bluetooth. With `uhid`, you open `/dev/uhid`, write a special CREATE message describing your virtual HID device (name, report descriptor, etc.), and the kernel creates a virtual `/dev/input/eventX` device. The OS (and all applications) treat it exactly as a real keyboard or mouse.

In PLAN.md's NiNo relay architecture, `uhid` is used on the "PC side":
- The attacker connects to the keyboard over Bluetooth (HID host role)
- The attacker uses `uhid` to appear as a virtual HID keyboard to the PC
- When the attacker receives a keystroke from the keyboard, it writes that keystroke to `/dev/uhid`, making it appear on the PC
- The PC never sees the real Bluetooth connection to the keyboard — it only sees the `uhid` virtual device

This is the key insight that makes a single-adapter MITM feasible: you don't need a second Bluetooth adapter to "be a keyboard" to the PC — you use `uhid` instead.

### 9.3 InternalBlue

**InternalBlue** is an open-source Bluetooth security research framework (from TU Darmstadt) that exploits Broadcom/Cypress Bluetooth chips' firmware. It:
- Communicates with the chip via special Broadcom **Vendor Specific HCI commands** (`0x3F xx`)
- Allows reading and writing the chip's RAM (including modifying in-memory functions and handlers)
- Allows **live firmware patching**: replacing a few bytes of the running firmware to change its behavior

For the KNOB Mode B attack, InternalBlue patches the firmware function that handles incoming `LMP_encryption_key_size_req` packets. Instead of forwarding the original packet, the patched function modifies the key size field from 16 to 1 before forwarding. This happens entirely at the firmware level, below the OS, making it invisible to standard monitoring.

InternalBlue supports chips that include: Broadcom BCM43xx series, Cypress CYW series (same architecture), and some Qualcomm chips. **It does NOT work on Intel Wireless chips** (which use a completely different, proprietary firmware). Check your adapter with `hciconfig -a | grep -i manufacturer`.

### 9.4 Scapy

**Scapy** is a Python library for constructing, sending, receiving, and dissecting network packets. It supports dozens of protocols including Bluetooth (both Classic and BLE). Scapy is used in PLAN.md for:
- Constructing SMP packets (Day 5, 9) with modified fields
- Building raw L2CAP frames (Day 11 fuzzing)
- Sniffing and dissecting BLE advertisement and connection packets

In the SMP downgrade attack (Day 9), you use Scapy to build a custom `SMP_Pairing_Request` packet where you explicitly clear the SC and MITM flags, then send it via a raw BLE socket.

---

## Part X: The Five Known Attacks — Deep Conceptual Explanation

### 10.1 NiNo Attack (No Input No Output)

**What it exploits**: Bluetooth devices with `NoInputNoOutput` IO capability are forced into **Just Works** pairing — the weakest association method, providing zero MITM protection.

**The attack**:
1. A legitimate keyboard declares its true IO capability (e.g., `DisplayOnly`). Normally, pairing with a PC (`DisplayYesNo`) would use **Passkey Entry**, which requires user interaction to confirm identity.
2. The attacker intercepts the pairing process and claims to BOTH the keyboard AND the PC that the attacker has `NoInputNoOutput` capability.
3. Both sides see an apparent NoInputNoOutput device and fall back to **Just Works** — no user confirmation required.
4. Both the keyboard and the PC complete pairing with the attacker, not with each other.
5. The attacker is now the relay between them, logging and optionally modifying all keystrokes.

**Why "NiNo"**: the attack is named after the IO capability it exploits — **N**o **I**nput **N**o **O**utput.

**Threat model**: the attacker must be present during the initial pairing. Once both sides have paired with the attacker, the MITM persists for all future communications (until re-pairing).

### 10.2 KNOB Attack (Key Negotiation of Bluetooth)

**CVE-2019-9506**. **What it exploits**: in BR/EDR, the encryption key size (1–16 bytes) is negotiated via the unauthenticated, unencrypted LMP protocol. Neither party verifies that the agreed key size hasn't been tampered with.

**The attack** (Mode A — relay MITM):
1. Attacker is already the relay MITM (e.g., via NiNo).
2. When negotiating encryption keys with the keyboard, attacker proposes Lmin=1 (1-byte key).
3. When negotiating with the PC, attacker also proposes Lmin=1.
4. Both accept (the spec allows any value from 1 to 16 — it does NOT enforce a minimum).
5. Both compute encryption keys with only 8 bits of entropy — 256 possible keys.
6. The attacker captures AU_RAND and EN_RAND from LMP packets, computes all 256 candidate keys using the E3 function, finds the correct one, and can now decrypt/re-encrypt all traffic.

**Why it's critical for keyboards specifically**: once you can decrypt keyboard traffic, you can read every password, credit card number, and message typed on that keyboard. You can also inject keystrokes — for example, inject a shell command when the screen is idle.

**The E0 cipher and SAFER+**: E0 is the stream cipher used for BR/EDR encryption. Key generation uses functions E1 and E3, which are built from a proprietary block cipher called **SAFER+** (Secure And Fast Encryption Routine Plus). The KNOB brute force recomputes the E3 function for all 256 possible 1-byte keys.

### 10.3 Method Confusion Attack

**What it exploits**: the Bluetooth spec selects different association methods based on each device's IO capabilities WITHOUT requiring both devices to agree on the same method. Two devices can independently use different methods that happen to produce the same 6-digit check value — and neither party can detect the confusion.

The full explanation of how this establishes MITM was covered in the main conversation (see the professor's answer to Question 1). In summary:
- Attacker runs NC (Numeric Comparison) with one victim and PE (Passkey Entry) with the other
- Both produce the same 6-digit value, so both victims "confirm" successfully
- Attacker holds separate ECDH session keys for each victim
- Both victims believe they are communicating with each other; in reality, both are communicating with the attacker

**Target**: BLE keyboards with `DisplayOnly` or `KeyboardDisplay` IO capability paired with a PC having `DisplayYesNo`. These are the IO capability combinations that allow the method confusion.

### 10.4 BLUR Attack

As described in Part VII. The core concept: CTKD allows BLE pairing to overwrite BR/EDR link keys without the victim knowing. An attacker impersonates a trusted device (by cloning its BD_ADDR) over BLE, completes a Just Works BLE pairing, and the CTKD mechanism silently overwrites the victim's stored key for the legitimate device.

### 10.5 WhisperPair

**CVE-2025-36911**. **What it exploits**: Google Fast Pair is a feature allowing BLE accessories (keyboards, earbuds) to quickly pair with Android and Chrome OS devices without going through the normal pairing flow. Devices announce Fast Pair support via a GATT service (UUID `0xFE2C`). The WhisperPair vulnerability finds that some Fast Pair accessories accept the initial pairing connection and complete pairing **even when the device is not in pairing mode** (i.e., not waiting to be paired). This allows an attacker nearby to forcibly pair with the accessory without the user initiating or approving the pairing.

---

## Part XI: The Three New Vulnerability Research Areas

### 11.1 HOGP Unauthenticated HID Write (Day 8)

**Root cause**: The HOGP specification requires HID Report characteristics to mandate "Authentication Required" security level. However, setting up ATT security levels is the responsibility of the firmware developer, and many cheap peripherals skip this, either from ignorance or to simplify implementation.

**Impact**: any BLE device within range that connects to the keyboard (without pairing) can write directly to the HID Report characteristic and inject keystrokes. No pairing, no bonding, no user interaction.

**Why it's testable without complex tools**: just use `gatttool` to connect and write. The vulnerability is in the GATT security configuration, not in any cryptographic mechanism.

### 11.2 BLE LE SC Pairing Downgrade (Day 9)

**Root cause**: BLE pairing negotiation is not authenticated. The `SMP_Pairing_Request` is sent in plaintext before any encryption exists. Nothing prevents an attacker from intercepting this packet and modifying the `AuthReq` flags before it reaches the peripheral.

**The attack**: a MITM intercepts the Central's `SMP_Pairing_Request`, strips `SC=1` → `SC=0` and `MITM=1` → `MITM=0`, and forwards the modified packet. If the peripheral accepts this (does not enforce SCO mode), it responds with `SMP_Pairing_Response` also having `SC=0`. Both sides then proceed with legacy Just Works pairing.

**Impact**: the session key is trivially derivable (TK=0 → STK computable from public Srand/Mrand), enabling full decryption of all subsequent traffic and a complete MITM.

**Why it's noteworthy**: this is the BLE equivalent of a TLS protocol downgrade attack. It's known theoretically, but documenting it against specific keyboard chipsets with full relay-MITM implementation constitutes a new targeted contribution.

### 11.3 IRK Privacy Leakage (Day 10)

**Root cause**: the BLE privacy mechanism (Resolvable Private Addresses) depends on IRK remaining secret between bonded pairs. However, the SMP Identity Exchange phase sends IRK to any device that successfully completes bonding. If a keyboard doesn't verify that the bonding initiator is a legitimate host (e.g., doesn't maintain a strict whitelist), then anyone who completes bonding receives the keyboard's IRK.

**Attack scenario**: attacker bonds to keyboard once (possibly using the Day 9 downgrade to bond without real authentication). Keyboard sends its IRK during the SM key exchange. Attacker now has the IRK forever. Even after the bonding is deleted, the keyboard still generates new RPAs from the same IRK — the attacker can passively track the keyboard indefinitely.

**Impact**: tracks the keyboard user's location and identity, even in public spaces (airports, coffee shops) where the keyboard might be in a laptop bag or briefcase.

---

## Part XII: Tools Reference

### Docker `--privileged` for Bluetooth Research

Docker containers are normally isolated from host hardware. Bluetooth requires access to the kernel's Bluetooth socket layer and the HCI interface. `--privileged` grants the container full access to all host devices and capabilities. `--net=host` shares the host's network namespace, which is necessary because Bluetooth sockets in Linux are part of the network socket API. The volume mounts (`-v /var/run/dbus:/var/run/dbus`) give the container access to the D-Bus system bus, which BlueZ uses for inter-process communication.

### NVD — National Vulnerability Database

**NVD (National Vulnerability Database)** is the US government repository of all publicly known security vulnerabilities, maintained by NIST. Each entry is identified by a **CVE number** (Common Vulnerabilities and Exposures), e.g., CVE-2019-9506 (KNOB). On Day 13, you search NVD to verify that your findings don't already have assigned CVEs.

### Braktooth

A BT Classic fuzzer (2021, SUTD) that found 18 new vulnerabilities across multiple BT chip manufacturers by fuzzing LMP and L2CAP. Relevant for Day 11. It works by sending malformed or unexpected protocol packets and observing crashes.

---

## Part XIII: Putting It All Together — How the Plan Flows

Reading PLAN.md with this background, the 14-day structure makes logical sense:

**Days 1-2** establish the foundation: the NiNo relay architecture (scatternet + uhid) is the reusable core that ALL other relay attacks build on top of.

**Day 3** adds the KNOB entropy reduction on top of the Day 2 relay — since you are already the relay endpoint, you simply propose weak keys to both sides.

**Day 5** implements a BLE version of the relay — instead of BR/EDR L2CAP, you relay ATT/GATT packets. The Method Confusion attack provides the mechanism to get both sides to pair with you.

**Days 8-12** (Week 2) are systematic audits of areas where implementation flaws, rather than specification flaws, are expected. The three most likely findings all exploit the gap between what the spec mandates and what cheap firmware actually implements.

Every attack and vulnerability ultimately enables the same end result: an attacker silently sitting between a keyboard and its host PC, reading every password and message typed, and capable of injecting arbitrary keystrokes — all without the user seeing any indication that anything is wrong.

---

## Quick Reference: All Acronyms

| Acronym | Full Name | Where It Appears |
|---------|-----------|-----------------|
| ACL | Asynchronous Connection-oriented Logical | BR/EDR data link type |
| ATT | Attribute Protocol | BLE data layer |
| BD_ADDR | Bluetooth Device Address | BR/EDR hardware address |
| BLE | Bluetooth Low Energy | BT 4.0+ low-power variant |
| BR/EDR | Basic Rate / Enhanced Data Rate | Classic Bluetooth |
| CTKD | Cross-Transport Key Derivation | BLUR attack mechanism |
| CVE | Common Vulnerabilities and Exposures | Vulnerability ID system |
| ECDH | Elliptic Curve Diffie-Hellman | SSP/LE SC key agreement |
| EN_RAND | Encryption Random | BR/EDR key derivation input |
| AU_RAND | Authentication Random | BR/EDR authentication |
| FHSS | Frequency-Hopping Spread Spectrum | BT radio technique |
| GAP | Generic Access Profile | BLE roles and procedures |
| GATT | Generic Attribute Profile | BLE data organization |
| HCI | Host Controller Interface | Host↔chip protocol |
| HID | Human Interface Device | Keyboard/mouse profile |
| HOGP | HID over GATT Profile | BLE keyboard/mouse profile |
| IO Cap | IO Capability | Defines pairing method |
| IRK | Identity Resolving Key | BLE address privacy |
| KNOB | Key Negotiation of Bluetooth | CVE-2019-9506 |
| L2CAP | Logical Link Control and Adaptation Protocol | BT multiplexing layer |
| LMP | Link Manager Protocol | BR/EDR controller control |
| LTK | Long Term Key | BLE session key |
| MITM | Man-in-the-Middle | Attacker between two victims |
| MTU | Maximum Transmission Unit | Max packet size |
| NC | Numeric Comparison | SSP/LE SC association method |
| NiNo | No Input No Output | SSP MITM attack name |
| NVD | National Vulnerability Database | CVE repository |
| OUI | Organizationally Unique Identifier | First 3 bytes of BD_ADDR |
| PE | Passkey Entry | SSP association method |
| PHY | Physical Layer | Radio hardware |
| PoC | Proof of Concept | Minimal working exploit |
| PSM | Protocol Service Multiplexer | L2CAP "port number" |
| RPA | Resolvable Private Address | BLE privacy address |
| SC | Secure Connections (flag) | LE SC flag in SMP |
| SCO | Secure Connections Only (mode) | Policy enforcing LE SC |
| SDP | Service Discovery Protocol | BR/EDR service lookup |
| SMP | Security Manager Protocol | BLE pairing protocol |
| SSP | Secure Simple Pairing | BT Classic pairing |
| STK | Short Term Key | BLE legacy pairing key |
| TK | Temporary Key | BLE legacy pairing input |
| uhid | User-space HID | Linux virtual HID device |
| UUID | Universally Unique Identifier | BLE attribute type ID |
| VS | Vendor Specific | Non-standard HCI commands |
