import socket
import threading
import time
import dns.resolver
from dnslib import DNSRecord
import os
import base64
import logging
from flask import Flask, request, make_response

log_flask = logging.getLogger('werkzeug')
log_flask.setLevel(logging.ERROR)

#---get ip from os for server---
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

#---configuration---
HOST = get_dynamic_ip()
PORT = 53
UPSTREAM_DNS = '8.8.8.8'
UPSTREAM_PORT = 53
SOCKET_TIMEOUT = 3.0
CACHE_CLEAN_INTERVAL = 300
LOG_FILE = "DNS.log"

#---DoH configuration---
DOH_PORT = 443
DOH_ENDPOINT = "/dns-query"
CERT_FILE = "cert.pem"
KEY_FILE = "key.pem"

#thread-safe cache: {(qname, qtype): (raw_response_bytes, expiry_timestamp)}
cache = {}
cache_lock = threading.Lock()
log_lock = threading.Lock()

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

def log(message):
    with log_lock:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{timestamp}] {message}"
        with open(LOG_FILE, "a") as f:
            f.write(entry + "\n")

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
        request = DNSRecord.parse(data)
        qname = str(request.q.qname)
        qtype = request.q.qtype
        log(f"Request [{protocol}]: FQDN={qname} Type={qtype}")

        with cache_lock:
            if (qname, qtype) in cache:
                raw_resp, expiry = cache[(qname, qtype)]
                if time.time() < expiry:
                    cached_resp = DNSRecord.parse(raw_resp)
                    cached_resp.header.id = request.header.id
                    return cached_resp.pack()
                else:
                    del cache[(qname, qtype)]

        response_data = forward_query(data)
        if not response_data: return None

        response_record = DNSRecord.parse(response_data)
        ttl = 60
        if response_record.rr:
            ttl = min([rr.ttl for rr in response_record.rr])

        with cache_lock:
            cache[(qname, qtype)] = (response_data, time.time() + ttl)
        return response_data
    except Exception as e:
        log(f"error processing request: {e}")
        return None

def handle_client(data, addr, server_socket):
    response = process_dns_logic(data, protocol=f"UDP {addr[0]}")
    if response: server_socket.sendto(response, addr)

def run_dns_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        server_socket.bind((HOST, PORT))
    except PermissionError:
        log("Permission denied for Port 53")
        os._exit(1)
    while True:
        data, addr = server_socket.recvfrom(512)
        threading.Thread(target=handle_client, args=(data, addr, server_socket), daemon=True).start()

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

def run_doh_server():
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        context = (CERT_FILE, KEY_FILE)
        log("DoH starting with provided certificates")
    else:
        context = 'adhoc'
        log("Certificates not found, falling back to adhoc")

    app.run(host=HOST, port=DOH_PORT, ssl_context=context, threaded=True, use_reloader=False)

def run_secret_listener():
    """One-time listener for the Marco Polo discovery method."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(('0.0.0.0', 9999))
        log("Companion discovery listener started on port 9999")
        while True:
            data, addr = sock.recvfrom(1024)
            if data == b"IM_A_BARBIE_GIRL_IN_A_BARBIE_WORLD":
                sock.sendto(b"COME_ON_BARBIE_LETS_GO_PARTY", addr)
                log(f"Companion DHCP discovered from {addr[0]}. Replied and closing listener.")
                break
    except Exception as e:
        log(f"Secret listener error: {e}")
    finally:
        sock.close()

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

if __name__ == "__main__":
    print("-" * 60)
    print(f"DNS SERVER STARTUP SEQUENCE")
    print(f"Interface: {HOST}")
    print(f"UDP Server: Port {PORT} | DoH Server: Port {DOH_PORT}")
    print(f"Log File: {os.path.abspath(LOG_FILE)}")
    print("-" * 60)
    print("NOTE: Real-time request events are hidden. View 'DNS.log' for details.")

    threading.Thread(target=cache_cleaner, daemon=True).start()
    threading.Thread(target=run_dns_server, daemon=True).start()
    threading.Thread(target=run_doh_server, daemon=True).start()
    threading.Thread(target=run_secret_listener, daemon=True).start()

    while True:
        try:
            command = input("\ndns-cli> ").strip()
            if command.lower() in ['quit', 'exit']: break
            elif command: run_propagation_test(command)
        except KeyboardInterrupt: break

    print("\nSHUTDOWN: Closing server...")
    log("shutting down")
