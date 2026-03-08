import socket
import threading
import time
import dns.resolver
from dnslib import DNSRecord
import os

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
UPSTREAM_DNS = '8.8.8.8'
UPSTREAM_PORT = 53
SOCKET_TIMEOUT = 3.0
CACHE_CLEAN_INTERVAL = 300
LOG_FILE = "DNS.log"

cache = {}
cache_lock = threading.Lock()
log_lock = threading.Lock()

GLOBAL_SERVERS = {
    "Google Primary": "8.8.8.8",
    "Google Secondary": "8.8.4.4",
    "Cloudflare": "1.1.1.1",
    "Quad9": "9.9.9.9",
    "OpenDNS Primary": "208.67.222.222",
    "OpenDNS Secondary": "208.67.220.220",
    "Level3 Primary": "4.2.2.1",
    "Level3 Secondary": "4.2.2.2",
    "AdGuard": "94.140.14.14",
    "Comodo": "8.26.56.26",
    "ControlD": "76.76.2.0",
    "NextDNS": "45.90.28.190",
    "CleanBrowsing": "185.228.168.9",
    "Yandex": "77.88.8.8",
    "Neustar": "156.154.70.1",
    "Mullvad": "194.242.2.2",
    "Hurricane Electric": "74.82.42.42",
    "PuntCAT": "109.69.8.51",
    "Verisign Primary": "64.6.64.6",
    "Verisign Secondary": "64.6.65.6"
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
        if removed:
            log(f"cache cleanup removed {removed} expired entries")
        else:
            log("cache cleanup run (no entries removed)")

def forward_query(data):
    try:
        log("forwarding query to upstream dns")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(SOCKET_TIMEOUT)
        sock.sendto(data, (UPSTREAM_DNS, UPSTREAM_PORT))
        response, _ = sock.recvfrom(4096)
        log("received response from upstream dns")
        return response
    except socket.timeout:
        log("upstream dns timeout")
        return None
    finally:
        sock.close()

def handle_client(data, addr, server_socket):
    try:
        request = DNSRecord.parse(data)
        qname = str(request.q.qname)
        qtype = request.q.qtype

        log(f"DNS Request: {qname} from {addr[0]}")

        with cache_lock:
            if (qname, qtype) in cache:
                raw_resp, expiry = cache[(qname, qtype)]
                if time.time() < expiry:
                    cached_resp = DNSRecord.parse(raw_resp)
                    cached_resp.header.id = request.header.id
                    server_socket.sendto(cached_resp.pack(), addr)
                    return
                else:
                    del cache[(qname, qtype)]

        response_data = forward_query(data)
        if not response_data:
            return

        response_record = DNSRecord.parse(response_data)
        ttl = 60
        if response_record.rr:
            ttl = min([rr.ttl for rr in response_record.rr])

        with cache_lock:
            cache[(qname, qtype)] = (response_data, time.time() + ttl)

        server_socket.sendto(response_data, addr)
    except Exception as e:
        log(f"error handling request from {addr}: {e}")

def run_dns_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        server_socket.bind((HOST, PORT))
        log(f"local dns server is up and listening on {HOST}:{PORT}")
    except PermissionError:
        log("permission denied: run as administrator/root to bind port 53")
        os._exit(1)

    while True:
        try:
            data, addr = server_socket.recvfrom(512)
            thread = threading.Thread(target=handle_client, args=(data, addr, server_socket))
            thread.daemon = True
            thread.start()
        except Exception as e:
            log(f"server error: {e}")

def run_propagation_test(domain):
    log(f"starting propagation test for {domain}")
    print(f"\n--- propagation test: {domain} ---")
    print(f"{'provider':<20} | {'status/ip':<15} | {'latency'}")
    print("-" * 55)
    for name, ip in GLOBAL_SERVERS.items():
        res = dns.resolver.Resolver(configure=False)
        res.nameservers = [ip]
        res.timeout = 2.0
        res.lifetime = 2.0
        start_time = time.time()
        try:
            answers = res.resolve(domain, 'A')
            latency = round((time.time() - start_time) * 1000, 2)
            resolved_ip = answers[0].to_text()
            print(f"{name:<20} | {resolved_ip:<15} | {latency}ms")
            log(f"propagation {name}: {resolved_ip} ({latency}ms)")
        except Exception:
            print(f"{name:<20} | {'server down':<15} | n/a")
            log(f"propagation {name}: server down")
    print("-" * 55)
    log(f"propagation test complete for {domain}")

if __name__ == "__main__":
    cleanup_thread = threading.Thread(target=cache_cleaner)
    cleanup_thread.daemon = True
    cleanup_thread.start()

    server_thread = threading.Thread(target=run_dns_server)
    server_thread.daemon = True
    server_thread.start()

    time.sleep(1)
    print(f"Startup: Server listening on {HOST}")
    log("server started")

    while True:
        try:
            command = input("\ndns-cli> ").strip()
            if command.lower() in ['quit', 'exit']:
                log("server shutdown requested")
                break
            elif command:
                run_propagation_test(command)
        except KeyboardInterrupt:
            log("server shutdown via keyboard interrupt")
            break

    print("Shutdown: Server closing")
    log("shutting down")
