import socket
import threading
import time
import dns.resolver
from dnslib import DNSRecord

# configurations
HOST = '0.0.0.0'
PORT = 53
UPSTREAM_DNS = '8.8.8.8'
UPSTREAM_PORT = 53
SOCKET_TIMEOUT = 3.0
CACHE_CLEAN_INTERVAL = 60 #cache cleanup every 60 seconds

# cache setup: {(qname, qtype): (raw_response_bytes, expiry_timestamp)} [exmaple_key: ("banana.com", A)]
cache = {}
cache_lock = threading.Lock() #make thread safe for multiple clients

# logging setup
LOG_FILE = "DNS.log"
log_lock = threading.Lock() #thread safe logging

def log(message):
    """log message to file and print"""
    with log_lock:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{timestamp}] {message}"
        print(entry)
        with open(LOG_FILE, "a") as f:
            f.write(entry + "\n")

# 20 global dns servers for propagation tool
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

# --- cache cleanup ---

def cache_cleaner():
    """periodically removes expired entries from the dns cache."""
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

# --- core server  ---

def forward_query(data):
    """forwards the raw query to 8.8.8.8 and returns the raw response."""
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
    """processes an individual incoming dns query."""
    try:
        request = DNSRecord.parse(data)
        qname = str(request.q.qname)
        qtype = request.q.qtype

        #check cache
        with cache_lock:
            if (qname, qtype) in cache:
                raw_resp, expiry = cache[(qname, qtype)]
                if time.time() < expiry:
                    #cache hit: rewrite cached transaction id to match the client's request
                    cached_resp = DNSRecord.parse(raw_resp)
                    cached_resp.header.id = request.header.id
                    server_socket.sendto(cached_resp.pack(), addr)
                    log(f"cache hit for {qname} type {qtype}")
                    return
                else:
                    #cache expired
                    del cache[(qname, qtype)]
                    log(f"cache expired for {qname} type {qtype}")

        #cache miss: forward to upstream
        log(f"cache miss for {qname} type {qtype}")
        response_data = forward_query(data)
        if not response_data:
            log("no response from upstream, dropping request")
            return

        response_record = DNSRecord.parse(response_data)

        #extract ttl and update cache
        ttl = 60 #default ttl if none found
        if response_record.rr:
            ttl = min([rr.ttl for rr in response_record.rr])

        with cache_lock:
            cache[(qname, qtype)] = (response_data, time.time() + ttl) #write to cache

        log(f"cached response for {qname} type {qtype} with ttl {ttl}")

        #send back to client
        server_socket.sendto(response_data, addr)
        log(f"response sent to client {addr}")

    except Exception as e:
        log(f"error handling request from {addr}: {e}")

def run_dns_server():
    """binds the udp socket and listens for incoming queries."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        server_socket.bind((HOST, PORT))
        log(f"local dns server is up and listening on {HOST}:{PORT}")
    except PermissionError:
        log("permission denied: run as administrator/root to bind port 53")
        import os
        os._exit(1)

    while True:
        try:
            data, addr = server_socket.recvfrom(512) #512 bytes are the classic dns udp limit
            thread = threading.Thread(target=handle_client, args=(data, addr, server_socket))
            thread.daemon = True
            thread.start()
        except Exception as e:
            log(f"server error: {e}")

# --- propagation engine ---

def run_propagation_test(domain):
    """queries 20 global servers for the a record of a domain."""
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
            #query a record
            answers = res.resolve(domain, 'A')
            latency = round((time.time() - start_time) * 1000, 2)
            #extract first ip for clean display
            resolved_ip = answers[0].to_text()
            print(f"{name:<20} | {resolved_ip:<15} | {latency}ms")
            log(f"propagation {name}: {resolved_ip} ({latency}ms)")
        except Exception:
            print(f"{name:<20} | {'server down':<15} | n/a")
            log(f"propagation {name}: server down")

    print("-" * 55)
    log(f"propagation test complete for {domain}")

# --- main cli interface ---

if __name__ == "__main__":
    #start cache cleanup thread
    cleanup_thread = threading.Thread(target=cache_cleaner)
    cleanup_thread.daemon = True
    cleanup_thread.start()

    #start dns server in background
    server_thread = threading.Thread(target=run_dns_server)
    server_thread.daemon = True
    server_thread.start()

    time.sleep(1)

    log("server started")
    print("\nserver is running in the background.")
    print("type a domain name to run the propagation engine, or 'quit' to exit.")

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

    log("shutting down")
