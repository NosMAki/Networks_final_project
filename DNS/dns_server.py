import socket
import threading
import time
import dns.resolver
from dnslib import DNSRecord

# --- Configuration ---
HOST = '0.0.0.0'
PORT = 53
UPSTREAM_DNS = '8.8.8.8'
UPSTREAM_PORT = 53
SOCKET_TIMEOUT = 3.0

# Thread-safe cache: {(qname, qtype): (raw_response_bytes, expiry_timestamp)}
cache = {}
cache_lock = threading.Lock()

# 20 Global DNS Servers for Propagation Testing
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

# --- Core Server Logic ---

def forward_query(data):
    """Forwards the raw query to 8.8.8.8 and returns the raw response."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(SOCKET_TIMEOUT)
        sock.sendto(data, (UPSTREAM_DNS, UPSTREAM_PORT))
        response, _ = sock.recvfrom(4096)
        return response
    except socket.timeout:
        return None
    finally:
        sock.close()

def handle_client(data, addr, server_socket):
    """Processes an individual incoming DNS query."""
    try:
        request = DNSRecord.parse(data)
        qname = str(request.q.qname)
        qtype = request.q.qtype

        # 1. Check Cache
        with cache_lock:
            if (qname, qtype) in cache:
                raw_resp, expiry = cache[(qname, qtype)]
                if time.time() < expiry:
                    # Cache hit: Rewrite transaction ID to match the client's request
                    cached_resp = DNSRecord.parse(raw_resp)
                    cached_resp.header.id = request.header.id
                    server_socket.sendto(cached_resp.pack(), addr)
                    return
                else:
                    # Cache expired
                    del cache[(qname, qtype)]

        # 2. Cache Miss: Forward to Upstream
        response_data = forward_query(data)
        if not response_data:
            return  # Upstream timeout, drop request

        response_record = DNSRecord.parse(response_data)

        # 3. Extract TTL and update Cache
        ttl = 60 # Default TTL if none found
        if response_record.rr:
            ttl = min([rr.ttl for rr in response_record.rr])
        
        with cache_lock:
            cache[(qname, qtype)] = (response_data, time.time() + ttl)

        # 4. Send back to client
        server_socket.sendto(response_data, addr)

    except Exception as e:
        print(f"\n[!] Error handling request from {addr}: {e}")

def run_dns_server():
    """Binds the UDP socket and listens for incoming queries."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        server_socket.bind((HOST, PORT))
        print(f"[*] Local DNS Server listening on {HOST}:{PORT}")
    except PermissionError:
        print("\n[!] Permission Denied. You must run this script as Administrator/Root to bind to port 53.")
        import os
        os._exit(1)

    while True:
        try:
            data, addr = server_socket.recvfrom(512)
            thread = threading.Thread(target=handle_client, args=(data, addr, server_socket))
            thread.daemon = True
            thread.start()
        except Exception as e:
            print(f"\n[!] Server error: {e}")

# --- Propagation Engine ---

def run_propagation_test(domain):
    """Queries 20 global servers for the A record of a domain."""
    print(f"\n--- Propagation Test: {domain} ---")
    print(f"{'Provider':<20} | {'Status/IP':<15} | {'Latency'}")
    print("-" * 55)

    for name, ip in GLOBAL_SERVERS.items():
        res = dns.resolver.Resolver(configure=False)
        res.nameservers = [ip]
        res.timeout = 2.0
        res.lifetime = 2.0
        
        start_time = time.time()
        try:
            # Query A record
            answers = res.resolve(domain, 'A')
            latency = round((time.time() - start_time) * 1000, 2)
            # Extract first IP for clean display
            resolved_ip = answers[0].to_text()
            print(f"{name:<20} | {resolved_ip:<15} | {latency}ms")
        except Exception:
            print(f"{name:<20} | {'SERVER DOWN':<15} | N/A")
    print("-" * 55)

# --- Main CLI Interface ---

if __name__ == "__main__":
    # Start the DNS server in a background daemon thread
    server_thread = threading.Thread(target=run_dns_server)
    server_thread.daemon = True
    server_thread.start()

    # Give the server a moment to output its startup message
    time.sleep(0.5)

    print("\nServer is running in the background.")
    print("Type a domain name to run a propagation test, or 'quit' to exit.")

    while True:
        try:
            command = input("\nDNS-CLI> ").strip()
            if command.lower() in ['quit', 'exit']:
                break
            elif command:
                run_propagation_test(command)
        except KeyboardInterrupt:
            break
        
    print("\nShutting down.")