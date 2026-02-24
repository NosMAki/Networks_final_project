# this is a central config module that contains shared constants
# (ports, timeouts, packet sizes, window size, defaults)
# so the client, servers, and RUDP transport all use the exact same parameters.
# Keeping them as constants prevents mismatches between components,
# and makes tuning the protocol easy without touching the core logic.

# Network addresses
HOST_ANY = "0.0.0.0"          # Servers bind here
HOST_LOCAL = "127.0.0.1"      # Client default target

# Service ports
DHCP_PORT = 55000             # Client - DHCP (discover/offer/request/ack)
DNS_PORT  = 55001             # Client - Local DNS (resolve FTP server)
FTP_PORT  = 55002             # Client - FTP control (TCP or RUDP on the same port)

# Timeouts and retries
SOCKET_TIMEOUT_SEC = 3.0      # Default blocking timeout
RUDP_RTO_SEC = 0.30           # RUDP retransmission timeout
RUDP_MAX_RETRIES = 20         # Hard stop to avoid infinite resend loops

# RUDP sliding window / ACK strategy
RUDP_WINDOW_SIZE = 8          # Sender window size (GBN-style)
RUDP_ACK_EVERY = 1            # Cumulative ACK every N in-order packets (1 = always)
RUDP_DUPACK_THRESHOLD = 3     # If we want implement fast-retransmit later (optional)

# Packet / message sizes
UDP_MTU = 1200                # Safe payload budget to avoid fragmentation (approx)
RUDP_HEADER_BUDGET = 64       # Reserve bytes for your header fields (rough)
RUDP_MAX_PAYLOAD = UDP_MTU - RUDP_HEADER_BUDGET  # Max bytes for data in one RUDP packet

TCP_RECV_CHUNK = 4096         # recv() chunk for TCP stream reads
LINE_DELIM = "\n"             # JSON-per-line delimiter

# Sequencing
SEQ_START = 0                 # First sequence number
SEQ_MODULO = 1 << 16          # 16-bit seq space

# DHCP defaults
DHCP_LEASE_SECONDS = 300      # Lease lifetime
DHCP_POOL_START = 100         # 192.168.1.<start>
DHCP_POOL_END   = 200         # 192.168.1.<end>
DHCP_NET_PREFIX = "192.168.1" # Simple /24-style prefix

# DNS defaults (local and minimal)
DNS_DEFAULT_TTL = 60          # Seconds to cache results
DNS_FTP_NAME = "ftp.local"    # Name that resolves to the FTP server

# FTP application defaults
FTP_ROOT_DIR = "storage"      # Server-side directory for files
FTP_DEFAULT_MODE = "rudp"     # "tcp" or "rudp" (client can override)
FTP_MAX_FILENAME = 255        # Simple sanity limit

# Debugging
DEBUG = True                 # Toggle noisy prints across the project