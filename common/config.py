# common/config.py
# Central config module: shared constants (ports, timeouts, sizes, defaults)
# so client/servers/RUDP use the exact same parameters.

# Network addresses
HOST_ANY = "0.0.0.0"          # Servers bind here
HOST_LOCAL = "127.0.0.1"      # Client default target

# Service ports (real / well-known)
DHCP_SERVER_PORT = 67         # DHCP server listens on UDP/67
DHCP_CLIENT_PORT = 68         # DHCP client uses UDP/68
DNS_PORT = 53                 # DNS server listens on UDP/53
FTP_PORT = 21                 # FTP control listens on TCP/21 (we also reuse for RUDP mode)

# Timeouts and retries
SOCKET_TIMEOUT_SEC = 3.0      # Default blocking timeout
RUDP_RTO_SEC = 0.30           # RUDP retransmission timeout
RUDP_MAX_RETRIES = 20         # Hard stop to avoid infinite resend loops

# RUDP sliding window / ACK strategy
RUDP_WINDOW_SIZE = 8          # Sender window size
RUDP_ACK_EVERY = 1            # Cumulative ACK every N in-order packets
RUDP_DUPACK_THRESHOLD = 3     # Optional: for fast-retransmit later

# Packet / message sizes
UDP_MTU = 1200                # Safe payload budget to avoid fragmentation
RUDP_HEADER_BUDGET = 64       # Reserve bytes for your header fields
RUDP_MAX_PAYLOAD = UDP_MTU - RUDP_HEADER_BUDGET  # Max bytes for data in one RUDP packet

TCP_RECV_CHUNK = 4096         # recv() chunk for TCP stream reads
LINE_DELIM = "\n"             # JSON-per-line delimiter

# Sequencing
SEQ_START = 0                 # First sequence number
SEQ_MODULO = 1 << 16          # 16-bit seq space

# DHCP defaults (project-scale, not full DHCP spec)
DHCP_LEASE_SECONDS = 300      # Lease lifetime
DHCP_POOL_START = 100         # 192.168.1.<start>
DHCP_POOL_END = 200           # 192.168.1.<end>
DHCP_NET_PREFIX = "192.168.1" # Simple /24-style prefix

# DNS defaults (local and minimal)
DNS_DEFAULT_TTL = 60          # Seconds to cache results
DNS_FTP_NAME = "ftp.local"    # Name that resolves to the FTP server

# FTP application defaults
FTP_ROOT_DIR = "storage"      # Server-side directory for files
FTP_DEFAULT_MODE = "rudp"     # "tcp" or "rudp" (client can override)
FTP_MAX_FILENAME = 255        # Simple sanity limit

# Debugging
DEBUG = True                  # Toggle noisy prints across the project