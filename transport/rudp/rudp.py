import socket
import struct
import select
import math

class RUDPSocket:
    """
    Reliable UDP Socket implementation featuring:
    - Packet segmentation (Max 60KB payload)
    - Sliding Window (Go-Back-N ARQ)
    - Dynamic Congestion Control (AIMD / Slow Start)
    """
    HEADER_FORMAT = "!IIB"
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
    MAX_PAYLOAD = 60000

    FLAG_SYN = 0x01
    FLAG_ACK = 0x02
    FLAG_DATA = 0x04
    FLAG_FIN = 0x08

    def __init__(self, sock=None):
        self.sock = sock if sock else socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setblocking(False)
        self.dest_addr = None
        
        self.seq_num = 0
        self.expected_seq = 0
        self.recv_buffer = bytearray()
        
        self.cwnd = 1.0
        self.ssthresh = 16.0
        self.base_timeout = 0.5  

    def bind(self, address):
        self.sock.bind(address)

    def set_destination(self, address):
        self.dest_addr = address

    def _pack_header(self, seq, ack, flags):
        return struct.pack(self.HEADER_FORMAT, seq, ack, flags)

    def _unpack_header(self, data):
        return struct.unpack(self.HEADER_FORMAT, data[:self.HEADER_SIZE])

    def sendall(self, data: bytes):
        chunks = [data[i:i + self.MAX_PAYLOAD] for i in range(0, len(data), self.MAX_PAYLOAD)]
        total_chunks = len(chunks)
        base = 0
        next_seq = 0
        
        MAX_SEND_RETRIES = 50
        timeout_retries = 0

        while base < total_chunks:
            # 1. Send packets up to the current congestion window size
            while next_seq < base + int(self.cwnd) and next_seq < total_chunks:
                header = self._pack_header(self.seq_num + next_seq, 0, self.FLAG_DATA)
                try:
                    self.sock.sendto(header + chunks[next_seq], self.dest_addr)
                except (BlockingIOError, ConnectionResetError):
                    pass # Ignore block/reset and let timeout handle retransmission
                next_seq += 1

            # 2. Drain all incoming ACKs (Non-blocking loop)
            ack_received = False
            while True:
                # Use a very short timeout if we are just draining, or base_timeout if we are waiting
                timeout = 0.01 if ack_received else self.base_timeout
                ready = select.select([self.sock], [], [], timeout)
                
                if ready[0]:
                    timeout_retries = 0 # Reset failsafe counter
                    try:
                        recv_data, addr = self.sock.recvfrom(65535)
                        if addr != self.dest_addr:
                            continue  # Ignore rogue packets
                            
                        recv_seq, recv_ack, recv_flags = self._unpack_header(recv_data)
                        
                        if (recv_flags & self.FLAG_ACK) and recv_ack >= self.seq_num + base:
                            acked_amount = recv_ack - (self.seq_num + base) + 1
                            base += acked_amount
                            ack_received = True
                            
                            # AIMD Congestion Control
                            if self.cwnd < self.ssthresh:
                                self.cwnd += 1.0  # Slow Start
                            else:
                                # Safe Additive Increase (prevents division by zero)
                                self.cwnd += 1.0 / max(1.0, math.floor(self.cwnd))
                    except (BlockingIOError, ConnectionResetError):
                        break # Buffer is empty or connection reset (handle reset via timeout)
                else:
                    # Timeout occurred, no more ACKs to read
                    if not ack_received:
                        timeout_retries += 1
                        if timeout_retries >= MAX_SEND_RETRIES:
                            raise TimeoutError("RUDP sendall timed out waiting for ACKs.")
                            
                        # Multiplicative Decrease
                        self.ssthresh = max(self.cwnd / 2.0, 2.0)
                        self.cwnd = 1.0
                        # Go-Back-N: Reset next_seq to base
                        next_seq = base
                    break

        self.seq_num += total_chunks

    def recvall(self, size: int) -> bytes:
        timeout_retries = 0
        MAX_RETRIES = 150  # 150 * 0.1s = 15 seconds max timeout

        while len(self.recv_buffer) < size:
            ready = select.select([self.sock], [], [], 0.1)
            
            if ready[0]:
                timeout_retries = 0  # Reset on activity
                try:
                    data, addr = self.sock.recvfrom(65535)
                    
                    # Prevent Connection Hijacking
                    if self.dest_addr is None:
                        self.dest_addr = addr
                    elif addr != self.dest_addr:
                        continue  

                    seq, ack, flags = self._unpack_header(data)
                    payload = data[self.HEADER_SIZE:]

                    if flags & self.FLAG_DATA:
                        if seq == self.expected_seq:
                            self.recv_buffer.extend(payload)
                            self.expected_seq += 1
                            
                        # Always ACK the highest in-order packet we have
                        if seq <= self.expected_seq:
                            ack_header = self._pack_header(0, max(0, self.expected_seq - 1), self.FLAG_ACK)
                            self.sock.sendto(ack_header, self.dest_addr)
                            
                except (BlockingIOError, ConnectionResetError):
                    pass
            else:
                timeout_retries += 1
                if timeout_retries >= MAX_RETRIES:
                    raise TimeoutError("RUDP recvall timed out waiting for packets.")

        data_to_return = self.recv_buffer[:size]
        self.recv_buffer = self.recv_buffer[size:]
        return bytes(data_to_return)

    def close(self):
        self.sock.close()
