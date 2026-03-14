import socket  # Provides low-level networking (UDP sockets)
import struct  # Used to pack and unpack packet headers
import select  # Used for timeout handling and non-blocking reads
import math
import time
import logging

# Initialize the logger for this module
logger = logging.getLogger(__name__)


class RUDPSocket:
    # Header format: Sequence (4 bytes), ACK (4 bytes), Flags (1 byte)
    HEADER_FORMAT = "!IIB"
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

    # Max message size in bytes to stay under UDP limit
    MAX_PAYLOAD = 60000

    # Message types
    FLAG_SYN = 0x01
    FLAG_ACK = 0x02
    FLAG_DATA = 0x04
    FLAG_FIN = 0x08

    def __init__(self, sock=None):
        # Create UDP socket
        self.sock = sock if sock else socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setblocking(False)  # Switch socket to non-blocking mode
        self.dest_addr = None

        self.seq_num = 0
        self.expected_seq = 0
        self.recv_buffer = bytearray()
        self.ooo_buffer = {}  # Stores out-of-order packets for Selective Repeat

        # -------- Congestion Control --------
        self.cwnd = 1.0  # Sliding window size
        self.ssthresh = 16.0  # Slow start threshold

        # -------- Timeout Variables --------
        self.estimated_rtt = 0.1  # Default estimated RTT (100ms)
        self.dev_rtt = 0.0
        self.rto = 0.5  # Timeout for retransmission (seconds)
        self.send_times = {}  # Tracks when packets were sent
        self.retransmitted = set()

        self.dup_ack_count = 0

    def bind(self, address):
        self.sock.bind(address)

    def set_destination(self, address):
        self.dest_addr = address

    def _pack_header(self, seq, ack, flags):
        return struct.pack(self.HEADER_FORMAT, seq, ack, flags)

    def _unpack_header(self, data):
        return struct.unpack(self.HEADER_FORMAT, data[:self.HEADER_SIZE])

    def sendall(self, data: bytes):
        # Split full file into smaller chunks
        chunks = [data[i:i + self.MAX_PAYLOAD] for i in range(0, len(data), self.MAX_PAYLOAD)]
        total_chunks = len(chunks)

        base = 0
        next_seq = 0

        MAX_SEND_RETRIES = 50
        timeout_retries = 0

        # Main sending loop
        while base < total_chunks:
            # -------- Send window --------
            while next_seq < base + int(self.cwnd) and next_seq < total_chunks:
                global_seq = self.seq_num + next_seq
                header = self._pack_header(global_seq, 0, self.FLAG_DATA)

                try:
                    self.sock.sendto(header + chunks[next_seq], self.dest_addr)
                except (BlockingIOError, ConnectionResetError):
                    pass  # Ignore block/reset and let timeout handle retransmission

                # Record send time to calculate RTT later
                if global_seq not in self.send_times:
                    self.send_times[global_seq] = time.time()

                next_seq += 1

            # Wait for ACKs
            ready = select.select([self.sock], [], [], self.rto)

            if ready[0]:
                timeout_retries = 0  # Reset failsafe counter

                # Receive all available packets from the OS buffer
                while True:
                    try:
                        recv_data, addr = self.sock.recvfrom(65535)
                        if addr != self.dest_addr:
                            continue

                        recv_seq, recv_ack, recv_flags = self._unpack_header(recv_data)

                        if recv_flags & self.FLAG_ACK:
                            ack_idx = recv_ack - self.seq_num

                            # Cumulative ACK for new data
                            if ack_idx > base:
                                sample_seq = self.seq_num + ack_idx - 1

                                # Update dynamic timeout (Karn's Algorithm)
                                if sample_seq in self.send_times and sample_seq not in self.retransmitted:
                                    sample_rtt = time.time() - self.send_times[sample_seq]
                                    self.estimated_rtt = 0.875 * self.estimated_rtt + 0.125 * sample_rtt
                                    self.dev_rtt = 0.75 * self.dev_rtt + 0.25 * abs(sample_rtt - self.estimated_rtt)
                                    self.rto = self.estimated_rtt + 4 * self.dev_rtt

                                    logger.info(
                                        f"[RTT Log] Sample: {sample_rtt * 1000:.1f}ms | Estimated: {self.estimated_rtt * 1000:.1f}ms | New RTO: {self.rto * 1000:.1f}ms"
                                    )

                                acked_amount = ack_idx - base
                                base = ack_idx
                                self.dup_ack_count = 0

                                old_cwnd = self.cwnd

                                # Increase window size
                                if self.cwnd < self.ssthresh:
                                    self.cwnd += acked_amount
                                    logger.info(f"[Slow Start] cwnd jumped from {old_cwnd:.2f} -> {self.cwnd:.2f}")
                                else:
                                    self.cwnd += acked_amount / self.cwnd
                                    logger.info(
                                        f"[Full Speed - Congestion Avoidance] cwnd grew from {old_cwnd:.2f} -> {self.cwnd:.2f}"
                                    )

                            # -------- Fast Retransmit --------
                            elif ack_idx == base:
                                self.dup_ack_count += 1
                                if self.dup_ack_count == 3:
                                    logger.warning(
                                        f"[Fast Retransmit] 3 Dup ACKs for packet {self.seq_num + base}. Retransmitting immediately!"
                                    )

                                    # Resend missing packet
                                    header = self._pack_header(self.seq_num + base, 0, self.FLAG_DATA)
                                    try:
                                        self.sock.sendto(header + chunks[base], self.dest_addr)
                                    except (BlockingIOError, ConnectionResetError):
                                        pass

                                    self.retransmitted.add(self.seq_num + base)

                                    # Cut threshold in half
                                    self.ssthresh = max(self.cwnd / 2.0, 2.0)
                                    self.cwnd = self.ssthresh + 3.0

                    except (BlockingIOError, ConnectionResetError):
                        break  # Buffer is empty or connection reset
            else:
                # -------- Timeout handling --------
                timeout_retries += 1
                if timeout_retries >= MAX_SEND_RETRIES:
                    raise TimeoutError("RUDP sendall timed out waiting for ACKs.")

                logger.warning(f"[TIMEOUT] RTO of {self.rto * 1000:.1f}ms expired! Resetting window.")

                # Drop window to 1
                self.ssthresh = max(self.cwnd / 2.0, 2.0)
                self.cwnd = 1.0
                self.dup_ack_count = 0
                self.retransmitted.add(self.seq_num + base)

                # Send the missing packet
                header = self._pack_header(self.seq_num + base, 0, self.FLAG_DATA)
                try:
                    self.sock.sendto(header + chunks[base], self.dest_addr)
                except (BlockingIOError, ConnectionResetError):
                    pass

        # Reset state for next transfer
        self.seq_num += total_chunks
        self.send_times.clear()
        self.retransmitted.clear()

    def recvall(self, size: int) -> bytes:
        timeout_retries = 0
        MAX_RETRIES = 150  # 150 * 0.1s = 15 seconds max timeout

        while len(self.recv_buffer) < size:
            ready = select.select([self.sock], [], [], 0.1)

            if ready[0]:
                timeout_retries = 0  # Reset on activity

                # Receive all available packets
                while True:
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
                                # Reassemble full message in order
                                self.recv_buffer.extend(payload)
                                self.expected_seq += 1

                                # Add any out-of-order packets that are ready
                                while self.expected_seq in self.ooo_buffer:
                                    self.recv_buffer.extend(self.ooo_buffer.pop(self.expected_seq))
                                    self.expected_seq += 1

                                # Send ACK
                                ack_header = self._pack_header(0, self.expected_seq, self.FLAG_ACK)
                                self.sock.sendto(ack_header, self.dest_addr)

                            elif seq > self.expected_seq:
                                # Store packet for later
                                if seq not in self.ooo_buffer:
                                    self.ooo_buffer[seq] = payload

                                # Send duplicate ACK
                                ack_header = self._pack_header(0, self.expected_seq, self.FLAG_ACK)
                                self.sock.sendto(ack_header, self.dest_addr)

                            elif seq < self.expected_seq:
                                # Acknowledge old packets again
                                ack_header = self._pack_header(0, self.expected_seq, self.FLAG_ACK)
                                self.sock.sendto(ack_header, self.dest_addr)

                    except (BlockingIOError, ConnectionResetError):
                        break
            else:
                timeout_retries += 1
                if timeout_retries >= MAX_RETRIES:
                    raise TimeoutError("RUDP recvall timed out waiting for packets.")

        # Return the requested amount of data
        data_to_return = bytes(self.recv_buffer[:size])
        del self.recv_buffer[:size]
        return data_to_return

    def close(self):
        # Close socket
        self.sock.close()