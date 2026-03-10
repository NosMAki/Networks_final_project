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

    # Header: Sequence Number (4 bytes), ACK Number (4 bytes), Flags (1 byte) -> Total 9 bytes
    HEADER_FORMAT = "!IIB"
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

    # Maximum payload size to strictly stay below the 64KB UDP limit
    MAX_PAYLOAD = 60000

    # Packet Flags
    FLAG_SYN = 0x01
    FLAG_ACK = 0x02
    FLAG_DATA = 0x04
    FLAG_FIN = 0x08

    def __init__(self, sock=None):
        self.sock = sock if sock else socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setblocking(False)  # Non-blocking socket for select() multiplexing
        self.dest_addr = None

        # Sequence and Acknowledgment tracking
        self.seq_num = 0
        self.expected_seq = 0

        # Buffer for incoming stream data
        self.recv_buffer = bytearray()

        # Congestion Control Variables (AIMD)
        self.cwnd = 1.0  # Congestion Window (starts at 1 packet)
        self.ssthresh = 16.0  # Slow Start Threshold
        self.base_timeout = 0.5  # RTO (Retransmission Timeout) in seconds

    def bind(self, address):
        self.sock.bind(address)

    def set_destination(self, address):
        """Sets the target address for outgoing packets."""
        self.dest_addr = address

    def _pack_header(self, seq, ack, flags):
        return struct.pack(self.HEADER_FORMAT, seq, ack, flags)

    def _unpack_header(self, data):
        return struct.unpack(self.HEADER_FORMAT, data[:self.HEADER_SIZE])

    def sendall(self, data: bytes):
        """
        Sends data reliably using a Sliding Window and AIMD Congestion Control.
        Segments the data into chunks of MAX_PAYLOAD.
        """
        # 1. Segment the data into allowed chunk sizes
        chunks = [data[i:i + self.MAX_PAYLOAD] for i in range(0, len(data), self.MAX_PAYLOAD)]
        total_chunks = len(chunks)

        base = 0  # Oldest unacknowledged packet index
        next_seq = 0  # Next packet index to be sent

        while base < total_chunks:
            # 2. Send packets up to the current congestion window size (cwnd)
            while next_seq < base + int(self.cwnd) and next_seq < total_chunks:
                header = self._pack_header(self.seq_num + next_seq, 0, self.FLAG_DATA)
                self.sock.sendto(header + chunks[next_seq], self.dest_addr)
                next_seq += 1

            # 3. Wait for ACKs using select (timeout based on RTO)
            ready = select.select([self.sock], [], [], self.base_timeout)

            if ready[0]:
                # We received something!
                try:
                    recv_data, addr = self.sock.recvfrom(65535)
                    if addr != self.dest_addr:
                        continue

                    recv_seq, recv_ack, recv_flags = self._unpack_header(recv_data)

                    # 4. Handle incoming ACK
                    if (recv_flags & self.FLAG_ACK) and recv_ack >= self.seq_num + base:
                        # Calculate how many packets were acknowledged (Cumulative ACK)
                        acked_amount = recv_ack - (self.seq_num + base) + 1
                        base += acked_amount

                        # 5. Congestion Control: Increase Window
                        if self.cwnd < self.ssthresh:
                            # Slow Start: Double the window size per RTT
                            self.cwnd += 1.0
                        else:
                            # Congestion Avoidance (Additive Increase)
                            self.cwnd += 1.0 / math.floor(self.cwnd)

                except BlockingIOError:
                    pass
            else:
                # 6. Timeout occurred (Packet Loss Detected!)
                # Multiplicative Decrease: Cut threshold in half, reset window
                self.ssthresh = max(self.cwnd / 2.0, 2.0)
                self.cwnd = 1.0

                # Go-Back-N: Reset next_seq to base to retransmit lost packets
                next_seq = base

        # Update the global sequence number for the next sendall() call
        self.seq_num += total_chunks

    def recvall(self, size: int) -> bytes:
        """
        Receives exactly 'size' bytes reliably.
        Buffers out-of-order packets and handles ACK generation.
        """
        while len(self.recv_buffer) < size:
            ready = select.select([self.sock], [], [], 0.1)

            if ready[0]:
                try:
                    data, addr = self.sock.recvfrom(65535)
                    self.dest_addr = addr  # Learn client address if acting as server

                    seq, ack, flags = self._unpack_header(data)
                    payload = data[self.HEADER_SIZE:]

                    if flags & self.FLAG_DATA:
                        if seq == self.expected_seq:
                            # In-order packet received: Append to buffer and increment expected_seq
                            self.recv_buffer.extend(payload)
                            self.expected_seq += 1

                            # Send ACK for the received packet
                            ack_header = self._pack_header(0, self.expected_seq - 1, self.FLAG_ACK)
                            self.sock.sendto(ack_header, self.dest_addr)

                        elif seq < self.expected_seq:
                            # Old packet received (our ACK might have been lost): Re-send ACK
                            ack_header = self._pack_header(0, self.expected_seq - 1, self.FLAG_ACK)
                            self.sock.sendto(ack_header, self.dest_addr)

                        # (If seq > self.expected_seq, it's out of order. In Go-Back-N, we simply drop it and wait for retransmission)

                except BlockingIOError:
                    pass

        # Extract exactly 'size' bytes from the buffer to return
        data_to_return = self.recv_buffer[:size]
        self.recv_buffer = self.recv_buffer[size:]
        return bytes(data_to_return)

    def close(self):
        self.sock.close()