import socket
import json
import struct

CONTROL_PORT = 8443
DATA_PORT_RANGE = (50000, 50050)
BUFFER_SIZE = 4096
FORMAT = 'utf-8'

def send_msg(sock, msg_dict):
    msg_bytes = json.dumps(msg_dict).encode(FORMAT)
    sock.sendall(struct.pack('!I', len(msg_bytes)))
    sock.sendall(msg_bytes)

def recv_msg(sock):
    raw_msglen = recvall(sock, 4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('!I', raw_msglen)[0]
    data = recvall(sock, msglen)
    if not data:
        return None
    return json.loads(data.decode(FORMAT))

def recvall(sock, n):
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return data

class DataConnection:
    def send_data(self, data: bytes):
        raise NotImplementedError

    def recv_data(self, buffer_size: int) -> bytes:
        raise NotImplementedError

    def close(self):
        raise NotImplementedError

class TCPDataConnection(DataConnection):
    def __init__(self, sock):
        self.sock = sock

    def send_data(self, data: bytes):
        self.sock.sendall(data)

    def recv_data(self, buffer_size: int) -> bytes:
        return self.sock.recv(buffer_size)
    
    def close(self):
        self.sock.close()

class RUDPDataConnection(DataConnection):
    def __init__(self, sock, dest_addr=None):
        self.sock = sock
        self.dest_addr = dest_addr

    def send_data(self, data: bytes):
        pass

    def recv_data(self, buffer_size: int) -> bytes:
        pass
    
    def close(self):
        pass
