import socket
import ssl
import threading
import os
import hashlib
import uuid
# Note: Added RUDPConnection to the import statement
from shared import send_msg, recv_msg, TCPDataConnection, RUDPConnection, CONTROL_PORT, DATA_PORT_RANGE, BUFFER_SIZE

USERS = {"admin": "password123"}
SERVER_DATA_DIR = "./server_data"


class BackupServer:
    def __init__(self):
        self.active_sessions = {}
        if not os.path.exists(SERVER_DATA_DIR):
            os.makedirs(SERVER_DATA_DIR)

    def get_file_hash(self, filepath):
        if not os.path.exists(filepath):
            return None
        hasher = hashlib.md5()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(BUFFER_SIZE), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    def generate_manifest(self, username):
        user_dir = os.path.join(SERVER_DATA_DIR, username)
        manifest = {}
        for filename in os.listdir(user_dir):
            filepath = os.path.join(user_dir, filename)
            if os.path.isfile(filepath):
                stat = os.stat(filepath)
                manifest[filename] = {
                    "size": stat.st_size,
                    "mtime": stat.st_mtime,
                    "hash": self.get_file_hash(filepath)
                }
        return manifest

    def handle_data_transfer(self, token, filename, file_size, protocol, action):
        # Choose socket type based on the protocol
        sock_type = socket.SOCK_STREAM if protocol == "TCP" else socket.SOCK_DGRAM
        data_sock = socket.socket(socket.AF_INET, sock_type)
        data_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        data_port = None

        for port in range(DATA_PORT_RANGE[0], DATA_PORT_RANGE[1] + 1):
            try:
                data_sock.bind(('0.0.0.0', port))
                data_port = port
                break
            except OSError:
                continue

        if not data_port:
            print("CRITICAL: No available data ports in the specified range.")
            data_sock.close()
            return None

        # TCP requires listening, UDP does not
        if protocol == "TCP":
            data_sock.listen(1)

        data_sock.settimeout(15.0)

        def transfer_worker():
            try:
                # Split connection logic based on the protocol
                if protocol == "TCP":
                    conn, addr = data_sock.accept()
                    data_conn = TCPDataConnection(conn)
                    client_token = data_conn.recv_data(36).decode('utf-8')
                elif protocol == "RUDP":
                    # In RUDP, pass the socket directly to the class handling the handshake
                    data_conn = RUDPConnection(data_sock, is_server=True)
                    client_token, addr = data_conn.accept_connection()
                else:
                    print(f"Unknown protocol requested: {protocol}")
                    data_sock.close()
                    return

                # Token authentication
                if client_token != token:
                    print(f"Auth failed on data channel from {addr}")
                    if hasattr(data_conn, 'close'):
                        data_conn.close()
                    return

                username = self.active_sessions[token]
                filepath = os.path.join(SERVER_DATA_DIR, username, filename)

                # From here on, the logic remains uniform (polymorphism of data_conn)
                if action == "UPLOAD":
                    print(f"[{username}] Receiving {filename} via {protocol}...")
                    with open(filepath, "wb") as f:
                        received = 0
                        while received < file_size:
                            chunk = data_conn.recv_data(min(BUFFER_SIZE, file_size - received))
                            if not chunk:
                                break
                            f.write(chunk)
                            received += len(chunk)
                    print(f"[{username}] Finished receiving {filename}")

                elif action == "DOWNLOAD":
                    print(f"[{username}] Sending {filename} via {protocol}...")
                    with open(filepath, "rb") as f:
                        while True:
                            chunk = f.read(BUFFER_SIZE)
                            if not chunk:
                                break
                            data_conn.send_data(chunk)
                    print(f"[{username}] Finished sending {filename}")

                if hasattr(data_conn, 'close'):
                    data_conn.close()

            except socket.timeout:
                print(f"Data transfer timed out on port {data_port}")
            except Exception as e:
                print(f"Data transfer error: {e}")
            finally:
                data_sock.close()

        threading.Thread(target=transfer_worker, daemon=True).start()
        return data_port

    def handle_client(self, conn, addr):
        print(f"[NEW CONNECTION] {addr} connected.")
        current_token = None

        try:
            while True:
                msg = recv_msg(conn)
                if not msg:
                    break

                cmd = msg.get("cmd")

                if cmd == "AUTH":
                    username = msg.get("username")
                    password = msg.get("password")
                    if USERS.get(username) == password:
                        current_token = str(uuid.uuid4())
                        self.active_sessions[current_token] = username

                        user_dir = os.path.join(SERVER_DATA_DIR, username)
                        if not os.path.exists(user_dir):
                            os.makedirs(user_dir)

                        send_msg(conn, {"status": "success", "token": current_token})
                        print(f"User '{username}' authenticated.")
                    else:
                        send_msg(conn, {"status": "error", "msg": "Invalid credentials"})

                elif not current_token or current_token not in self.active_sessions:
                    send_msg(conn, {"status": "error", "msg": "Unauthorized."})
                    continue

                elif cmd == "GET_MANIFEST":
                    username = self.active_sessions[current_token]
                    manifest = self.generate_manifest(username)
                    send_msg(conn, {"status": "success", "manifest": manifest})

                elif cmd == "UPLOAD_INIT":
                    filename = os.path.basename(msg.get("filename", ""))
                    file_size = msg.get("file_size", 0)
                    protocol = msg.get("protocol", "TCP")

                    data_port = self.handle_data_transfer(current_token, filename, file_size, protocol, action="UPLOAD")
                    if data_port:
                        send_msg(conn, {"status": "ready", "data_port": data_port})
                    else:
                        send_msg(conn, {"status": "error", "msg": "Server ports exhausted."})

                elif cmd == "DOWNLOAD_INIT":
                    filename = os.path.basename(msg.get("filename", ""))
                    protocol = msg.get("protocol", "TCP")

                    username = self.active_sessions[current_token]
                    filepath = os.path.join(SERVER_DATA_DIR, username, filename)

                    if not os.path.exists(filepath):
                        send_msg(conn, {"status": "error", "msg": "File not found"})
                        continue

                    file_size = os.path.getsize(filepath)
                    data_port = self.handle_data_transfer(current_token, filename, file_size, protocol,action="DOWNLOAD")

                    if data_port:
                        send_msg(conn, {"status": "ready", "data_port": data_port, "file_size": file_size})
                    else:
                        send_msg(conn, {"status": "error", "msg": "Server ports exhausted."})

                elif cmd == "VERIFY_HASH":
                    filename = os.path.basename(msg.get("filename", ""))
                    username = self.active_sessions[current_token]
                    filepath = os.path.join(SERVER_DATA_DIR, username, filename)

                    file_hash = self.get_file_hash(filepath)
                    if file_hash:
                        send_msg(conn, {"status": "success", "hash": file_hash})
                    else:
                        send_msg(conn, {"status": "error", "msg": "File not found"})

        except Exception as e:
            print(f"Error handling client {addr}: {e}")
        finally:
            if current_token in self.active_sessions:
                del self.active_sessions[current_token]
            conn.close()
            print(f"[DISCONNECTED] {addr} disconnected.")

    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', CONTROL_PORT))
        server.listen(5)

        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")
        secure_server = context.wrap_socket(server, server_side=True)

        print(f"[STARTING] Server listening on port {CONTROL_PORT} with TLS")
        while True:
            conn, addr = secure_server.accept()
            thread = threading.Thread(target=self.handle_client, args=(conn, addr))
            thread.start()


if __name__ == "__main__":
    BackupServer().start()