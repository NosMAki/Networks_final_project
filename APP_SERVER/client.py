import socket
import ssl
import os
import time
import hashlib
import sys
import signal
from tqdm import tqdm
from shared import send_msg, recv_msg, TCPDataConnection, RUDPDataConnection, CONTROL_PORT, BUFFER_SIZE

SERVER_IP = '127.0.0.1' # Change to your live server's IP when deploying

class SyncClient:
    def __init__(self):
        self.secure_client = None
        self.token = None
        self.username = None
        self.sync_dir = os.path.abspath("./client_data")
        self.protocol = "TCP" # Default, can be toggled to RUDP
        self.running = True

        # Graceful Shutdown hook
        signal.signal(signal.SIGINT, self.shutdown_handler)

    def shutdown_handler(self, signum, frame):
        print("\n[!] Ctrl+C detected. Shutting down client safely...")
        self.running = False
        if self.secure_client:
            self.secure_client.close()
        sys.exit(0)

    def connect(self):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.secure_client = context.wrap_socket(client, server_hostname=SERVER_IP)
        
        try:
            print(f"[*] Connecting to server at {SERVER_IP}:{CONTROL_PORT}...")
            self.secure_client.connect((SERVER_IP, CONTROL_PORT))
            return True
        except Exception as e:
            print(f"[!] CRITICAL: Could not connect to server. {e}")
            return False

    def authenticate(self):
        while not self.token:
            print("\n--- SERVER AUTHENTICATION ---")
            user = input("Username: ").strip()
            pwd = input("Password: ").strip()

            send_msg(self.secure_client, {"cmd": "AUTH", "username": user, "password": pwd})
            resp = recv_msg(self.secure_client)
            
            if resp and resp.get("status") == "success":
                self.token = resp.get("token")
                self.username = user
                print("[+] Authentication successful!")
            else:
                print(f"[-] Login failed: {resp.get('msg') if resp else 'No response'}")

    def get_file_hash(self, filepath):
        if not os.path.exists(filepath):
            return None
        hasher = hashlib.md5()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(BUFFER_SIZE), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    def get_local_manifest(self):
        if not os.path.exists(self.sync_dir):
            os.makedirs(self.sync_dir)
        manifest = {}
        for filename in os.listdir(self.sync_dir):
            filepath = os.path.join(self.sync_dir, filename)
            if os.path.isfile(filepath):
                stat = os.stat(filepath)
                manifest[filename] = {
                    "size": stat.st_size,
                    "mtime": stat.st_mtime,
                    "hash": self.get_file_hash(filepath)
                }
        return manifest

    def upload_file(self, filename, file_size):
        filepath = os.path.join(self.sync_dir, filename)

        send_msg(self.secure_client, {
            "cmd": "UPLOAD_INIT",
            "filename": filename,
            "file_size": file_size,
            "protocol": self.protocol
        })
        init_resp = recv_msg(self.secure_client)
        
        if init_resp.get("status") != "ready":
            print(f"[-] Server rejected upload for {filename}: {init_resp.get('msg')}")
            return False

        data_port = init_resp.get("data_port")
        sock_type = socket.SOCK_STREAM if self.protocol == "TCP" else socket.SOCK_DGRAM
        data_sock = socket.socket(socket.AF_INET, sock_type)
        
        try:
            if self.protocol == "TCP":
                data_sock.connect((SERVER_IP, data_port))
                data_conn = TCPDataConnection(data_sock)
                data_conn.send_data(self.token.encode('utf-8'))
            elif self.protocol == "RUDP":
                data_conn = RUDPDataConnection(data_sock)
                data_conn.connect(self.token, (SERVER_IP, data_port))
            else:
                return False

            # Progress bar for Upload
            with open(filepath, "rb") as f, tqdm(
                desc=f"Uploading {filename}", total=file_size, unit="B", unit_scale=True, unit_divisor=1024
            ) as pbar:
                while True:
                    chunk = f.read(BUFFER_SIZE)
                    if not chunk:
                        break
                    data_conn.send_data(chunk)
                    pbar.update(len(chunk))

        except Exception as e:
            print(f"[-] Failed to upload {filename}: {e}")
            return False
        finally:
            if 'data_conn' in locals() and hasattr(data_conn, 'close'):
                data_conn.close()

        # Buffer time to ensure the server finishes writing to disk
        time.sleep(0.5) 
        
        # Post-Transfer Verification
        send_msg(self.secure_client, {"cmd": "VERIFY_HASH", "filename": filename})
        verify_resp = recv_msg(self.secure_client)
        
        if verify_resp.get("status") == "success":
            if verify_resp.get("hash") == self.get_file_hash(filepath):
                return True
        print(f"[-] ERROR: Hash mismatch for '{filename}'! Data corrupted during transfer.")
        return False

    def download_file(self, filename, expected_hash, expected_size):
        filepath = os.path.join(self.sync_dir, filename)

        send_msg(self.secure_client, {
            "cmd": "DOWNLOAD_INIT",
            "filename": filename,
            "protocol": self.protocol
        })
        init_resp = recv_msg(self.secure_client)
        
        if init_resp.get("status") != "ready":
            print(f"[-] Server rejected download for {filename}: {init_resp.get('msg')}")
            return False

        data_port = init_resp.get("data_port")
        sock_type = socket.SOCK_STREAM if self.protocol == "TCP" else socket.SOCK_DGRAM
        data_sock = socket.socket(socket.AF_INET, sock_type)

        try:
            if self.protocol == "TCP":
                data_sock.connect((SERVER_IP, data_port))
                data_conn = TCPDataConnection(data_sock)
                data_conn.send_data(self.token.encode('utf-8'))
            elif self.protocol == "RUDP":
                data_conn = RUDPDataConnection(data_sock)
                data_conn.connect(self.token, (SERVER_IP, data_port))
            else:
                return False

            # Progress bar for Download
            with open(filepath, "wb") as f, tqdm(
                desc=f"Downloading {filename}", total=expected_size, unit="B", unit_scale=True, unit_divisor=1024
            ) as pbar:
                received = 0
                while received < expected_size:
                    chunk = data_conn.recv_data(min(BUFFER_SIZE, expected_size - received))
                    if not chunk:
                        break
                    f.write(chunk)
                    received += len(chunk)
                    pbar.update(len(chunk))

        except Exception as e:
            print(f"[-] Failed to download {filename}: {e}")
            return False
        finally:
            if 'data_conn' in locals() and hasattr(data_conn, 'close'):
                data_conn.close()

        # Check hash locally to verify RUDP/TCP integrity
        if self.get_file_hash(filepath) == expected_hash:
            return True
        print(f"[-] ERROR: Hash mismatch for '{filename}'! Data corrupted during transfer.")
        return False

    def menu(self):
        while self.running:
            print("\n" + "="*45)
            print(f" BACKUP CLIENT | User: {self.username}")
            print(f" Directory: {self.sync_dir}")
            print(f" Protocol:  {self.protocol}")
            print("="*45)
            print("1. Sync Local Folder to Server (Upload Changes)")
            print("2. Restore All Files from Server (Download All)")
            print("3. Deep Manifest Verification (Check Integrity)")
            print("4. Change Target Directory")
            print("5. Toggle Protocol (TCP/RUDP)")
            print("6. Request Quota Increase")
            print("7. Exit")
            
            choice = input("\nSelect an option: ").strip()

            if choice == '1':
                self.action_sync()
            elif choice == '2':
                self.action_restore_all()
            elif choice == '3':
                self.action_view_manifest()
            elif choice == '4':
                new_dir = input("Enter new absolute or relative path: ").strip()
                if new_dir:
                    self.sync_dir = os.path.abspath(new_dir)
                    if not os.path.exists(self.sync_dir):
                        os.makedirs(self.sync_dir)
                    print(f"[+] Directory set to {self.sync_dir}")
            elif choice == '5':
                self.protocol = "RUDP" if self.protocol == "TCP" else "TCP"
                print(f"[+] Protocol switched to {self.protocol}")
            elif choice == '6':
                amount = input("How many additional MB do you need? ").strip()
                if amount.isdigit():
                    send_msg(self.secure_client, {"cmd": "QUOTA_REQUEST", "amount_mb": int(amount)})
                    resp = recv_msg(self.secure_client)
                    print(f"\n[Server Response]: {resp.get('msg', 'Request sent to admin.')}")
                else:
                    print("[-] Please enter a valid number.")
            elif choice == '7':
                self.shutdown_handler(None, None)
            else:
                print("[-] Invalid choice.")

    def action_view_manifest(self):
        print("\n[*] Fetching server manifest and verifying local hashes...")
        send_msg(self.secure_client, {"cmd": "GET_MANIFEST"})
        resp = recv_msg(self.secure_client)
        server_manifest = resp.get("manifest", {})
        
        local_manifest = self.get_local_manifest()
        
        if not server_manifest and not local_manifest:
            print("[-] Both server and local directories are empty.")
            return

        print("\n--- DEEP MANIFEST VERIFICATION ---")
        
        # 1. Compare local files against the server's truth
        for filename, local_data in local_manifest.items():
            server_data = server_manifest.get(filename)
            
            if not server_data:
                print(f"[?] {filename:<20} | LOCAL ONLY (Not backed up)")
            else:
                if local_data["hash"] == server_data["hash"]:
                    print(f"[+] {filename:<20} | OK (Hashes match)")
                else:
                    print(f"[!] {filename:<20} | MODIFIED / CORRUPTED (Hash mismatch)")

        # 2. Find files that exist on the server but are missing locally
        for filename, server_data in server_manifest.items():
            if filename not in local_manifest:
                size_mb = server_data['size'] / (1024*1024)
                print(f"[-] {filename:<20} | SERVER ONLY ({size_mb:.2f} MB)")
        print("-" * 34)

    def action_sync(self):
        send_msg(self.secure_client, {"cmd": "GET_MANIFEST"})
        server_manifest = recv_msg(self.secure_client).get("manifest", {})
        local_manifest = self.get_local_manifest()
        
        files_to_upload = []
        for filename, local_data in local_manifest.items():
            server_data = server_manifest.get(filename)
            # Upload if missing on server, or if local is newer
            if not server_data or local_data["mtime"] > server_data["mtime"]:
                files_to_upload.append((filename, local_data["size"]))

        if not files_to_upload:
            print("[+] Local folder is fully synced. Nothing to upload.")
            return

        print(f"[*] Found {len(files_to_upload)} files to update/upload.")
        for filename, size in files_to_upload:
            if self.upload_file(filename, size):
                print(f"[+] Successfully synced {filename}")

    def action_restore_all(self):
        send_msg(self.secure_client, {"cmd": "GET_MANIFEST"})
        server_manifest = recv_msg(self.secure_client).get("manifest", {})
        
        if not server_manifest:
            print("[-] Nothing on the server to restore.")
            return

        print(f"[*] Restoring {len(server_manifest)} files from server...")
        for filename, data in server_manifest.items():
            if self.download_file(filename, data["hash"], data["size"]):
                print(f"[+] Restored {filename}")

if __name__ == "__main__":
    client = SyncClient()
    if client.connect():
        client.authenticate()
        client.menu()
