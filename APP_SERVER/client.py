import socket
import ssl
import os
import hashlib
from shared import send_msg, recv_msg, TCPDataConnection, RUDPDataConnection, CONTROL_PORT, BUFFER_SIZE

CLIENT_DATA_DIR = "./client_data"
SERVER_IP = '127.0.0.1'  # Change this to your live server IP or 127.0.0.1 for local testing

def get_file_hash(filepath):
    if not os.path.exists(filepath):
        return None
    hasher = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(BUFFER_SIZE), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

def get_local_manifest():
    if not os.path.exists(CLIENT_DATA_DIR):
        os.makedirs(CLIENT_DATA_DIR)
    manifest = {}
    for filename in os.listdir(CLIENT_DATA_DIR):
        filepath = os.path.join(CLIENT_DATA_DIR, filename)
        if os.path.isfile(filepath):
            stat = os.stat(filepath)
            manifest[filename] = {
                "size": stat.st_size,
                "mtime": stat.st_mtime,
                "hash": get_file_hash(filepath)
            }
    return manifest

def upload_file(secure_client, filename, file_size, token, protocol="TCP"):
    print(f"Uploading '{filename}' via {protocol}...")
    filepath = os.path.join(CLIENT_DATA_DIR, filename)

    send_msg(secure_client, {
        "cmd": "UPLOAD_INIT",
        "filename": filename,
        "file_size": file_size,
        "protocol": protocol
    })
    init_resp = recv_msg(secure_client)

    if init_resp.get("status") != "ready":
        print(f"Server rejected upload for {filename}: {init_resp.get('msg')}")
        return False

    data_port = init_resp.get("data_port")
    sock_type = socket.SOCK_STREAM if protocol == "TCP" else socket.SOCK_DGRAM
    data_sock = socket.socket(socket.AF_INET, sock_type)

    try:
        if protocol == "TCP":
            data_sock.connect((SERVER_IP, data_port))
            data_conn = TCPDataConnection(data_sock)
            data_conn.send_data(token.encode('utf-8'))
        elif protocol == "RUDP":
            data_conn = RUDPDataConnection(data_sock)
            data_conn.connect(token, (SERVER_IP, data_port))
        else:
            print(f"Unknown protocol requested: {protocol}")
            data_sock.close()
            return False

        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(BUFFER_SIZE)
                if not chunk:
                    break
                data_conn.send_data(chunk)

    except Exception as e:
        print(f"Failed to upload {filename}: {e}")
        return False
    finally:
        if 'data_conn' in locals() and hasattr(data_conn, 'close'):
            data_conn.close()

    # Wait for the server to verify the hash (server handles the wait natively now)
    send_msg(secure_client, {"cmd": "VERIFY_HASH", "filename": filename})
    verify_resp = recv_msg(secure_client)

    if verify_resp.get("status") == "success":
        server_hash = verify_resp.get("hash")
        local_hash = get_file_hash(filepath)
        if server_hash == local_hash:
            print(f"SUCCESS: '{filename}' uploaded and verified.")
            return True
        else:
            print(f"ERROR: Hash mismatch for '{filename}'.")
            return False
    return False

def download_file(secure_client, filename, expected_hash, token, protocol="TCP"):
    print(f"Downloading '{filename}' via {protocol}...")
    filepath = os.path.join(CLIENT_DATA_DIR, filename)

    send_msg(secure_client, {
        "cmd": "DOWNLOAD_INIT",
        "filename": filename,
        "protocol": protocol
    })
    init_resp = recv_msg(secure_client)

    if init_resp.get("status") != "ready":
        print(f"Server rejected download for {filename}: {init_resp.get('msg')}")
        return False

    data_port = init_resp.get("data_port")
    expected_size = init_resp.get("file_size")

    sock_type = socket.SOCK_STREAM if protocol == "TCP" else socket.SOCK_DGRAM
    data_sock = socket.socket(socket.AF_INET, sock_type)

    try:
        if protocol == "TCP":
            data_sock.connect((SERVER_IP, data_port))
            data_conn = TCPDataConnection(data_sock)
            data_conn.send_data(token.encode('utf-8'))
        elif protocol == "RUDP":
            data_conn = RUDPDataConnection(data_sock)
            data_conn.connect(token, (SERVER_IP, data_port))
        else:
            print(f"Unknown protocol requested: {protocol}")
            data_sock.close()
            return False

        with open(filepath, "wb") as f:
            received = 0
            while received < expected_size:
                chunk = data_conn.recv_data(min(BUFFER_SIZE, expected_size - received))
                if not chunk:
                    break
                f.write(chunk)
                received += len(chunk)

    except Exception as e:
        print(f"Failed to download {filename}: {e}")
        return False
    finally:
        if 'data_conn' in locals() and hasattr(data_conn, 'close'):
            data_conn.close()

    local_hash = get_file_hash(filepath)
    if local_hash == expected_hash:
        print(f"SUCCESS: '{filename}' downloaded and verified.")
        return True
    else:
        print(f"ERROR: Hash mismatch for '{filename}'.")
        return False

def main():
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    secure_client = context.wrap_socket(client, server_hostname=SERVER_IP)

    try:
        secure_client.connect((SERVER_IP, CONTROL_PORT))
    except Exception as e:
        print(f"CRITICAL: Could not connect to {SERVER_IP}:{CONTROL_PORT}. {e}")
        return

    send_msg(secure_client, {"cmd": "AUTH", "username": "admin", "password": "password123"})
    auth_resp = recv_msg(secure_client)

    if auth_resp.get("status") != "success":
        print(f"Authentication failed: {auth_resp.get('msg')}")
        secure_client.close()
        return

    token = auth_resp.get("token")
    print("Authentication successful.")

    send_msg(secure_client, {"cmd": "GET_MANIFEST"})
    manifest_resp = recv_msg(secure_client)
    server_manifest = manifest_resp.get("manifest", {})

    local_manifest = get_local_manifest()
    files_to_upload = []
    files_to_download = []

    for filename, local_data in local_manifest.items():
        server_data = server_manifest.get(filename)
        if not server_data or local_data["mtime"] > server_data["mtime"]:
            files_to_upload.append((filename, local_data["size"]))

    for filename, server_data in server_manifest.items():
        local_data = local_manifest.get(filename)
        if not local_data or server_data["mtime"] > local_data["mtime"]:
            if filename not in [f[0] for f in files_to_upload]:
                files_to_download.append((filename, server_data["hash"]))

    if not files_to_upload and not files_to_download:
        print("Folders are fully synchronized. Nothing to do.")
    else:
        print(f"Sync Plan: {len(files_to_upload)} files to upload, {len(files_to_download)} files to download.")

    for filename, file_size in files_to_upload:
        upload_file(secure_client, filename, file_size, token, protocol="RUDP")

    for filename, expected_hash in files_to_download:
        download_file(secure_client, filename, expected_hash, token, protocol="RUDP")

    secure_client.close()
    print("Session closed.")

if __name__ == "__main__":
    main()
