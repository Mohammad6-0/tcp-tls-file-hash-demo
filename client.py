import hashlib
import socket
import ssl
from pathlib import Path

from protocol import CHUNK_SIZE, MAX_FILE_BYTES, receive_json, send_json

#---variables------
HOST = "127.0.0.1"
TLS_SERVER_NAME = "localhost"
PLAIN_PORT = 4444
TLS_PORT = 4443
CERT_FILE = Path(__file__).resolve().with_name("server.crt")
MAX_MESSAGE_CHARS = 32_000
#------------------

def connect(use_tls: bool) -> socket.socket:
    port = TLS_PORT if use_tls else PLAIN_PORT
    raw_socket = socket.create_connection((HOST, port), timeout=10)
    raw_socket.settimeout(30)
    if not use_tls:
        return raw_socket

    if not CERT_FILE.is_file():
        raw_socket.close()
        raise FileNotFoundError("Start server.py first so it can create server.crt.")

    context = ssl.create_default_context(cafile=str(CERT_FILE))
    try:
        connection = context.wrap_socket(raw_socket, server_hostname=TLS_SERVER_NAME)
    except Exception:
        raw_socket.close()
        raise
    return connection


def send_message(connection: socket.socket) -> None:
    text = input("Message (type /back to return): ")
    if text == "/back":
        return
    if len(text) > MAX_MESSAGE_CHARS:
        print(f"Message is too long (limit: {MAX_MESSAGE_CHARS} characters).")
        return
    send_json(connection, {"action": "message", "text": text})
    reply = receive_json(connection)
    if reply.get("ok"):
        print("Server:", reply.get("reply", ""))
    else:
        print("Server error:", reply.get("error", "unknown error"))


def send_file_hash_request(connection: socket.socket) -> None:
    raw_path = input("Path to a file on this computer: ").strip().strip('"')
    path = Path(raw_path).expanduser()
    if not path.is_file():
        print("That file does not exist or is not a regular file.")
        return

    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        print(f"File is too large (limit: {MAX_FILE_BYTES // (1024 * 1024)} MiB).")
        return

    send_json(connection, {
        "action": "hash_file",
        "filename": path.name,
        "size": size,
    })

    local_digest = hashlib.sha256()
    bytes_sent = 0
    with path.open("rb") as file_handle:
        while bytes_sent < size:
            chunk = file_handle.read(min(CHUNK_SIZE, size - bytes_sent))
            if not chunk:
                raise OSError("The file changed or ended while it was being sent.")
            connection.sendall(chunk)
            local_digest.update(chunk)
            bytes_sent += len(chunk)
        if file_handle.read(1):
            raise OSError("The file grew while it was being sent; retry the operation.")

    reply = receive_json(connection)
    if not reply.get("ok"):
        print("Server error:", reply.get("error", "unknown error"))
        return

    client_hash = local_digest.hexdigest()
    server_hash = reply.get("sha256", "")
    print("Client SHA-256:", client_hash)
    print("Server SHA-256:", server_hash)
    print("Hashes match." if client_hash == server_hash else "Hashes differ.")


def main() -> int:
    print("Choose connection type: 1) TLS  2) Plain TCP")
    choice = input("Enter 1 or 2: ").strip()
    if choice not in {"1", "2"}:
        print("Choose 1 or 2.")
        return 2

    use_tls = choice == "1"
    try:
        with connect(use_tls) as connection:
            if use_tls:
                print(f"TLS connection verified ({connection.version()}).")
            else:
                print("Plain TCP selected: traffic is not encrypted or authenticated.")

            while True:
                print("\n1) Send a message  2) Compare a file SHA-256  3) Exit")
                action = input("Choose an option: ").strip()
                if action == "1":
                    send_message(connection)
                elif action == "2":
                    send_file_hash_request(connection)
                elif action == "3":
                    send_json(connection, {"action": "exit"})
                    receive_json(connection)
                    break
                else:
                    print("Invalid option.")
    except (OSError, ssl.SSLError, ValueError, ConnectionError) as error:
        print(f"Connection error: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
