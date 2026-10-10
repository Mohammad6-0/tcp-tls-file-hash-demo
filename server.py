import hashlib
import ipaddress
import socket
import ssl
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from protocol import CHUNK_SIZE, MAX_FILE_BYTES, receive_exact, receive_json, send_json

HOST = "127.0.0.1"
PLAIN_PORT = 4444
TLS_PORT = 4443
CERT_FILE = Path(__file__).resolve().with_name("server.crt")
KEY_FILE = Path(__file__).resolve().with_name("server.key")
MAX_MESSAGE_CHARS = 32_000


def ensure_certificate() -> None:
    if CERT_FILE.is_file() and KEY_FILE.is_file():
        return

    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    except ImportError as error:
        raise RuntimeError("Install dependencies with: python -m pip install -r requirements.txt") from error

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Local TCP TLS Demo"),
    ])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before_utc(now - timedelta(minutes=1))
        .not_valid_after_utc(now + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address(HOST)),
            ]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(private_key, hashes.SHA256())
    )

    KEY_FILE.write_bytes(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    CERT_FILE.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    print("Created a local self-signed certificate and private key.")


def handle_request(connection: socket.socket, request: dict) -> bool:
    action = request.get("action")

    if action == "message":
        text = request.get("text")
        if not isinstance(text, str) or len(text) > MAX_MESSAGE_CHARS:
            send_json(connection, {"ok": False, "error": "Invalid or oversized message."})
        else:
            print("Client message:", text)
            send_json(connection, {"ok": True, "reply": f"Received: {text}"})
        return True

    if action == "hash_file":
        filename = request.get("filename")
        size = request.get("size")
        if not isinstance(filename, str) or not filename or Path(filename).name != filename:
            raise ValueError("Invalid file name.")
        if type(size) is not int or not 0 <= size <= MAX_FILE_BYTES:
            raise ValueError("Invalid file size.")

        digest = hashlib.sha256()
        remaining = size
        while remaining:
            chunk = receive_exact(connection, min(CHUNK_SIZE, remaining))
            digest.update(chunk)
            remaining -= len(chunk)
        send_json(connection, {"ok": True, "filename": filename, "sha256": digest.hexdigest()})
        print(f"Hashed {filename} ({size} bytes).")
        return True

    if action == "exit":
        send_json(connection, {"ok": True, "reply": "Disconnected."})
        return False

    send_json(connection, {"ok": False, "error": "Unknown action."})
    return True


def handle_client(raw_connection: socket.socket, address, secure: bool, tls_context) -> None:
    connection = raw_connection
    mode = "TLS" if secure else "plain TCP"
    try:
        if secure:
            connection = tls_context.wrap_socket(raw_connection, server_side=True)
        with connection:
            print(f"{mode} client connected: {address}")
            while True:
                request = receive_json(connection)
                if not handle_request(connection, request):
                    break
    except (ConnectionError, OSError, ssl.SSLError, ValueError) as error:
        print(f"{mode} client {address} disconnected: {error}")
        raw_connection.close()


def serve_port(port: int, secure: bool, tls_context) -> None:
    mode = "TLS" if secure else "plain TCP"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((HOST, port))
        listener.listen()
        print(f"{mode} server listening on {HOST}:{port}")
        while True:
            connection, address = listener.accept()
            threading.Thread(
                target=handle_client,
                args=(connection, address, secure, tls_context),
                daemon=True,
            ).start()


def main() -> None:
    ensure_certificate()
    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
    tls_context.load_cert_chain(certfile=str(CERT_FILE), keyfile=str(KEY_FILE))

    listeners = [
        threading.Thread(target=serve_port, args=(PLAIN_PORT, False, tls_context), daemon=True),
        threading.Thread(target=serve_port, args=(TLS_PORT, True, tls_context), daemon=True),
    ]
    for listener in listeners:
        listener.start()

    print("Press Ctrl+C to stop the server.")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\nServer stopped.")


if __name__ == "__main__":
    main()
