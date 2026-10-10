import socket
import ssl
import os

HOST = "0.0.0.0"
PORT = 4443

CERT_FILE = "server.crt"
KEY_FILE = "server.key"

# -----------------------------------------------------
#  Auto-generate SSL certificate if missing
# -----------------------------------------------------
def generate_certificate():
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        return

    print("[SERVER] SSL certificate not found. Generating new certificate...")

    from OpenSSL import crypto

    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)

    cert = crypto.X509()
    cert.get_subject().CN = "localhost"
    cert.set_serial_number(1)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, "sha256")

    with open(CERT_FILE, "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

    with open(KEY_FILE, "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

    print("[SERVER] SSL certificate generated successfully!")


# -----------------------------------------------------
#  MAIN SERVER
# -----------------------------------------------------
def start_server():
    generate_certificate()

    print("Server listening on", HOST, PORT)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)

    while True:
        conn, addr = server_socket.accept()
        print(f"[SERVER] Connection from {addr}")

        mode = conn.recv(1).decode()

        # -----------------------------------------------------
        # 1 → SSL Secure Connection
        # -----------------------------------------------------
        if mode == "1":
            print("[SERVER] Switching to SSL secure connection")

            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

            conn = ssl_context.wrap_socket(conn, server_side=True)

            data = conn.recv(1024).decode()
            print("[SERVER][SSL] Received:", data)
            conn.send(b"Secure message received by server")

        # -----------------------------------------------------
        # 2 → Normal TCP Connection
        # -----------------------------------------------------
        else:
            print("[SERVER] Using normal unsecure connection")
            data = conn.recv(1024).decode()
            print("[SERVER][UNSECURE] Received:", data)
            conn.send(b"Unsecure message received by server")

        conn.close()


start_server()
