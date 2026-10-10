import socket
import ssl

HOST = "127.0.0.1"
PORT = 4443

print("Choose connection type:")
print("1 = Secure SSL")
print("2 = Normal TCP")

choice = input("Enter 1 or 2: ").strip()

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

# Send mode to server
client_socket.send(choice.encode())

# -----------------------------------------------------
# 1 → SSL secure connection
# -----------------------------------------------------
if choice == "1":
    print("[CLIENT] SSL mode selected")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    client_socket = context.wrap_socket(client_socket, server_hostname=HOST)

    client_socket.send(b"Hello from client (secure)")
    reply = client_socket.recv(1024)
    print("[CLIENT][SSL] Server:", reply.decode())

# -----------------------------------------------------
# 2 → Normal TCP
# -----------------------------------------------------
else:
    print("[CLIENT] Normal unsecure mode selected")

    client_socket.send(b"Hello from client (unsecure)")
    reply = client_socket.recv(1024)
    print("[CLIENT][UNSECURE] Server:", reply.decode())

client_socket.close()
