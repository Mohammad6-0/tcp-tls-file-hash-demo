import json
import socket
import struct
from typing import Any

MAX_JSON_BYTES = 1024 * 1024
MAX_FILE_BYTES = 50 * 1024 * 1024
CHUNK_SIZE = 64 * 1024


def receive_exact(connection: socket.socket, size: int) -> bytes:
    """Read exactly size bytes from a TCP stream or raise if it closes early."""
    if size < 0:
        raise ValueError("size cannot be negative")
    data = bytearray()
    while len(data) < size:
        chunk = connection.recv(min(CHUNK_SIZE, size - len(data)))
        if not chunk:
            raise ConnectionError("The peer closed the connection early.")
        data.extend(chunk)
    return bytes(data)


def send_json(connection: socket.socket, message: dict[str, Any]) -> None:
    payload = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_JSON_BYTES:
        raise ValueError("JSON message is too large.")
    header = struct.pack("!I", len(payload))
    connection.sendall(header + payload)


def receive_json(connection: socket.socket) -> dict[str, Any]:
    header = receive_exact(connection, 4)
    (size,) = struct.unpack("!I", header)
    if size == 0 or size > MAX_JSON_BYTES:
        raise ValueError("Invalid JSON message size.")
    payload = receive_exact(connection, size)
    message = json.loads(payload.decode("utf-8"))
    if not isinstance(message, dict):
        raise ValueError("Expected a JSON object.")
    return message
