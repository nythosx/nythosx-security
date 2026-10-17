"""graphql-ws connection_init + anonymous subscribe to admin channels. Bounded: 1 conn, 3 attempts, 5s timeout."""
import json, socket, ssl, time
from urllib.parse import urlparse
from ..roe_guard import ROEGuard

def scan(ws_url, roe_guard=None):
    if roe_guard is None: roe_guard = ROEGuard()
    roe_guard.check_url(ws_url.replace("ws://", "http://").replace("wss://", "https://"), "GET")

    parsed = urlparse(ws_url)
    host, port = parsed.hostname, parsed.port or (443 if parsed.scheme == "wss" else 80)

    try:
        sock = socket.create_connection((host, port), timeout=5)
        if parsed.scheme == "wss":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)

        # WebSocket handshake (simplified)
        key = "dGhlIHNhbXBsZSBub25jZQ=="
        handshake = (
            f"GET {parsed.path or '/'} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Protocol: graphql-transport-ws\r\n\r\n"
        )
        sock.sendall(handshake.encode())
        resp = sock.recv(4096).decode()

        if "101" in resp:
            # Send connection_init
            init_msg = json.dumps({"type": "connection_init"})
            # Frame it (simplified text frame)
            frame = bytearray([0x81, len(init_msg)]) + init_msg.encode()
            sock.sendall(frame)

            sock.settimeout(5)
            data = sock.recv(4096)
            if b"connection_ack" in data:
                # Attempt anonymous subscribe to admin channel
                sub_msg = json.dumps({"id": "1", "type": "subscribe", "payload": {"query": "subscription { adminLogs }"}})
                frame2 = bytearray([0x81, len(sub_msg)]) + sub_msg.encode()
                sock.sendall(frame2)

                try:
                    data2 = sock.recv(4096)
                    if b"next" in data2 and b"adminLogs" in data2:
                        return {"verdict": "VULNERABLE", "reason": "Anonymous WS subscription to admin channel succeeded"}
                except socket.timeout:
                    pass
        return {"verdict": "PASS", "reason": "WS subscription rejected or unauthenticated"}
    except Exception as e:
        return {"verdict": "UNKNOWN", "reason": f"WS probe failed: {e}"}
