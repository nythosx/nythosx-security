import threading, json, http.server, socketserver
from urllib.parse import urlparse, parse_qs

class AuthT2Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/jwks":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            # Return a mock RSA key
            key = {"kty": "RSA", "kid": "test-kid", "n": "abc", "e": "AQAB"}
            self.wfile.write(json.dumps({"keys": [key]}).encode())
        elif parsed.path == "/protected":
            cookie = self.headers.get("Cookie", "")
            if "admin" in cookie:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Welcome admin")
            elif "user" in cookie:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Welcome user")
            else:
                self.send_response(401)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/login":
            # Simulate session fixation: do NOT rotate session_id
            self.send_response(200)
            self.send_header("Set-Cookie", "session_id=sec_checker_pre_plant_12345")
            self.end_headers()
            self.wfile.write(b"OK")
        elif parsed.path == "/graphql":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length))
            query = body.get("query", "")
            # Simulate batch alias bypass
            if query.count("a") > 50:
                data = {f"a{i}": {"id": f"1_{i}"} for i in range(1, 101)}
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"data": data}).encode())
            else:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"data": {}}')
        else:
            self.send_response(404)
            self.end_headers()

class AuthT2Fixture:
    def __init__(self):
        self.server = socketserver.TCPServer(("127.0.0.1", 0), AuthT2Handler)
        self.port = self.server.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
