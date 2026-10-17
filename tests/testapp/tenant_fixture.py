import threading, json, http.server, socketserver

class TenantHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self):
        if self.path == "/api/org/2/data":
            auth = self.headers.get("Authorization", "")
            if "token_a" in auth:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"data": "org_2_data"}')
            else:
                self.send_response(403)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()
    def do_POST(self):
        if self.path == "/api/register":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length))
            if body.get("role") == "admin":
                self.send_response(201)
                self.end_headers()
                self.wfile.write(json.dumps({"role": "admin", "email": body.get("email")}).encode())
            else:
                self.send_response(201)
                self.end_headers()
                self.wfile.write(json.dumps({"role": "user"}).encode())
        elif self.path == "/api/password/reset":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"token": "1234"}')
        else:
            self.send_response(404)
            self.end_headers()

class TenantFixture:
    def __init__(self):
        self.server = socketserver.TCPServer(("127.0.0.1", 0), TenantHandler)
        self.port = self.server.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
    def __enter__(self):
        self.thread.start()
        return self
    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
