import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class MockHandler(BaseHTTPRequestHandler):
    """Base mock handler.

    Subclasses override handle_request(method, path, headers, body)
    and return (status, headers_dict, body_bytes_or_str).

    The POST body is always read before responding, so clients that
    write a request body don't get a connection reset.
    """

    def _read_body(self):
        try:
            n = int(self.headers.get("Content-Length", 0) or 0)
        except (TypeError, ValueError):
            n = 0
        if n <= 0:
            return b""
        try:
            return self.rfile.read(n)
        except Exception:
            return b""

    def _respond(self, method):
        body = self._read_body()
        try:
            status, headers, response = self.handle_request(
                method, self.path, dict(self.headers), body)
        except Exception as e:
            status, headers, response = (
                500, {"Content-Type": "text/plain"},
                f"mock error: {type(e).__name__}: {e}",
            )
        if isinstance(response, str):
            response = response.encode("utf-8")
        headers = dict(headers or {})
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        if "Content-Length" not in headers:
            self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        if method != "HEAD" and response:
            try:
                self.wfile.write(response)
            except Exception:
                pass

    def handle_request(self, method, path, headers, body):
        return (404, {"Content-Type": "application/json"},
                b'{"error": "not found"}')

    def do_GET(self): self._respond("GET")
    def do_POST(self): self._respond("POST")
    def do_PUT(self): self._respond("PUT")
    def do_PATCH(self): self._respond("PATCH")
    def do_DELETE(self): self._respond("DELETE")
    def do_HEAD(self): self._respond("HEAD")
    def do_OPTIONS(self): self._respond("OPTIONS")

    def log_message(self, *a):
        pass


def serve(handler_cls):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def serve_url(handler_cls):
    srv = serve(handler_cls)
    _, port = srv.server_address
    return f"http://127.0.0.1:{port}", srv
