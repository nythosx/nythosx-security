from __future__ import annotations

import contextlib
import http.server
import threading
import urllib.parse
import urllib.request


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        fx = getattr(self.server, "fixture", None)
        if fx is not None:
            fx.record({"path": parsed.path, "query": qs})
        if parsed.path == "/fetch":
            url = (qs.get("url") or [""])[0]
            if not url:
                self._respond(200, "no url to fetch")
                return
            try:
                r = urllib.request.urlopen(url, timeout=0.3)
                body = "fetched: status=%s len=%d" % (
                    getattr(r, "status", 0), len(r.read()))
            except Exception as e:
                body = "fetch_error: %s" % type(e).__name__
            self._respond(200, body)
            return
        if parsed.path == "/safe":
            self._respond(200, "OK")
            return
        self._respond(404, "")

    def _respond(self, status, body):
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if payload:
            self.wfile.write(payload)

    def log_message(self, *args):
        pass


class Fixture:
    def __init__(self):
        self.httpd = None
        self.thread = None
        self.base_url = ""
        self.requests = []

    def record(self, entry):
        if len(self.requests) < 500:
            self.requests.append(entry)

    def start(self):
        self.httpd = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), _Handler)
        self.httpd.fixture = self
        port = self.httpd.server_address[1]
        self.base_url = "http://127.0.0.1:%d" % port
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return self

    def stop(self):
        if self.httpd is not None:
            with contextlib.suppress(Exception):
                self.httpd.shutdown()
                self.httpd.server_close()
            self.httpd = None
            self.thread = None

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
        return False
