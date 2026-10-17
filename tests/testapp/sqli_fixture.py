from __future__ import annotations

import contextlib
import http.server
import threading
import urllib.parse


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        param = (qs.get("id") or [""])[0]
        if parsed.path == "/vuln":
            body = self._vuln_response(param)
        elif parsed.path == "/safe":
            body = "OK id=%s" % param
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        payload = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _vuln_response(self, param):
        low = param.lower()
        if "convert(int,1)" in low:
            return "Microsoft OLE DB Provider for SQL Server error '80040e07'"
        if "::int" in low:
            return "postgresql error: invalid input syntax for type integer"
        if "1 and 1=2" in low or "1=2--" in low:
            return "Result set: empty"
        if "1 and 1=1" in low or "1=1--" in low:
            return "Result set: 1 row found"
        if "'" in param:
            return "You have an error in your SQL syntax"
        return "Result set: 1 row found"

    def log_message(self, *args):
        pass


class Fixture:
    def __init__(self):
        self.httpd = None
        self.thread = None
        self.base_url = ""

    def start(self):
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        port = self.httpd.server_address[1]
        self.base_url = "http://127.0.0.1:%d" % port
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
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
