"""Loopback fixture for XSS tier-2 tests.

Reflects payloads but never executes (execution requires Playwright +
browser, which is covered by the base Phase 2 tests). Tests here verify
payload reflection and CSP enumeration logic.
"""
from __future__ import annotations

import contextlib
import http.server
import threading
import urllib.parse


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        q = (qs.get("q") or [""])[0]
        if parsed.path == "/xss2/mutation":
            body = "<html><body>%s</body></html>" % q
            self._resp(200, body)
            return
        if parsed.path == "/xss2/csp_strict":
            self._resp(200, "<html><body>%s</body></html>" % q,
                        headers={
                            "Content-Security-Policy":
                                "script-src 'self'; base-uri 'self'; "
                                "object-src 'none'",
                        })
            return
        if parsed.path == "/xss2/csp_loose":
            self._resp(200, "<html><body>%s</body></html>" % q,
                        headers={
                            "Content-Security-Policy":
                                "script-src 'unsafe-inline' 'unsafe-eval' *",
                        })
            return
        self._resp(404, "")

    def _resp(self, status, body, headers=None):
        payload = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if payload:
            self.wfile.write(payload)

    def log_message(self, *args):
        pass


class XssT2Fixture:
    def __init__(self):
        self.httpd = None
        self.port = 0
        self.thread = None

    def start(self):
        self.httpd = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), _Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return self

    def stop(self):
        with contextlib.suppress(Exception):
            self.httpd.shutdown()
            self.httpd.server_close()

    @property
    def base_url(self):
        return "http://127.0.0.1:%d" % self.port

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
        return False
