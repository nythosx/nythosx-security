"""Loopback fixture for SQLi tier-2 tests.

Two surfaces:
  store + reader  -- second-order: reader misbehaves when store holds
                     a payload containing a single quote.
  error endpoint  -- returns DB-specific error when a CAST/convert-style
                     payload is present, else 200 OK.
  boolean timing  -- SLEEP payload adds a real delay; parameterised.
"""
from __future__ import annotations

import contextlib
import http.server
import json
import threading
import time
import urllib.parse


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        fx = getattr(self.server, "fixture", None)
        if parsed.path == "/sqli2/reader":
            return self._reader(qs, fx)
        if parsed.path == "/sqli2/error":
            return self._error(qs)
        if parsed.path == "/sqli2/boolean":
            return self._boolean(qs)
        self._resp(404, b"")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        ct = (self.headers.get("Content-Type") or "").lower()
        fx = getattr(self.server, "fixture", None)
        if parsed.path == "/sqli2/store":
            body = {}
            if "json" in ct:
                try:
                    body = json.loads(raw)
                except Exception:
                    pass
            else:
                try:
                    parsed_q = urllib.parse.parse_qs(raw.decode())
                    body = {k: v[0] for k, v in parsed_q.items()}
                except Exception:
                    pass
            if fx is not None:
                fx.stored["bio"] = body.get("bio", "")
            self._resp(200, b'{"ok":true}')
            return
        if parsed.path == "/sqli2/json":
            return self._json_context(raw)
        self._resp(404, b"")

    def _reader(self, qs, fx):
        stored = (fx.stored.get("bio") if fx else "") or ""
        q = (qs.get("q") or [""])[0]
        if "'" in stored:
            self._resp(500, b"SQL syntax error near stored value")
            return
        self._resp(200, ("reader ok: %s stored=%r"
                          % (q, stored[:60])).encode())

    def _error(self, qs):
        param = (qs.get("id") or [""])[0]
        low = param.lower()
        if "extractvalue" in low:
            self._resp(500,
                        b"XPATH syntax error: '~8.0.32-mysql~'")
            return
        if "cast" in low and "version" in low:
            self._resp(500, b"invalid input syntax for type integer: "
                            b"'PostgreSQL 15.2'")
            return
        if "convert" in low and "@@version" in low:
            self._resp(500,
                        b"Conversion failed: 'Microsoft SQL Server 2019'")
            return
        self._resp(200, b"ok")

    def _boolean(self, qs):
        param = (qs.get("id") or [""])[0]
        if "SLEEP(" in param:
            try:
                secs = int(param.split("SLEEP(")[1].split(")")[0])
            except (IndexError, ValueError):
                secs = 0
            if 0 < secs <= 5:
                time.sleep(secs)
        self._resp(200, b"ok")

    def _json_context(self, raw):
        try:
            body = json.loads(raw)
        except Exception:
            body = {}
        if isinstance(body, dict) and "$where" in body:
            self._resp(500, b"MongoError: $where not allowed")
            return
        self._resp(200, b'{"ok":true}')

    def _resp(self, status, body):
        payload = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if payload:
            self.wfile.write(payload)

    def log_message(self, *args):
        pass


class SqliT2Fixture:
    def __init__(self):
        self.httpd = None
        self.port = 0
        self.thread = None
        self.stored = {}

    def start(self):
        self.httpd = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), _Handler)
        self.httpd.fixture = self
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
