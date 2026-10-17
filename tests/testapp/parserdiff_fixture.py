"""Loopback fixtures for parser-differential tests.

Two servers:
  BoundaryFixture   - raw TCP, interprets duplicate CL / CL+TE per path
  HttpFixture       - BaseHTTPRequestHandler for bodyparser + charset
"""
from __future__ import annotations

import contextlib
import http.server
import json
import socket
import threading
import unicodedata
import urllib.parse


# --- Boundary (raw TCP) ---------------------------------------------------

class _BoundaryServer:
    def __init__(self):
        self.sock = None
        self.port = 0
        self.thread = None
        self.requests = []

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(10)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()
        return self

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,),
                              daemon=True).start()

    def _handle(self, conn):
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data += chunk
                if len(data) > 65536:
                    return
            head, _, body = data.partition(b"\r\n\r\n")
            lines = head.split(b"\r\n")
            if not lines:
                return
            parts = lines[0].split(b" ")
            path = parts[1].decode("latin-1") if len(parts) >= 2 else "/"
            cl_vals = []
            te_vals = []
            for line in lines[1:]:
                if b":" not in line:
                    continue
                name, _, val = line.partition(b":")
                kl = name.strip().lower()
                if kl == b"content-length":
                    cl_vals.append(val.strip())
                elif kl == b"transfer-encoding":
                    te_vals.append(val.strip().lower())
            self.requests.append({"path": path,
                                   "cl": [v.decode() for v in cl_vals],
                                   "te": [v.decode() for v in te_vals]})
            resp = self._decide(path, cl_vals, te_vals, body)
            conn.sendall(resp)
        except Exception:
            pass
        finally:
            with contextlib.suppress(Exception):
                conn.close()

    def _decide(self, path, cl_vals, te_vals, body):
        if path.startswith("/boundary/strict"):
            if len(set(cl_vals)) > 1:
                return self._r(400, "ambiguous CL", "strict")
            if cl_vals and te_vals:
                return self._r(400, "CL+TE conflict", "strict")
            if len(set(te_vals)) > 1:
                return self._r(400, "ambiguous TE", "strict")
            if len(cl_vals) > 1:
                return self._r(200, "dup cl same", "strict")
            return self._r(200, "clean ok", "none")
        if path.startswith("/boundary/lenient_cl"):
            if len(cl_vals) > 1 and len(set(cl_vals)) > 1:
                return self._r(200, "cl_last", "cl_last")
            if cl_vals and te_vals:
                return self._r(200, "cl", "cl")
            return self._r(200, "clean", "none")
        if path.startswith("/boundary/lenient_te"):
            if cl_vals and te_vals:
                return self._r(200, "te", "te")
            return self._r(200, "clean", "none")
        return self._r(404, "unknown", "none")

    def _r(self, status, body_str, winner):
        body = body_str.encode()
        head = ("HTTP/1.1 %d X\r\n"
                "Content-Type: text/plain\r\n"
                "X-Winner: %s\r\n"
                "Content-Length: %d\r\n"
                "Connection: close\r\n\r\n") % (status, winner, len(body))
        return head.encode() + body

    def stop(self):
        with contextlib.suppress(Exception):
            self.sock.close()


# --- HTTP fixture (bodyparser + charset) ---------------------------------

_HOMOGLYPH_FOLD = str.maketrans({
    "\u0430": "a", "\u0435": "e", "\u043e": "o",
    "\u0456": "i", "\u0443": "u", "\u0441": "c",
    "\u0455": "s", "\u043c": "m",
    "\uff41": "a", "\uff45": "e", "\uff4f": "o",
    "\uff49": "i", "\uff55": "u", "\uff43": "c",
    "\uff53": "s", "\uff4d": "m",
})


class _HttpHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        path = self.path.split("?")[0]
        ct = self.headers.get("Content-Type", "").lower()
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        if path == "/bodyparser/json_only":
            return self._bodyparser(raw, ct, strict_json=True)
        if path == "/bodyparser/both":
            return self._bodyparser(raw, ct, strict_json=False)
        if path == "/charset/auth_strict":
            return self._charset_auth(raw, ct, lenient=False)
        if path == "/charset/auth_lenient":
            return self._charset_auth(raw, ct, lenient=True)
        self._respond(404, b"")

    def do_GET(self):
        self._respond(200, b"ok")

    def _bodyparser(self, raw, ct, strict_json):
        accepts_json = "application/json" in ct
        accepts_form = "application/x-www-form-urlencoded" in ct
        if strict_json and not accepts_json:
            return self._respond(415, b"json only")
        if not (accepts_json or accepts_form):
            return self._respond(415, b"unsupported")
        if accepts_json:
            if strict_json:
                try:
                    data = json.loads(raw)
                except Exception:
                    return self._respond(400, b"bad json")
                return self._respond(
                    200, json.dumps({"accepted": list(data.keys()),
                                     "method": "json"}).encode())
            return self._respond(
                200, json.dumps({"accepted": ["json_endpoint"]}).encode())
        if accepts_form:
            try:
                parsed = urllib.parse.parse_qs(raw.decode("utf-8", "replace"))
            except Exception:
                return self._respond(400, b"bad form")
            return self._respond(
                200, json.dumps({"accepted": list(parsed.keys()),
                                 "method": "form"}).encode())

    def _charset_auth(self, raw, ct, lenient):
        if "charset=utf-16" in ct:
            return self._respond(400, b"only utf-8")
        try:
            body = json.loads(raw.decode("utf-8", "replace"))
        except Exception:
            return self._respond(400, b"bad json")
        user = body.get("username", "")
        if lenient:
            user_norm = (unicodedata.normalize("NFKC", user)
                         .translate(_HOMOGLYPH_FOLD).lower())
            if user_norm == "admin":
                return self._respond(200, b"ok lenient")
            return self._respond(401, b"unauthorized")
        if user == "admin":
            return self._respond(200, b"ok strict")
        return self._respond(401, b"unauthorized")

    def _respond(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def log_message(self, *args):
        pass


class _HttpServer:
    def __init__(self):
        self.httpd = None
        self.port = 0
        self.thread = None

    def start(self):
        self.httpd = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), _HttpHandler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return self

    def stop(self):
        with contextlib.suppress(Exception):
            self.httpd.shutdown()
            self.httpd.server_close()


# --- Public composite -----------------------------------------------------

class BoundaryFixture:
    def __init__(self):
        self._srv = _BoundaryServer()

    @property
    def base_url(self):
        return "http://127.0.0.1:%d" % self._srv.port

    @property
    def requests(self):
        return self._srv.requests

    def start(self):
        self._srv.start()
        return self

    def stop(self):
        self._srv.stop()

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
        return False


class HttpFixture:
    def __init__(self):
        self._srv = _HttpServer()

    @property
    def base_url(self):
        return "http://127.0.0.1:%d" % self._srv.port

    def start(self):
        self._srv.start()
        return self

    def stop(self):
        self._srv.stop()

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
        return False
