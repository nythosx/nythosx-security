from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import http.server
import json
import threading
import urllib.parse


SECRET = "weaksecret123"


def _b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64e(b):
    if isinstance(b, str):
        b = b.encode()
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _decode_jwt(token):
    parts = token.split(".")
    if len(parts) != 3:
        return None, None, None
    try:
        header = json.loads(_b64d(parts[0]))
        payload = json.loads(_b64d(parts[1]))
    except Exception:
        return None, None, None
    return header, payload, parts


def _make_token(header, payload, secret=SECRET):
    h = _b64e(json.dumps(header, separators=(",", ":")))
    p = _b64e(json.dumps(payload, separators=(",", ":")))
    if str(header.get("alg", "")).lower() == "none":
        return "%s.%s." % (h, p)
    sig = hmac.new(secret.encode(), ("%s.%s" % (h, p)).encode(),
                   hashlib.sha256).digest()
    return "%s.%s.%s" % (h, p, _b64e(sig))


REAL_TOKEN = _make_token(
    {"alg": "HS256", "typ": "JWT"},
    {"sub": "1", "role": "admin", "iss": "fixture",
     "aud": "fixture", "exp": 9999999999},
)


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/jwt/protected":
            return self._jwt_check()
        if parsed.path == "/rate-limited":
            return self._rate_check()
        if parsed.path == "/reset":
            self._respond(200, "<html><form method=post>Reset</form></html>")
            return
        self._respond(404, "")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw) if raw else {}
        except Exception:
            body = {}
        if parsed.path == "/reset":
            return self._reset(body)
        if parsed.path == "/mfa/verify":
            return self._mfa(body)
        if parsed.path == "/login":
            return self._login(body)
        self._respond(404, "")

    def _respond(self, status, body, extra_headers=None):
        payload = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        if payload:
            self.wfile.write(payload)

    def _jwt_check(self):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return self._respond(401, "no bearer")
        token = auth[7:]
        header, payload, parts = _decode_jwt(token)
        if header is None:
            return self._respond(401, "invalid jwt")
        alg = str(header.get("alg", "")).lower()
        if alg == "none":
            self._respond(200, "protected: sub=" + str(payload.get("sub")))
            return
        if alg == "hs256":
            try:
                sig = hmac.new(SECRET.encode(),
                               ("%s.%s" % (parts[0], parts[1])).encode(),
                               hashlib.sha256).digest()
                provided = _b64d(parts[2])
                if hmac.compare_digest(sig, provided):
                    self._respond(200, "protected: sub=" + str(payload.get("sub")))
                    return
            except Exception:
                pass
        self._respond(401, "bad signature")

    def _reset(self, body):
        email = body.get("email", "")
        host = (self.headers.get("X-Forwarded-Host")
                or self.headers.get("Host")
                or self.headers.get("Referer")
                or "fixture")
        if "://" in host:
            host = urllib.parse.urlparse(host).hostname or host
        link = "http://%s/reset?token=abc123" % host
        html = ('<html><body>Reset link for %s: '
                '<a href="%s">click</a></body></html>') % (email, link)
        self._respond(200, html)

    def _mfa(self, body):
        if (body.get("success") is True
                or body.get("ok") is True
                or body.get("verified") is True
                or body.get("mfa_verified") is True
                or body.get("mfaVerified") is True
                or body.get("mfa_required") is False
                or body.get("mfaRequired") is False
                or body.get("skip_mfa") is True
                or body.get("skipMfa") is True):
            self._respond(200, '{"token":"mfa-bypassed"}')
            return
        self._respond(401, '{"error":"invalid code"}')

    def _login(self, body):
        self._respond(200, json.dumps({"token": REAL_TOKEN}))

    def _rate_check(self):
        fx = getattr(self.server, "fixture", None)
        if fx is None:
            return self._respond(200, "ok")
        xff = self.headers.get("X-Forwarded-For", "")
        key = xff or self.client_address[0]
        count = fx.counts.get(key, 0) + 1
        fx.counts[key] = count
        if count > 1:
            return self._respond(429, "too many")
        self._respond(200, "ok")

    def log_message(self, *args):
        pass


class Fixture:
    def __init__(self):
        self.httpd = None
        self.thread = None
        self.base_url = ""
        self.counts = {}

    def start(self):
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
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

    @property
    def real_token(self):
        return REAL_TOKEN
