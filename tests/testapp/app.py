"""Local test application for end-to-end scanner acceptance tests.

Served on 127.0.0.1 (in ROE scope). Endpoints are intentionally shaped to
exercise specific detections:

  GET  /api/item?id=        strict-numeric param (numeric accepted, else 400)
  GET  /api/search?q=       loose-string param (everything accepted)
  POST /api/profile         container-typed "settings" (mass-assignment)
  GET  /api/doc/<id>        IDOR surface — user_a/user_b owned records
  POST /login               issues a session cookie per account
  GET  /api/me              reflects the caller's account

Later phases add weak-JWT and reflected-XSS surfaces on the same app.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# account -> session token
_ACCOUNTS = {
    "user_a": {"token": "tok-user-a", "id": 1},
    "user_b": {"token": "tok-user-b", "id": 2},
    "admin": {"token": "tok-admin", "id": 99},
}
# doc id -> owner account
_DOCS = {
    "1": {"id": 1, "owner": "user_a", "title": "A's doc", "secret": "aaa",
          "email": "alice@example.com", "account": "4111111111111234"},
    "2": {"id": 2, "owner": "user_b", "title": "B's doc", "secret": "bbb",
          "email": "bob@example.com", "account": "4222222222225678"},
    "3": {"id": 3, "owner": "user_a", "title": "A's second", "secret": "ccc",
          "email": "alice2@example.com", "account": "4333333333339012"},
    "99": {"id": 99, "owner": "admin", "title": "admin doc", "secret": "zzz",
           "email": "admin@example.com", "account": "4999999999993456"},
}
_TOKEN_TO_ACCOUNT = {v["token"]: k for k, v in _ACCOUNTS.items()}

# A weak-JWT HS256 token signed with "secret" — payload {"sub":"user_a"}.
WEAK_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiJ1c2VyX2EiLCJyb2xlIjoidXNlciJ9."
    "Ug9b2n5gkiQ8w3kz1xq8kH0cQ0wq6Qv8xP2mXcY0tE")


def _looks_numeric(s):
    try:
        float(s)
        return True
    except (TypeError, ValueError):
        return False


class TestAppHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

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

    def _account(self):
        auth = self.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            tok = auth[7:].strip()
            if tok in _TOKEN_TO_ACCOUNT:
                return _TOKEN_TO_ACCOUNT[tok]
        cookie = self.headers.get("Cookie", "") or ""
        for part in cookie.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                if k == "session" and v in _TOKEN_TO_ACCOUNT:
                    return _TOKEN_TO_ACCOUNT[v]
        return None

    def _send(self, status, obj, headers=None):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(body)
            except Exception:
                pass

    def do_GET(self):
        body = self._read_body()
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query, keep_blank_values=True)
        if path == "/api/item":
            vals = qs.get("id", [""])
            v = vals[0] if vals else ""
            if _looks_numeric(v):
                return self._send(200, {"id": v, "name": "item-" + v})
            return self._send(400, {"error": "id must be numeric"})
        if path == "/api/search":
            vals = qs.get("q", [""])
            v = vals[0] if vals else ""
            return self._send(200, {"query": v, "results": []})
        if path.startswith("/api/doc/"):
            doc_id = path[len("/api/doc/"):]
            doc = _DOCS.get(doc_id)
            if doc is None:
                return self._send(404, {"error": "not found"})
            # Broken object-level authz: any authenticated caller may read
            # any document regardless of owner.
            if self._account() is None:
                return self._send(401, {"error": "auth required"})
            return self._send(200, doc)
        if path == "/api/me":
            acct = self._account()
            if acct is None:
                return self._send(401, {"error": "auth required"})
            return self._send(200, {"account": acct,
                                    "id": _ACCOUNTS[acct]["id"]})
        if path == "/api/admin/users":
            # Correctly enforced: admin only.
            if self._account() != "admin":
                return self._send(403, {"error": "forbidden"})
            return self._send(200, {"users": list(_ACCOUNTS.keys())})
        if path == "/api/admin/config":
            # Broken access control: reachable by anyone, including anon.
            return self._send(200, {"debug": True, "secret_key": "s3cr3t"})
        if path == "/api/reflect":
            vals = qs.get("name", [""])
            v = vals[0] if vals else ""
            html = "<html><body>Hello " + v + "</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            if self.command != "HEAD":
                try:
                    self.wfile.write(html.encode("utf-8"))
                except Exception:
                    pass
            return
        return self._send(404, {"error": "not found"})

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        body = self._read_body()
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/login":
            try:
                data = json.loads(body or b"{}")
            except Exception:
                data = {}
            acct = data.get("username")
            if acct in _ACCOUNTS:
                tok = _ACCOUNTS[acct]["token"]
                return self._send(200, {"account": acct},
                                  headers={"Set-Cookie":
                                           f"session={tok}; HttpOnly"})
            return self._send(401, {"error": "bad credentials"})
        if path == "/api/profile":
            try:
                data = json.loads(body or b"{}")
            except Exception:
                return self._send(400, {"error": "invalid json"})
            if "settings" not in data:
                return self._send(400, {"error": "settings required"})
            settings = data["settings"]
            # Container-typed: only array/object settings accepted.
            if isinstance(settings, (list, dict)):
                return self._send(200, {"ok": True, "settings": settings})
            return self._send(400, {"error": "settings must be object/array"})
        return self._send(404, {"error": "not found"})


def start_app():
    """Start the app on an ephemeral 127.0.0.1 port. Returns (base_url, srv)."""
    srv = ThreadingHTTPServer(("127.0.0.1", 0), TestAppHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _, port = srv.server_address
    return f"http://127.0.0.1:{port}", srv
