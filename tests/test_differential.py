import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from engine import differential
from engine import roe_guard as roe_mod


@pytest.fixture(autouse=True)
def permissive_roe(monkeypatch):
    monkeypatch.setattr(roe_mod, "load_roe", lambda: {
        "enabled": True,
        "scope": {"in_scope": ["127.0.0.1"], "out_of_scope": [],
                  "allowed_methods": ["GET", "POST"], "forbidden_paths": []},
    })


_USERS = {}


class _BolaServer(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/api/register":
            n = int(self.headers.get("Content-Length", 0) or 0)
            try:
                data = json.loads(self.rfile.read(n) or b"{}")
            except Exception:
                data = {}
            email = data.get("email", "")
            token = "tok_" + email.replace("@", "_")
            _USERS[token] = email
            body = json.dumps({"token": token}).encode()
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        auth = self.headers.get("Authorization", "")
        token = auth.replace("Bearer ", "") if auth else ""
        user = _USERS.get(token)
        if self.path == "/api/me":
            if not user:
                self.send_response(401)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = json.dumps({"email": user, "role": "user"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/api/orders/"):
            if not user:
                self.send_response(401)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            order_id = self.path.rsplit("/", 1)[1]
            if order_id == "1":
                body = json.dumps({"id": 1, "owner_email": list(_USERS.values())[0] if _USERS else "x"}).encode()
            elif order_id == "2":
                other = list(_USERS.values())[1] if len(_USERS) > 1 else "y"
                body = json.dumps({"id": 2, "owner_email": other}).encode()
            else:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


class _NoAuthServer(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/api/register":
            body = json.dumps({"token": "anytoken"}).encode()
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        body = json.dumps({"id": 1}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class _NoSignupServer(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


def _serve(handler):
    _USERS.clear()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_module_imports():
    assert differential is not None
    assert differential.CAPABILITY.name == "differential_scan"


def test_scan_returns_scanresult_on_dead_host():
    from engine.contract import ScanResult
    r = differential.scan("http://127.0.0.1:1")
    assert isinstance(r, ScanResult)
    assert r["verdict"] in ("UNKNOWN", "PASS")


def test_no_signup_and_no_creds_returns_unknown():
    srv = _serve(_NoSignupServer)
    _, port = srv.server_address
    try:
        r = differential.scan(f"http://127.0.0.1:{port}",
                              endpoints=[f"http://127.0.0.1:{port}/api/me"])
    finally:
        srv.shutdown()
        srv.server_close()
    assert r["verdict"] == "UNKNOWN"
    assert "session" in r.reason.lower()


def test_detects_public_no_auth():
    srv = _serve(_NoAuthServer)
    _, port = srv.server_address
    try:
        r = differential.scan(
            f"http://127.0.0.1:{port}",
            endpoints=[f"http://127.0.0.1:{port}/api/me"])
    finally:
        srv.shutdown()
        srv.server_close()
    assert r["verdict"] in ("VULNERABLE", "UNKNOWN")


def test_bola_found_when_users_see_distinct_bodies():
    srv = _serve(_BolaServer)
    _, port = srv.server_address
    try:
        r = differential.scan(
            f"http://127.0.0.1:{port}",
            endpoints=[f"http://127.0.0.1:{port}/api/orders/1",
                       f"http://127.0.0.1:{port}/api/orders/2"])
    finally:
        srv.shutdown()
        srv.server_close()
    kinds = {f["type"] for f in (r.evidence or {}).get("findings", [])}
    assert r["verdict"] == "VULNERABLE"
    assert ({"bola_cross_user", "bola_shared_access", "anon_vs_auth_diff"}
            & kinds), f"no BOLA/anon finding in {kinds}"


def test_probes_recorded_for_every_endpoint():
    srv = _serve(_BolaServer)
    _, port = srv.server_address
    try:
        r = differential.scan(
            f"http://127.0.0.1:{port}",
            endpoints=[f"http://127.0.0.1:{port}/api/me"])
    finally:
        srv.shutdown()
        srv.server_close()
    probes = (r.evidence or {}).get("probes") or []
    assert any(p["url"].endswith("/api/me") for p in probes)


def test_roe_block_returns_unknown(monkeypatch):
    monkeypatch.setattr(roe_mod, "load_roe", lambda: {
        "enabled": True,
        "scope": {"in_scope": ["10.0.0.1"], "out_of_scope": [],
                  "allowed_methods": ["GET", "POST"], "forbidden_paths": []},
    })
    r = differential.scan("http://127.0.0.1:1")
    assert r["verdict"] == "UNKNOWN"
    assert "ROE_BLOCK" in r.reason
