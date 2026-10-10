import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from engine import roe_guard as roe_mod


@pytest.fixture(autouse=True)
def permissive_roe(monkeypatch):
    monkeypatch.setattr(roe_mod, "load_roe", lambda: {
        "enabled": True,
        "scope": {"in_scope": ["127.0.0.1"], "out_of_scope": [],
                  "allowed_methods": ["GET", "POST"], "forbidden_paths": []},
    })


def test_oauth_modules_import():
    from engine.oauth import discovery, redirect_uri, state_probe, pkce_probe, id_token
    for m in (discovery, redirect_uri, state_probe, pkce_probe, id_token):
        assert hasattr(m, "scan")
        assert hasattr(m, "CAPABILITY")


def test_oauth_scan_returns_scanresult():
    from engine.contract import ScanResult
    from engine.oauth import discovery, redirect_uri, state_probe, pkce_probe
    for m in (discovery, redirect_uri, state_probe, pkce_probe):
        r = m.scan("http://127.0.0.1:1")
        assert isinstance(r, ScanResult), m.__name__


class _OIDCServer(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/.well-known/openid-configuration":
            import json
            body = json.dumps({
                "issuer": "https://issuer.example.com",
                "authorization_endpoint": "https://issuer.example.com/oauth/authorize",
                "token_endpoint": "https://issuer.example.com/oauth/token",
            }).encode()
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


def test_oauth_discovery_finds_wellknown():
    from engine.oauth import discovery
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _OIDCServer)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _, port = srv.server_address
    try:
        out = discovery.fetch(f"http://127.0.0.1:{port}")
    finally:
        srv.shutdown(); srv.server_close()
    assert out is not None
    assert "config" in out
    assert out["config"]["issuer"] == "https://issuer.example.com"


class _OpenRedirectAuth(BaseHTTPRequestHandler):
    def do_GET(self):
        from urllib.parse import urlparse, parse_qs
        q = parse_qs(urlparse(self.path).query)
        redirect_uri = (q.get("redirect_uri") or [""])[0]
        if "attacker.example.com" in redirect_uri:
            self.send_response(302)
            self.send_header("Location", redirect_uri)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def test_oauth_redirect_uri_bypass_detected():
    from engine.oauth import redirect_uri
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _OpenRedirectAuth)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _, port = srv.server_address
    try:
        r = redirect_uri.scan(f"http://127.0.0.1:{port}/oauth/authorize",
                              target_host="127.0.0.1")
    finally:
        srv.shutdown(); srv.server_close()
    assert r["verdict"] == "VULNERABLE"
