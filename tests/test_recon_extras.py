import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from engine.recon import sourcemaps, ct_logs
from engine import roe_guard as roe_mod


@pytest.fixture(autouse=True)
def permissive_roe(monkeypatch):
    monkeypatch.setattr(roe_mod, "load_roe", lambda: {
        "enabled": True,
        "scope": {"in_scope": ["127.0.0.1"], "out_of_scope": [],
                  "allowed_methods": ["GET", "POST"], "forbidden_paths": []},
    })


_SOURCE_MAP = {
    "version": 3,
    "sources": ["app.ts", "api.ts"],
    "sourcesContent": [
        "const API_URL = 'https://api.internal.example.com/v1';\n"
        "fetch('/api/orders', {params: {userId: id, status: 'active'}});",
        "const query = fetch('/api/users/' + uid);\n"
        "const params = {email: e, role: 'admin', sessionToken: s};",
    ],
}


class _SourcemapServer(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/static/app.js":
            body = b"//# sourceMappingURL=app.js.map\nconsole.log('hi');"
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/static/app.js.map":
            body = json.dumps(_SOURCE_MAP).encode()
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


class _NoSourcemapServer(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_sourcemap_fetch_and_extract():
    srv = _serve(_SourcemapServer)
    _, port = srv.server_address
    base = f"http://127.0.0.1:{port}"
    try:
        sm = sourcemaps.fetch_sourcemap(f"{base}/static/app.js")
    finally:
        srv.shutdown(); srv.server_close()
    assert sm is not None
    assert sm.get("version") == 3
    extracted = sourcemaps.extract_from_sourcemap(sm)
    assert "userId" in extracted["params"]
    assert "role" in extracted["params"]
    assert "sessionToken" in extracted["params"]
    assert any("/api/orders" in p for p in extracted["paths"])
    assert any("/api/users" in p for p in extracted["paths"])


def test_mine_aggregates():
    srv = _serve(_SourcemapServer)
    _, port = srv.server_address
    try:
        r = sourcemaps.mine([f"http://127.0.0.1:{port}/static/app.js"])
    finally:
        srv.shutdown(); srv.server_close()
    assert len(r["maps_found"]) == 1


def test_no_sourcemap_returns_empty():
    srv = _serve(_NoSourcemapServer)
    _, port = srv.server_address
    try:
        sm = sourcemaps.fetch_sourcemap(
            f"http://127.0.0.1:{port}/nonexistent.js")
    finally:
        srv.shutdown(); srv.server_close()
    assert sm is None


def test_ct_parse():
    rows = [
        {"name_value": "www.example.com\napi.example.com"},
        {"name_value": "*.staging.example.com"},
        {"name_value": "example.com"},
        {"name_value": "unrelated.org"},
    ]
    body = json.dumps(rows).encode()
    import httpx

    class _Resp:
        status_code = 200
        content = body
        text = body.decode()

    class _Client:
        def __init__(self, *a, **k):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def get(self, *a, **k):
            return _Resp()

    import engine.recon.ct_logs as ct_mod
    real_client = httpx.Client
    try:
        httpx.Client = _Client
        names = ct_mod.query_crt_sh("example.com", timeout=1)
    finally:
        httpx.Client = real_client
    assert "www.example.com" in names
    assert "api.example.com" in names
    assert "staging.example.com" in names
    assert "unrelated.org" not in names


def test_ct_disabled(monkeypatch):
    monkeypatch.setattr(ct_logs, "_cfg", lambda: {"enabled": False})
    assert ct_logs.harvest("example.com") is None


def test_resolve_subdomains_localhost():
    r = ct_logs.resolve_subdomains(["127.0.0.1", "this-name-does-not-exist-sec-checker.invalid"])
    assert any(x["name"] == "127.0.0.1" for x in r["live"])
    assert "this-name-does-not-exist-sec-checker.invalid" in r["dead"]
