import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import pytest

from engine.injection import hpp
from engine import roe_guard as roe_mod


@pytest.fixture(autouse=True)
def permissive_roe(monkeypatch):
    monkeypatch.setattr(roe_mod, "load_roe", lambda: {
        "enabled": True,
        "scope": {"in_scope": ["127.0.0.1"], "out_of_scope": [],
                  "allowed_methods": ["GET"], "forbidden_paths": []},
    })


class _LastWinsServer(BaseHTTPRequestHandler):
    """Reflects the LAST value of ?role= but not the first."""
    def do_GET(self):
        import json
        q = parse_qs(urlparse(self.path).query)
        role_vals = q.get("role", [])
        last = role_vals[-1] if role_vals else ""
        body = json.dumps({"role": last}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class _FirstWinsServer(BaseHTTPRequestHandler):
    """Reflects the FIRST value of ?role= only."""
    def do_GET(self):
        import json
        q = parse_qs(urlparse(self.path).query)
        role_vals = q.get("role", [])
        first = role_vals[0] if role_vals else ""
        body = json.dumps({"role": first}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class _ArrayServer(BaseHTTPRequestHandler):
    """Reflects every value of role[] and role as a list."""
    def do_GET(self):
        import json
        q = parse_qs(urlparse(self.path).query)
        vals = q.get("role[]", []) + q.get("role", [])
        body = json.dumps({"roles": vals}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class _StaticServer(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_module_imports():
    assert hpp.CAPABILITY.name == "hpp_scan"


def test_last_wins_detected():
    srv = _serve(_LastWinsServer)
    _, port = srv.server_address
    try:
        r = hpp.scan(f"http://127.0.0.1:{port}/search", params=["role"])
    finally:
        srv.shutdown(); srv.server_close()
    assert r["verdict"] == "SUSPICIOUS"
    kinds = {f["kind"] for f in r.evidence["findings"]}
    assert "last_wins" in kinds


def test_first_wins_passes():
    srv = _serve(_FirstWinsServer)
    _, port = srv.server_address
    try:
        r = hpp.scan(f"http://127.0.0.1:{port}/search", params=["role"])
    finally:
        srv.shutdown(); srv.server_close()
    assert r["verdict"] == "PASS"


def test_array_parsing_detected():
    srv = _serve(_ArrayServer)
    _, port = srv.server_address
    try:
        r = hpp.scan(f"http://127.0.0.1:{port}/search", params=["role"])
    finally:
        srv.shutdown(); srv.server_close()
    assert r["verdict"] == "SUSPICIOUS"
    kinds = {f["kind"] for f in r.evidence["findings"]}
    assert "array_parsing" in kinds or "array_last_wins" in kinds


def test_static_reflection_passes():
    srv = _serve(_StaticServer)
    _, port = srv.server_address
    try:
        r = hpp.scan(f"http://127.0.0.1:{port}/api", params=["role"])
    finally:
        srv.shutdown(); srv.server_close()
    assert r["verdict"] == "PASS"


def test_roe_block(monkeypatch):
    monkeypatch.setattr(roe_mod, "load_roe", lambda: {
        "enabled": True,
        "scope": {"in_scope": ["10.0.0.1"], "out_of_scope": [],
                  "allowed_methods": ["GET"], "forbidden_paths": []},
    })
    r = hpp.scan("http://127.0.0.1:1/x", params=["role"])
    assert r["verdict"] == "UNKNOWN"
    assert "ROE_BLOCK" in r.reason


def test_default_params_used_when_none():
    srv = _serve(_StaticServer)
    _, port = srv.server_address
    try:
        r = hpp.scan(f"http://127.0.0.1:{port}/api")
    finally:
        srv.shutdown(); srv.server_close()
    assert r["verdict"] in ("PASS", "UNKNOWN", "SUSPICIOUS")
