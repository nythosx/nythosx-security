import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from engine import roe_guard as roe_mod


@pytest.fixture(autouse=True)
def permissive_roe(monkeypatch):
    monkeypatch.setattr(roe_mod, "load_roe", lambda: {
        "enabled": True,
        "scope": {"in_scope": ["127.0.0.1"], "out_of_scope": [],
                  "allowed_methods": ["GET"], "forbidden_paths": []},
    })


_SECRET_BODY = b'{"user":"alice","ssn":"123-45-6789"}'


class _CachingCDN(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/sensitive":
            body = _SECRET_BODY
            self.send_response(200)
            self.send_header("Cache-Control", "private, no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/sensitive.css":
            body = _SECRET_BODY
            self.send_response(200)
            self.send_header("X-Cache", "HIT")
            self.send_header("Age", "120")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def log_message(self, *a):
        pass


class _SafeCDN(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/sensitive":
            body = _SECRET_BODY
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def log_message(self, *a):
        pass


class _NoCacheHeader(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/sensitive":
            body = _SECRET_BODY
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path.endswith(".css"):
            body = b'/* stylesheet */'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def log_message(self, *a):
        pass


def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_module_imports():
    from engine.injection import cache_deception
    assert cache_deception is not None
    assert hasattr(cache_deception, "scan")
    assert cache_deception.CAPABILITY.name == "cache_deception_scan"


def test_detects_cache_hit_on_sensitive_response():
    from engine.injection import cache_deception
    srv = _serve(_CachingCDN)
    _, port = srv.server_address
    try:
        r = cache_deception.scan(f"http://127.0.0.1:{port}/sensitive")
    finally:
        srv.shutdown()
        srv.server_close()
    assert r["verdict"] == "VULNERABLE"
    exts = {f["ext"] for f in r.evidence["findings"]}
    assert ".css" in exts


def test_no_cache_header_passes():
    from engine.injection import cache_deception
    srv = _serve(_NoCacheHeader)
    _, port = srv.server_address
    try:
        r = cache_deception.scan(f"http://127.0.0.1:{port}/sensitive")
    finally:
        srv.shutdown()
        srv.server_close()
    assert r["verdict"] == "PASS"


def test_404_extensions_pass():
    from engine.injection import cache_deception
    srv = _serve(_SafeCDN)
    _, port = srv.server_address
    try:
        r = cache_deception.scan(f"http://127.0.0.1:{port}/sensitive")
    finally:
        srv.shutdown()
        srv.server_close()
    assert r["verdict"] == "PASS"


def test_baseline_not_200_passes():
    from engine.injection import cache_deception
    srv = _serve(_SafeCDN)
    _, port = srv.server_address
    try:
        r = cache_deception.scan(f"http://127.0.0.1:{port}/nonexistent")
    finally:
        srv.shutdown()
        srv.server_close()
    assert r["verdict"] == "PASS"
    assert "not a sensitive" in r.reason


def test_roe_block_returns_unknown(monkeypatch):
    from engine.injection import cache_deception
    monkeypatch.setattr(roe_mod, "load_roe", lambda: {
        "enabled": True,
        "scope": {"in_scope": ["10.0.0.1"], "out_of_scope": [],
                  "allowed_methods": ["GET"], "forbidden_paths": []},
    })
    r = cache_deception.scan("http://127.0.0.1:1/sensitive")
    assert r["verdict"] == "UNKNOWN"
    assert "ROE_BLOCK" in r.reason


def test_disabled_via_config(monkeypatch):
    from engine.injection import cache_deception
    monkeypatch.setattr(cache_deception, "_cfg",
                        lambda: {"enabled": False})
    r = cache_deception.scan("http://127.0.0.1:1/sensitive")
    assert r["verdict"] == "UNKNOWN"
    assert "enabled=false" in r.reason
