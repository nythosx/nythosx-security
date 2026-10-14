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


class _BypassGate(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split("?")[0].split("#")[0]
        if self.headers.get("X-Original-URL"):
            body = b'{"bypass":"header"}'
            code = 200
        elif path == "/secret/":
            body = b'{"bypass":"path"}'
            code = 200
        else:
            body = b'{"error":"forbidden"}'
            code = 403
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class _SafeGate(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"error":"forbidden"}'
        self.send_response(403)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class _PublicServer(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"ok":true}'
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
    from engine.injection import access_bypass
    assert access_bypass is not None
    assert hasattr(access_bypass, "scan")
    assert access_bypass.CAPABILITY.name == "access_bypass_scan"


def test_vulnerable_when_header_overrides_403():
    from engine.injection import access_bypass
    srv = _serve(_BypassGate)
    _, port = srv.server_address
    try:
        r = access_bypass.scan(f"http://127.0.0.1:{port}/secret")
    finally:
        srv.shutdown()
        srv.server_close()
    assert r["verdict"] == "VULNERABLE"
    types = {f["type"] for f in r.evidence["findings"]}
    assert "header" in types
    header_findings = [f for f in r.evidence["findings"]
                       if f["type"] == "header"]
    assert any(f["header"] == "X-Original-URL" for f in header_findings)


def test_path_mutation_bypass_detected():
    from engine.injection import access_bypass
    srv = _serve(_BypassGate)
    _, port = srv.server_address
    try:
        r = access_bypass.scan(f"http://127.0.0.1:{port}/secret")
    finally:
        srv.shutdown()
        srv.server_close()
    path_findings = [f for f in r.evidence["findings"] if f["type"] == "path"]
    assert any(f["path"] == "/secret/" for f in path_findings)


def test_safe_403_gate_passes():
    from engine.injection import access_bypass
    srv = _serve(_SafeGate)
    _, port = srv.server_address
    try:
        r = access_bypass.scan(f"http://127.0.0.1:{port}/secret")
    finally:
        srv.shutdown()
        srv.server_close()
    assert r["verdict"] == "PASS"
    assert "no bypass" in r.reason.lower()


def test_non_403_baseline_passes_with_hint():
    from engine.injection import access_bypass
    srv = _serve(_PublicServer)
    _, port = srv.server_address
    try:
        r = access_bypass.scan(f"http://127.0.0.1:{port}/api/public")
    finally:
        srv.shutdown()
        srv.server_close()
    assert r["verdict"] == "PASS"
    assert "not an access-control gate" in r.reason


def test_roe_block_returns_unknown(monkeypatch):
    from engine.injection import access_bypass
    monkeypatch.setattr(roe_mod, "load_roe", lambda: {
        "enabled": True,
        "scope": {"in_scope": ["10.0.0.1"], "out_of_scope": [],
                  "allowed_methods": ["GET"], "forbidden_paths": []},
    })
    r = access_bypass.scan("http://127.0.0.1:1/secret")
    assert r["verdict"] == "UNKNOWN"
    assert "ROE_BLOCK" in r.reason


def test_disabled_via_config(monkeypatch):
    from engine.injection import access_bypass
    monkeypatch.setattr(access_bypass, "_cfg",
                        lambda: {"enabled": False})
    r = access_bypass.scan("http://127.0.0.1:1")
    assert r["verdict"] == "UNKNOWN"
    assert "enabled=false" in r.reason


def test_connection_error_returns_unknown():
    from engine.injection import access_bypass
    r = access_bypass.scan("http://127.0.0.1:1/secret")
    assert r["verdict"] in ("UNKNOWN", "PASS")
