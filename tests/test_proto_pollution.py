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


class _Reflector(BaseHTTPRequestHandler):
    def do_GET(self):
        body = ("<html><body>" + self.path + "</body></html>").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
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
    from engine.injection import proto_pollution
    assert proto_pollution is not None
    assert hasattr(proto_pollution, "scan")


def test_reflection_detected():
    from engine.injection import proto_pollution
    srv = _serve(_Reflector)
    _, port = srv.server_address
    try:
        result = proto_pollution.scan(f"http://127.0.0.1:{port}/")
    finally:
        srv.shutdown(); srv.server_close()
    assert result["verdict"] == "SUSPICIOUS"


def test_no_reflection_passes():
    from engine.injection import proto_pollution
    class _Empty(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"<html><body>static</body></html>"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *a):
            pass
    srv = _serve(_Empty)
    _, port = srv.server_address
    try:
        result = proto_pollution.scan(f"http://127.0.0.1:{port}/")
    finally:
        srv.shutdown(); srv.server_close()
    assert result["verdict"] == "PASS"
