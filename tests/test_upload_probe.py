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


def test_module_imports():
    from engine import upload_probe
    assert upload_probe is not None
    assert hasattr(upload_probe, "scan")
    assert upload_probe.CAPABILITY.destructive is True
    assert upload_probe.CAPABILITY.default_on is False


def test_disabled_by_default():
    from engine import upload_probe
    r = upload_probe.scan("http://127.0.0.1:1")
    assert r["verdict"] == "UNKNOWN"
    assert "disabled" in r.reason.lower() or "opt_in" in r.reason.lower()


class _PermissiveUpload(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        self.rfile.read(n)
        out = b'{"ok": true, "url": "/uploads/probe.php"}'
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


def test_upload_vulnerable_when_enabled(monkeypatch):
    from engine import upload_probe
    from engine import config as cfg_mod

    real_load = cfg_mod.load_engine

    def patched_load():
        c = real_load() or {}
        c = dict(c)
        c["upload"] = {"enabled": True, "opt_in": True}
        return c

    monkeypatch.setattr(upload_probe, "load_engine", patched_load)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _PermissiveUpload)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _, port = srv.server_address
    try:
        r = upload_probe.scan(f"http://127.0.0.1:{port}/upload")
    finally:
        srv.shutdown(); srv.server_close()
    assert r["verdict"] == "VULNERABLE"
