import base64
import pickle
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from engine import deserialization
from engine import roe_guard as roe_mod


@pytest.fixture(autouse=True)
def permissive_roe(monkeypatch):
    monkeypatch.setattr(roe_mod, "load_roe", lambda: {
        "enabled": True,
        "scope": {"in_scope": ["127.0.0.1"], "out_of_scope": [],
                  "allowed_methods": ["GET", "POST"], "forbidden_paths": []},
    })


class _JavaDeserVuln(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        self.rfile.read(n)
        cookie = self.headers.get("Cookie", "")
        body = b'{"ok": true}'
        if "session=rO0AB" in cookie:
            body = (b"java.io.InvalidClassException: sec-checker-probe; "
                    b"no valid constructor")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class _PhpDeserVuln(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(n) if n else b""
        body = b'{"ok": true}'
        if b'O:8:' in raw or b"O:8:" in self.headers.get("Cookie", "").encode():
            body = b"Warning: unserialize(): Error at offset 0"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class _CleanServer(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        self.rfile.read(n)
        body = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
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
    assert deserialization.CAPABILITY.name == "deserialization_scan"


def test_java_magic_detected():
    srv = _serve(_JavaDeserVuln)
    _, port = srv.server_address
    try:
        r = deserialization.scan(f"http://127.0.0.1:{port}/api")
    finally:
        srv.shutdown(); srv.server_close()
    assert r["verdict"] == "VULNERABLE"
    langs = {s["language"] for f in r.evidence["findings"]
             for s in f["signatures"]}
    assert "java" in langs


def test_php_object_detected():
    srv = _serve(_PhpDeserVuln)
    _, port = srv.server_address
    try:
        r = deserialization.scan(f"http://127.0.0.1:{port}/api")
    finally:
        srv.shutdown(); srv.server_close()
    assert r["verdict"] == "VULNERABLE"
    langs = {s["language"] for f in r.evidence["findings"]
             for s in f["signatures"]}
    assert "php" in langs


def test_clean_server_passes():
    srv = _serve(_CleanServer)
    _, port = srv.server_address
    try:
        r = deserialization.scan(f"http://127.0.0.1:{port}/api")
    finally:
        srv.shutdown(); srv.server_close()
    assert r["verdict"] == "PASS"


def test_roe_block(monkeypatch):
    monkeypatch.setattr(roe_mod, "load_roe", lambda: {
        "enabled": True,
        "scope": {"in_scope": ["10.0.0.1"], "out_of_scope": [],
                  "allowed_methods": ["GET", "POST"], "forbidden_paths": []},
    })
    r = deserialization.scan("http://127.0.0.1:1/api")
    assert r["verdict"] == "UNKNOWN"
    assert "ROE_BLOCK" in r.reason


def test_payloads_are_valid_magic_bytes():
    java = base64.b64decode(deserialization._JAVA_PAYLOAD)
    assert java.startswith(b"\xac\xed\x00\x05")
    php = deserialization._PHP_PAYLOAD
    assert php.startswith("O:")
    assert "stdClass" in php
    py = base64.b64decode(deserialization._PYTHON_PAYLOAD)
    assert py.startswith(b"\x80\x02")
    dn = base64.b64decode(deserialization._DOTNET_PAYLOAD)
    assert dn.startswith(b"\x00\x01\x00\x00\x00")
