import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import pytest

from engine import roe_guard as roe_mod


@pytest.fixture(autouse=True)
def permissive_roe(monkeypatch):
    monkeypatch.setattr(roe_mod, "load_roe", lambda: {
        "enabled": True,
        "scope": {"in_scope": ["127.0.0.1"], "out_of_scope": [],
                  "allowed_methods": ["GET", "POST"], "forbidden_paths": []},
    })


def test_modules_import():
    from engine.injection import ssti, xxe, nosql, crlf, open_redirect, host_header
    for m in (ssti, xxe, nosql, crlf, open_redirect, host_header):
        assert m is not None
        assert hasattr(m, "scan")
        assert hasattr(m, "CAPABILITY")


def test_all_modules_expose_contract():
    import inspect
    from engine.contract import Capability
    from engine.injection import ssti, xxe, nosql, crlf, open_redirect, host_header
    for m in (ssti, xxe, nosql, crlf, open_redirect, host_header):
        assert callable(m.scan), m.__name__
        assert isinstance(m.CAPABILITY, Capability), m.__name__
        sig = inspect.signature(m.scan)
        keys = list(sig.parameters.keys())
        assert any(k in keys for k in ("target_url", "login_url")), m.__name__


class _VulnSSTI(BaseHTTPRequestHandler):
    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        body = ""
        for v in q.values():
            for val in v:
                body += val.replace("{{7*7}}", "49").replace("${7*7}", "49")
        out = body.encode() or b"hi"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


def test_ssti_detected():
    from engine.injection import ssti
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _VulnSSTI)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _, port = srv.server_address
    try:
        r = ssti.scan(f"http://127.0.0.1:{port}/", param="q")
    finally:
        srv.shutdown(); srv.server_close()
    assert r["verdict"] == "VULNERABLE"


class _OpenRedirectServer(BaseHTTPRequestHandler):
    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        location = ""
        for v in q.values():
            for val in v:
                if "attacker.example.com" in val:
                    location = val
                    break
        if location:
            self.send_response(302)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def test_open_redirect_detected():
    from engine.injection import open_redirect
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _OpenRedirectServer)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _, port = srv.server_address
    try:
        r = open_redirect.scan(f"http://127.0.0.1:{port}/", param="next")
    finally:
        srv.shutdown(); srv.server_close()
    assert r["verdict"] == "VULNERABLE"


class _HostEcho(BaseHTTPRequestHandler):
    def do_GET(self):
        host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or ""
        body = host.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def test_host_header_reflection_detected():
    from engine.injection import host_header
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _HostEcho)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _, port = srv.server_address
    try:
        r = host_header.scan(f"http://127.0.0.1:{port}/")
    finally:
        srv.shutdown(); srv.server_close()
    assert r["verdict"] == "VULNERABLE"


class _XxeVulnServer(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(n).decode("utf-8", "ignore") if n else ""
        if "/etc/passwd" in raw:
            body = b"root:x:0:0:root:/root:/bin/bash\n"
        elif "win.ini" in raw:
            body = b"[fonts]\nfoo=bar\n"
        elif "environment" in raw:
            body = b"PATH=/usr/bin\n"
        elif "hostname" in raw:
            body = b"my-hostname\n"
        elif "hosts" in raw:
            body = b"127.0.0.1 localhost\n"
        else:
            body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def test_xxe_detected():
    from engine.injection import xxe
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _XxeVulnServer)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _, port = srv.server_address
    try:
        r = xxe.scan(f"http://127.0.0.1:{port}/")
    finally:
        srv.shutdown(); srv.server_close()
    assert r["verdict"] == "VULNERABLE"


class _CrlfVuln(BaseHTTPRequestHandler):
    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        for v in q.values():
            for val in v:
                if "X-Injected" in val:
                    self.send_response(200)
                    self.send_header("X-Injected", "payload")
                    self.send_header("Content-Length", "2")
                    self.end_headers()
                    self.wfile.write(b"ok")
                    return
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def test_crlf_detected():
    from engine.injection import crlf
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _CrlfVuln)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _, port = srv.server_address
    try:
        r = crlf.scan(f"http://127.0.0.1:{port}/", param="q")
    finally:
        srv.shutdown(); srv.server_close()
    assert r["verdict"] == "VULNERABLE"


class _NoSqlVuln(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        try:
            import json as _json
            body = _json.loads(self.rfile.read(n).decode() or "{}") if n else {}
        except Exception:
            body = {}
        u = body.get("username")
        p = body.get("password")
        bypass = isinstance(u, dict) and isinstance(p, dict)
        if bypass:
            out = b'{"token": "admin-session-abc", "success": true}'
        else:
            out = b'{"error": "invalid credentials"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


def test_nosql_detected():
    from engine.injection import nosql
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _NoSqlVuln)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _, port = srv.server_address
    try:
        r = nosql.scan(f"http://127.0.0.1:{port}/login")
    finally:
        srv.shutdown(); srv.server_close()
    assert r["verdict"] == "VULNERABLE"
