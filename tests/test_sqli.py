import re
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


class _BoolVuln(BaseHTTPRequestHandler):
    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        val = (q.get("q") or [""])[0]
        if "1=1" in val and "1=2" not in val:
            body = b"A" * 500
        elif "1=2" in val:
            body = b"B" * 200
        else:
            body = b"C" * 200
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class _ErrVuln(BaseHTTPRequestHandler):
    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        val = (q.get("q") or [""])[0]
        if "'" in val or '"' in val:
            body = b"You have an error in your SQL syntax near " + val.encode()
        else:
            body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class _UnionVuln(BaseHTTPRequestHandler):
    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        val = (q.get("q") or [""])[0]
        if "UNION" in val.upper() and "SC_UNION_7733" in val:
            markers = re.findall(r"SC_UNION_7733_\d+", val)
            body = ("<td>" + "</td><td>".join(markers) + "</td>").encode()
        else:
            body = b"not union"
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
    from engine.injection import sqli
    assert sqli is not None
    assert hasattr(sqli, "scan")


def test_boolean_detects():
    from engine.injection import sqli
    srv = _serve(_BoolVuln)
    _, port = srv.server_address
    try:
        result = sqli.scan(f"http://127.0.0.1:{port}/", param="q",
                            probes=["boolean"])
    finally:
        srv.shutdown(); srv.server_close()
    assert result["verdict"] == "VULNERABLE"


def test_error_detects():
    from engine.injection import sqli
    srv = _serve(_ErrVuln)
    _, port = srv.server_address
    try:
        result = sqli.scan(f"http://127.0.0.1:{port}/", param="q",
                            probes=["error"])
    finally:
        srv.shutdown(); srv.server_close()
    assert result["verdict"] == "VULNERABLE"


def test_union_detects():
    from engine.injection import sqli
    srv = _serve(_UnionVuln)
    _, port = srv.server_address
    try:
        result = sqli.scan(f"http://127.0.0.1:{port}/", param="q",
                            probes=["union"], max_cols=3)
    finally:
        srv.shutdown(); srv.server_close()
    assert result["verdict"] == "VULNERABLE"


def test_no_param_returns_unknown():
    from engine.injection import sqli
    result = sqli.scan("http://127.0.0.1:1/")
    assert result["verdict"] == "UNKNOWN"
    assert "parameter" in result["reason"].lower()


def test_roe_block(monkeypatch):
    from engine.injection import sqli
    monkeypatch.setattr(roe_mod, "load_roe", lambda: {
        "enabled": True,
        "scope": {"in_scope": ["10.0.0.1"], "out_of_scope": [],
                  "allowed_methods": ["GET"], "forbidden_paths": []},
    })
    result = sqli.scan("http://127.0.0.1:1/", param="q")
    assert result["verdict"] == "UNKNOWN"
