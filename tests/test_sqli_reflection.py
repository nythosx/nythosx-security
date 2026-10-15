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
                  "allowed_methods": ["GET"], "forbidden_paths": []},
    })


class _EchoReflector(BaseHTTPRequestHandler):
    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        val = (q.get("q") or [""])[0]
        body = ("query was: " + val).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class _ExecutedUnion(BaseHTTPRequestHandler):
    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        val = (q.get("q") or [""])[0]
        if "UNION" in val.upper() and "SC_UNION_7733" in val:
            body = b"result: SC_UNION_7733"
        else:
            body = b"no result"
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


def test_payload_reflection_not_flagged():
    from engine.injection import sqli
    srv = _serve(_EchoReflector)
    _, port = srv.server_address
    try:
        r = sqli.scan(f"http://127.0.0.1:{port}/", param="q",
                       probes=["union"], max_cols=2)
    finally:
        srv.shutdown(); srv.server_close()
    assert r["verdict"] != "VULNERABLE", r


def test_payload_reflection_reported_as_pass_or_unknown():
    from engine.injection import sqli
    srv = _serve(_EchoReflector)
    _, port = srv.server_address
    try:
        r = sqli.scan(f"http://127.0.0.1:{port}/", param="q",
                       probes=["union"], max_cols=2)
    finally:
        srv.shutdown(); srv.server_close()
    assert r["verdict"] in ("PASS", "UNKNOWN")


def test_real_union_execution_still_flagged():
    from engine.injection import sqli
    srv = _serve(_ExecutedUnion)
    _, port = srv.server_address
    try:
        r = sqli.scan(f"http://127.0.0.1:{port}/", param="q",
                       probes=["union"], max_cols=2)
    finally:
        srv.shutdown(); srv.server_close()
    assert r["verdict"] == "VULNERABLE"
