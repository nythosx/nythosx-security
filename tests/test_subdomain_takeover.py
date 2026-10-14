import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from engine import subdomain_takeover
from engine import roe_guard as roe_mod


@pytest.fixture(autouse=True)
def permissive_roe(monkeypatch):
    monkeypatch.setattr(roe_mod, "load_roe", lambda: {
        "enabled": True,
        "scope": {"in_scope": ["127.0.0.1"], "out_of_scope": [],
                  "allowed_methods": ["GET"], "forbidden_paths": []},
    })


class _HerokuGhost(BaseHTTPRequestHandler):
    def do_GET(self):
        body = (b"<html><head><title>No such app</title></head>"
                b"<body>Heroku | No such app</body></html>")
        self.send_response(404)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class _GithubGhost(BaseHTTPRequestHandler):
    def do_GET(self):
        body = (b"<html><body>There isn't a GitHub Pages site here."
                b" For root URLs (like http://example.com/) you must provide"
                b" an index.html file.</body></html>")
        self.send_response(404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class _S3Ghost(BaseHTTPRequestHandler):
    def do_GET(self):
        body = (b'<?xml version="1.0"?><Error><Code>NoSuchBucket</Code>'
                b'<Message>The specified bucket does not exist</Message></Error>')
        self.send_response(404)
        self.send_header("Content-Type", "application/xml")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class _LiveSite(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<html><body>Welcome to the real site</body></html>"
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
    assert subdomain_takeover.CAPABILITY.name == "subdomain_takeover"


def test_heroku_fingerprint():
    srv = _serve(_HerokuGhost)
    _, port = srv.server_address
    try:
        r = subdomain_takeover.scan([f"http://127.0.0.1:{port}/"])
    finally:
        srv.shutdown(); srv.server_close()
    assert r["verdict"] == "VULNERABLE"
    assert r.evidence["findings"][0]["service"] == "heroku"


def test_github_pages_fingerprint():
    srv = _serve(_GithubGhost)
    _, port = srv.server_address
    try:
        r = subdomain_takeover.scan([f"http://127.0.0.1:{port}/"])
    finally:
        srv.shutdown(); srv.server_close()
    assert r["verdict"] == "VULNERABLE"
    assert r.evidence["findings"][0]["service"] == "github_pages"


def test_s3_fingerprint():
    srv = _serve(_S3Ghost)
    _, port = srv.server_address
    try:
        r = subdomain_takeover.scan([f"http://127.0.0.1:{port}/"])
    finally:
        srv.shutdown(); srv.server_close()
    assert r["verdict"] == "VULNERABLE"
    assert r.evidence["findings"][0]["service"] == "aws_s3"


def test_live_site_passes():
    srv = _serve(_LiveSite)
    _, port = srv.server_address
    try:
        r = subdomain_takeover.scan([f"http://127.0.0.1:{port}/"])
    finally:
        srv.shutdown(); srv.server_close()
    assert r["verdict"] == "PASS"


def test_empty_urls_returns_unknown():
    r = subdomain_takeover.scan([])
    assert r["verdict"] == "UNKNOWN"


def test_roe_block(monkeypatch):
    monkeypatch.setattr(roe_mod, "load_roe", lambda: {
        "enabled": True,
        "scope": {"in_scope": ["10.0.0.1"], "out_of_scope": [],
                  "allowed_methods": ["GET"], "forbidden_paths": []},
    })
    r = subdomain_takeover.scan(["http://127.0.0.1:1/"])
    assert r["verdict"] == "UNKNOWN"
    assert "ROE_BLOCK" in r.reason


def test_multiple_urls_reports_all():
    srv = _serve(_HerokuGhost)
    _, port = srv.server_address
    try:
        r = subdomain_takeover.scan([
            f"http://127.0.0.1:{port}/",
            f"http://127.0.0.1:{port}/other",
        ])
    finally:
        srv.shutdown(); srv.server_close()
    assert r["verdict"] == "VULNERABLE"
    assert len(r.evidence["findings"]) >= 1
