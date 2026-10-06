import html
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import pytest

from engine import xss
from engine import roe_guard as roe_mod


def _browser_available():
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            b = p.chromium.launch()
            b.close()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _browser_available(),
                                reason="playwright chromium not installed")


class _ReflectedXSS(BaseHTTPRequestHandler):
    escape = False

    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        val = (q.get("q") or [""])[0]
        if self.escape:
            val = html.escape(val)
        page = f"<!doctype html><html><body><div>{val}</div></body></html>"
        body = page.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class _VulnXSS(_ReflectedXSS):
    escape = False


class _SafeXSS(_ReflectedXSS):
    escape = True


@pytest.fixture(autouse=True)
def permissive_roe(monkeypatch):
    monkeypatch.setattr(roe_mod, "load_roe", lambda: {
        "enabled": True,
        "scope": {"in_scope": ["127.0.0.1"], "out_of_scope": [],
                  "allowed_methods": ["GET"], "forbidden_paths": []},
    })


def _cfg():
    return {"http": {"timeout_seconds": 10, "verify_tls": False},
            "rate_limit": {"global_rps": 100, "per_endpoint_rps": 100, "burst": 100},
            "roe": {"enabled": True}}


def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_with_param_builds_url():
    u = xss._with_param("http://t/search?a=1", "q", "<x>")
    assert "q=%3Cx%3E" in u
    assert "a=1" in u


def test_reflected_xss_detected():
    srv = _serve(_VulnXSS)
    _, port = srv.server_address
    try:
        out = xss.probe(f"http://127.0.0.1:{port}/search", "q",
                        engine_cfg=_cfg(), wait_timeout=4.0)
    finally:
        srv.shutdown(); srv.server_close()
    assert out["result"]["verdict"] == "VULNERABLE"
    assert out["callbacks"]


def test_escaped_output_safe():
    srv = _serve(_SafeXSS)
    _, port = srv.server_address
    try:
        out = xss.probe(f"http://127.0.0.1:{port}/search", "q",
                        engine_cfg=_cfg(), wait_timeout=2.0)
    finally:
        srv.shutdown(); srv.server_close()
    assert out["result"]["verdict"] == "PASS"
