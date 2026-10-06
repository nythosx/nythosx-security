import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from engine import browser
from engine import roe_guard as roe_mod

_PAGE = b"""<!doctype html><html><head><title>Probe Page</title></head>
<body><h1>hello</h1>
<script>
console.log("plain log");
console.error("BOOM_CONSOLE_ERROR");
throw new Error("BOOM_PAGE_ERROR");
</script></body></html>"""


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(_PAGE)))
        self.end_headers()
        self.wfile.write(_PAGE)

    def log_message(self, *a):
        pass


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


@pytest.fixture
def html_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _, port = srv.server_address
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        srv.shutdown()
        srv.server_close()


@pytest.fixture
def permissive_roe(monkeypatch):
    monkeypatch.setattr(roe_mod, "load_roe", lambda: {
        "enabled": True,
        "scope": {"in_scope": ["127.0.0.1", "localhost"], "out_of_scope": [],
                  "allowed_methods": ["GET"], "forbidden_paths": []},
    })


def test_capture_collects_console_and_errors(html_server, permissive_roe, tmp_path, monkeypatch):
    monkeypatch.setattr(browser, "BROWSER_EVIDENCE_DIR", tmp_path / "browser")
    r = browser.capture(html_server, timeout_ms=15000)
    assert r["error"] is None
    assert r["status"] == 200
    assert r["title"] == "Probe Page"
    console_texts = " ".join(m["text"] for m in r["console"])
    assert "BOOM_CONSOLE_ERROR" in console_texts
    assert any("BOOM_PAGE_ERROR" in e for e in r["page_errors"])
    assert r["screenshot"] is not None
    assert (tmp_path / "browser").exists()
    assert browser.console_errors(r)


def test_capture_respects_roe(monkeypatch):
    monkeypatch.setattr(roe_mod, "load_roe", lambda: {
        "enabled": True,
        "scope": {"in_scope": ["127.0.0.1"], "out_of_scope": [],
                  "allowed_methods": ["GET"], "forbidden_paths": []},
    })
    r = browser.capture("http://example.com/", screenshot=False)
    assert r["error"].startswith("ROE_BLOCK")
    assert r["screenshot"] is None
