import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import httpx
import pytest

from engine import oob as oob_mod
from engine import ssrf
from engine import roe_guard as roe_mod


def test_oob_records_interaction():
    with oob_mod.OOBServer() as server:
        token, url = server.payload_url()
        httpx.get(url, timeout=3)
        assert server.wait_for_hit(token, timeout=3)
        hits = server.interactions(token)
        assert len(hits) == 1
        assert hits[0]["method"] == "GET"
        assert token in hits[0]["path"]


def test_oob_isolated_tokens():
    with oob_mod.OOBServer() as server:
        t1, u1 = server.payload_url()
        t2, _ = server.payload_url()
        httpx.get(u1, timeout=3)
        assert server.wait_for_hit(t1, timeout=3)
        assert server.hit_count(t1) == 1
        assert server.hit_count(t2) == 0


class _VulnSSRF(BaseHTTPRequestHandler):
    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        for vals in q.values():
            for v in vals:
                if v.startswith("http"):
                    try:
                        httpx.get(v, timeout=3)
                    except Exception:
                        pass
        self._ok()

    def _ok(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


class _SafeSSRF(_VulnSSRF):
    def do_GET(self):
        self._ok()


@pytest.fixture(autouse=True)
def permissive_roe(monkeypatch):
    monkeypatch.setattr(roe_mod, "load_roe", lambda: {
        "enabled": True,
        "scope": {"in_scope": ["127.0.0.1"], "out_of_scope": [],
                  "allowed_methods": ["GET", "POST"], "forbidden_paths": []},
    })


def _cfg():
    return {"http": {"timeout_seconds": 10, "max_retries": 1},
            "rate_limit": {"global_rps": 100, "per_endpoint_rps": 100, "burst": 100},
            "roe": {"enabled": True}}


def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_ssrf_probe_detects_callback():
    srv = _serve(_VulnSSRF)
    _, port = srv.server_address
    try:
        out = ssrf.probe(f"http://127.0.0.1:{port}/fetch",
                         params=["url"], engine_cfg=_cfg(), wait_timeout=5.0)
    finally:
        srv.shutdown(); srv.server_close()
    assert out["result"]["verdict"] == "VULNERABLE"
    assert any(c["vector"] == "param:url" for c in out["callbacks"])


def test_ssrf_probe_safe_target():
    srv = _serve(_SafeSSRF)
    _, port = srv.server_address
    try:
        out = ssrf.probe(f"http://127.0.0.1:{port}/fetch",
                         params=["url", "callback"], engine_cfg=_cfg(),
                         wait_timeout=2.0)
    finally:
        srv.shutdown(); srv.server_close()
    assert out["result"]["verdict"] == "PASS"
    assert out["callbacks"] == []
