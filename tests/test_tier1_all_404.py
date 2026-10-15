import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from engine import roe_guard as roe_mod


@pytest.fixture(autouse=True)
def permissive_roe(monkeypatch):
    monkeypatch.setattr(roe_mod, "load_roe", lambda: {
        "enabled": True,
        "scope": {"in_scope": ["127.0.0.1"], "out_of_scope": [],
                  "allowed_methods": ["GET", "POST", "PUT", "PATCH",
                                       "DELETE", "HEAD", "OPTIONS"],
                  "forbidden_paths": []},
    })


class _All404(BaseHTTPRequestHandler):
    def _404(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        if n:
            try:
                self.rfile.read(n)
            except Exception:
                pass
        body = b'{"error": "not found"}'
        self.send_response(404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _404
    do_POST = _404
    do_PUT = _404
    do_PATCH = _404
    do_DELETE = _404
    do_HEAD = _404
    do_OPTIONS = _404

    def log_message(self, *a):
        pass


@pytest.fixture
def all_404():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _All404)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _, port = srv.server_address
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        srv.shutdown()
        srv.server_close()


def _assert_unknown_and_reason(r, url_contains=None):
    assert r["verdict"] == "UNKNOWN", (
        f"expected UNKNOWN, got {r['verdict']}: {r.get('reason')}")
    reason = (r.get("reason") or "")
    assert "404" in reason or "not found" in reason.lower() or \
           "unreached" in reason.lower() or "no probes" in reason.lower(), (
        f"reason does not name the failure: {reason!r}")


def test_deserialization_all_404(all_404):
    from engine import deserialization
    r = deserialization.scan(all_404 + "/api")
    _assert_unknown_and_reason(r)


def test_ssti_all_404(all_404):
    from engine.injection import ssti
    r = ssti.scan(all_404 + "/search", param="q")
    _assert_unknown_and_reason(r)


def test_xxe_all_404(all_404):
    from engine.injection import xxe
    r = xxe.scan(all_404 + "/api")
    _assert_unknown_and_reason(r)


def test_crlf_all_404(all_404):
    from engine.injection import crlf
    r = crlf.scan(all_404 + "/api", param="q")
    _assert_unknown_and_reason(r)


def test_host_header_all_404(all_404):
    from engine.injection import host_header
    r = host_header.scan(all_404 + "/api")
    _assert_unknown_and_reason(r)


def test_open_redirect_all_404(all_404):
    from engine.injection import open_redirect
    r = open_redirect.scan(all_404 + "/api", param="next")
    _assert_unknown_and_reason(r)


def test_nosql_all_404(all_404):
    from engine.injection import nosql
    r = nosql.scan(all_404 + "/api/login")
    _assert_unknown_and_reason(r)


def test_oauth_redirect_uri_all_404(all_404):
    from engine.oauth import redirect_uri
    r = redirect_uri.scan(all_404 + "/oauth/authorize", target_host="127.0.0.1")
    _assert_unknown_and_reason(r)


def test_oauth_state_all_404(all_404):
    from engine.oauth import state_probe
    r = state_probe.scan(all_404 + "/oauth/authorize")
    _assert_unknown_and_reason(r)


def test_oauth_pkce_all_404(all_404):
    from engine.oauth import pkce_probe
    r = pkce_probe.scan(all_404 + "/oauth/authorize")
    _assert_unknown_and_reason(r)


def test_timing_sqli_all_404(all_404):
    from engine import oracles_timing
    r = oracles_timing.timing_sqli(all_404 + "/api", param="q",
                                   baseline_samples=1, threshold_ms=500,
                                   timeout=5)
    assert r["verdict"] == "UNKNOWN"


def test_timing_ssti_all_404(all_404):
    from engine import oracles_timing
    r = oracles_timing.timing_ssti(all_404 + "/api", param="q",
                                   baseline_samples=1, timeout=5)
    assert r["verdict"] == "UNKNOWN"


def test_timing_xxe_all_404(all_404):
    from engine import oracles_timing
    r = oracles_timing.timing_xxe(all_404 + "/api", baseline_samples=1,
                                  timeout=5)
    assert r["verdict"] == "UNKNOWN"


def test_upload_all_404_monkeypatched(all_404, monkeypatch):
    from engine import upload_probe
    from engine import config as cfg_mod
    real = cfg_mod.load_engine

    def patched():
        c = dict(real() or {})
        c["upload"] = {"enabled": True, "opt_in": True}
        return c

    monkeypatch.setattr(upload_probe, "load_engine", patched)
    r = upload_probe.scan(all_404 + "/upload")
    _assert_unknown_and_reason(r)
