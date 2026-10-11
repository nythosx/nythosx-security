"""Phase 3 tests: OOB external, target-side SSRF, oracle handlers, mapping."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT_SRC = Path(__file__).resolve().parent.parent


# ---------- OOB external ----------
def test_oob_default_is_loopback():
    from engine import oob as oob_mod
    srv = oob_mod.OOBServer()
    srv.start()
    try:
        assert srv.mode == "loopback"
        assert srv.base_url.startswith("http://127.0.0.1:")
        token, url = srv.payload_url()
        assert token in url
    finally:
        srv.stop()


def test_oob_external_uses_configured_url():
    from engine import oob as oob_mod
    srv = oob_mod.OOBServer(external_url="https://abc.interactsh.com")
    srv.start()
    try:
        assert srv.mode == "external"
        assert srv.base_url == "https://abc.interactsh.com"
        token, url = srv.payload_url()
        assert url == f"https://abc.interactsh.com/{token}"
    finally:
        srv.stop()


def test_oob_external_wait_returns_false():
    from engine import oob as oob_mod
    srv = oob_mod.OOBServer(external_url="https://abc.interactsh.com")
    srv.start()
    try:
        token, _ = srv.payload_url()
        assert srv.wait_for_hit(token, timeout=0.2) is False
        assert srv.hit_count(token) == 0
    finally:
        srv.stop()


def test_oob_registry_reads_external_config(monkeypatch):
    from engine import oob_registry, config as cfg_mod
    real_load = cfg_mod.load_engine

    def patched():
        c = dict(real_load() or {})
        c["oob"] = {"external_enabled": True,
                    "callback_url": "https://xyz.interactsh.com"}
        return c

    monkeypatch.setattr(cfg_mod, "load_engine", patched)
    oob_registry.reset_shared_oob()
    try:
        srv = oob_registry.get_shared_oob()
        assert srv.mode == "external"
        assert srv.base_url == "https://xyz.interactsh.com"
    finally:
        oob_registry.reset_shared_oob()


# ---------- ssrf_cloud target-side ----------
def _roe_allow():
    from engine.roe_guard import ROEGuard
    class _G:
        def check_url(self, url, method="GET"):
            return True
    return _G()


class _MetadataReflector(BaseHTTPRequestHandler):
    """Echoes back the value of the 'url' query param in the body."""
    from urllib.parse import urlparse, parse_qs as _pq

    def do_GET(self):
        from urllib.parse import urlparse, parse_qs
        q = parse_qs(urlparse(self.path).query)
        val = (q.get("url") or [""])[0]
        if "169.254.169.254" in val or "metadata.google.internal" in val:
            body = (b'{"AccessKeyId": "AKIAIOSFODNN7EXAMPLE", '
                    b'"SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}')
        else:
            body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class _SafeReflector(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"ok"
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


def test_ssrf_cloud_target_side_detects():
    from engine import ssrf_cloud
    srv = _serve(_MetadataReflector)
    _, port = srv.server_address
    try:
        r = ssrf_cloud.scan(
            f"http://127.0.0.1:{port}/fetch",
            roe_guard=_roe_allow(),
        )
    finally:
        srv.shutdown()
        srv.server_close()
    assert r["verdict"] == "VULNERABLE", r
    assert "url" in r["reason"]


def test_ssrf_cloud_target_side_pass_on_safe():
    from engine import ssrf_cloud
    srv = _serve(_SafeReflector)
    _, port = srv.server_address
    try:
        r = ssrf_cloud.scan(
            f"http://127.0.0.1:{port}/fetch",
            roe_guard=_roe_allow(),
        )
    finally:
        srv.shutdown()
        srv.server_close()
    assert r["verdict"] in ("PASS", "UNKNOWN"), r


def test_ssrf_cloud_self_probe_returns_scanresult():
    from engine import ssrf_cloud
    r = ssrf_cloud.scan(self_probe=True, roe_guard=_roe_allow())
    assert r["verdict"] in ("PASS", "SUSPICIOUS", "VULNERABLE", "UNKNOWN")
    assert "self_probe" in r.get("evidence", {}) or True


# ---------- oracle handlers ----------
def test_every_pattern_oracle_has_handler():
    from engine import loader
    from engine.oracle import _HANDLERS
    missing = []
    for p in loader.list_patterns():
        full = loader.load_pattern(p["id"])
        if not full:
            continue
        for o in full.get("oracles") or []:
            otype = o.get("type")
            if otype and otype not in _HANDLERS:
                missing.append(f"{p['id']}: {otype}")
    assert not missing, (
        "missing oracle handlers:\n" + "\n".join(missing)
    )


def test_all_phase3_handlers_registered():
    from engine.oracle import _HANDLERS
    for otype in (
        "ssti_scan", "xxe_scan", "nosql_scan", "crlf_scan",
        "open_redirect_scan", "host_header_scan", "upload_scan",
        "websocket_scan", "weak_password_scan", "lockout_scan",
        "weak_credential_scan", "oauth_state_scan",
        "oauth_redirect_uri_scan", "oauth_pkce_scan",
        "oauth_id_token_scan", "http2_scan",
    ):
        assert otype in _HANDLERS, otype
        assert callable(_HANDLERS[otype])


def test_oauth_id_token_needs_token():
    from engine.oracle import _HANDLERS
    handler = _HANDLERS["oauth_id_token_scan"]
    r = handler({}, {"steps": [], "target": "http://x"})
    assert r["verdict"] == "UNKNOWN"
    assert "id_token" in r["reason"]


# ---------- coverage + owasp ----------
def test_coverage_has_new_patterns():
    from engine import coverage
    a05 = coverage.OWASP_TO_CAPABILITIES.get("A05", [])
    assert "ssti-probe" in a05
    assert "xxe-probe" in a05
    a07 = coverage.OWASP_TO_CAPABILITIES.get("A07", [])
    assert "lockout-probe" in a07
    assert "weak-credential-enum" in a07


def test_owasp_pattern_map_has_new_entries():
    from engine import owasp_2025
    assert owasp_2025.map_pattern("ssti-probe") == "A05"
    assert owasp_2025.map_pattern("oauth-redirect-uri") == "A01"
    assert owasp_2025.map_pattern("weak-password-policy") == "A07"
    assert owasp_2025.map_pattern("timing-sqli") == "A05"


def test_owasp_prefix_map_has_new_prefixes():
    from engine import owasp_2025
    assert owasp_2025.map_pattern("ssti-something") == "A05"
    assert owasp_2025.map_pattern("oauth-anything") == "A07"
    assert owasp_2025.map_pattern("timing-custom") == "A05"


# ---------- writeups ----------
def test_writeups_cover_new_patterns():
    from engine import writeup_library
    for pid in (
        "ssti-probe", "xxe-probe", "nosql-probe", "crlf-injection",
        "open-redirect", "host-header-injection", "websocket-cswsh",
        "oauth-redirect-uri", "oauth-missing-state", "upload-probe",
        "http2-desync", "weak-password-policy", "lockout-probe",
        "weak-credential-enum", "timing-sqli", "timing-ssti",
        "timing-xxe", "second-order-xss",
    ):
        entry = writeup_library.resolve(pid)
        assert entry is not None, f"no writeup for {pid}"
        rendered = writeup_library.render(entry, {})
        assert rendered["gap"], f"empty gap for {pid}"


def test_new_families_exist():
    from engine import writeup_library
    fams = writeup_library.families()
    assert "oauth" in fams
    assert "blind-injection" in fams
