import time
import threading
import socketserver

import pytest

from engine import smuggle
from engine import roe_guard as roe_mod


def test_build_payload_clte_has_both_headers():
    p = smuggle.build_payload("clte", "example.com", "/api").decode()
    assert "Transfer-Encoding: chunked" in p
    assert "Content-Length: 4" in p
    assert p.startswith("POST /api HTTP/1.1")


def test_build_payload_baseline_no_te():
    p = smuggle.build_payload("baseline", "example.com").decode()
    assert "Transfer-Encoding" not in p
    assert "Content-Length: 0" in p


def test_build_payload_unknown_raises():
    with pytest.raises(ValueError):
        smuggle.build_payload("bogus", "h")


def test_analyze_flags_timeout():
    probes = {"clte": {"elapsed_ms": 5000, "timed_out": True, "error": None},
              "tecl": {"elapsed_ms": 10, "timed_out": False, "error": None}}
    r = smuggle.analyze(10.0, probes, threshold_ms=3000)
    assert r["verdict"] == "SUSPICIOUS"
    assert r["evidence"]["delayed"][0]["vector"] == "clte"


def test_analyze_flags_delta():
    probes = {"clte": {"elapsed_ms": 4000, "timed_out": False, "error": None}}
    r = smuggle.analyze(50.0, probes, threshold_ms=1500)
    assert r["verdict"] == "SUSPICIOUS"


def test_analyze_pass_when_fast():
    probes = {"clte": {"elapsed_ms": 60, "timed_out": False, "error": None},
              "tecl": {"elapsed_ms": 55, "timed_out": False, "error": None}}
    assert smuggle.analyze(50.0, probes, threshold_ms=1500)["verdict"] == "PASS"


class _VulnTCP(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            data = self.request.recv(8192)
        except Exception:
            data = b""
        if b"transfer-encoding: chunked" in data.lower():
            time.sleep(2.5)
        try:
            self.request.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        except Exception:
            pass


class _SafeTCP(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            self.request.recv(8192)
        except Exception:
            pass
        try:
            self.request.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        except Exception:
            pass


class _TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


@pytest.fixture(autouse=True)
def permissive_roe(monkeypatch):
    monkeypatch.setattr(roe_mod, "load_roe", lambda: {
        "enabled": True,
        "scope": {"in_scope": ["127.0.0.1"], "out_of_scope": [],
                  "allowed_methods": ["POST", "GET"], "forbidden_paths": []},
    })


def _cfg():
    return {"http": {"verify_tls": False}, "roe": {"enabled": True}}


def _serve(handler):
    srv = _TCPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_probe_detects_timing_differential():
    srv = _serve(_VulnTCP)
    _, port = srv.server_address
    try:
        out = smuggle.probe(f"http://127.0.0.1:{port}/", engine_cfg=_cfg(),
                            timeout=5.0, threshold_ms=1500)
    finally:
        srv.shutdown(); srv.server_close()
    assert out["result"]["verdict"] == "SUSPICIOUS"
    assert out["result"]["evidence"]["delayed"]


def test_probe_safe_server_passes():
    srv = _serve(_SafeTCP)
    _, port = srv.server_address
    try:
        out = smuggle.probe(f"http://127.0.0.1:{port}/", engine_cfg=_cfg(),
                            timeout=5.0, threshold_ms=1500)
    finally:
        srv.shutdown(); srv.server_close()
    assert out["result"]["verdict"] == "PASS"


def test_probe_respects_roe(monkeypatch):
    monkeypatch.setattr(roe_mod, "load_roe", lambda: {
        "enabled": True,
        "scope": {"in_scope": ["127.0.0.1"], "out_of_scope": [],
                  "allowed_methods": ["POST"], "forbidden_paths": []},
    })
    out = smuggle.probe("http://10.1.2.3/", engine_cfg=_cfg())
    assert out["result"]["verdict"] == "UNKNOWN"
    assert "ROE_BLOCK" in out["error"]
