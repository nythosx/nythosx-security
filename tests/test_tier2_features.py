"""Tier 2 features: 2.1 -> 2.7."""
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest


# ---------- 2.1 ----------
def test_extract_params_axios_params():
    from engine import discovery
    js = 'axios.get("/api/users", {params: {id: userId, role: "admin"}})'
    out = discovery.extract_api_params_from_js(js)
    assert "/api/users" in out
    assert "id" in out["/api/users"]["query"]
    assert "role" in out["/api/users"]["query"]


def test_extract_params_fetch_query():
    from engine import discovery
    js = 'fetch("/api/search?q=hello&page=1")'
    out = discovery.extract_api_params_from_js(js)
    assert "/api/search" in out
    assert "q" in out["/api/search"]["query"]
    assert "page" in out["/api/search"]["query"]


def test_extract_params_path_param():
    from engine import discovery
    js = 'api.get("/users/{id}/orders")'
    out = discovery.extract_api_params_from_js(js)
    assert "/users/{id}/orders" in out
    assert "id" in out["/users/{id}/orders"]["path"]


def test_extract_params_no_false_positive():
    from engine import discovery
    assert discovery.extract_api_params_from_js('x("not-a-path")') == {}


# ---------- 2.2 ----------
def test_classify_unknown_unreachable():
    from engine.chain_engine import _classify_unknown
    assert _classify_unknown({"reason": "connection refused"}) == "unreachable"
    assert _classify_unknown({"error": "ROE_BLOCK: not in scope"}) == "unreachable"


def test_classify_unknown_timeout():
    from engine.chain_engine import _classify_unknown
    assert _classify_unknown({"reason": "read timeout"}) == "timeout"
    assert _classify_unknown({"error": "TimeoutException"}) == "timeout"


def test_classify_unknown_ambiguous():
    from engine.chain_engine import _classify_unknown
    assert _classify_unknown({"reason": "empty response body"}) == "ambiguous"


class _Allow:
    def check_url(self, url, method="GET"):
        return True


def _orch(handlers):
    from engine.chain_engine import ChainOrchestrator
    orch = ChainOrchestrator("http://test.local",
                             roe_guard=_Allow(), engine_cfg={})
    orch.run_recon = lambda: None
    orch._TOOL_HANDLERS = handlers
    return orch


def test_chain_aborts_on_unreachable():
    orch = _orch({
        "dead": lambda self, a: {"verdict": "UNKNOWN",
                                  "reason": "connection refused",
                                  "evidence": {}},
        "ok": lambda self, a: {"verdict": "PASS", "reason": "ok"},
    })
    chain = {"id": "t", "name": "t",
             "trigger": {"mode": "any",
                         "conditions": [{"fact": "framework"}]},
             "steps": [{"id": "s1", "tool": "dead"},
                       {"id": "s2", "tool": "ok"}]}
    orch.add_fact("framework", "generic")
    result = orch.execute_chain(chain)
    assert result.get("aborted") is True
    assert len(result["steps"]) == 1


def test_chain_marks_reduced_confidence_on_ambiguous():
    orch = _orch({
        "vague": lambda self, a: {"verdict": "UNKNOWN",
                                   "reason": "empty response body",
                                   "evidence": {}},
        "ok": lambda self, a: {"verdict": "PASS", "reason": "ok"},
    })
    chain = {"id": "t", "name": "t",
             "trigger": {"mode": "any",
                         "conditions": [{"fact": "framework"}]},
             "steps": [{"id": "s1", "tool": "vague"},
                       {"id": "s2", "tool": "ok"}]}
    orch.add_fact("framework", "generic")
    result = orch.execute_chain(chain)
    assert result.get("reduced_confidence") is True
    assert len(result["steps"]) == 2


# ---------- 2.3 ----------
def test_second_order_candidate_filter():
    from engine import second_order
    got = second_order.candidate_endpoints(
        ["/api/users", "/api/profile", "/api/health"])
    assert "/api/users" in got
    assert "/api/profile" in got


class _Reflector(BaseHTTPRequestHandler):
    store = {}

    def do_GET(self):
        from urllib.parse import urlparse, parse_qs
        p = urlparse(self.path)
        q = parse_qs(p.query)
        if p.path == "/api/store":
            marker = (q.get("m") or [""])[0]
            if marker:
                self.store["marker"] = marker
            return self._ok(b"stored")
        if p.path == "/api/profile":
            marker = self.store.get("marker", "")
            return self._ok(("hello " + marker).encode())
        self._ok(b"ok")

    def _ok(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def test_second_order_check_detects_propagation():
    from engine import second_order
    import httpx
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Reflector)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _, port = srv.server_address
    base = f"http://127.0.0.1:{port}"
    try:
        httpx.get(f"{base}/api/store?m=SEC_MARKER_XYZ", timeout=3)
        out = second_order.check_propagation(
            base, ["/api/profile"], "SEC_MARKER_XYZ", roe_guard=_Allow())
    finally:
        srv.shutdown(); srv.server_close()
    assert out["verdict"] == "VULNERABLE"
    assert out["evidence"]["hits"]


# ---------- 2.4 ----------
class _Sleeper(BaseHTTPRequestHandler):
    def do_GET(self):
        from urllib.parse import urlparse, parse_qs
        q = parse_qs(urlparse(self.path).query)
        val = (q.get("q") or [""])[0]
        if "SLEEP" in val.upper() or "pg_sleep" in val:
            time.sleep(1.2)
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class _Safe(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def test_timing_sqli_detects_delay():
    from engine import oracles_timing
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Sleeper)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _, port = srv.server_address
    try:
        out = oracles_timing.timing_sqli(
            f"http://127.0.0.1:{port}/", param="q",
            baseline_samples=1, threshold_ms=500,
            timeout=5, roe_guard=_Allow())
    finally:
        srv.shutdown(); srv.server_close()
    assert out["verdict"] == "SUSPICIOUS", out


def test_timing_sqli_passes_on_safe_target():
    from engine import oracles_timing
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Safe)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _, port = srv.server_address
    try:
        out = oracles_timing.timing_sqli(
            f"http://127.0.0.1:{port}/", param="q",
            baseline_samples=1, threshold_ms=1500,
            timeout=5, roe_guard=_Allow())
    finally:
        srv.shutdown(); srv.server_close()
    assert out["verdict"] == "PASS", out


# ---------- 2.5 ----------
def test_svg_renders():
    from engine import report_graph
    chains = [{
        "id": "c1", "name": "Chain One", "verdict": "CONFIRMED",
        "severity": "critical", "matched": [
            {"pattern_id": "a", "verdict": "VULNERABLE"},
            {"pattern_id": "b", "verdict": "VULNERABLE"},
        ],
    }]
    svg = report_graph.render_chain_svg(chains)
    assert svg.startswith("<svg")
    assert "Chain One" in svg
    assert "a" in svg and "b" in svg


def test_svg_empty_returns_empty():
    from engine import report_graph
    assert report_graph.render_chain_svg([]) == ""


# ---------- 2.6 ----------
def test_nuclei_export_produces_valid_yaml():
    import yaml
    from engine import nuclei_export
    chain = {
        "id": "test-chain", "name": "Test Chain", "severity": "high",
        "steps": [
            {"id": "s1", "tool": "graphql_scan", "args": {}},
            {"id": "s2", "tool": "openapi_scan", "args": {}},
        ],
    }
    tpl = nuclei_export.chain_to_nuclei(chain)
    parsed = yaml.safe_load(yaml.safe_dump(tpl, sort_keys=False))
    assert parsed["id"] == "test-chain"
    assert parsed["info"]["severity"] == "high"
    assert isinstance(parsed["http"], list)
    assert len(parsed["http"]) == 2


def test_nuclei_export_notes_untranslated_steps():
    from engine import nuclei_export
    chain = {"id": "x", "name": "X", "severity": "low",
             "steps": [{"id": "s1", "tool": "unknown_tool", "args": {}}]}
    tpl = nuclei_export.chain_to_nuclei(chain)
    assert "metadata" in tpl["info"]
    assert tpl["info"]["metadata"]["untranslated_steps"]


# ---------- 2.7 ----------
def test_chain_stats_roundtrip(tmp_path, monkeypatch):
    from engine import ledger
    monkeypatch.setattr(ledger, "DB_PATH", tmp_path / "ledger.db")
    ledger.record_chain_step("jwt-chain", "alg_none", "jwt_attack",
                              "VULNERABLE", 120.0)
    ledger.record_chain_step("jwt-chain", "weak_secret", "jwt_attack",
                              "PASS", 80.0)
    ledger.record_chain_step("race-chain", "barrier", "race_scan",
                              "SUSPICIOUS", 2000.0)
    stats = ledger.chain_stats()
    by_id = {c["chain_id"]: c for c in stats["chains"]}
    assert by_id["jwt-chain"]["runs"] == 2
    assert by_id["jwt-chain"]["vulnerable"] == 1
    assert by_id["jwt-chain"]["pass_count"] == 1
    assert by_id["race-chain"]["suspicious"] == 1
    assert by_id["race-chain"]["avg_duration_ms"] == 2000.0
    assert stats["total_runs"] == 3


def test_chain_stats_limit(tmp_path, monkeypatch):
    from engine import ledger
    monkeypatch.setattr(ledger, "DB_PATH", tmp_path / "ledger.db")
    for i in range(5):
        ledger.record_chain_step(f"c{i}", "s", "t", "PASS", 1.0)
    stats = ledger.chain_stats(limit=2)
    assert len(stats["chains"]) == 2
