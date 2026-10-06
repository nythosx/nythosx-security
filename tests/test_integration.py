import json
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from engine import executor, loader, ledger, report, cli
from engine import roe_guard as roe_mod
from engine import ratelimit


class _Handler(BaseHTTPRequestHandler):
    def _respond(self):
        self.server.hits.append(time.monotonic())
        body = json.dumps({"ok": True, "path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _respond
    do_POST = _respond
    do_OPTIONS = _respond

    def log_message(self, *args):
        pass


@pytest.fixture
def live_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    srv.hits = []
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    host, port = srv.server_address
    try:
        yield {"base": f"http://127.0.0.1:{port}", "server": srv}
    finally:
        srv.shutdown()
        srv.server_close()


@pytest.fixture(autouse=True)
def permissive_roe(monkeypatch):
    roe = {
        "enabled": True,
        "scope": {
            "in_scope": ["127.0.0.1", "localhost"],
            "out_of_scope": [],
            "allowed_methods": ["GET", "POST", "OPTIONS", "PUT", "DELETE", "HEAD"],
            "forbidden_paths": [],
        },
    }
    monkeypatch.setattr(roe_mod, "load_roe", lambda: roe)


@pytest.fixture(autouse=True)
def isolated_limiter():
    ratelimit.reset_shared_limiters()
    yield
    ratelimit.reset_shared_limiters()


@pytest.fixture
def temp_ledger(tmp_path, monkeypatch):
    monkeypatch.setattr(ledger, "DB_PATH", tmp_path / "ledger.db")
    return tmp_path


def _engine_cfg(global_rps=10, burst=20):
    return {
        "http": {"timeout_seconds": 10, "verify_tls": False, "max_retries": 1,
                 "backoff_base_ms": 50, "user_agent_rotation": False},
        "rate_limit": {"global_rps": global_rps, "per_endpoint_rps": global_rps,
                       "burst": burst, "on_429_backoff_ms": 100},
        "roe": {"enabled": True, "enforce_scope": True, "enforce_methods": True},
    }


def test_execute_pattern_hits_live_server(live_server):
    base = live_server["base"]
    pattern = {
        "id": "it-single",
        "steps": [{"name": "probe", "request": {"method": "GET", "url": base + "/api/me"}}],
        "oracles": [],
    }
    ctx = executor.execute_pattern(pattern, {"target_url": base}, base,
                                   engine_config=_engine_cfg())
    assert len(ctx["steps"]) == 1
    step = ctx["steps"][0]
    assert step["status"] == 200
    assert step["error"] is None
    assert json.loads(step["body"])["path"] == "/api/me"


def test_roe_blocks_out_of_scope_host(monkeypatch):
    monkeypatch.setattr(roe_mod, "load_roe", lambda: {
        "enabled": True,
        "scope": {"in_scope": ["127.0.0.1"], "out_of_scope": [],
                  "allowed_methods": ["GET"], "forbidden_paths": []},
    })
    pattern = {
        "id": "it-oos",
        "steps": [{"name": "probe", "request": {"method": "GET",
                   "url": "http://10.0.0.1/secret"}}],
        "oracles": [],
    }
    ctx = executor.execute_pattern(pattern, {}, "http://10.0.0.1",
                                   engine_config=_engine_cfg())
    assert ctx["steps"][0]["error"].startswith("ROE_BLOCK")


def test_global_rate_limiter_is_shared(live_server):
    base = live_server["base"]
    pattern = {
        "id": "it-repeat",
        "steps": [{"name": "r", "repeat": "5",
                   "request": {"method": "GET", "url": base + "/x"}}],
        "oracles": [],
    }
    cfg = _engine_cfg(global_rps=5, burst=1)

    def run():
        executor.execute_pattern(pattern, {}, base, engine_config=cfg)

    t0 = time.monotonic()
    threads = [threading.Thread(target=run) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.monotonic() - t0

    assert len(live_server["server"].hits) == 10
    assert elapsed >= 1.3


def test_race_step_bypasses_rate_limiter(live_server):
    base = live_server["base"]
    pattern = {
        "id": "it-race",
        "steps": [{"name": "burst", "concurrency": "20",
                   "request": {"method": "POST", "url": base + "/cart"}}],
        "oracles": [],
    }
    cfg = _engine_cfg(global_rps=2, burst=1)
    t0 = time.monotonic()
    ctx = executor.execute_pattern(pattern, {}, base, engine_config=cfg)
    elapsed = time.monotonic() - t0

    assert len(ctx["steps"]) == 20
    assert len(live_server["server"].hits) == 20
    assert elapsed < 4.0


def test_real_pattern_through_loader(live_server, temp_ledger):
    base = live_server["base"]
    pattern = loader.load_pattern("security-headers-missing")
    assert pattern is not None
    inputs = {"target_url": base}
    ctx = executor.execute_pattern(pattern, inputs, base, engine_config=_engine_cfg())
    assert ctx["steps"]
    assert ctx["steps"][0]["status"] == 200


def test_sarif_output_is_schema_valid(temp_ledger):
    target = "http://127.0.0.1:8000/api"
    ledger.record_finding(
        pattern_id="laravel-debug-mode", target=target, verdict="VULNERABLE",
        severity="critical", reason="debug page exposed", evidence_path="",
        evidence_json={}, category="content", wstg_id="WSTG-CONF-02", cwe_id="CWE-209")
    ledger.record_finding(
        pattern_id="cors-wildcard", target=target, verdict="SUSPICIOUS",
        severity="high", reason="Access-Control-Allow-Origin: *", evidence_path="",
        evidence_json={}, category="single")

    path = report.generate_sarif(target)
    sarif = json.loads(open(path, encoding="utf-8").read())

    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].endswith("sarif-2.1.0.json")
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "sec-checker"
    assert len(run["results"]) == 2
    assert {r["ruleId"] for r in run["results"]} == {"laravel-debug-mode", "cors-wildcard"}
    for r in run["results"]:
        assert r["level"] in ("error", "warning", "note")
        assert r["message"]["text"]

    try:
        import jsonschema
        schema = json.loads(urllib.request.urlopen(
            "https://json.schemastore.org/sarif-2.1.0.json", timeout=15).read())
    except Exception as e:
        pytest.skip(f"schema unavailable offline: {e}")
    jsonschema.validate(sarif, schema)


def test_fail_on_returns_nonzero_when_threshold_met(live_server, temp_ledger):
    base = live_server["base"]
    code = cli.main(["scan", "security-headers-missing", base, "--fail-on", "medium"])
    assert code == cli.EXIT_FINDINGS


def test_fail_on_returns_zero_below_threshold(live_server, temp_ledger):
    base = live_server["base"]
    code = cli.main(["scan", "security-headers-missing", base, "--fail-on", "critical"])
    assert code == 0


def test_no_fail_on_returns_zero(live_server, temp_ledger):
    base = live_server["base"]
    code = cli.main(["scan", "security-headers-missing", base])
    assert code == 0


def test_unknown_command_returns_one():
    assert cli.main(["definitely-not-a-command"]) == 1


def test_sarif_excludes_pass_findings(temp_ledger):
    target = "http://127.0.0.1:9000/api"
    ledger.record_finding(
        pattern_id="server-disclosure", target=target, verdict="PASS",
        severity="low", reason="clean", evidence_path="", evidence_json={})
    ledger.record_finding(
        pattern_id="cors-wildcard", target=target, verdict="VULNERABLE",
        severity="high", reason="cors *", evidence_path="", evidence_json={})
    path = report.generate_sarif(target)
    sarif = json.loads(open(path, encoding="utf-8").read())
    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "cors-wildcard"
