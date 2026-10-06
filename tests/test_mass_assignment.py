import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from engine import oracle, executor
from engine import roe_guard as roe_mod


def _ctx(body):
    return {"steps": [{"step_name": "inject", "body": body, "headers": {}}],
            "inputs": {}, "target": "http://t"}


def test_oracle_detects_reflected_privileged_field():
    body = json.dumps({"id": 1, "name": "x", "is_admin": True})
    r = oracle.evaluate({"type": "mass_assignment"}, _ctx(body))
    assert r["verdict"] == "VULNERABLE"
    assert any(h["field"] == "is_admin" for h in r["evidence"]["reflected"])


def test_oracle_pass_when_stripped():
    body = json.dumps({"id": 1, "name": "x", "is_admin": False, "role": "user"})
    r = oracle.evaluate({"type": "mass_assignment"}, _ctx(body))
    assert r["verdict"] == "PASS"


def test_oracle_custom_injected_fields():
    body = json.dumps({"account_type": "premium"})
    r = oracle.evaluate({"type": "mass_assignment",
                         "injected": {"account_type": "premium"}}, _ctx(body))
    assert r["verdict"] == "VULNERABLE"


def test_oracle_non_json_pass():
    r = oracle.evaluate({"type": "mass_assignment"}, _ctx("<html>not json</html>"))
    assert r["verdict"] == "PASS"


class _EchoHandler(BaseHTTPRequestHandler):
    strip = False

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw)
        except Exception:
            data = {}
        if self.strip:
            data = {k: v for k, v in data.items()
                    if k not in ("is_admin", "role", "is_superuser", "admin", "verified")}
        data["id"] = 101
        body = json.dumps(data).encode()
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class _VulnEcho(_EchoHandler):
    strip = False


class _SafeEcho(_EchoHandler):
    strip = True


@pytest.fixture(autouse=True)
def permissive_roe(monkeypatch):
    monkeypatch.setattr(roe_mod, "load_roe", lambda: {
        "enabled": True,
        "scope": {"in_scope": ["127.0.0.1"], "out_of_scope": [],
                  "allowed_methods": ["POST"], "forbidden_paths": []},
    })


def _cfg():
    return {"http": {"timeout_seconds": 10, "max_retries": 1},
            "rate_limit": {"global_rps": 50, "per_endpoint_rps": 50, "burst": 50},
            "roe": {"enabled": True}}


def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _run_pattern_against(base):
    from engine import loader
    pattern = loader.load_pattern("mass-assignment")
    ctx = executor.execute_pattern(pattern, {"target_url": base}, base,
                                   engine_config=_cfg())
    return oracle.evaluate(pattern["oracles"][0], ctx)


def test_live_vulnerable_echo():
    srv = _serve(_VulnEcho)
    _, port = srv.server_address
    try:
        r = _run_pattern_against(f"http://127.0.0.1:{port}/api/users")
    finally:
        srv.shutdown(); srv.server_close()
    assert r["verdict"] == "VULNERABLE"


def test_live_safe_echo():
    srv = _serve(_SafeEcho)
    _, port = srv.server_address
    try:
        r = _run_pattern_against(f"http://127.0.0.1:{port}/api/users")
    finally:
        srv.shutdown(); srv.server_close()
    assert r["verdict"] == "PASS"
