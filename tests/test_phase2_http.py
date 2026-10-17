"""Phase 2 tests: central HTTP client, ROE normalisation, budget."""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT_SRC = Path(__file__).resolve().parent.parent


# ---------- budget ----------
def test_budget_configure_and_record():
    from engine import budget
    budget.configure(max_requests=3, max_per_host=None,
                     max_duration_seconds=None)
    budget.record("http://a.test/x")
    budget.record("http://a.test/y")
    snap = budget.snapshot()
    assert snap["requests"] == 2
    assert snap["per_host"].get("a.test") == 2


def test_budget_exceeded_total():
    from engine import budget
    budget.configure(max_requests=1, max_per_host=None,
                     max_duration_seconds=None)
    budget.record("http://a.test/x")
    with pytest.raises(budget.BudgetExceeded):
        budget.record("http://a.test/y")


def test_budget_exceeded_per_host():
    from engine import budget
    budget.configure(max_requests=None, max_per_host=1,
                     max_duration_seconds=None)
    budget.record("http://a.test/x")
    with pytest.raises(budget.BudgetExceeded):
        budget.record("http://a.test/y")
    budget.record("http://b.test/x")


def test_budget_exceeded_duration():
    from engine import budget
    budget.configure(max_requests=None, max_per_host=None,
                     max_duration_seconds=0.01)
    time.sleep(0.03)
    with pytest.raises(budget.BudgetExceeded):
        budget.record("http://a.test/x")


def test_budget_disable():
    from engine import budget
    budget.configure(max_requests=1)
    budget.disable()
    for _ in range(5):
        budget.record("http://a.test/x")
    budget.enable()


# ---------- ROE normalisation ----------
def _guard(roe_dict, engine_cfg=None):
    from engine.roe_guard import ROEGuard
    return ROEGuard(roe=roe_dict, engine_cfg=engine_cfg or {})


def test_roe_normalizes_dot_segments():
    from engine.roe_guard import ROEViolation
    g = _guard({
        "enabled": True,
        "scope": {"in_scope": ["site.test"], "out_of_scope": [],
                  "allowed_methods": ["GET"], "forbidden_paths": ["/admin"]},
    })
    with pytest.raises(ROEViolation):
        g.check_url("http://site.test/foo/../admin", "GET")


def test_roe_normalizes_encoded_slash():
    from engine.roe_guard import ROEViolation
    g = _guard({
        "enabled": True,
        "scope": {"in_scope": ["site.test"], "out_of_scope": [],
                  "allowed_methods": ["GET"], "forbidden_paths": ["/admin"]},
    })
    with pytest.raises(ROEViolation):
        g.check_url("http://site.test/%2fadmin", "GET")


def test_roe_normalizes_double_slash():
    from engine.roe_guard import ROEViolation
    g = _guard({
        "enabled": True,
        "scope": {"in_scope": ["site.test"], "out_of_scope": [],
                  "allowed_methods": ["GET"], "forbidden_paths": ["/admin"]},
    })
    with pytest.raises(ROEViolation):
        g.check_url("http://site.test//admin", "GET")


def test_roe_allows_safe_path():
    g = _guard({
        "enabled": True,
        "scope": {"in_scope": ["site.test"], "out_of_scope": [],
                  "allowed_methods": ["GET"], "forbidden_paths": ["/admin"]},
    })
    assert g.check_url("http://site.test/api/users", "GET") is True


def test_roe_time_window_closed(monkeypatch):
    from datetime import datetime as _dt, timezone as _tz
    from engine import roe_guard as _rg
    from engine.roe_guard import ROEViolation

    monkeypatch.setattr(
        _rg, "_utc_now",
        lambda: _dt(2026, 1, 1, 12, 0, 0, tzinfo=_tz.utc),
    )

    g = _guard({
        "enabled": True,
        "scope": {"in_scope": ["site.test"], "out_of_scope": [],
                  "allowed_methods": ["GET"], "forbidden_paths": []},
        "time_window": {"enabled": True, "start": "03:00",
                          "end": "03:01"},
    })
    with pytest.raises(ROEViolation, match="TIME WINDOW"):
        g.check_url("http://site.test/", "GET")


def test_roe_time_window_open(monkeypatch):
    from datetime import datetime as _dt, timezone as _tz
    from engine import roe_guard as _rg

    monkeypatch.setattr(
        _rg, "_utc_now",
        lambda: _dt(2026, 1, 1, 12, 0, 0, tzinfo=_tz.utc),
    )

    g = _guard({
        "enabled": True,
        "scope": {"in_scope": ["site.test"], "out_of_scope": [],
                  "allowed_methods": ["GET"], "forbidden_paths": []},
        "time_window": {"enabled": True, "start": "00:00",
                          "end": "23:59"},
    })
    assert g.check_url("http://site.test/", "GET") is True


# ---------- central HTTP client ----------
class _Echo(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self.do_GET()

    def log_message(self, *a):
        pass


@pytest.fixture
def permissive_roe(monkeypatch):
    from engine import roe_guard as roe_mod
    monkeypatch.setattr(roe_mod, "load_roe", lambda: {
        "enabled": True,
        "scope": {
            "in_scope": ["127.0.0.1"],
            "out_of_scope": [],
            "allowed_methods": ["GET", "POST"],
            "forbidden_paths": [],
        },
    })


@pytest.fixture
def echo_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Echo)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _, port = srv.server_address
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        srv.shutdown()
        srv.server_close()


def test_http_client_returns_response(permissive_roe, echo_server):
    from engine import budget
    budget.configure(max_requests=100)
    from engine import http as _http
    with _http.Client(timeout=5) as c:
        r = c.get(echo_server + "/api/x")
    assert r.status_code == 200
    assert json.loads(r.text)["path"] == "/api/x"


def test_http_client_counts_budget(permissive_roe, echo_server):
    from engine import budget
    budget.configure(max_requests=100)
    from engine import http as _http
    with _http.Client(timeout=5) as c:
        c.get(echo_server + "/a")
        c.get(echo_server + "/b")
    assert budget.snapshot()["requests"] == 2


def test_http_client_respects_roe(permissive_roe, echo_server):
    from engine import budget
    budget.configure(max_requests=100)
    from engine import http as _http
    with _http.Client(timeout=5) as c:
        with pytest.raises(_http.ROEBlock):
            c.get("http://evil.example.com/secret")


def test_http_client_budget_exceeded(permissive_roe, echo_server):
    from engine import budget
    budget.configure(max_requests=1)
    from engine import http as _http
    with _http.Client(timeout=5) as c:
        c.get(echo_server + "/a")
        with pytest.raises(budget.BudgetExceeded):
            c.get(echo_server + "/b")
    budget.configure(max_requests=100)


def test_http_client_redirect_same_origin(permissive_roe):
    from engine import budget
    budget.configure(max_requests=100)

    class _Redir(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/redir":
                self.send_response(302)
                self.send_header("Location", "/target")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = b"arrived"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Redir)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _, port = srv.server_address
    from engine import http as _http
    try:
        with _http.Client(timeout=5, follow_redirects=True) as c:
            r = c.get(f"http://127.0.0.1:{port}/redir")
        assert r.status_code == 200
        assert r.text == "arrived"
    finally:
        srv.shutdown()
        srv.server_close()


# ---------- leaf migration sanity ----------
# Every external, non-target service call routes through
# engine/external_http.py: shared external rate limiter + per-host
# circuit breaker + TLS from config, no target budget consumed.
#
# engine/http.py, engine/http_client.py, and engine/external_http.py
# are excluded by the loop below: they are the three wrappers and are
# the one legitimate place where httpx.Client(...) may appear.
# engine/http_async.py uses httpx.AsyncClient, which this check does
# not match.
#
# If a new module needs to talk to a non-target external service, add
# it to the wrapper rather than re-adding an entry here.
ALLOWED_RAW_HTTPX = set()


def test_no_leaf_module_calls_raw_httpx_client():
    """No migrated leaf module should still call httpx.Client(...)."""
    root = ROOT_SRC / "engine"
    offenders = []
    for p in root.rglob("*.py"):
        if p.name in ("http.py", "http_client.py",
                       "external_http.py"):
            continue
        rel = str(p.relative_to(ROOT_SRC)).replace("\\", "/")
        if rel in ALLOWED_RAW_HTTPX:
            continue
        text = p.read_text(encoding="utf-8")
        if "httpx.Client(" in text:
            offenders.append(rel)
    assert not offenders, f"raw httpx.Client still used in: {offenders}"


# ---------- scope.py wrapper ----------
def test_scope_broadness_detects_broad():
    import importlib
    import scope as scope_mod
    importlib.reload(scope_mod)
    is_broad, _why = scope_mod._broadness("*")
    assert is_broad
    is_broad, _why = scope_mod._broadness("*.com")
    assert is_broad
    is_broad, _why = scope_mod._broadness("10.*")
    assert is_broad


def test_scope_broadness_allows_narrow():
    import importlib
    import scope as scope_mod
    importlib.reload(scope_mod)
    is_broad, _why = scope_mod._broadness("localhost")
    assert not is_broad
    is_broad, _why = scope_mod._broadness("*.staging.example.com")
    assert not is_broad
