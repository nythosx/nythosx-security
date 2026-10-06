import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from engine import idor
from engine import roe_guard as roe_mod


def test_extract_ids_nested():
    body = json.dumps({"data": {"id": 5, "profile": {"user_id": "77"}},
                       "items": [{"account_id": 9}]})
    ids = dict(idor.extract_ids(body))
    assert ids["id"] == 5
    assert ids["user_id"] == "77"
    assert ids["account_id"] == 9


def test_extract_ids_bad_json():
    assert idor.extract_ids("not json") == []


def test_neighbor_ids():
    assert idor.neighbor_ids(5) == [4, 6]
    assert idor.neighbor_ids("1") == [2]          # no 0
    assert idor.neighbor_ids("abc") == []


def test_analyze_vulnerable():
    self_p = {"id": 5, "status": 200, "body_hash": "aaa", "body": "me"}
    neighbors = [{"id": 4, "status": 200, "body_hash": "bbb", "body": "alice"},
                 {"id": 6, "status": 404, "body_hash": "ccc", "body": "nope"}]
    r = idor.analyze(self_p, neighbors)
    assert r["verdict"] == "VULNERABLE"
    assert r["evidence"]["offender_ids"] == [4]


def test_analyze_suspicious_identical_body():
    self_p = {"id": 5, "status": 200, "body_hash": "aaa", "body": "me"}
    neighbors = [{"id": 4, "status": 200, "body_hash": "aaa", "body": "me"}]
    r = idor.analyze(self_p, neighbors)
    assert r["verdict"] == "SUSPICIOUS"


def test_analyze_pass():
    self_p = {"id": 5, "status": 200, "body_hash": "aaa", "body": "me"}
    neighbors = [{"id": 4, "status": 403, "body_hash": "x", "body": "denied"},
                 {"id": 6, "status": 404, "body_hash": "y", "body": "none"}]
    r = idor.analyze(self_p, neighbors)
    assert r["verdict"] == "PASS"


class _VulnHandler(BaseHTTPRequestHandler):
    users = {4: {"id": 4, "name": "alice"}, 5: {"id": 5, "name": "me"},
             6: {"id": 6, "name": "bob"}}

    def do_GET(self):
        if self.path == "/api/me":
            return self._json(self.users[5])
        if self.path.startswith("/api/users/"):
            uid = int(self.path.rsplit("/", 1)[1])
            if uid in self.users:
                return self._json(self.users[uid])
            return self._json({"error": "not found"}, 404)
        self._json({}, 404)

    def _json(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class _SafeHandler(_VulnHandler):
    def do_GET(self):
        if self.path == "/api/me":
            return self._json(self.users[5])
        if self.path.startswith("/api/users/"):
            uid = int(self.path.rsplit("/", 1)[1])
            if uid == 5:
                return self._json(self.users[5])
            return self._json({"error": "forbidden"}, 403)
        self._json({}, 404)


@pytest.fixture(autouse=True)
def permissive_roe(monkeypatch):
    monkeypatch.setattr(roe_mod, "load_roe", lambda: {
        "enabled": True,
        "scope": {"in_scope": ["127.0.0.1"], "out_of_scope": [],
                  "allowed_methods": ["GET"], "forbidden_paths": []},
    })


def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_live_probe_detects_idor():
    srv = _serve(_VulnHandler)
    _, port = srv.server_address
    base = f"http://127.0.0.1:{port}"
    try:
        out = idor.run_probe(f"{base}/api/me", f"{base}/api/users")
    finally:
        srv.shutdown(); srv.server_close()
    assert out["result"]["verdict"] == "VULNERABLE"
    assert set(out["result"]["evidence"]["offender_ids"]) <= {4, 6}


def test_live_probe_safe_endpoint():
    srv = _serve(_SafeHandler)
    _, port = srv.server_address
    base = f"http://127.0.0.1:{port}"
    try:
        out = idor.run_probe(f"{base}/api/me", f"{base}/api/users")
    finally:
        srv.shutdown(); srv.server_close()
    assert out["result"]["verdict"] == "PASS"
