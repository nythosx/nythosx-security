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
                  "allowed_methods": ["POST"], "forbidden_paths": []},
    })


class _NestedErrorEcho(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        self.rfile.read(n)
        body = json.dumps({
            "data": {"error": "out of stock"},
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_nested_error_not_success():
    from engine import bizlogic
    r = {"status": 200, "body": '{"data": {"error": "out of stock"}}'}
    assert not bizlogic._looks_like_success(r)


def test_deeply_nested_error_not_success():
    from engine import bizlogic
    r = {"status": 200, "body": '{"a": {"b": {"c": {"errors": ["x"]}}}}'}
    assert not bizlogic._looks_like_success(r)


def test_false_success_flag_not_success():
    from engine import bizlogic
    r = {"status": 200, "body": '{"success": false}'}
    assert not bizlogic._looks_like_success(r)


def test_clean_response_still_success():
    from engine import bizlogic
    r = {"status": 200, "body": '{"order_id": 1, "total": 100}'}
    assert bizlogic._looks_like_success(r)


def test_nested_error_server_not_marked_success():
    from engine import bizlogic
    srv = _serve(_NestedErrorEcho)
    _, port = srv.server_address
    try:
        out = bizlogic.probe_price_tampering(
            f"http://127.0.0.1:{port}/checkout",
            baseline_body={"price": 100, "qty": 1},
        )
    finally:
        srv.shutdown(); srv.server_close()
    assert out["verdict"] in ("PASS", "UNKNOWN")
