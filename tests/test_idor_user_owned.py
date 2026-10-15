import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from engine import roe_guard as roe_mod


@pytest.fixture(autouse=True)
def permissive_roe(monkeypatch):
    monkeypatch.setattr(roe_mod, "load_roe", lambda: {
        "enabled": True,
        "scope": {"in_scope": ["127.0.0.1"], "out_of_scope": [],
                  "allowed_methods": ["GET"], "forbidden_paths": []},
    })


class _PublicCatalog(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'[{"id": 1, "title": "p1"}, {"id": 2, "title": "p2"}]'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class _UserOwnedList(BaseHTTPRequestHandler):
    def do_GET(self):
        m = re.search(r"/(\d+)/?$", self.path)
        oid = int(m.group(1)) if m else 1
        obj = {"id": oid, "owner_id": 42 + oid, "total": 100 * oid}
        body = json.dumps([obj]).encode()
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


def test_public_catalog_not_enumerable():
    from engine import idor_sweep
    srv = _serve(_PublicCatalog)
    _, port = srv.server_address
    try:
        r = idor_sweep.scan_endpoint(f"http://127.0.0.1:{port}",
                                       "/api/products", ids=(1, 2, 3))
    finally:
        srv.shutdown(); srv.server_close()
    assert not r["summary"]["enumerable_unauth"]
    assert r["summary"]["category"] in ("content", "unknown", "by_design")


def test_user_owned_list_enumerable():
    from engine import idor_sweep
    srv = _serve(_UserOwnedList)
    _, port = srv.server_address
    try:
        r = idor_sweep.scan_endpoint(f"http://127.0.0.1:{port}",
                                       "/api/orders", ids=(1, 2, 3))
    finally:
        srv.shutdown(); srv.server_close()
    assert r["summary"]["enumerable_unauth"]


def test_path_noun_alone_is_enough():
    from engine import idor_sweep
    assert idor_sweep._is_user_owned("/api/orders", set())


def test_field_alone_is_enough():
    from engine import idor_sweep
    assert idor_sweep._is_user_owned("/api/things", ["owner_id"])


def test_neither_is_not_user_owned():
    from engine import idor_sweep
    assert not idor_sweep._is_user_owned("/api/products", ["title", "price"])
