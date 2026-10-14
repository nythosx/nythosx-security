import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from engine import graphql_schema
from engine import roe_guard as roe_mod


@pytest.fixture(autouse=True)
def permissive_roe(monkeypatch):
    monkeypatch.setattr(roe_mod, "load_roe", lambda: {
        "enabled": True,
        "scope": {"in_scope": ["127.0.0.1"], "out_of_scope": [],
                  "allowed_methods": ["GET", "POST"], "forbidden_paths": []},
    })


_FIELDS = {
    "me": True, "user": True, "users": True,
    "orders": True, "products": True, "cart": True,
}

_FIELD_RE = re.compile(
    r"\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\{\s*__typename")


class _SuggestServer(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            body = {}
        query = body.get("query", "")

        if query.strip() == "{ __typename }":
            response = {"data": {"__typename": "Query"}}
        else:
            m = _FIELD_RE.search(query)
            if not m:
                response = {"errors": [{"message": "syntax error"}]}
            else:
                field = m.group(1)
                if _FIELDS.get(field):
                    response = {"data": {field: {"__typename": "Node"}}}
                else:
                    suggestion = None
                    for known in _FIELDS:
                        if known.startswith(field[:2]):
                            suggestion = known
                            break
                    msg = 'Cannot query field "' + field + '".'
                    if suggestion:
                        msg = msg + ' Did you mean "' + suggestion + '"?'
                    response = {"errors": [{"message": msg}]}

        body_bytes = json.dumps(response).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)

    def log_message(self, *a):
        pass


class _NonGraphqlServer(BaseHTTPRequestHandler):
    def do_POST(self):
        body = b'{"ok":true}'
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


def test_module_imports():
    assert graphql_schema.CAPABILITY.name == "graphql_schema_walk"


def test_suggestion_extraction():
    body = json.dumps({"errors": [
        {"message": 'Cannot query field "usr". Did you mean "user"?'}]})
    assert graphql_schema._extract_suggestion(body) == "user"


def test_discover_finds_seed_fields():
    srv = _serve(_SuggestServer)
    _, port = srv.server_address
    try:
        r = graphql_schema.discover_fields(
            f"http://127.0.0.1:{port}/graphql",
            max_fields=10, max_probes=50)
    finally:
        srv.shutdown(); srv.server_close()
    fields = set(r["discovered_fields"])
    assert "me" in fields
    assert "users" in fields


def test_scan_returns_scanresult():
    srv = _serve(_SuggestServer)
    _, port = srv.server_address
    try:
        r = graphql_schema.scan(f"http://127.0.0.1:{port}/graphql",
                                max_fields=20, max_probes=60)
    finally:
        srv.shutdown(); srv.server_close()
    assert r["verdict"] in ("SUSPICIOUS", "PASS", "VULNERABLE")


def test_non_graphql_passes_or_unknown():
    srv = _serve(_NonGraphqlServer)
    _, port = srv.server_address
    try:
        r = graphql_schema.scan(f"http://127.0.0.1:{port}/api",
                                max_fields=5, max_probes=5)
    finally:
        srv.shutdown(); srv.server_close()
    assert r["verdict"] in ("UNKNOWN", "PASS")


def test_roe_block(monkeypatch):
    monkeypatch.setattr(roe_mod, "load_roe", lambda: {
        "enabled": True,
        "scope": {"in_scope": ["10.0.0.1"], "out_of_scope": [],
                  "allowed_methods": ["GET", "POST"], "forbidden_paths": []},
    })
    r = graphql_schema.scan("http://127.0.0.1:1/graphql")
    assert r["verdict"] == "UNKNOWN"
    assert "ROE_BLOCK" in r.reason
