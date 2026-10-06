import itertools
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from engine import combo
from engine import roe_guard as roe_mod


def test_cartesian_product():
    dims = {"method": ["GET", "POST"], "path": ["/a", "/b"]}
    out = combo.cartesian(dims)
    assert len(out) == 4
    assert {"method": "GET", "path": "/a"} in out


def test_pairwise_covers_all_pairs():
    dims = {"method": ["GET", "POST"], "path": ["/a", "/b", "/c"],
            "header:X": ["0", "1"]}
    combos = combo.pairwise(dims)
    keys = list(dims.keys())
    required = set()
    for a, b in itertools.combinations(keys, 2):
        for va in dims[a]:
            for vb in dims[b]:
                required.add(((a, va), (b, vb)))
    covered = set()
    for c in combos:
        items = [(k, c[k]) for k in keys]
        covered |= set(itertools.combinations(items, 2))
    assert required <= covered
    assert len(combos) < len(combo.cartesian(dims))


def test_pairwise_single_dimension():
    assert combo.pairwise({"method": ["GET", "POST"]}) == \
        combo.cartesian({"method": ["GET", "POST"]})


def test_build_request_maps_dimensions():
    method, url, headers, params = combo.build_request(
        {"method": "POST", "path": "/x", "header:A": "1", "param:q": "z"},
        "http://t")
    assert method == "POST"
    assert url == "http://t/x"
    assert headers == {"A": "1"}
    assert params == {"q": "z"}


def test_analyze_flags_outlier():
    results = [{"combo": {"path": "/a"}, "status": 401, "body_hash": "x"}
               for _ in range(5)]
    results.append({"combo": {"path": "/admin"}, "status": 200, "body_hash": "y"})
    r = combo.analyze(results)
    assert r["verdict"] == "SUSPICIOUS"
    assert r["evidence"]["outliers"][0]["status"] == 200


def test_analyze_uniform_pass():
    results = [{"combo": {}, "status": 401, "body_hash": "x"} for _ in range(5)]
    assert combo.analyze(results)["verdict"] == "PASS"


class _AccessHandler(BaseHTTPRequestHandler):
    def _h(self):
        code = 200 if self.path.startswith("/public") else 401
        body = b"{}"
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _h
    do_POST = _h

    def log_message(self, *a):
        pass


@pytest.fixture(autouse=True)
def permissive_roe(monkeypatch):
    monkeypatch.setattr(roe_mod, "load_roe", lambda: {
        "enabled": True,
        "scope": {"in_scope": ["127.0.0.1"], "out_of_scope": [],
                  "allowed_methods": ["GET", "POST"], "forbidden_paths": []},
    })


def test_explore_live_finds_outlier():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _AccessHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _, port = srv.server_address
    base = f"http://127.0.0.1:{port}"
    cfg = {"http": {"timeout_seconds": 10},
           "rate_limit": {"global_rps": 100, "per_endpoint_rps": 100, "burst": 100},
           "roe": {"enabled": True}}
    dims = {"method": ["GET", "POST"],
            "path": ["/admin", "/orders", "/users", "/public"]}
    try:
        out = combo.explore(base, dims, strategy="cartesian", engine_cfg=cfg)
    finally:
        srv.shutdown(); srv.server_close()
    assert out["combos_run"] == 8
    assert out["analysis"]["verdict"] == "SUSPICIOUS"
    assert any(o["status"] == 200 for o in out["analysis"]["evidence"]["outliers"])
