from engine.desync import tunnel
from tests.testapp.desync_fixture import DesyncFixture


def test_build_cl_te_produces_valid_prefix():
    prefix, smuggled, marker_b = tunnel._build_cl_te(
        "http://127.0.0.1:9999/x", "/admin", "marker1")
    assert prefix.startswith(b"POST /x HTTP/1.1\r\n")
    assert b"Transfer-Encoding: chunked" in prefix
    assert b"Content-Length:" in prefix
    assert b"0\r\n\r\n" in prefix
    assert smuggled.startswith(b"GET /admin HTTP/1.1")
    assert marker_b == b"marker1"
    assert b"marker1" in prefix


def test_build_te_cl_produces_valid_prefix():
    prefix, smuggled, marker_b = tunnel._build_te_cl(
        "http://127.0.0.1:9999/x", "/admin", "marker2")
    assert b"Transfer-Encoding: chunked" in prefix
    assert b"Content-Length:" in prefix
    assert smuggled.startswith(b"GET /admin HTTP/1.1")
    assert b"marker2" in prefix


def test_split_responses_parses_two():
    raw = (
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nABCD"
    )
    responses = tunnel._split_responses(raw)
    assert len(responses) == 2
    assert responses[0][1] == b"OK"
    assert responses[1][1] == b"ABCD"


def test_split_responses_partial_body():
    raw = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nOK"
    responses = tunnel._split_responses(raw)
    assert len(responses) == 1
    assert responses[0][1] == b"OK"


def test_tunnel_vulnerable_fixture():
    with DesyncFixture() as fx:
        r = tunnel.tunnel_to_path(
            fx.base_url + "/tunnel/vulnerable",
            "/admin", timeout=3)
    assert r["verdict"] == "VULNERABLE", r
    assert r.get("tunnel_confirmed") is True
    attempts = r["evidence"]["attempts"]
    assert any(a.get("smuggled_detected") for a in attempts)


def test_tunnel_clean_fixture():
    with DesyncFixture() as fx:
        r = tunnel.tunnel_to_path(
            fx.base_url + "/tunnel/clean",
            "/admin", timeout=3)
    assert r["verdict"] == "PASS", r
    assert r.get("tunnel_confirmed") is False


def test_tunnel_roe_blocked():
    from engine.roe_guard import ROEGuard
    guard = ROEGuard(
        roe={"enabled": True, "scope": {
            "in_scope": ["example.invalid"],
            "out_of_scope": [],
            "allowed_methods": ["GET", "POST"],
            "forbidden_paths": [],
        }},
        engine_cfg={"roe": {"enforce_scope": True,
                             "enforce_methods": True}},
    )
    with DesyncFixture() as fx:
        r = tunnel.tunnel_to_path(
            fx.base_url + "/tunnel/vulnerable",
            "/admin", timeout=3, roe_guard=guard)
    assert r["verdict"] == "UNKNOWN", r
    assert "ROE" in r.get("reason", "").upper()
