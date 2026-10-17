import pytest

try:
    import h2.connection  # noqa: F401
    HAS_H2 = True
except ImportError:
    HAS_H2 = False

from engine import h2_t2
from tests.testapp.desync_fixture import H2Fixture


def test_probe_variants_shape():
    variants = h2_t2._probe_h2_desync_variants()
    ids = [v["id"] for v in variants]
    assert "cl_zero" in ids
    assert "path_crlf" in ids
    assert "te_cl" in ids


def test_probe_variants_have_probe_fn():
    for v in h2_t2._probe_h2_desync_variants():
        assert callable(v["probe_fn"])


def test_host_path_helper():
    authority, path, scheme = h2_t2._host_path("http://127.0.0.1:8080/foo?x=1")
    assert authority == "127.0.0.1:8080"
    assert path == "/foo?x=1"
    assert scheme == "http"


# CL:0 + body is a protocol violation rejected by h2 both client-
# and server-side. A compliant h2 fixture cannot simulate a
# non-compliant server. probe_cl_zero is covered by mocked tests
# below that verify its decision logic against canned statuses.
@pytest.mark.skip(
    reason="h2 library rejects CL:0+body on both client and server; "
           "a compliant h2 fixture cannot simulate a non-compliant "
           "server. Decision logic covered by mocked tests below.")
def test_cl_zero_strict():
    pass


@pytest.mark.skip(reason="same fixture limitation as test_cl_zero_strict")
def test_cl_zero_lenient():
    pass


def test_probe_cl_zero_200_mocked(monkeypatch):
    def fake_send(url, headers, body, timeout=6, roe_guard=None):
        return {"ok": True, "status": 200, "body_len": 5}
    monkeypatch.setattr(h2_t2, "_h2_send", fake_send)
    r = h2_t2.probe_cl_zero("http://127.0.0.1/x")
    assert r["verdict"] == "SUSPICIOUS", r
    assert r["evidence"]["status"] == 200


def test_probe_cl_zero_400_mocked(monkeypatch):
    def fake_send(url, headers, body, timeout=6, roe_guard=None):
        return {"ok": True, "status": 400, "body_len": 5}
    monkeypatch.setattr(h2_t2, "_h2_send", fake_send)
    r = h2_t2.probe_cl_zero("http://127.0.0.1/x")
    assert r["verdict"] == "PASS", r
    assert r["evidence"]["status"] == 400


def test_probe_cl_zero_unreachable_mocked(monkeypatch):
    def fake_send(url, headers, body, timeout=6, roe_guard=None):
        return {"ok": False, "error": "connection refused"}
    monkeypatch.setattr(h2_t2, "_h2_send", fake_send)
    r = h2_t2.probe_cl_zero("http://127.0.0.1/x")
    assert r["verdict"] == "UNKNOWN", r


@pytest.mark.skipif(not HAS_H2, reason="h2 library not installed")
def test_path_crlf_strict():
    with H2Fixture() as fx:
        r = h2_t2.probe_path_crlf(fx.base_url + "/h2/strict", timeout=3)
    assert r["verdict"] == "PASS", r


@pytest.mark.skipif(not HAS_H2, reason="h2 library not installed")
def test_path_crlf_lenient():
    with H2Fixture() as fx:
        r = h2_t2.probe_path_crlf(fx.base_url + "/h2/lenient", timeout=3)
    assert r["verdict"] == "VULNERABLE", r


@pytest.mark.skipif(not HAS_H2, reason="h2 library not installed")
def test_scan_lenient_returns_vulnerable():
    with H2Fixture() as fx:
        r = h2_t2.scan(fx.base_url + "/h2/lenient", timeout=3)
    assert r["verdict"] == "VULNERABLE", r
    assert r.get("h2_desync") is True


@pytest.mark.skipif(not HAS_H2, reason="h2 library not installed")
def test_scan_strict_returns_pass():
    with H2Fixture() as fx:
        r = h2_t2.scan(fx.base_url + "/h2/strict", timeout=3)
    assert r["verdict"] == "PASS", r
    assert r.get("h2_desync") is False
