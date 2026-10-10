from engine import roe_guard as roe_mod


def test_module_imports():
    from engine import http2_probe
    assert http2_probe is not None
    assert hasattr(http2_probe, "scan")


def test_scan_returns_scanresult():
    from engine import http2_probe
    from engine.contract import ScanResult
    r = http2_probe.scan("http://127.0.0.1:1")
    assert isinstance(r, ScanResult)
    assert r.capability == "http2_scan"


def test_h2_library_detected():
    from engine import http2_probe
    assert isinstance(http2_probe.HAS_H2, bool)


def test_h2_probe_error_on_unreachable():
    from engine import http2_probe
    r = http2_probe._probe_h2("http://127.0.0.1:1", timeout=1)
    assert r["ok"] is False
    assert r.get("error")
