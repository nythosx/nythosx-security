from engine import http2_desync


def test_module_imports():
    assert http2_desync is not None
    assert hasattr(http2_desync, "scan")


def test_scan_returns_scanresult():
    from engine.contract import ScanResult
    result = http2_desync.scan("http://127.0.0.1:1/")
    assert isinstance(result, ScanResult)
    assert result.capability == "http2_desync_scan"


def test_h2_detected():
    assert isinstance(http2_desync.HAS_H2, bool)
