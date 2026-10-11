from engine.oauth import flow_probe


def test_module_imports():
    assert flow_probe is not None
    assert hasattr(flow_probe, "scan")


def test_capability_defined():
    assert flow_probe.CAPABILITY.name == "oauth_flow_probe"


def test_scan_returns_scanresult():
    from engine.contract import ScanResult
    result = flow_probe.scan("http://127.0.0.1:1/oauth/authorize")
    assert isinstance(result, ScanResult)
    assert result["verdict"] in ("PASS", "UNKNOWN", "SUSPICIOUS", "VULNERABLE")
