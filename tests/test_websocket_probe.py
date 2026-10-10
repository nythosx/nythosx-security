import pytest

from engine import roe_guard as roe_mod


@pytest.fixture(autouse=True)
def permissive_roe(monkeypatch):
    monkeypatch.setattr(roe_mod, "load_roe", lambda: {
        "enabled": True,
        "scope": {"in_scope": ["127.0.0.1"], "out_of_scope": [],
                  "allowed_methods": ["GET", "POST"], "forbidden_paths": []},
    })


def test_module_imports():
    from engine import websocket_probe
    assert websocket_probe is not None
    assert hasattr(websocket_probe, "scan")


def test_scan_returns_scanresult():
    from engine import websocket_probe
    from engine.contract import ScanResult
    r = websocket_probe.scan("http://127.0.0.1:1")
    assert isinstance(r, ScanResult)
    assert r.capability == "websocket_scan"


def test_ws_url_conversion():
    from engine import websocket_probe
    assert websocket_probe._ws_url("http://a/b") == "ws://a/b"
    assert websocket_probe._ws_url("https://a/b") == "wss://a/b"
