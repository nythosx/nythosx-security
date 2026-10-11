from engine import confirm


def test_module_imports():
    assert confirm is not None
    assert hasattr(confirm, "confirm")


def test_unknown_capability_returns_false():
    r = confirm.confirm("nonexistent_cap", {}, {})
    assert r["confirmed"] is False
    assert "no confirmation" in r["reason"]


def test_no_capability_returns_false():
    r = confirm.confirm(None, {}, {})
    assert r["confirmed"] is False


def test_dispatch_table_has_handlers():
    assert "auth_bypass" in confirm._DISPATCH
    assert "sqli_scan" in confirm._DISPATCH
    assert "idor_scan" in confirm._DISPATCH
    assert "ssrf_scan" in confirm._DISPATCH


def test_confirm_handles_exception_gracefully(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("network")
    monkeypatch.setitem(confirm._DISPATCH, "auth_bypass", boom)
    r = confirm.confirm("auth_bypass", {}, {"target": "http://x"})
    assert r["confirmed"] is False
