from engine.injection import password_reset
from engine.roe_guard import ROEGuard
from tests.testapp.auth_fixture import Fixture


def _guard():
    return ROEGuard(
        roe={"enabled": True, "scope": {
            "in_scope": ["127.0.0.1"],
            "out_of_scope": [],
            "allowed_methods": ["GET", "POST"],
            "forbidden_paths": [],
        }},
        engine_cfg={"roe": {"enforce_scope": True,
                             "enforce_methods": True}},
    )


def test_host_injection_detected():
    with Fixture() as fx:
        r = password_reset.scan(fx.base_url, email="x@example.com",
                                 roe_guard=_guard())
    assert r["verdict"] == "VULNERABLE", (
        "expected VULNERABLE, got %r / %r"
        % (r["verdict"], r.get("reason")))


def test_referer_in_headers():
    hnames = [h.lower() for h, _v in password_reset.INJECT_HEADERS]
    assert "referer" in hnames


def test_extended_headers_present():
    hnames = [h.lower() for h, _v in password_reset.INJECT_HEADERS]
    assert "host" in hnames
    assert "x-forwarded-host" in hnames
    assert any("forwarded" in h for h in hnames)


def test_scan_unknown_target():
    r = password_reset.scan("http://127.0.0.1:1/", email="x@example.com",
                             roe_guard=_guard())
    assert r["verdict"] in ("PASS", "UNKNOWN")
