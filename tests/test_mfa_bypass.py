from engine import mfa_probe
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


def test_success_field_strategy_present():
    names = [n for n, _ov in mfa_probe.BYPASS_STRATEGIES]
    assert "success_field_trust" in names


def test_scan_detects_bypass():
    with Fixture() as fx:
        r = mfa_probe.scan(fx.base_url + "/mfa/verify",
                            base_body={"code": "000000"},
                            authorized=True,
                            roe_guard=_guard())
    assert r["verdict"] == "VULNERABLE", (
        "expected VULNERABLE, got %r / %r"
        % (r["verdict"], r.get("reason")))


def test_scan_unauthorized_returns_unknown():
    with Fixture() as fx:
        r = mfa_probe.scan(fx.base_url + "/mfa/verify",
                            base_body={"code": "000000"},
                            authorized=False,
                            roe_guard=_guard())
    assert r["verdict"] == "UNKNOWN"
