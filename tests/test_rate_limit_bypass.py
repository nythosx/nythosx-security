from engine import rate_limit_bypass
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
                             "enforce_methods": True,
                             "enforce_rate_limit": False}},
    )


def test_ipv6_helper_present():
    assert hasattr(rate_limit_bypass, "_fake_ipv6")


def test_fake_ipv6_format():
    v = rate_limit_bypass._fake_ipv6(3)
    assert "::ffff:" in v
    assert v.count(":") >= 2


def test_parallelism_probe_present():
    assert hasattr(rate_limit_bypass, "_parallelism_probe")


def test_bypass_detected_with_rotated_xff():
    with Fixture() as fx:
        r = rate_limit_bypass.test_bypass(
            fx.base_url + "/rate-limited",
            roe_guard=_guard(), count=15)
    assert r["verdict"] == "VULNERABLE", (
        "expected VULNERABLE, got %r / %r"
        % (r["verdict"], r.get("reason")))


def test_parallelism_probe_verdict_shape():
    with Fixture() as fx:
        r = rate_limit_bypass._parallelism_probe(
            fx.base_url + "/rate-limited",
            roe_guard=_guard(), timeout=5, count=10)
    assert "verdict" in r
    assert r["verdict"] in ("VULNERABLE", "PASS", "UNKNOWN")
    assert "evidence" in r
