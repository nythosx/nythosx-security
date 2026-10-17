from engine.injection import sqli
from engine.roe_guard import ROEGuard
from tests.testapp.sqli_fixture import Fixture


def _guard():
    roe = {
        "enabled": True,
        "scope": {
            "in_scope": ["127.0.0.1", "localhost"],
            "out_of_scope": [],
            "allowed_methods": ["GET", "POST"],
            "forbidden_paths": [],
        },
    }
    engine_cfg = {"roe": {"enforce_scope": True, "enforce_methods": True,
                          "enforce_rate_limit": False}}
    return ROEGuard(roe=roe, engine_cfg=engine_cfg)


def test_scan_vulnerable_endpoint():
    with Fixture() as fx:
        r = sqli.scan(fx.base_url + "/vuln", param="id", roe_guard=_guard())
    assert r["verdict"] == "VULNERABLE"


def test_scan_safe_endpoint():
    with Fixture() as fx:
        r = sqli.scan(fx.base_url + "/safe", param="id",
                      probes=["differential", "error", "union"],
                      roe_guard=_guard())
    assert r["verdict"] in ("PASS", "SUSPICIOUS")


def test_scan_requires_param():
    r = sqli.scan("http://127.0.0.1:1/", param=None, roe_guard=_guard())
    assert r["verdict"] == "UNKNOWN"


def test_scan_roe_blocks_out_of_scope():
    with Fixture() as fx:
        bad_guard = ROEGuard(
            roe={"enabled": True, "scope": {
                "in_scope": ["example.invalid"],
                "out_of_scope": [],
                "allowed_methods": ["GET", "POST"],
                "forbidden_paths": [],
            }},
            engine_cfg={"roe": {"enforce_scope": True,
                                "enforce_methods": True}},
        )
        r = sqli.scan(fx.base_url + "/vuln", param="id",
                      probes=["error"], roe_guard=bad_guard)
    assert r["verdict"] == "UNKNOWN"
    reason = r.get("reason") or ""
    assert "ROE" in reason or "scope" in reason.lower()
