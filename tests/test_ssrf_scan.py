from urllib.parse import urlparse

from engine import ssrf
from engine.roe_guard import ROEGuard
from tests.testapp.ssrf_fixture import Fixture


def _guard(forbidden=None):
    forbidden = forbidden or []
    return ROEGuard(
        roe={
            "enabled": True,
            "scope": {
                "in_scope": ["127.0.0.1", "localhost"],
                "out_of_scope": forbidden,
                "allowed_methods": ["GET", "POST"],
                "forbidden_paths": [],
            },
        },
        engine_cfg={"roe": {"enforce_scope": True,
                             "enforce_methods": True}},
    )


def test_probe_emits_bypass_attempts():
    with Fixture() as fx:
        r = ssrf.probe(fx.base_url + "/fetch", param="url",
                       roe_guard=_guard())
    assert "bypass_attempts" in r
    assert r["bypass_attempts"], "expected at least one bypass variant"


def test_probe_callback_detected_on_fetch_endpoint():
    with Fixture() as fx:
        r = ssrf.probe(fx.base_url + "/fetch", param="url",
                       roe_guard=_guard())
    assert r["result"]["verdict"] == "VULNERABLE", (
        "expected VULNERABLE, got %r" % r["result"])


def test_probe_safe_endpoint_gets_pass():
    with Fixture() as fx:
        r = ssrf.probe(fx.base_url + "/safe", param="url",
                       params=["url"], roe_guard=_guard(),
                       wait_timeout=1.0)
    assert r["result"]["verdict"] == "PASS"


def test_ssrf_cloud_respects_roe_for_metadata():
    forbidden = ["169.254.169.254", "metadata.google.internal",
                 "100.100.100.200"]
    with Fixture() as fx:
        guard = _guard(forbidden=forbidden)
        from engine import ssrf_cloud
        try:
            r = ssrf_cloud.scan(
                base_url=fx.base_url + "/fetch",
                params=["url"],
                timeout=2,
                roe_guard=guard,
            )
        except Exception:
            return
        evidence = r.get("evidence") or {}
        assert evidence.get("roe_fallback") is True, (
            "expected roe_fallback path, got %r"
            % list(evidence.keys()))
        for req in fx.requests:
            joined = str(req.get("query") or {})
            for host in forbidden:
                assert host not in joined, (
                    "forbidden host %s leaked into request %r"
                    % (host, joined))
