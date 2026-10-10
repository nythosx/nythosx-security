import pytest


def test_scanresult_attr_and_dict_access():
    from engine.contract import ScanResult, Verdict, Severity
    r = ScanResult(capability="x", target="http://t", verdict="VULNERABLE",
                   severity="high", reason="r", evidence={"k": "v"})
    assert r.verdict == Verdict.VULNERABLE
    assert r["verdict"] == "VULNERABLE"
    assert r.severity == Severity.HIGH
    assert r["severity"] == "high"
    assert r["reason"] == "r"
    assert r["evidence"] == {"k": "v"}
    assert r.get("verdict") == "VULNERABLE"
    assert "verdict" in r
    assert "unknown_extra" not in r


def test_scanresult_get_default():
    from engine.contract import ScanResult
    r = ScanResult()
    assert r.get("nope", "fallback") == "fallback"
    assert r["nope"] is None


def test_finding_attr_and_dict_access():
    from engine.contract import Finding, Verdict, Severity
    f = Finding(id="a", type="t", verdict="SUSPICIOUS", severity="medium",
                reason="why", evidence={"e": 1})
    assert f.verdict == Verdict.SUSPICIOUS
    assert f["verdict"] == "SUSPICIOUS"
    assert f.severity == Severity.MEDIUM
    assert f["severity"] == "medium"
    assert f["evidence"] == {"e": 1}
    assert f.get("reason") == "why"


def test_make_result_from_dict():
    from engine.contract import make_result, ScanResult, Verdict
    raw = {"verdict": "VULNERABLE", "reason": "bad", "evidence": {"x": 1}}
    r = make_result(raw, capability="test", args=("http://t",), kwargs={})
    assert isinstance(r, ScanResult)
    assert r.capability == "test"
    assert r.verdict == Verdict.VULNERABLE
    assert r["reason"] == "bad"
    assert r.evidence == {"x": 1}


def test_make_result_from_overall():
    from engine.contract import make_result, Verdict
    raw = {"overall": "SUSPICIOUS", "reason": "maybe"}
    r = make_result(raw, capability="x")
    assert r.verdict == Verdict.SUSPICIOUS


def test_make_result_from_nested_result():
    from engine.contract import make_result, Verdict
    raw = {"target": "http://t", "result": {"verdict": "VULNERABLE", "reason": "r", "evidence": {}}}
    r = make_result(raw, capability="x")
    assert r.verdict == Verdict.VULNERABLE
    assert r.reason == "r"


def test_make_result_from_list():
    from engine.contract import make_result, Verdict
    raw = [
        {"verdict": "PASS", "reason": "ok"},
        {"verdict": "VULNERABLE", "reason": "bad", "severity": "high"},
        {"verdict": "PASS", "reason": "ok2"},
    ]
    r = make_result(raw, capability="llm")
    assert r.verdict == Verdict.VULNERABLE
    assert r.severity.value == "high"
    assert len(r.findings) == 3


def test_make_result_from_sca_style():
    from engine.contract import make_result, Verdict
    raw = {"vulnerabilities": [{"dep": "x"}], "summary": {"high": 1}}
    r = make_result(raw, capability="sca")
    assert r.verdict == Verdict.VULNERABLE


def test_make_result_passthrough_scanresult():
    from engine.contract import ScanResult, make_result
    r = ScanResult(capability="a", target="http://t")
    r2 = make_result(r, capability="ignored")
    assert r2 is r


def test_wrap_evaluate_dict():
    from engine.contract import wrap_evaluate, Finding
    f = wrap_evaluate({"verdict": "VULNERABLE", "reason": "r", "evidence": {"k": 1}}, "pattern_match")
    assert isinstance(f, Finding)
    assert f["verdict"] == "VULNERABLE"
    assert f["evidence"] == {"k": 1}
    assert f.type == "pattern_match"


def test_wrap_evaluate_finding_passthrough():
    from engine.contract import wrap_evaluate, Finding
    orig = Finding(id="x", type="y", verdict="PASS")
    out = wrap_evaluate(orig, "y")
    assert out is orig


def test_wrappers_installed():
    from engine import (bizlogic, jwt_attacks, graphql_security, ssrf_cloud,
                        dom_xss, llm_security, openapi_scanner, idor, ssrf,
                        xss, smuggle, race_advanced, sca)
    pairs = [
        (bizlogic, "scan", "_scan_impl"),
        (jwt_attacks, "run_attack_suite", "_run_attack_suite_impl"),
        (graphql_security, "scan", "_scan_impl"),
        (ssrf_cloud, "scan", "_scan_impl"),
        (dom_xss, "scan", "_scan_impl"),
        (llm_security, "scan", "_scan_impl"),
        (openapi_scanner, "scan", "_scan_impl"),
        (idor, "run_probe", "_run_probe_impl"),
        (ssrf, "probe", "_probe_impl"),
        (xss, "probe", "_probe_impl"),
        (smuggle, "probe", "_probe_impl"),
        (race_advanced, "race_scan", "_race_scan_impl"),
        (sca, "scan_dependencies", "_scan_dependencies_impl"),
    ]
    for mod, pub, priv in pairs:
        assert hasattr(mod, pub), f"{mod.__name__}.{pub} missing"
        assert hasattr(mod, priv), f"{mod.__name__}.{priv} missing"


def test_bizlogic_scan_returns_scanresult():
    from engine import bizlogic
    from engine.contract import ScanResult
    r = bizlogic.scan("http://127.0.0.1:1", endpoints=None)
    assert isinstance(r, ScanResult)
    assert r["verdict"] == "UNKNOWN"
    assert r.verdict.value == "UNKNOWN"
    assert r.capability == "bizlogic"


def test_smuggle_accepts_protocol_param():
    from engine import smuggle
    import inspect
    sig = inspect.signature(smuggle.probe)
    assert "protocol" in sig.parameters


def test_smuggle_h2_is_implemented():
    from engine import smuggle
    try:
        smuggle.probe("http://127.0.0.1:1", protocol="h2")
    except NotImplementedError:
        raise AssertionError("h2 is implemented in Phase 4; it must not raise "
                             "NotImplementedError")
    except Exception:
        pass


def test_route_enum_accepts_adapter():
    from engine import route_enum
    import inspect
    sig = inspect.signature(route_enum.enumerate_routes)
    assert "adapter" in sig.parameters


def test_discovery_has_extract_websocket_urls():
    from engine import discovery
    assert hasattr(discovery, "extract_websocket_urls")
    found = discovery.extract_websocket_urls(
        '<script>const u = "wss://api.example.com/ws";</script>'
    )
    assert "wss://api.example.com/ws" in found


def test_oracle_evaluate_returns_finding():
    from engine import oracle
    from engine.contract import Finding
    ctx = {"steps": [{"step_name": "s", "body": "SECRET_KEY=abc",
                      "headers": {}, "status": 200}],
           "inputs": {}, "target": "http://t"}
    r = oracle.evaluate({"type": "pattern_match", "regex": r"SECRET_KEY=",
                         "verdict": "VULNERABLE"}, ctx)
    assert isinstance(r, Finding)
    assert r["verdict"] == "VULNERABLE"
    assert r["evidence"]["matched_step"] == "s"


def test_evidence_supports_new_fields(tmp_path, monkeypatch):
    from engine import evidence
    monkeypatch.setattr(evidence, "EVIDENCE_DIR", tmp_path)
    ctx = {"steps": [{"step_name": "s", "loop_index": 0, "status": 200,
                      "time_ms": 1.0, "body_hash": "h", "url": "http://t",
                      "error": None, "headers": {}, "body": "x"}],
           "inputs": {}, "target": "http://t"}
    path = evidence.save_evidence(
        "p", "http://t", ctx, "PASS",
        {"reason": "r", "evidence": {}},
        engine_cfg={"evidence": {"save_raw_bodies": True, "max_body_size_kb": 100}},
        author="template", confidence=0.9, chain_ids=["chain-1"],
    )
    import json as _json
    from pathlib import Path as _P
    data = _json.loads((_P(path) / "summary.json").read_text(encoding="utf-8"))
    assert data["author"] == "template"
    assert data["confidence"] == 0.9
    assert data["chain_ids"] == ["chain-1"]
