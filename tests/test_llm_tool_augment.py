import json

from engine import oracle, llm_service, openapi_scanner
from engine.brains import payload_author
from engine.brains.chain_synth import ChainSynthesizer
from engine.brains.bundle_analyst import BundleAnalyst


def test_oracle_classifier_downgrades_false_positive(monkeypatch):
    oracle._ORACLE_LLM_CACHE.clear()
    monkeypatch.setattr(
        llm_service, "get_client",
        lambda capability=None, cfg=None: (
            lambda p: '{"meaningful": false, "reason": "matched in HTML doc"}'))
    orc = {"type": "pattern_match", "pattern": "version", "verdict": "VULNERABLE"}
    res = {"verdict": "VULNERABLE", "reason": "matched 'version'", "evidence": {}}
    ctx = {"steps": [{"body": "<html>version 1.2.3</html>",
                      "headers": {"Content-Type": "text/html"}}]}
    out = oracle._annotate_with_oracle_llm(dict(res), orc, ctx)
    assert out["verdict"] == "PASS"
    assert out["oracle_llm_override"] is True


def test_oracle_classifier_keeps_true_positive(monkeypatch):
    oracle._ORACLE_LLM_CACHE.clear()
    monkeypatch.setattr(
        llm_service, "get_client",
        lambda capability=None, cfg=None: (
            lambda p: '{"meaningful": true, "reason": "real leak"}'))
    orc = {"type": "pattern_match", "pattern": "x", "verdict": "VULNERABLE"}
    res = {"verdict": "VULNERABLE", "reason": "m", "evidence": {}}
    ctx = {"steps": [{"body": '{"secret":"abc"}', "headers": {}}]}
    out = oracle._annotate_with_oracle_llm(dict(res), orc, ctx)
    assert out["verdict"] == "VULNERABLE"


def test_oracle_classifier_no_ai_unchanged(monkeypatch):
    oracle._ORACLE_LLM_CACHE.clear()
    monkeypatch.setattr(llm_service, "get_client",
                        lambda capability=None, cfg=None: None)
    orc = {"type": "pattern_match", "pattern": "x", "verdict": "VULNERABLE"}
    res = {"verdict": "VULNERABLE", "reason": "m", "evidence": {}}
    ctx = {"steps": [{"body": "<html>x</html>", "headers": {}}]}
    assert oracle._annotate_with_oracle_llm(dict(res), orc, ctx)["verdict"] == "VULNERABLE"


def test_fuzz_values_augmented(monkeypatch):
    monkeypatch.setattr(
        llm_service, "get_client",
        lambda capability=None, cfg=None: (lambda p: '["USD","EUR",840]'))
    vals = openapi_scanner._make_fuzz_values({"type": "string"})
    llm_vals = [v for v in vals if v.get("type") == "llm"]
    assert {"USD", "EUR"}.issubset({v["value"] for v in llm_vals})


def test_fuzz_values_no_ai_is_base(monkeypatch):
    monkeypatch.setattr(llm_service, "get_client",
                        lambda capability=None, cfg=None: None)
    vals = openapi_scanner._make_fuzz_values({"type": "integer",
                                              "minimum": 1, "maximum": 10})
    assert all(v.get("type") != "llm" for v in vals)
    assert vals == openapi_scanner._make_fuzz_values_base(
        {"type": "integer", "minimum": 1, "maximum": 10})


def test_chain_synth_from_facts():
    def client(p):
        return json.dumps({"chains": [
            {"id": "graphql-bola", "name": "GraphQL BOLA",
             "narrative": "introspect then BOLA", "confidence": 0.8}]})
    cs = ChainSynthesizer(client=client)
    out = cs.synthesize_from_facts({"framework": "express", "has_graphql": True})
    assert out and out[0]["id"].startswith("auto-llm-")
    assert ChainSynthesizer(client=None).synthesize_from_facts({"a": 1}) == []


def test_open_redirect_payloads_augmented(monkeypatch):
    from engine.injection import open_redirect as orr
    from engine.injection.payloads import OPEN_REDIRECT_PAYLOADS
    monkeypatch.setattr(llm_service, "get_client",
                        lambda capability=None, cfg=None: None)
    assert orr._augmented_redirect_payloads("http://t/") == list(
        OPEN_REDIRECT_PAYLOADS)
    monkeypatch.setattr(
        llm_service, "get_client",
        lambda capability=None, cfg=None: (lambda p: '["//evil.test"]'))
    got = orr._augmented_redirect_payloads("http://t/")
    assert got[0] == "//evil.test"
    assert set(OPEN_REDIRECT_PAYLOADS).issubset(set(got))


def test_bundle_trace():
    def client(p):
        return json.dumps({"taints": [
            {"source": "location.hash", "sink": "innerHTML",
             "via": "render()", "sink_type": "dom_xss"}],
            "auth_sequence": ["GET /csrf", "POST /login"]})
    ba = BundleAnalyst(client=client)
    r = ba.trace("var x = location.hash; el.innerHTML = x;")
    assert r["taints"][0]["sink"] == "innerHTML"
    assert BundleAnalyst(client=None).trace("x")["taints"] == []
