import json

from engine import llm_service
from engine import discovery as _disc
from engine.chain_engine import ChainOrchestrator


_COMBINED = json.dumps({
    "endpoints": ["/api/v1/users"],
    "secrets": ["sk_live_x"],
    "auth_flow": [],
    "debug_flags": [],
    "crypto": [],
    "taints": [{"source": "location.hash", "sink": "innerHTML",
                "via": "render", "sink_type": "dom_xss"}],
    "auth_sequence": ["GET /csrf", "POST /login"],
})


def _orch():
    return ChainOrchestrator("http://127.0.0.1", job_id=None)


def test_bundle_analysis_noop_without_ai(monkeypatch):
    monkeypatch.setattr(llm_service, "get_client",
                        lambda capability=None, cfg=None: None)
    orch = _orch()
    orch._run_bundle_analysis([{"url": "http://127.0.0.1/app.js", "size": 100}])
    assert "bundle_taints" not in orch.recon


def test_bundle_analysis_adds_facts_with_ai(monkeypatch):
    monkeypatch.setattr(_disc, "fetch_js_text",
                        lambda url, **k: "var x = location.hash; el.innerHTML=x;")
    monkeypatch.setattr(
        llm_service, "get_client",
        lambda capability=None, cfg=None: (lambda p: _COMBINED))
    orch = _orch()
    orch._run_bundle_analysis([{"url": "http://127.0.0.1/app.js", "size": 500}])
    assert orch.recon.get("bundle_taints")
    assert orch.recon["bundle_taints"][0]["sink"] == "innerHTML"
    assert orch.recon.get("auth_sequence") == ["GET /csrf", "POST /login"]
    facts = orch.fact_store.to_dict()
    assert "bundle_endpoints" in facts or "bundle_taint_count" in facts
