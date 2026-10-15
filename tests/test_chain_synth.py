import json

from engine.brains.chain_synth import ChainSynthesizer


_FINDINGS = [
    {"pattern_id": "jwt-weak-secret", "verdict": "VULNERABLE"},
    {"pattern_id": "authed-idor", "verdict": "VULNERABLE"},
    {"pattern_id": "cors-wildcard", "verdict": "SUSPICIOUS"},
]


def test_offline_returns_empty():
    cs = ChainSynthesizer(client=None)
    assert cs.synthesize(_FINDINGS, []) == []


def test_too_few_findings_returns_empty():
    cs = ChainSynthesizer(client=lambda p: "[]")
    assert cs.synthesize([_FINDINGS[0]], []) == []


def test_client_proposes_valid_chain():
    def client(prompt):
        return json.dumps({"chains": [{
            "id": "jwt-then-idor",
            "name": "JWT forgery then IDOR",
            "requires": ["jwt-weak-secret", "authed-idor"],
            "narrative": "Forge a token, then walk IDs.",
            "confidence": 0.85,
        }]})
    cs = ChainSynthesizer(client=client)
    chains = cs.synthesize(_FINDINGS, [])
    assert len(chains) == 1
    assert chains[0]["id"] == "auto-llm-jwt-then-idor"
    assert set(chains[0]["requires"]) == {"jwt-weak-secret", "authed-idor"}


def test_hallucinated_requires_dropped():
    def client(prompt):
        return json.dumps({"chains": [{
            "id": "fake",
            "name": "x",
            "requires": ["nonexistent-pattern", "jwt-weak-secret"],
            "narrative": "x",
            "confidence": 0.5,
        }]})
    cs = ChainSynthesizer(client=client)
    chains = cs.synthesize(_FINDINGS, [])
    assert chains == []


def test_chain_with_fewer_than_two_real_requires_dropped():
    def client(prompt):
        return json.dumps({"chains": [{
            "id": "x",
            "name": "x",
            "requires": ["jwt-weak-secret", "nonexistent-other"],
            "narrative": "x",
            "confidence": 0.5,
        }]})
    cs = ChainSynthesizer(client=client)
    chains = cs.synthesize(_FINDINGS, [])
    assert chains == []


def test_max_chains_respected():
    def client(prompt):
        return json.dumps({"chains": [
            {"id": f"c{i}", "name": f"c{i}",
             "requires": ["jwt-weak-secret", "authed-idor"],
             "narrative": "x", "confidence": 0.5}
            for i in range(20)
        ]})
    cs = ChainSynthesizer(client=client, max_chains=3)
    chains = cs.synthesize(_FINDINGS, [])
    assert len(chains) == 3


def test_garbage_falls_back():
    cs = ChainSynthesizer(client=lambda p: "not json")
    assert cs.synthesize(_FINDINGS, []) == []
