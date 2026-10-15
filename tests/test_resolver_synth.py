def test_offline_synth_does_not_break_resolver():
    from engine.correlator.resolver import resolve_chains
    findings = [
        {"pattern_id": "env-file-exposure", "verdict": "VULNERABLE"},
        {"pattern_id": "mass-assignment", "verdict": "VULNERABLE"},
    ]
    chains = resolve_chains(findings)
    ids = {c.id for c in chains}
    assert "env-file-to-admin-takeover" in ids


def test_empty_findings_no_synth():
    from engine.correlator.resolver import resolve_chains
    chains = resolve_chains([])
    assert all(not c.id.startswith("auto-llm-") for c in chains)
