from engine import capgraph


def test_granted_for_jwt_tool():
    caps = capgraph.granted_capabilities({
        "verdict": "VULNERABLE",
        "capability": "jwt_attack",
    })
    assert "obtain_token" in caps


def test_granted_for_ssrf_tool():
    caps = capgraph.granted_capabilities({
        "verdict": "VULNERABLE",
        "capability": "ssrf_cloud",
    })
    assert "ssrf_to_internal" in caps


def test_granted_for_idor_tool():
    caps = capgraph.granted_capabilities({
        "verdict": "VULNERABLE",
        "capability": "idor_scan",
    })
    assert "write_data" in caps


def test_not_granted_for_pass():
    caps = capgraph.granted_capabilities({
        "verdict": "PASS",
        "capability": "jwt_attack",
    })
    assert caps == []


def test_not_granted_for_unknown_tool():
    caps = capgraph.granted_capabilities({
        "verdict": "VULNERABLE",
        "capability": "zzz_unknown_tool_zzz",
    })
    assert caps == []


def test_none_finding_safe():
    assert capgraph.granted_capabilities(None) == []


def test_capability_to_fact_mapping():
    assert capgraph.capability_to_fact("obtain_token") == "has_obtained_token"
    assert capgraph.capability_to_fact("read_data") == "has_read_data"
    assert capgraph.capability_to_fact("write_data") == "has_write_data"
    assert capgraph.capability_to_fact("ssrf_to_internal") == "has_ssrf_to_internal"
    assert capgraph.capability_to_fact("") is None
    assert capgraph.capability_to_fact("nonsense") is None


def test_cap_to_fact_table_complete():
    for verb in capgraph.CANONICAL_VERBS:
        assert verb in capgraph.CAP_TO_FACT
