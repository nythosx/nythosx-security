def test_chains_load():
    from engine.correlator import library
    chains = library.load_chains()
    assert len(chains) >= 15


def test_every_prerequisite_is_real_pattern():
    from engine import loader
    from engine.correlator import library
    pattern_ids = {p["id"] for p in loader.list_patterns()}
    for chain in library.load_chains():
        assert chain.id, "chain missing id"
        assert chain.name, f"{chain.id} missing name"
        assert chain.prerequisites, f"{chain.id} has no prerequisites"
        for req in chain.prerequisites:
            assert req in pattern_ids, f"{chain.id}: unknown prerequisite {req}"


def test_chain_severities_valid():
    from engine.correlator import library
    valid = {"info", "low", "medium", "high", "critical"}
    for chain in library.load_chains():
        assert chain.severity in valid, f"{chain.id}: {chain.severity}"


def test_chain_ids_unique():
    from engine.correlator import library
    ids = [c.id for c in library.load_chains()]
    assert len(ids) == len(set(ids))
