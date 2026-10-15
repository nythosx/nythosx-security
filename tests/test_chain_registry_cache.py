def test_cache_returns_same_object():
    from engine import chain_registry
    chain_registry.reload()
    a = chain_registry.get_all_chains()
    b = chain_registry.get_all_chains()
    assert a is b


def test_reload_busts_cache():
    from engine import chain_registry
    chain_registry.reload()
    a = chain_registry.get_all_chains()
    chain_registry.reload()
    b = chain_registry.get_all_chains()
    assert a is not b
    assert len(a) == len(b)


def test_validation_runs_once_on_cache_hit(monkeypatch):
    from engine import chain_registry, schema
    chain_registry.reload()
    calls = []
    real = schema.validate_chain

    def spy(c, where=None):
        calls.append(where)
        return real(c, where=where)

    monkeypatch.setattr(schema, "validate_chain", spy)
    chain_registry.reload()
    first = len(calls)
    assert first > 0
    chain_registry.get_all_chains()
    chain_registry.get_all_chains()
    chain_registry.get_all_chains()
    assert len(calls) == first


def test_cached_chains_match_first_call():
    from engine import chain_registry
    chain_registry.reload()
    first = chain_registry.get_all_chains()
    second = chain_registry.get_all_chains()
    ids_first = [c["id"] for c in first]
    ids_second = [c["id"] for c in second]
    assert ids_first == ids_second
