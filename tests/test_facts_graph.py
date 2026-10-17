import pytest

from engine.facts import FactStore, FRESH, INVALIDATED


def test_add_and_get():
    fs = FactStore()
    fs.add("a", 1, source="cli")
    assert fs.get("a") == 1
    assert fs.has("a")
    assert "a" in fs


def test_requires_returns_missing():
    fs = FactStore()
    fs.add("present", True, source="cli")
    missing = fs.requires(["present", "absent"])
    assert missing == ["absent"]


def test_provider_resolves_missing_fact():
    fs = FactStore()

    def provide(store, ctx):
        store.add("lazy", "made", source="cli")

    fs.register_provider("lazy", provide)
    assert not fs.has("lazy")
    fact, provider = fs.resolve("lazy")
    assert fact is not None
    assert fact.value == "made"
    assert provider is provide


def test_provider_cycle_rejected():
    fs = FactStore()

    def self_cycle(store, ctx):
        store.resolve("cycle")

    fs.register_provider("cycle", self_cycle)
    fact, provider = fs.resolve("cycle")
    assert fact is None
    assert provider is self_cycle


def test_has_confidence_threshold():
    fs = FactStore()
    fs.add("low", True, source="js_match")
    assert fs.has("low")
    assert not fs.has("low", min_confidence=0.9)


def test_invalidate_blocks_reads():
    fs = FactStore()
    fs.add("k", "v", source="cli")
    assert fs.is_valid("k")
    fs.invalidate("k", "stale")
    assert not fs.is_valid("k")
    assert fs.get("k") is None
    assert "k" not in fs


def test_effects_and_provenance_recorded():
    fs = FactStore()
    fs.add("e", 1, source="cli",
           preconditions=["p1", "p2"],
           effects=["f1"],
           provenance=["origin"])
    f = fs.get_fact("e")
    assert f.preconditions == ["p1", "p2"]
    assert f.effects == ["f1"]
    assert f.provenance == ["origin"]


def test_resolve_all_partial():
    fs = FactStore()
    fs.add("ok", True, source="cli")

    def provide_missing(store, ctx):
        store.add("made", True, source="cli")

    fs.register_provider("made", provide_missing)
    unresolved, produced = fs.resolve_all(["ok", "made", "nope"])
    assert unresolved == ["nope"]
    produced_keys = [k for k, _ in produced]
    assert produced_keys == ["made"]


def test_to_dict_shape():
    fs = FactStore()
    fs.add("k", "v", source="cli")
    d = fs.to_dict()
    assert "k" in d
    assert d["k"]["value"] == "v"
    assert d["k"]["validity"] == FRESH


def test_invalidate_missing_returns_false():
    fs = FactStore()
    assert fs.invalidate("nope", "x") is False
