from engine.facts import FactStore, SOURCE_CONFIDENCE

def test_add_and_get():
    s = FactStore()
    s.add("has_jwt", True, source="active_probe")
    assert s.get("has_jwt") is True
    assert s.has("has_jwt")
    assert s.confidence("has_jwt") == 0.9

def test_confidence_by_source():
    s = FactStore()
    s.add("a", 1, source="js_match")
    s.add("b", 2, source="passive_header")
    s.add("c", 3, source="active_probe")
    s.add("d", 4, source="live_confirm")
    assert s.confidence("a") == SOURCE_CONFIDENCE["js_match"]
    assert s.confidence("b") == SOURCE_CONFIDENCE["passive_header"]
    assert s.confidence("c") == SOURCE_CONFIDENCE["active_probe"]
    assert s.confidence("d") == SOURCE_CONFIDENCE["live_confirm"]

def test_override_confidence():
    s = FactStore()
    s.add("x", 1, source="js_match", confidence=0.75)
    assert s.confidence("x") == 0.75

def test_confidence_clamped():
    s = FactStore()
    s.add("x", 1, confidence=5.0)
    assert s.confidence("x") == 1.0
    s.add("y", 2, confidence=-1.0)
    assert s.confidence("y") == 0.0

def test_higher_confidence_wins():
    s = FactStore()
    s.add("x", "low", source="js_match")
    s.add("x", "high", source="active_probe")
    assert s.get("x") == "high"
    s.add("x", "lower_again", source="js_match")
    assert s.get("x") == "high"

def test_min_confidence_threshold():
    s = FactStore()
    s.add("hint", True, source="js_match")
    assert s.has("hint", min_confidence=0.3)
    assert not s.has("hint", min_confidence=0.5)

def test_expiry():
    s = FactStore()
    s.add("x", 1, ttl_seconds=-1.0)
    assert s.get("x") is None
    assert not s.has("x")

def test_to_dict():
    s = FactStore()
    s.add("a", 1, source="active_probe")
    d = s.to_dict()
    assert "a" in d
    assert d["a"]["value"] == 1
    assert d["a"]["source"] == "active_probe"
    assert d["a"]["confidence"] == 0.9

def test_iter_keys():
    s = FactStore()
    s.add("a", 1)
    s.add("b", 2)
    assert sorted(s.keys()) == ["a", "b"]
    assert "a" in s
    assert "c" not in s

def test_evidence_accumulates_on_tie():
    s = FactStore()
    s.add("x", 1, source="active_probe", evidence=["first"])
    s.add("x", 1, source="active_probe", evidence=["second"])
    f = s.get_fact("x")
    assert "first" in f.evidence
    assert "second" in f.evidence
