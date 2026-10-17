from engine import payloads


def test_pack_dataclass_fields():
    p = payloads.PayloadPack(id="x", family="y")
    assert p.waf_safe == []
    assert p.expected_signal == {}


def test_register_and_get():
    payloads.register(payloads.PayloadPack(
        id="t1", family="t1", waf_safe=["a"]))
    assert payloads.get("t1") is not None
    assert payloads.get("t1").waf_safe == ["a"]


def test_all_payloads_concatenates():
    p = payloads.PayloadPack(
        id="t2", family="t2",
        waf_safe=["a"], waf_bypass=["b"],
        context_variants={"json": ["c"]})
    got = [x[1] for x in p.all_payloads()]
    assert got == ["a", "b", "c"]


def test_must_never_blocks_destructive():
    p = payloads.PayloadPack(id="t3", family="t3", waf_safe=["rm -rf /"])
    assert payloads.violates_must_never("rm -rf /", p) is True


def test_must_never_passes_safe():
    p = payloads.PayloadPack(id="t4", family="t4", waf_safe=["1 AND 1=1"])
    assert payloads.violates_must_never("1 AND 1=1", p) is False


def test_must_never_unions_roe_forbidden_paths():
    blockers = payloads.combined_must_never()
    assert any("/admin/delete" in b or "/api/drop" in b for b in blockers)


def test_pick_filters_must_never():
    p = payloads.PayloadPack(
        id="t5", family="t5",
        waf_safe=["1 AND 1=1", "rm -rf /tmp"],
        waf_bypass=[],
        context_variants={})
    picked = payloads.pick(p, ctx=None, waf=None, budget=None)
    assert "1 AND 1=1" in picked
    assert "rm -rf /tmp" not in picked


def test_pick_budget():
    p = payloads.PayloadPack(
        id="t6", family="t6",
        waf_safe=["a", "b", "c", "d"],
        context_variants={})
    picked = payloads.pick(p, ctx=None, waf=None, budget=2)
    assert len(picked) == 2


def test_pick_context_priority():
    p = payloads.PayloadPack(
        id="t7", family="t7",
        waf_safe=["safe1"],
        waf_bypass=["bypass1"],
        context_variants={"json": ["json1"]})
    picked = payloads.pick(p, ctx="json", waf=None, budget=None)
    assert picked[0] == "json1"


def test_pick_signal_lookup():
    p = payloads.PayloadPack(
        id="t8", family="t8",
        waf_safe=["x"],
        expected_signal={"x": {"kind": "error"}})
    assert payloads.pick_signal(p, "x") == {"kind": "error"}
    assert payloads.pick_signal(p, "unknown") == {}


def test_pick_prioritizes_context_over_safe():
    p = payloads.PayloadPack(
        id="t9", family="t9",
        waf_safe=["safe"],
        waf_bypass=["bypass"],
        context_variants={"json": ["json1", "json2"]})
    picked = payloads.pick(p, ctx="json", waf=None, budget=None)
    assert picked[0] == "json1"
    assert picked[1] == "json2"
    assert "safe" in picked[2:]
