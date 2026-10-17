from engine.injection import sqli_pack
from engine import payloads


def test_pack_registered():
    assert payloads.get("sqli") is not None


def test_pack_has_tiers():
    p = sqli_pack.PACK
    assert len(p.waf_safe) >= 8
    assert len(p.waf_bypass) >= 10
    assert "dialect" in p.context_variants
    assert "json" in p.context_variants


def test_every_payload_has_expected_signal():
    p = sqli_pack.PACK
    for _kind, payload in p.all_payloads():
        assert p.expected_signal.get(payload), (
            "missing expected_signal for %r" % payload)


def test_no_payload_violates_must_never():
    p = sqli_pack.PACK
    for _kind, payload in p.all_payloads():
        assert not payloads.violates_must_never(payload, p), (
            "payload violates must_never: %r" % payload)


def test_differential_pairs_present():
    assert len(sqli_pack.DIFFERENTIAL_PAIRS) >= 3


def test_dialect_probes_cover_core_dialects():
    for d in ("mssql", "postgres", "mysql"):
        assert d in sqli_pack.DIALECT_PROBES


def test_hpp_combos_present():
    assert len(sqli_pack.HPP_COMBOS) >= 2
    for label, a, b in sqli_pack.HPP_COMBOS:
        assert isinstance(label, str) and label
        assert isinstance(a, str) and isinstance(b, str)


def test_union_marker_defined():
    assert sqli_pack.UNION_MARKER
    assert isinstance(sqli_pack.UNION_MARKER, str)
