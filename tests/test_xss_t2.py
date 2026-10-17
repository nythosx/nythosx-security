import pytest

from engine.injection import xss_t2
from tests.testapp.xss_t2_fixture import XssT2Fixture


def test_mutation_classes_count():
    total = sum(len(v) for v in xss_t2.MUTATION_CLASSES.values())
    assert total >= 15
    assert "namespace_confusion" in xss_t2.MUTATION_CLASSES
    assert "template_nesting" in xss_t2.MUTATION_CLASSES
    assert "comment_quirks" in xss_t2.MUTATION_CLASSES
    assert "cdata_in_html" in xss_t2.MUTATION_CLASSES


def test_waf_defeats_count():
    total = sum(len(v) for v in xss_t2.WAF_DEFEATS.values())
    assert total >= 40, "expected >= 40 WAF defeats, got %d" % total
    assert "low_frequency_handlers" in xss_t2.WAF_DEFEATS
    assert len(xss_t2.WAF_DEFEATS["low_frequency_handlers"]) >= 30


def test_all_payloads_have_signal():
    for _label, payload in xss_t2.all_tier2_payloads():
        assert xss_t2.SIGNAL.get(payload), (
            "missing SIGNAL for %r" % payload)


def test_sanitizer_detect_unknown_when_empty():
    r = xss_t2.detect_sanitizer("")
    assert r["name"] == "unknown"
    assert r["confidence"] == 0.0


def test_sanitizer_detect_dompurify():
    r = xss_t2.detect_sanitizer(
        "function sanitize(x){return DOMPurify.sanitize(x);}")
    assert r["name"] == "dompurify"
    assert r["confidence"] >= 0.5


def test_sanitizer_detect_sanitize_html():
    r = xss_t2.detect_sanitizer(
        "const sanitizeHtml = require('sanitize-html');")
    assert r["name"] == "sanitize-html"


def test_csp_bypass_empty_header_returns_nothing():
    assert xss_t2.enumerate_csp_bypasses("") == []
    assert xss_t2.enumerate_csp_bypasses(None) == []


def test_csp_bypass_strict_header_no_bypass():
    bypasses = xss_t2.enumerate_csp_bypasses(
        "script-src 'self'; base-uri 'self'; object-src 'none'")
    assert bypasses == []


def test_csp_bypass_loose_header_enumerates():
    bypasses = xss_t2.enumerate_csp_bypasses(
        "script-src 'unsafe-inline' 'unsafe-eval' *")
    classes = {b["class"] for b in bypasses}
    assert "unsafe_inline" in classes
    assert "unsafe_eval" in classes
    assert "wildcard_script_src" in classes


def test_csp_bypass_missing_base_uri():
    bypasses = xss_t2.enumerate_csp_bypasses("script-src 'self'")
    classes = {b["class"] for b in bypasses}
    assert "missing_base_uri" in classes
    assert "missing_object_src" in classes


def test_render_csp_bypass_payloads_substitutes_listener():
    bypasses = xss_t2.enumerate_csp_bypasses("script-src 'self'")
    rendered = xss_t2.render_csp_bypass_payloads(bypasses,
                                                   listener="evil.example")
    for r in rendered:
        assert "{listener}" not in r["payload"], (
            "placeholder not substituted: %r" % r["payload"])


def test_mutation_reflection_fixture():
    from engine.chain_engine import _TOOL_SPECS  # noqa: F401 — import only
    with XssT2Fixture() as fx:
        # reflection check via direct HTTP round-trip
        from engine import http as _http
        with _http.Client(timeout=3, follow_redirects=False) as c:
            payload = xss_t2.MUTATION_CLASSES["comment_quirks"][0]
            r = c.get(fx.base_url + "/xss2/mutation",
                      params={"q": payload})
        assert payload in (r.text or "")


def test_csp_fixture_strict_header_parses():
    with XssT2Fixture() as fx:
        from engine import http as _http
        with _http.Client(timeout=3, follow_redirects=False) as c:
            r = c.get(fx.base_url + "/xss2/csp_strict")
        header = r.headers.get("Content-Security-Policy", "")
        bypasses = xss_t2.enumerate_csp_bypasses(header)
        assert bypasses == [], (
            "strict CSP should yield no bypasses, got %r" % bypasses)


def test_csp_fixture_loose_header_parses():
    with XssT2Fixture() as fx:
        from engine import http as _http
        with _http.Client(timeout=3, follow_redirects=False) as c:
            r = c.get(fx.base_url + "/xss2/csp_loose")
        header = r.headers.get("Content-Security-Policy", "")
        bypasses = xss_t2.enumerate_csp_bypasses(header)
        classes = {b["class"] for b in bypasses}
        assert "unsafe_inline" in classes
        assert "unsafe_eval" in classes
