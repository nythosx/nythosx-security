from engine.injection import csp_bypass


def test_parse_csp_basic():
    d = csp_bypass.parse_csp("default-src 'self'; script-src 'self'")
    assert d["default-src"] == ["'self'"]
    assert d["script-src"] == ["'self'"]


def test_parse_csp_empty():
    assert csp_bypass.parse_csp("") == {}


def test_unsafe_inline_detected():
    d = csp_bypass.parse_csp("script-src 'unsafe-inline'")
    findings = csp_bypass.analyze(d)
    assert any(f["issue"] == "unsafe-inline_without_strict_dynamic"
               for f in findings)


def test_unsafe_inline_with_nonce_not_flagged():
    d = csp_bypass.parse_csp("script-src 'unsafe-inline' 'nonce-abc123'")
    findings = csp_bypass.analyze(d)
    assert not any(f["issue"] == "unsafe-inline_without_strict_dynamic"
                   for f in findings)


def test_unsafe_eval_detected():
    d = csp_bypass.parse_csp("script-src 'unsafe-eval'")
    findings = csp_bypass.analyze(d)
    assert any(f["issue"] == "unsafe-eval" for f in findings)


def test_wildcard_detected():
    d = csp_bypass.parse_csp("script-src *")
    findings = csp_bypass.analyze(d)
    assert any(f["issue"] == "wildcard_script_src" for f in findings)


def test_missing_base_uri_detected():
    d = csp_bypass.parse_csp("script-src 'self'")
    findings = csp_bypass.analyze(d)
    assert any(f["issue"] == "missing_base_uri" for f in findings)


def test_jsonp_host_detected():
    d = csp_bypass.parse_csp("script-src 'self' https://jsonp.example.com")
    findings = csp_bypass.analyze(d)
    assert any(f["issue"] == "jsonp_capable_host" for f in findings)


def test_strong_csp_passes():
    d = csp_bypass.parse_csp(
        "default-src 'none'; script-src 'nonce-abc' 'strict-dynamic'; "
        "base-uri 'self'; form-action 'self'"
    )
    findings = csp_bypass.analyze(d)
    assert not findings
