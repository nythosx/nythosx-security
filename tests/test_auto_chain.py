from engine.correlator import auto_chain
from engine.correlator.resolver import resolve_chains


def _v(pid, verdict="VULNERABLE"):
    return {"pattern_id": pid, "verdict": verdict}


def test_generate_empty_findings():
    assert auto_chain.generate([]) == []


def test_generate_single_missing_prereq():
    out = auto_chain.generate([_v("env-file-exposure")])
    ids = [c.id for c in out]
    assert "auto-env-plus-ssrf-cloud" not in ids


def test_generate_env_plus_ssrf():
    out = auto_chain.generate([
        _v("env-file-exposure"),
        _v("ssrf-cloud-metadata"),
    ])
    ids = [c.id for c in out]
    assert "auto-env-plus-ssrf-cloud" in ids


def test_generate_cors_plus_graphql():
    out = auto_chain.generate([
        _v("cors-wildcard"),
        _v("graphql-introspection"),
    ])
    ids = [c.id for c in out]
    assert "auto-cors-plus-graphql-introspection" in ids


def test_generate_two_suspicious_is_theoretical():
    out = auto_chain.generate([
        _v("crlf-injection", "SUSPICIOUS"),
        _v("cache-poisoning-probe", "SUSPICIOUS"),
    ])
    match = next((c for c in out if c.id == "auto-crlf-plus-cache-poison"),
                 None)
    assert match is not None
    assert match.verdict == "THEORETICAL"


def test_generate_one_vuln_is_likely():
    out = auto_chain.generate([
        _v("nosql-probe", "VULNERABLE"),
        _v("authed-idor", "SUSPICIOUS"),
    ])
    match = next((c for c in out if c.id == "auto-nosql-plus-idor"), None)
    assert match is not None
    assert match.verdict in ("LIKELY", "CONFIRMED")


def test_generate_all_pass_is_excluded():
    out = auto_chain.generate([
        _v("weak-password-policy", "PASS"),
        _v("user-enumeration-timing", "PASS"),
    ])
    ids = [c.id for c in out]
    assert "auto-weak-pw-plus-enum-timing" not in ids


def test_resolve_chains_merges_auto():
    findings = [
        _v("env-file-exposure"),
        _v("ssrf-cloud-metadata"),
    ]
    chains = resolve_chains(findings)
    ids = [c.id for c in chains]
    assert "auto-env-plus-ssrf-cloud" in ids


def test_resolve_chains_static_still_present():
    findings = [
        _v("env-file-exposure"),
        _v("mass-assignment"),
    ]
    chains = resolve_chains(findings)
    ids = [c.id for c in chains]
    assert "env-file-to-admin-takeover" in ids


def test_generate_matched_has_all_prereqs():
    out = auto_chain.generate([
        _v("xxe-probe"),
        _v("host-header-injection"),
    ])
    match = next((c for c in out if c.id == "auto-xxe-plus-host-header"),
                 None)
    assert match is not None
    matched_ids = [m["pattern_id"] for m in match.matched]
    assert "xxe-probe" in matched_ids
    assert "host-header-injection" in matched_ids
