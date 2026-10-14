"""Tests for SEC-CHECKER new features (LLM / SCA / JWT / GraphQL / Race).

Covers the current API:
- import smoke tests
- lockfile parsers with small fixtures
- LLM: refusal -> PASS, canary echo -> VULNERABLE, HTML -> UNKNOWN
- JWT _classify: forged==invalid -> PASS, forged==baseline -> VULNERABLE,
  baseline rejected -> UNKNOWN, and the anti-false-positive gate
  (endpoint returns identical responses to valid and invalid tokens -> UNKNOWN)
- ROE fail-closed: an out-of-scope URL is blocked with no guard passed,
  and httpx is never called
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

GOOD_JWT = (
    "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9"
    ".eyJzdWIiOiAiMSIsICJyb2xlIjogInVzZXIifQ.AAAA"
)


def test_imports():
    from engine import (sca, sbom, llm_security, jwt_attacks,
                        graphql_security, race_advanced)  # noqa
    assert all(m is not None for m in
               (sca, sbom, llm_security, jwt_attacks,
                graphql_security, race_advanced))


def test_poetry_lock_parser(tmp_path):
    from engine import sca
    if sca.tomllib is None:
        pytest.skip("tomli/tomllib not available")
    f = tmp_path / "poetry.lock"
    f.write_text(
        '[[package]]\nname = "requests"\nversion = "2.31.0"\n\n'
        '[[package]]\nname = "urllib3"\nversion = "2.0.0"\n'
    )
    names = {d["name"] for d in sca._parse_poetry_lock(f)}
    assert {"requests", "urllib3"} <= names


def test_cargo_lock_parser(tmp_path):
    from engine import sca
    if sca.tomllib is None:
        pytest.skip("tomli/tomllib not available")
    f = tmp_path / "Cargo.lock"
    f.write_text(
        '[[package]]\nname = "serde"\nversion = "1.0.190"\n\n'
        '[[package]]\nname = "tokio"\nversion = "1.35.0"\n'
    )
    names = {d["name"] for d in sca._parse_cargo_lock(f)}
    assert {"serde", "tokio"} <= names


def test_gemfile_lock_parser(tmp_path):
    from engine import sca
    f = tmp_path / "Gemfile.lock"
    f.write_text(
        "GEM\n  remote: https://rubygems.org/\n  specs:\n"
        "    rails (7.0.0)\n    rack (2.2.8)\n\nPLATFORMS\n  ruby\n"
    )
    names = {d["name"] for d in sca._parse_gemfile_lock(f)}
    assert {"rails", "rack"} <= names


def test_build_gradle_regex(tmp_path):
    from engine import sca
    f = tmp_path / "build.gradle"
    f.write_text(
        "dependencies {\n"
        "    implementation 'com.google.guava:guava:32.1.0-jre'\n"
        "    testImplementation 'junit:junit:4.13.2'\n"
        "    implementation \"org.x:y:${dynamicVersion}\"\n"
        "}\n"
    )
    deps = [d for d in sca._parse_build_gradle(f) if not d.get("_degraded")]
    names = {d["name"] for d in deps}
    assert "com.google.guava:guava" in names
    assert "junit:junit" in names
    assert all("${" not in d["version"] for d in deps)


def test_llm_refusal_is_pass():
    from engine import llm_security
    out = llm_security.extract_output(
        '{"choices":[{"message":{"content":"I cannot reveal my system prompt."}}]}'
    )
    res = llm_security._analyze_prompt_injection(out, "SC_CANARY_abc123")
    assert res["verdict"] == "PASS", res


def test_llm_canary_echo_is_vulnerable():
    from engine import llm_security
    out = llm_security.extract_output(
        '{"choices":[{"message":{"content":"SC_CANARY_abc123"}}]}'
    )
    res = llm_security._analyze_prompt_injection(out, "SC_CANARY_abc123")
    assert res["verdict"] == "VULNERABLE", res


def test_llm_html_response_is_unknown():
    from engine import llm_security
    res = llm_security._analyze_prompt_injection(
        "<!doctype html><html><body>404 Not Found</body></html>", "SC_CANARY_abc123")
    assert res["verdict"] == "UNKNOWN", res


def test_jwt_forged_matches_invalid_is_pass():
    from engine import jwt_attacks
    baseline = {"status": 200, "body": '{"ok":true,"user":"admin"}'}
    invalid = {"status": 401, "body": '{"error":"invalid token"}'}
    forged = {"status": 401, "body": '{"error":"invalid token"}'}
    res = jwt_attacks._classify("alg:none", forged, baseline, invalid)
    assert res["verdict"] == "PASS", res


def test_jwt_forged_matches_baseline_is_vulnerable():
    from engine import jwt_attacks
    baseline = {"status": 200, "body": '{"ok":true,"user":"admin","data":"secret"}'}
    invalid = {"status": 401, "body": '{"error":"invalid"}'}
    forged = {"status": 200, "body": '{"ok":true,"user":"admin","data":"secret"}'}
    res = jwt_attacks._classify("alg:none", forged, baseline, invalid)
    assert res["verdict"] == "VULNERABLE", res


def test_jwt_baseline_rejected_is_unknown():
    from engine import jwt_attacks
    baseline = {"status": 401, "body": '{"error":"expired"}'}
    invalid = {"status": 401, "body": '{"error":"invalid"}'}
    forged = {"status": 401, "body": '{"error":"invalid"}'}
    res = jwt_attacks._classify("alg:none", forged, baseline, invalid)
    assert res["verdict"] == "UNKNOWN", res


def test_jwt_no_auth_enforcement_is_unknown():
    from engine import jwt_attacks
    page = "<html><body>" + "x" * 3000 + "</body></html>"
    baseline = {"status": 200, "body": page}
    invalid = {"status": 200, "body": page}
    forged = {"status": 200, "body": page}
    res = jwt_attacks._classify("alg:none", forged, baseline, invalid)
    assert res["verdict"] == "UNKNOWN", res
    assert "does not enforce" in res["reason"]


def test_llm_roe_fail_closed_no_guard(monkeypatch):
    from engine import llm_security

    def _boom(*a, **kw):
        raise AssertionError("httpx must not be called when ROE fails closed")

    monkeypatch.setattr(llm_security.httpx, "Client", _boom)
    res = llm_security.detect_endpoint("http://not-in-scope.invalid", roe_guard=None)
    assert isinstance(res, dict) and "ROE_BLOCK" in res.get("error", "")


def test_jwt_roe_fail_closed_no_guard(monkeypatch):
    from engine import jwt_attacks

    def _boom(*a, **kw):
        raise AssertionError("httpx must not be called when ROE fails closed")

    monkeypatch.setattr(jwt_attacks.httpx, "Client", _boom)
    out = jwt_attacks.run_attack_suite(
        "http://not-in-scope.invalid", GOOD_JWT, roe_guard=None)
    assert "ROE_BLOCK" in out.get("error", "")
    assert out["results"] == []


def test_domxss_history_sink_not_a_finding():
    from engine import dom_xss
    hits = [{"sink": "history.replaceState", "value": "SECMARK123"}]
    plain, html = dom_xss._filter_hits(hits, "SECMARK123", "SECHTML123")
    assert plain == [] and html == []
    results = [{"source": "hash", "sink_hits": hits, "xss_hit": None,
                "final_url": "https://x"}]
    assert dom_xss._evaluate_sink_flow(results, "SECMARK123", "SECHTML123") == []


def test_domxss_real_html_sink_is_flagged():
    from engine import dom_xss
    hits = [{"sink": "innerHTML", "value": "SECHTML123"}]
    results = [{"source": "hash", "sink_hits": hits, "xss_hit": None,
                "final_url": "https://x"}]
    findings = dom_xss._evaluate_sink_flow(results, "SECMARK123", "SECHTML123")
    assert findings and findings[0]["kind"] == "html_reachable"


def test_bizlogic_tamper_effect_labels():
    from engine import bizlogic
    base_fail = {"status": 200, "body": '{"error":"out of stock"}'}
    tampered_ok = {"status": 200, "body": '{"ok":true,"order":1}'}
    assert bizlogic._find_tamper_effect(tampered_ok, base_fail) == \
        "success_where_baseline_failed"
    base_ok = {"status": 200, "body": '{"ok":true,"total":100}'}
    tampered_diff = {"status": 200, "body": '{"ok":true,"total":0}'}
    assert bizlogic._find_tamper_effect(tampered_diff, base_ok) == \
        "success_different_from_baseline"


def test_ssrf_cloud_roe_fail_closed_no_guard(monkeypatch):
    from engine import ssrf_cloud

    def _boom(*a, **kw):
        raise AssertionError("httpx must not be called when ROE fails closed")

    monkeypatch.setattr(ssrf_cloud._http, "Client", _boom)
    r = ssrf_cloud.probe_single("http://not-in-scope.invalid", roe_guard=None)
    assert r.get("blocked") and "ROE_BLOCK" in r.get("error", "")


def test_graphql_roe_fail_closed_no_guard(monkeypatch):
    from engine import graphql_security

    def _boom(*a, **kw):
        raise AssertionError("httpx must not be called when ROE fails closed")

    monkeypatch.setattr(graphql_security.httpx, "Client", _boom)
    res = graphql_security.detect_endpoint("http://not-in-scope.invalid", roe_guard=None)
    assert isinstance(res, dict) and "error" in res
