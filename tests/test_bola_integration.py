import pytest

from engine.bola_confirm import (
    BolaDecision, classify, build_evidence,
    CONFIRMED, REFUTED, INCONCLUSIVE,
)


def test_confirmed_when_only_b_returns_200():
    a = {"/x/1": {"status": 403, "body": "denied"}}
    b = {"/x/1": {"status": 200, "body": "secret-b"}}
    d = classify(a, b, ["/x/1"])
    assert d.status == CONFIRMED
    assert "cross-user" in d.reason
    assert d.proof["basis"] == "user_a token read user_b resource"


def test_confirmed_when_both_return_distinct_200():
    a = {"/x/1": {"status": 200, "body": "a-data"}}
    b = {"/x/1": {"status": 200, "body": "b-data"}}
    d = classify(a, b, ["/x/1"])
    assert d.status == CONFIRMED
    assert "/x/1" in d.proof["both_200_distinct"]


def test_refuted_when_identical_bodies():
    a = {"/x/1": {"status": 200, "body": "public"}}
    b = {"/x/1": {"status": 200, "body": "public"}}
    d = classify(a, b, ["/x/1"])
    assert d.status == REFUTED
    assert d.proof["basis"] == "both sessions returned identical bodies"


def test_refuted_when_only_a_reaches_resource():
    a = {"/x/1": {"status": 200, "body": "a-only"}}
    b = {"/x/1": {"status": 403, "body": "denied"}}
    d = classify(a, b, ["/x/1"])
    assert d.status == REFUTED


def test_inconclusive_when_missing_responses():
    d = classify({}, {"/x/1": {"status": 200}}, ["/x/1"])
    assert d.status == INCONCLUSIVE


def test_evidence_signed():
    d = BolaDecision(CONFIRMED, "test", {"paths_checked": ["/x/1"]})
    ev = build_evidence(d, "http://example.com")
    assert "signature" in ev
    assert ev["status"] == CONFIRMED
    assert len(ev["signature"]) == 64
