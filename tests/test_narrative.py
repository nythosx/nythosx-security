import json

from engine.brains.narrative import NarrativeWriter


_FINDINGS = [
    {"pattern_id": "jwt-weak-secret", "verdict": "VULNERABLE",
     "severity": "critical", "reason": "hmac cracked"},
    {"pattern_id": "cors-wildcard", "verdict": "SUSPICIOUS",
     "severity": "high", "reason": "reflected"},
]


_CHAINS = [
    {"id": "jwt-chain", "verdict": "CONFIRMED"},
    {"id": "graphql-chain", "verdict": "PASS"},
]


_COVERAGE = {"executed_count": 5, "total_count": 10}


def test_offline_returns_template_summary():
    nw = NarrativeWriter(client=None)
    summary = nw.executive_summary(_FINDINGS, _CHAINS, _COVERAGE)
    assert isinstance(summary, str)
    assert len(summary) > 10
    assert "1 confirmed" in summary or "vulnerability" in summary


def test_offline_no_findings():
    nw = NarrativeWriter(client=None)
    summary = nw.executive_summary([], [], _COVERAGE)
    assert isinstance(summary, str)
    assert "0 finding" in summary or "none" in summary


def test_client_returns_summary():
    def client(prompt):
        return json.dumps({"summary": "Critical JWT flaw enables full account takeover across the API."})
    nw = NarrativeWriter(client=client)
    summary = nw.executive_summary(_FINDINGS, _CHAINS, _COVERAGE)
    assert "account takeover" in summary


def test_garbage_falls_back():
    nw = NarrativeWriter(client=lambda p: "not json")
    summary = nw.executive_summary(_FINDINGS, _CHAINS, _COVERAGE)
    assert isinstance(summary, str)
    assert len(summary) > 10


def test_too_short_summary_rejected():
    nw = NarrativeWriter(client=lambda p: json.dumps({"summary": "short"}))
    summary = nw.executive_summary(_FINDINGS, _CHAINS, _COVERAGE)
    assert len(summary) > 10


def test_canary_in_summary_rejected():
    nw = NarrativeWriter(client=lambda p: "x")
    leaked = json.dumps({"summary": "leak " + nw._canary + " " * 50})
    nw2 = NarrativeWriter(client=lambda p: leaked)
    summary = nw2.executive_summary(_FINDINGS, _CHAINS, _COVERAGE)
    assert nw2._canary not in summary
