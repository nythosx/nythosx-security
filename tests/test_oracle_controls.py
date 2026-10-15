import pytest

from engine.oracles import controls as ctl
from engine.facts import FactStore


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda *a, **k: None)


# ---- negative_control mutations ------------------------------------------

def test_negative_control_known_families():
    assert ctl.negative_control("xss", "<script>") == "<img src=x onerr"
    assert ctl.negative_control("sqli", "' OR 1=1--") == "'''"
    assert ctl.negative_control("ssrf", "http://x").startswith("zzz://")


def test_negative_control_prefix_match():
    assert ctl.negative_control("xss-stored", "p") == "<img src=x onerr"


def test_negative_control_generic_fallback():
    assert ctl.negative_control("totally-unknown", "abc").startswith(
        "benign-control-")


# ---- OracleGate: over-matching oracle suppressed -------------------------

def _vuln(_payload):
    return {"verdict": "VULNERABLE", "reason": "fires on everything"}


def test_over_matching_oracle_suppressed_and_disabled():
    fs = FactStore()
    gate = ctl.OracleGate(fact_store=fs, sleep=lambda *_: None)
    res = gate.run("xss", _vuln, {"verdict": "VULNERABLE"},
                   exploit_payload="<script>")
    assert res.status == ctl.SUPPRESSED
    assert res.control_fired is True
    assert gate.is_disabled("xss")
    assert fs.get("oracle_unsound:xss")


def test_disabled_oracle_short_circuits():
    gate = ctl.OracleGate(sleep=lambda *_: None)
    gate.disable_oracle("sqli", "manual")
    res = gate.run("sqli", _vuln, {"verdict": "VULNERABLE"})
    assert res.status == ctl.SUPPRESSED
    assert res.stage == "disabled"


def test_benign_args_firing_suppresses():
    gate = ctl.OracleGate(fact_store=FactStore(), sleep=lambda *_: None)
    res = gate.run("sqli", _vuln, {"verdict": "VULNERABLE"},
                   benign_payload="1", exploit_payload="' OR 1=1--")
    assert res.status == ctl.SUPPRESSED
    assert res.stage == "benign"
    assert gate.is_disabled("sqli")


# ---- OracleGate: sound oracle survives -----------------------------------

def _sound_probe(payload):
    # Fires ONLY for the real exploit; negative control / benign do not fire.
    if payload == "' OR 1=1-- -":
        return {"verdict": "VULNERABLE", "reason": "union reflected"}
    return {"verdict": "PASS", "reason": "no reflection"}


def test_sound_oracle_confirms():
    gate = ctl.OracleGate(fact_store=FactStore(), sleep=lambda *_: None)
    res = gate.run("sqli", _sound_probe, {"verdict": "VULNERABLE"},
                   exploit_payload="' OR 1=1-- -")
    assert res.status == ctl.CONFIRMED
    assert res.control_fired is False
    assert res.rerun_verdict == "VULNERABLE"


def test_sound_oracle_flaky_rerun_downgrades():
    calls = {"n": 0}

    def flaky(payload):
        if payload == "exploit":
            calls["n"] += 1
            # first (initial not routed here); rerun returns PASS
            return {"verdict": "PASS" if calls["n"] else "VULNERABLE"}
        return {"verdict": "PASS"}
    gate = ctl.OracleGate(sleep=lambda *_: None)
    res = gate.run("sqli", flaky, {"verdict": "VULNERABLE"},
                   exploit_payload="exploit")
    assert res.status == ctl.SUSPICIOUS
    assert res.stage == "rerun"


# ---- cross-oracle corroboration ------------------------------------------

def test_corroborate_two_families_confirm():
    status, _ = ctl.corroborate([
        {"family": "sqli", "confidence": 0.7},
        {"family": "timing", "confidence": 0.6},
    ])
    assert status == ctl.CONFIRMED


def test_corroborate_single_high_confidence_with_passing_control():
    status, _ = ctl.corroborate([
        ctl.OracleSignal("sqli", 0.97, negative_control_passed=True),
    ])
    assert status == ctl.CONFIRMED


def test_corroborate_single_high_confidence_failed_control_downgrades():
    status, _ = ctl.corroborate([
        ctl.OracleSignal("sqli", 0.97, negative_control_passed=False),
    ])
    assert status == ctl.SUSPICIOUS


def test_corroborate_single_low_confidence_suspicious():
    status, _ = ctl.corroborate([{"family": "sqli", "confidence": 0.6}])
    assert status == ctl.SUSPICIOUS


# ---- chain_engine integration --------------------------------------------

from engine.chain_engine import ChainOrchestrator


class _Allow:
    def check_url(self, url, method="GET"):
        return True


def _orch(handlers):
    o = ChainOrchestrator("http://test.local", roe_guard=_Allow(),
                          engine_cfg={}, allow_destructive=True)
    o.run_recon = lambda: None
    o._TOOL_HANDLERS = handlers
    o._is_idempotent_tool = lambda name: True
    return o


def _chain(step_extra):
    step = {"id": "s1", "tool": "t"}
    step.update(step_extra)
    return {"id": "c", "name": "c",
            "trigger": {"mode": "any", "conditions": [{"fact": "framework"}]},
            "steps": [step]}


def test_chain_over_matching_oracle_suppressed(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda *a, **k: None)

    def tool(orch, args):
        # Over-matches: fires VULNERABLE for any payload incl. the control.
        return {"verdict": "VULNERABLE", "reason": "boom", "evidence": {}}
    o = _orch({"t": tool})
    o.add_fact("framework", "generic")
    result = o.execute_chain(_chain({
        "oracle": "xss",
        "args": {"payload": "<script>alert(1)</script>"},
    }))
    s = result["steps"][0]
    assert s["verdict"] == "PASS"
    assert s["confirmation_status"] == "tool_unsound"
    assert o._oracle_gate.is_disabled("xss")


def test_chain_sound_oracle_confirmed(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda *a, **k: None)
    exploit = "<svg/onload=alert(1)>"

    def tool(orch, args):
        if args.get("payload") == exploit:
            return {"verdict": "VULNERABLE", "reason": "reflected",
                    "evidence": {}}
        return {"verdict": "PASS", "reason": "neutralised", "evidence": {}}
    o = _orch({"t": tool})
    o.add_fact("framework", "generic")
    result = o.execute_chain(_chain({
        "oracle": "xss",
        "args": {"payload": exploit},
    }))
    s = result["steps"][0]
    assert s["verdict"] == "VULNERABLE"
    assert s["confirmation_status"] == "confirmed"
    assert not o._oracle_gate.is_disabled("xss")
