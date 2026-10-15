from engine.chain_engine import ChainOrchestrator


class _Allow:
    def check_url(self, url, method="GET"):
        return True


def _orch(**kw):
    o = ChainOrchestrator("http://test.local", roe_guard=_Allow(),
                          engine_cfg={}, **kw)
    o.run_recon = lambda: None
    return o


def test_specific_reason_preserved_when_already_set():
    o = _orch()
    o.stopped_reason = "http duration budget exceeded (900s/900s)"
    o._budget_exceeded = lambda: True
    assert o._stop_condition() is True
    assert "duration budget exceeded" in o.stopped_reason
    assert o.stopped_reason != "budget exceeded"


def test_generic_reason_set_when_none():
    o = _orch()
    o.stopped_reason = None
    o._budget_exceeded = lambda: True
    assert o._stop_condition() is True
    assert o.stopped_reason == "budget exceeded"


def test_kill_on_vuln_preserves_specific_reason():
    o = _orch(kill_on_vuln=True)
    o.stopped_reason = "http budget exceeded (250/500)"
    o._budget_exceeded = lambda: False
    o.findings.append({"verdict": "VULNERABLE"})
    assert o._stop_condition() is True
    assert "http budget exceeded" in o.stopped_reason
    assert "kill_on_vuln" not in o.stopped_reason


def test_kill_on_vuln_sets_generic_reason_when_none():
    o = _orch(kill_on_vuln=True)
    o.stopped_reason = None
    o._budget_exceeded = lambda: False
    o.findings.append({"verdict": "VULNERABLE"})
    assert o._stop_condition() is True
    assert o.stopped_reason == "kill_on_vuln: first finding recorded"
