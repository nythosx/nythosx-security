def _finding(pid, verdict="VULNERABLE", confidence=None):
    return {"pattern_id": pid, "verdict": verdict, "confidence": confidence}


def test_confirmed_when_all_vulnerable():
    from engine.correlator import resolve_chains
    findings = [_finding("env-file-exposure"),
                _finding("mass-assignment")]
    chains = resolve_chains(findings, threshold=0.7)
    target = next(c for c in chains if c.id == "env-file-to-admin-takeover")
    assert target.verdict == "CONFIRMED"
    assert not target.missing
    assert target.confidence > 0.7


def test_incomplete_when_missing():
    from engine.correlator import resolve_chains
    findings = [_finding("env-file-exposure")]
    chains = resolve_chains(findings)
    target = next(c for c in chains if c.id == "env-file-to-admin-takeover")
    assert target.verdict == "INCOMPLETE"
    assert "mass-assignment" in target.missing


def test_theoretical_when_suspicious():
    from engine.correlator import resolve_chains
    findings = [_finding("env-file-exposure", "SUSPICIOUS"),
                _finding("mass-assignment", "SUSPICIOUS")]
    chains = resolve_chains(findings)
    target = next(c for c in chains if c.id == "env-file-to-admin-takeover")
    assert target.verdict == "THEORETICAL"


def test_confidence_geometric_mean():
    from engine.correlator import resolve_chains
    findings = [_finding("env-file-exposure", "VULNERABLE", 0.9),
                _finding("mass-assignment", "VULNERABLE", 0.4)]
    chains = resolve_chains(findings)
    target = next(c for c in chains if c.id == "env-file-to-admin-takeover")
    assert 0.4 < target.confidence < 0.9


def test_empty_findings_all_incomplete():
    from engine.correlator import resolve_chains
    chains = resolve_chains([])
    for c in chains:
        assert c.verdict == "INCOMPLETE"


def test_findings_accepted_as_scanresult_like():
    from engine.correlator import resolve_chains
    from engine.contract import ScanResult
    r1 = ScanResult(capability="env-file-exposure", target="http://t",
                    verdict="VULNERABLE", confidence=0.9)
    r2 = ScanResult(capability="mass-assignment", target="http://t",
                    verdict="VULNERABLE", confidence=0.85)
    chains = resolve_chains([r1, r2])
    target = next(c for c in chains if c.id == "env-file-to-admin-takeover")
    assert target.verdict == "CONFIRMED"


def test_narrative_render_contains_name_and_steps():
    from engine.correlator import resolve_chains, render
    chains = resolve_chains([_finding("env-file-exposure"),
                             _finding("mass-assignment")])
    target = next(c for c in chains if c.id == "env-file-to-admin-takeover")
    text = render(target)
    assert "Env File to Admin Takeover" in text
    assert "CONFIRMED" in text
    assert "env-file-exposure" in text
