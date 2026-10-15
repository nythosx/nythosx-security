from engine import capgraph as cg


def _f(fid, pattern, severity="high"):
    return {"id": fid, "pattern_id": pattern, "verdict": "VULNERABLE",
            "severity": severity}


# ---- map + edges ---------------------------------------------------------

def test_load_map_has_defaults():
    m = cg.load_capability_map()
    assert m["jwt_weak_secret"]["grants"] == "obtain_token"


def test_add_finding_creates_edges():
    g = cg.CapabilityGraph()
    g.add_finding(_f(1, "jwt-weak-secret"))
    assert any(e.src == "anon" and e.dst == "obtain_token" for e in g.edges)


def test_unknown_finding_class_no_edge():
    g = cg.CapabilityGraph()
    assert g.add_finding(_f(1, "totally-unknown-xyz")) == []


# ---- BFS / attack paths --------------------------------------------------

def test_no_chain_for_single_step():
    # weak jwt alone only reaches obtain_token (not a target), no >=2 path
    chains = cg.analyze([_f(1, "jwt-weak-secret")])
    assert chains == []


def test_two_step_chain_jwt_plus_idor():
    findings = [_f(1, "jwt-weak-secret", "high"),
                _f(2, "idor", "high")]
    chains = cg.analyze(findings)
    assert chains, "expected a capability chain"
    c = chains[0]
    assert c["n_steps"] == 2
    assert c["path"] == ["anon", "obtain_token", "write_data"]
    assert set(c["finding_ids"]) == {1, 2}


def test_severity_bumped_above_worst_component():
    findings = [_f(1, "jwt-weak-secret", "high"),
                _f(2, "idor", "high")]
    c = cg.analyze(findings)[0]
    assert c["severity"] == "critical"  # high -> +1 -> critical


def test_severity_bump_capped_at_critical():
    findings = [_f(1, "jwt-weak-secret", "critical"),
                _f(2, "idor", "critical")]
    c = cg.analyze(findings)[0]
    assert c["severity"] == "critical"


def test_chain_render_markdown():
    findings = [_f(1, "jwt-weak-secret"), _f(2, "idor")]
    g = cg.CapabilityGraph().build(findings)
    chains = g.chain_findings()
    md = g.render_markdown(chains[0])
    assert "2-step attack path" in md
    assert "finding `1`" in md and "finding `2`" in md


def test_mass_assignment_reaches_escalate_role():
    findings = [_f(1, "jwt-weak-secret"), _f(2, "mass_assignment")]
    chains = cg.analyze(findings)
    assert any("escalate_role" in c["path"] for c in chains)


# ---- acceptance: weak JWT + IDOR on the local test app -------------------

def test_acceptance_weak_jwt_plus_idor_two_step_chain():
    # These two findings model what a scan of tests/testapp produces:
    #   - jwt-weak-secret: the app ships a HS256 token signed with "secret"
    #   - idor: /api/doc/{id} lets any authed caller read another's record
    findings = [
        {"id": 101, "pattern_id": "jwt-weak-secret", "verdict": "VULNERABLE",
         "severity": "high", "reason": "HS256 token cracked"},
        {"id": 102, "pattern_id": "idor", "verdict": "VULNERABLE",
         "severity": "high", "reason": "cross-account doc read"},
    ]
    chains = cg.analyze(findings)
    assert len(chains) >= 1
    c = chains[0]
    assert c["n_steps"] == 2
    assert c["finding_ids"] == [101, 102] or set(c["finding_ids"]) == {101, 102}
    assert c["path"][-1] in cg.TARGET_VERBS
