import json

import pytest

from engine import chainscore as cs


def _chain(cid, steps=1, vuln_class=None):
    c = {"id": cid, "steps": [{"id": f"s{i}", "tool": "t",
                               "oracle": cid} for i in range(steps)]}
    if vuln_class:
        c["vuln_class"] = vuln_class
    return c


# ---- probability model ---------------------------------------------------

def test_beta_posterior_prior():
    # no data -> prior mean alpha/(alpha+beta) = 1/10
    assert abs(cs.beta_posterior(0, 0) - 0.1) < 1e-9


def test_beta_posterior_updates_with_hits():
    p0 = cs.beta_posterior(0, 0)
    p1 = cs.beta_posterior(8, 10)
    assert p1 > p0


def test_p_vuln_uses_framework_slot():
    stats = {"vuln": {"data_exposure|express": {"attempts": 10, "hits": 9}},
             "oracle": {}}
    c = _chain("bola-chain")
    high = cs.p_vuln(c, "express", stats)
    low = cs.p_vuln(c, "django", stats)  # falls back to generic -> prior
    assert high > low


def test_p_fp_worst_oracle():
    stats = {"vuln": {}, "oracle": {
        "sqli": {"confirmed": 1, "fp": 9},
        "xss": {"confirmed": 10, "fp": 0}}}
    c = {"id": "x", "steps": [{"oracle": "sqli"}, {"oracle": "xss"}]}
    assert abs(cs.p_fp(c, stats) - 0.9) < 1e-9


# ---- weights / novelty / cost --------------------------------------------

def test_impact_value_classes_ordered():
    w = cs.load_weights()
    assert w["credential_access"] > w["data_exposure"] > w["info_disclosure"]


def test_novelty_bonus_for_bizlogic():
    assert cs.novelty_bonus(_chain("bizlogic-chain")) == cs.NOVELTY_BONUS
    assert cs.novelty_bonus(_chain("xss-chain")) == 1.0


def test_est_cost_scales_with_steps():
    assert cs.est_cost(_chain("a", steps=3)) > cs.est_cost(_chain("a", steps=1))


# ---- EV + selection -------------------------------------------------------

def test_scorer_prefers_high_prior_high_impact():
    stats = {"vuln": {
        "credential_access|generic": {"attempts": 10, "hits": 9},
        "info_disclosure|generic": {"attempts": 10, "hits": 1}},
        "oracle": {}}
    high = _chain("jwt-chain")           # credential_access, high prior
    low = _chain("cve-chain")            # info_disclosure, low prior
    ranked = cs.rank_chains_ev([low, high], framework="generic", stats=stats)
    assert ranked[0]["id"] == "jwt-chain"


def test_ev_subtracts_cost():
    stats = {"vuln": {}, "oracle": {}}
    cheap = _chain("info", steps=1, vuln_class="info_disclosure")
    ev = cs.expected_value(cheap, "generic", stats)
    # prior 0.1 * 50 * 1 * 1 - (1*6) = 5 - 6 = -1
    assert ev == pytest.approx(0.1 * 50 - 6, abs=1e-6)


def test_beam_search_deterministic_and_optimal():
    stats = {"vuln": {
        "credential_access|generic": {"attempts": 10, "hits": 9},
        "data_exposure|generic": {"attempts": 10, "hits": 7},
        "info_disclosure|generic": {"attempts": 10, "hits": 1}},
        "oracle": {}}
    chains = [_chain("jwt-chain"), _chain("bola-chain"), _chain("cve-chain")]
    plan1 = cs.beam_search(chains, framework="generic", stats=stats)
    plan2 = cs.beam_search(chains, framework="generic", stats=stats)
    assert [c["id"] for c in plan1] == [c["id"] for c in plan2]  # deterministic
    assert len(plan1) == cs.BEAM_DEPTH
    assert plan1[0]["id"] == "jwt-chain"  # highest EV first


def test_golden_score_ordering_stable():
    stats = {"vuln": {}, "oracle": {}}
    chains = [_chain("xss-chain"), _chain("jwt-chain"), _chain("bola-chain"),
              _chain("cve-chain"), _chain("graphql-chain")]
    order = [c["id"] for c in cs.rank_chains_ev(chains, "generic", stats)]
    # flat priors: EV = 0.1*impact*novelty - cost. graphql_deep gets the
    # 2.0x novelty bonus, lifting it above data_exposure.
    assert order == ["jwt-chain", "graphql-chain", "bola-chain",
                     "xss-chain", "cve-chain"]


# ---- stats persistence ----------------------------------------------------

def test_record_and_load_roundtrip(tmp_path):
    path = tmp_path / "chains.jsonl"
    cs.record_run([
        {"vuln_class": "data_exposure", "framework": "express",
         "attempts": 1, "hits": 1},
        {"oracle": "sqli", "confirmed": 1, "fp": 0}], path=path)
    cs.record_run([
        {"vuln_class": "data_exposure", "framework": "express",
         "attempts": 1, "hits": 0}], path=path)
    stats = cs.load_stats(path=path)
    slot = stats["vuln"]["data_exposure|express"]
    assert slot["attempts"] == 2 and slot["hits"] == 1
    assert stats["oracle"]["sqli"]["confirmed"] == 1
