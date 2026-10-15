"""Phase 6 — Expected-Value Chain Scoring.

Replaces the heuristic priority score with an expected-value model:

    EV = P_vuln * impact_value * (1 - P_fp) * novelty_bonus - est_cost

  * impact_value  — per-vuln-class dollar weight (impact_weights.yaml).
  * P_vuln        — Bayesian per (vuln_class, framework): Beta posterior
                    P = (hits + alpha) / (attempts + alpha + beta),
                    alpha=1, beta=9. Persisted to stats/chains.jsonl.
  * P_fp          — per-oracle historical false-positive rate
                    (FP / ever-confirmed), from the same stats file.
  * novelty_bonus — 2.0x for bizlogic / graphql_deep / mass_assignment.
  * est_cost      — chain step count x probe fanout.

Selection is an exact beam search (width 5, depth 2) over the chain set,
maximising cumulative EV, recomputed after each chain completes. The legacy
heuristic (`engine.scoring`) stays available behind `--legacy-scoring`.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

ROOT = Path(__file__).parent.parent.absolute()
STATS_FILE = ROOT / "stats" / "chains.jsonl"
IMPACT_WEIGHTS = ROOT / "configs" / "impact_weights.yaml"

ALPHA = 1.0
BETA = 9.0
PROBE_FANOUT = 6
BEAM_WIDTH = 5
BEAM_DEPTH = 2

NOVELTY_CLASSES = {"bizlogic", "graphql_deep", "mass_assignment"}
NOVELTY_BONUS = 2.0

_DEFAULT_WEIGHTS = {
    "credential_access": 1000.0,
    "session_hijack": 1000.0,
    "data_exposure": 600.0,
    "bizlogic": 550.0,
    "mass_assignment": 500.0,
    "graphql_deep": 450.0,
    "defacement": 200.0,
    "info_disclosure": 50.0,
    "default": 100.0,
}

# chain id/family -> vuln_class (for impact + novelty lookup)
_CHAIN_CLASS = {
    "jwt-chain": "credential_access",
    "oauth-chain": "credential_access",
    "bola-chain": "data_exposure",
    "unauth-exposure-chain": "data_exposure",
    "data-extraction-chain": "data_exposure",
    "blind-sqli-chain": "data_exposure",
    "bizlogic-chain": "bizlogic",
    "race-chain": "bizlogic",
    "graphql-chain": "graphql_deep",
    "graphql-schema-chain": "graphql_deep",
    "xss-chain": "defacement",
    "injection-family-chain": "data_exposure",
    "ssrf-chain": "data_exposure",
    "cve-chain": "info_disclosure",
}


def _vuln_class(chain):
    if chain.get("vuln_class"):
        return chain["vuln_class"]
    cid = chain.get("id", "")
    if cid in _CHAIN_CLASS:
        return _CHAIN_CLASS[cid]
    for key, cls in _CHAIN_CLASS.items():
        if cid.startswith(key.replace("-chain", "")):
            return cls
    return "default"


# ---- stats persistence ---------------------------------------------------

def load_stats(path=None):
    """Aggregate stats/chains.jsonl into per-(class,framework) and per-oracle
    counters. Returns {"vuln": {...}, "oracle": {...}}.
    """
    p = Path(path) if path else STATS_FILE
    vuln = {}
    oracle = {}
    if not p.exists():
        return {"vuln": vuln, "oracle": oracle}
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        vc = rec.get("vuln_class")
        fw = rec.get("framework") or "generic"
        if vc:
            key = f"{vc}|{fw}"
            slot = vuln.setdefault(key, {"attempts": 0, "hits": 0})
            slot["attempts"] += int(rec.get("attempts", 0) or 0)
            slot["hits"] += int(rec.get("hits", 0) or 0)
        orc = rec.get("oracle")
        if orc:
            oslot = oracle.setdefault(orc, {"confirmed": 0, "fp": 0})
            oslot["confirmed"] += int(rec.get("confirmed", 0) or 0)
            oslot["fp"] += int(rec.get("fp", 0) or 0)
    return {"vuln": vuln, "oracle": oracle}


def record_run(entries, path=None):
    """Append run records (list of dicts) to stats/chains.jsonl."""
    p = Path(path) if path else STATS_FILE
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a", encoding="utf-8") as fh:
        for e in entries or []:
            fh.write(json.dumps(e, default=str) + "\n")
    return str(p)


# ---- probability model ---------------------------------------------------

def beta_posterior(hits, attempts, alpha=ALPHA, beta=BETA):
    return (hits + alpha) / (attempts + alpha + beta)


def p_vuln(chain, framework, stats):
    vc = _vuln_class(chain)
    fw = framework or "generic"
    slot = (stats.get("vuln") or {}).get(f"{vc}|{fw}")
    if slot is None:
        slot = (stats.get("vuln") or {}).get(f"{vc}|generic")
    hits = slot["hits"] if slot else 0
    attempts = slot["attempts"] if slot else 0
    return beta_posterior(hits, attempts)


def _chain_oracles(chain):
    orc = set()
    for s in chain.get("steps") or []:
        orc.add(s.get("oracle") or s.get("tool") or "")
    return {o for o in orc if o}


def p_fp(chain, stats):
    """Max per-oracle FP rate across the chain's oracles (worst case)."""
    omap = stats.get("oracle") or {}
    worst = 0.0
    for o in _chain_oracles(chain):
        slot = omap.get(o)
        if not slot:
            continue
        denom = slot["confirmed"] + slot["fp"]
        if denom <= 0:
            continue
        worst = max(worst, slot["fp"] / denom)
    return worst


# ---- weights / novelty / cost --------------------------------------------

def load_weights(path=None):
    data = dict(_DEFAULT_WEIGHTS)
    p = Path(path) if path else IMPACT_WEIGHTS
    if p.exists():
        try:
            import yaml
            loaded = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            if isinstance(loaded, dict):
                data.update({k: float(v) for k, v in loaded.items()})
        except Exception:
            pass
    return data


def impact_value(chain, weights=None):
    weights = weights or load_weights()
    vc = _vuln_class(chain)
    return weights.get(vc, weights.get("default", 100.0))


def novelty_bonus(chain):
    return NOVELTY_BONUS if _vuln_class(chain) in NOVELTY_CLASSES else 1.0


def est_cost(chain):
    steps = len(chain.get("steps") or []) or 1
    return float(steps * PROBE_FANOUT)


# ---- expected value ------------------------------------------------------

def expected_value(chain, framework=None, stats=None, weights=None):
    stats = stats if stats is not None else load_stats()
    weights = weights if weights is not None else load_weights()
    pv = p_vuln(chain, framework, stats)
    iv = impact_value(chain, weights)
    pfp = p_fp(chain, stats)
    nov = novelty_bonus(chain)
    return pv * iv * (1.0 - pfp) * nov - est_cost(chain)


def score_chains(chains, framework=None, stats=None, weights=None):
    """Return [(ev, chain)] sorted by EV desc, deterministic tie-break by id."""
    stats = stats if stats is not None else load_stats()
    weights = weights if weights is not None else load_weights()
    scored = [(expected_value(c, framework, stats, weights), c)
              for c in chains or []]
    scored.sort(key=lambda pair: (-pair[0], str(pair[1].get("id", ""))))
    return scored


# ---- exact beam search ---------------------------------------------------

def beam_search(chains, framework=None, stats=None, weights=None,
                width=BEAM_WIDTH, depth=BEAM_DEPTH):
    """Exact beam search over chain orderings maximising cumulative EV.

    Chains contribute additively, so the optimum is the top-`depth` by EV;
    the beam makes the search explicit and deterministic for A/B and golden
    tests. Returns the best ordered plan (list of chains, length <= depth).
    """
    stats = stats if stats is not None else load_stats()
    weights = weights if weights is not None else load_weights()
    ev_by_id = {}
    for ev, c in score_chains(chains, framework, stats, weights):
        ev_by_id[str(c.get("id", id(c)))] = (ev, c)

    # beam state: (cumulative_ev, [chain_ids])
    beam = [(0.0, [])]
    for _ in range(depth):
        candidates = []
        for cum, seq in beam:
            for cid, (ev, _c) in ev_by_id.items():
                if cid in seq:
                    continue
                candidates.append((cum + ev, seq + [cid]))
        if not candidates:
            break
        # deterministic: higher cumulative EV first; on a tie prefer the
        # sequence that front-loads the higher-EV chains, then lexicographic.
        def _key(state):
            cum, seq = state
            ev_desc = tuple(-ev_by_id[cid][0] for cid in seq)
            return (-cum, ev_desc, seq)
        candidates.sort(key=_key)
        beam = candidates[:width]
    if not beam or not beam[0][1]:
        return []
    best_seq = beam[0][1]
    return [ev_by_id[cid][1] for cid in best_seq]


def rank_chains_ev(chains, framework=None, stats=None, weights=None):
    """Full EV-ranked chain list (selection order for the engine)."""
    return [c for _ev, c in score_chains(chains, framework, stats, weights)]


__all__ = [
    "expected_value", "score_chains", "beam_search", "rank_chains_ev",
    "load_stats", "record_run", "beta_posterior", "p_vuln", "p_fp",
    "impact_value", "novelty_bonus", "est_cost", "load_weights",
    "STATS_FILE", "BEAM_WIDTH", "BEAM_DEPTH", "NOVELTY_CLASSES",
]
