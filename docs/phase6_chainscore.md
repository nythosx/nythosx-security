# Phase 6 — Expected-Value Chain Scoring

`engine/chainscore.py` replaces the heuristic priority with an expected-value
model:

```
EV = P_vuln * impact_value * (1 - P_fp) * novelty_bonus - est_cost
```

## Terms

- **impact_value** — per-vuln-class dollar weight from
  `configs/impact_weights.yaml` (credential/session > data exposure >
  defacement > info disclosure; tunable).
- **P_vuln** — Bayesian per `(vuln_class, framework)`: Beta posterior
  `P = (hits + α) / (attempts + α + β)` with `α = 1, β = 9` (prior mean 0.1).
  Falls back to the generic-framework slot, then the prior.
- **P_fp** — per-oracle historical false-positive rate (FP / ever-confirmed);
  a chain takes its worst oracle.
- **novelty_bonus** — `2.0×` for `bizlogic`, `graphql_deep`, and
  `mass_assignment` classes, else `1.0`.
- **est_cost** — `step_count × PROBE_FANOUT` (6).

## Stats persistence

Run stats are appended to `stats/chains.jsonl` (gitignored) after every run by
`ChainOrchestrator._persist_ev_stats` — one record per chain
(`vuln_class, framework, attempts, hits`) and per oracle
(`confirmed, fp`). `load_stats()` aggregates the file at startup, so priors
sharpen across runs.

## Selection

`beam_search(chains, width=5, depth=2)` runs an exact beam search over chain
orderings, maximising cumulative EV. Because chains contribute additively the
optimum front-loads the highest-EV chains; ties break toward front-loading the
higher-EV chain, then lexicographically, so ordering is deterministic (golden
test). The engine's `select_chains` re-ranks the trigger-matched candidate set
with `rank_chains_ev`, recomputed after each chain completes.

## A/B with the legacy scorer

`--legacy-scoring` (global CLI flag → `scoring.legacy` / `orch.legacy_scoring`)
keeps the old `engine.scoring` heuristic for A/B comparison; it also skips EV
stats persistence.

## Acceptance

`tests/test_chainscore.py` proves the scorer prefers a high-prior/high-impact
chain over a low-impact one given synthetic stats, that EV subtracts cost,
that the beam search is deterministic and optimal, and a golden test pins a
stable, deterministic score ordering. Module coverage: 91%.
