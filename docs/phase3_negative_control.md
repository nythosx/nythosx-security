# Phase 3 — Negative-Control Oracle Gate

`engine/oracles/controls.py` generalises the confirmation gate. Every oracle
family declares a `negative_control(payload)` mutation that **should fail** if
the oracle is sound; when a VULNERABLE verdict is reached the gate re-runs
that control with identical routing to prove the oracle is not over-matching.

## Negative controls

`NEGATIVE_CONTROLS` maps a family to a mutator:

| family | mutation | rationale |
|--------|----------|-----------|
| `xss`  | `<img src=x onerr` | broken handler — never executes |
| `sqli` | `'''`              | unbalanced quote count |
| `ssrf` | `zzz://localhost.invalid.nonexistent/` | scheme can't resolve |
| `ssti` | `{{7*'7'}}zz{{`    | literal braces, no engine evaluates |
| `crlf` | `%250d%250a…`      | double-encoded newline, already neutral |
| `nosql`| scalar string      | not an operator object |

Unknown families fall back to a generic benign mutation. Prefix matching lets
`xss-stored` reuse the `xss` control.

## The gate

`OracleGate.run(oracle, probe, verdict, …)` runs, short-circuiting on failure:

1. **benign-args check** — if the benign payload fires VULNERABLE the tool is
   unsound; suppress and disable.
2. **negative control** — run the control mutation; if it ALSO fires the
   oracle is over-matching; suppress, record `oracle_unsound:<name>`, and
   disable the oracle for the session.
3. **1.5 s re-run** — re-run the real exploit; if it no longer fires,
   downgrade to SUSPICIOUS.

A disabled oracle short-circuits every later finding to SUPPRESSED. Session
state lives on the gate; the engine holds one gate per `ChainOrchestrator`.

## Cross-oracle corroboration

`corroborate(signals)` returns CONFIRMED only when **≥2 independent oracle
families agree**, OR **one family with confidence ≥ 0.95 and a passing
negative control**; otherwise SUSPICIOUS.

## Engine integration

`ChainOrchestrator._confirm_step` now runs benign-args → negative control →
1.5 s re-run in that order. A step opts into auto-synthesised negative
controls by naming an `oracle` (and optionally `payload_arg`); the existing
explicit `control_args` path is preserved, and both record
`oracle_unsound:<name>` and disable the oracle on a firing control.

## Acceptance

`tests/test_oracle_controls.py`: a deliberately over-matching mock oracle
(fires on everything) is suppressed and disabled; a sound oracle's finding
survives and confirms; corroboration and the chain-level integration are
covered. Module coverage: 94%.
