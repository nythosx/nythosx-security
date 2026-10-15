# Phase 5 — Capability Graph

`engine/capgraph.py` models what an attacker can *do* after each confirmed
finding and reports multi-step attack paths a per-finding view misses.

## Model

A capability is a verb an actor gains. Canonical verbs:

```
read_data, write_data, obtain_token, escalate_role,
ssrf_to_internal, execute_js_in_victim, pivot_internal
```

Confirmed findings are **edges**: a finding `requires` a capability (or starts
from `anon`) and `grants` another. The finding-class → edge mapping is
declarative in `configs/capability_map.yaml`, e.g.:

```yaml
jwt_weak_secret: {requires: [anon], grants: obtain_token}
idor:            {requires: [obtain_token], grants: write_data}
mass_assignment: {requires: [obtain_token], grants: escalate_role}
stored-xss:      {requires: [anon], grants: execute_js_in_victim}
```

Keys match a finding's class / pattern_id / kind — exact first, then
prefix/substring.

## BFS and chain findings

On each new finding the graph runs BFS from `anon`. Any path of length **≥ 2**
that reaches `write_data` or `escalate_role` (`TARGET_VERBS`) is reported as a
`capability_chain` finding. Its severity is **one step above the worst
component**, capped at critical (high + idor → critical). Chains are rendered
as an *N-step attack path*, each step referencing the originating finding and
its evidence row:

```
### 2-step attack path (CRITICAL)
`anon -> obtain_token -> write_data`
1. anon → obtain_token — finding `101` (jwt-weak-secret); see its evidence row.
2. obtain_token → write_data — finding `102` (idor); see its evidence row.
```

`engine.report.build_capability_chains()` renders these into the Markdown and
HTML reports under **Capability Attack Paths**.

## Acceptance

`tests/test_capgraph.py` builds the graph from a weak-JWT finding plus an IDOR
finding — exactly what a scan of `tests/testapp/` yields (the app ships an
HS256 token signed with `secret`, and `/api/doc/{id}` lets any authenticated
caller read another account's record) — and asserts a 2-step chain finding
(`anon → obtain_token → write_data`) that links both findings. A single weak
JWT alone produces no chain. Module coverage: 92%.
