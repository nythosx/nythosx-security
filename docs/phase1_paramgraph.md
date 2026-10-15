# Phase 1 — Param Context Graph

`engine/paramgraph.py` replaces flat parameter-name strings with typed
`ParamNode` objects that carry provenance and the result of a type-inference
oracle, so chains target the right injection families instead of spraying
every family at every parameter.

## Data model

```
ParamNode = {
  name, sources[], observed_types[], reflected, auth_contexts[],
  framework_param, probes[ProbeResult], mutation_candidates[],
  classification, arithmetic_injection
}
```

`sources` ⊆ `url, body, header, cookie, graphql, json_path`.
`observed_types` ⊆ `int, float, string, email, uuid, url, base64, jwt,
filename, bool, enum`. `auth_contexts` ⊆ `anon, user_a, user_b, admin`.

## Type-inference oracle

`infer_param_type(name, probe_runner, baseline, ...)` sends six canonical
probes — `1, 1.5, abc, [], {}, null` — and records HTTP status plus a
`semantic_diff` signal against the baseline for each. A probe is *accepted*
when the status is 2xx/3xx and *rejected* on 4xx.

Classification (`classify_from_probes`):

| classification    | rule                                             | families routed              |
|-------------------|--------------------------------------------------|------------------------------|
| `strict_numeric`  | numeric accepted, strings 4xx                    | `sqli`                       |
| `loose_string`    | everything accepted                              | `sqli, ssti, xss, crlf`      |
| `container_typed` | empty array/object accepted, scalars rejected    | `nosql, mass_assignment`     |
| `unknown`         | none of the above                                | —                            |

For `strict_numeric` params the oracle additionally probes arithmetic
injection: it sends `id=2-1` and compares the response to `id=1` with the
structural `semantic_diff` hash. When they are structurally equivalent the
server evaluated the expression, and `arithmetic_injection` is set with a
`mutation_candidates` entry.

## Rate limiting & scope

`make_http_probe_runner` builds a probe runner over `engine.http.Client`, so
every probe passes through the shared rate limiter (global 5 rps, 3 rps per
endpoint) and the ROE scope gate. Unit tests inject their own in-memory
runner; no network call bypasses the HTTP layer.

## Integration

`record_param_node(fact_store, endpoint, node)` stores the node as a fact
`param:<endpoint>:<name>` (`source=route_probe`, `confidence=0.7`) and emits
the family facts the chain registry triggers on:

```
has_sqli_param, has_ssti_param, has_xss_param, has_crlf_param,
has_nosql_param, has_mass_assignment_param,
has_numeric_injection_param, has_container_param, has_loose_string_param
```

Chain triggers updated in `engine/chain_registry.py`:

- `blind-sqli-chain` ← `has_sqli_param`, `has_numeric_injection_param`
- `injection-family-chain` ← `has_ssti_param`, `has_nosql_param`
- `xss-chain` ← `has_xss_param`
- `crlf-chain` ← `has_crlf_param`
- `bizlogic-chain` ← `has_mass_assignment_param`

## Acceptance

`tests/test_paramgraph.py` covers the classification logic with mocked HTTP
and runs an end-to-end integration test against the local app in
`tests/testapp/` — a strict-numeric endpoint (`/api/item`), a loose-string
endpoint (`/api/search`), and a mass-assignment endpoint (`/api/profile`) —
asserting each routes to the correct chain. Module coverage: 90%.
