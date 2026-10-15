# Phase 7 — Deep Injection Surface + Drupal/University-CMS Chains

Two packages. All requests route through `engine.http` (scope gate + rate
limiter); GET-only probing where the spec requires it, hard per-chain caps,
soft-404 fingerprinting before any flag, and no destructive/brute-force/DoS
patterns.

## Part A — Deep Injection Surface (`engine/inject/`)

- **`structural.py` (A1)** — mutates JSON trees and classifies parser
  behaviour via `semantic_diff`: duplicate keys (last-wins vs first-wins vs
  reject), type juggling (`{"$ne":null}`, `true`, `[]` → NoSQL/loose-typing),
  deep nesting capped at depth 8 (classification only, never expansion), and
  prototype-pollution keys (`__proto__`, `constructor.prototype`). Capped at
  8 mutations/endpoint, deduped against the paramgraph `mutation_candidates`.
- **`parserdiff.py` (A2)** — re-sends an accepted payload with a mismatched
  Content-Type (JSON as form-urlencoded, XML `text/xml` vs `application/xml`,
  multipart with two `file` parts sharing a filename). Divergence → WAF/parser
  bypass candidate. Capped at 4 variants.
- **`graphqlx.py` (A3)** — introspection dump
  (`graphql_introspection_exposed`), alias batching (2–4 aliases, single
  query), field-suggestion mining from `Did you mean …` errors, and mutation
  discovery on read-only-marked endpoints.
- **`headersurf.py` (A4)** — replays each endpoint with mutated routing/trust
  headers (`X-Forwarded-For: 127.0.0.1`, `X-Original-URL`, `X-Rewrite-URL`,
  `X-HTTP-Method-Override`, `X-Forwarded-Host`); a forbidden baseline turning
  reachable, or a structural shift, flags an access-control/routing bypass.

## Part B — Drupal / University-CMS chains (`engine/drupalchain/`)

Seven chains, registered in `chain_registry` (triggered by
`framework=drupal` or `has_drupal`) and dispatched by the engine's
`drupal_chain` tool:

| Chain | Finding | Severity |
|-------|---------|----------|
| B1 `drupal-user-idor-chain` | `user_enumeration` (+`idor` on private fields) | med→high |
| B2 `drupal-rest-exposure-chain` | `broken_access_control` (anon JSON:API) | high |
| B3 `drupal-views-ajax-chain` | `unauthenticated_data_disclosure` | high |
| B4 `drupal-updatephp-and-install-chain` | `maintenance_endpoint_exposed` | critical |
| B5 `drupal-file-storage-chain` | `sensitive_file_exposure` (masked Row-2) | high |
| B6 `drupal-config-exposure-chain` | `config_disclosure`, `version_disclosure` | critical/info |
| B7 `university-org-recon-chain` | `org_email_patterns` (informational) | info |

B1 is GET-only, ≤20 requests, no login/password probing. B5 enumerates
adjacent IDs within ±5 of observed storage IDs plus a sensitive-name
wordlist, ≤60 requests, soft-404 fingerprinted. B6's `CHANGELOG.txt` version
upgrades the `framework` fact from `Generic (Fallback)` to `drupal <version>`,
feeding the framework-exploit chain a concrete version. `/rest/session/token`
anonymous is recorded as PASS (expected Drupal behaviour), not flagged.

## Verdict & evidence wiring

B4/B6 findings carry a `negative_control_path` (a benign nonexistent path);
`_apply_gate` suppresses the finding if that control is also reachable
(detector unsound). New finding classes map into `configs/capability_map.yaml`:
`maintenance_endpoint_exposed → escalate_role`,
`config_disclosure → obtain_token`, `sensitive_file_exposure → read_data`,
`user_enumeration → read_data`. So a config leak (→ obtain_token) plus a
`/user` IDOR (obtain_token → write_data) composes into a capability chain
automatically.

## Acceptance

`tests/test_drupalchain.py` runs against `tests/testapp/drupal_mimic/`: all
five named surfaces flagged with correct severities, `framework` upgraded to
`drupal 9.4.8`, the `config_disclosure → obtain_token → write_data`
capability chain composes, and request counts stay within per-chain caps.
`tests/test_inject.py` covers A1–A4 with mocked HTTP. Module coverage: inject
92–98%, drupalchain 88%.

## Non-goals (enforced)

No brute-force login, no password spraying, no resource-exhaustion payloads,
no writes to storage endpoints, and no requests to any host outside the ROE
allowlist — wayback/CT-harvested URLs re-enter the scope gate before probing
(`make_send` checks `roe_guard` on every request).
