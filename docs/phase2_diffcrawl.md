# Phase 2 — Auth-Context Differential Crawler

`engine/diffcrawl.py` crawls the target once per authentication context and
diffs the result sets to surface access-control defects that a single-session
crawl cannot see.

## Contexts & credentials

Four contexts: `anon` (no cookies/headers), `user_a`, `user_b`, and optional
`admin`. Credentials load from `configs/diffcrawl.creds.yaml` (gitignored);
`configs/diffcrawl.creds.example.yaml` is the committed template. Sessions are
established with `engine.auth_flow.perform_login`, yielding per-context
headers + cookies carried through `engine.http` (scope gate + rate limiter).

## Result sets

Each context's crawl produces a map keyed by
`(method, path, param_signature)` — `endpoint_key()` — to a record holding
status, body hash, and a `reachable` flag (2xx).

## Differentials

`compute_differentials`:

| differential                                   | verdict                      |
|------------------------------------------------|------------------------------|
| endpoint reachable by **admin ∩ anon**         | `missing_access_control` (high) |
| reachable by admin, **absent/denied** to user  | `authz_enforced` (info, PASS)   |

`id_substitution_candidates`: as `user_a`, substitute `user_b`'s known IDs
(and bounded neighbors) into ID-typed params; a distinct, reachable body that
differs from `user_a`'s own record is an IDOR/BOLA candidate. Cross-account
hits are emitted as facts `idor_candidate:<method>:<path>` and
`has_idor_candidate` (`source=live_confirm`, `confidence=0.9`), then handed to
the existing confirmation gate (`engine.confirm.confirm("idor_scan", …)`) with
`user_a`'s session so the neighbor read is reproduced under real auth.

## Safety bounds

ID substitution stays within the two operator-owned test accounts' `known_ids`
plus sequentially adjacent integers within **±2**
(`ID_SUBST_NEIGHBOR_BOUND`), capped at **6 requests per endpoint**
(`MAX_REQUESTS_PER_ENDPOINT`), and every request is additionally bounded by
the shared rate limiter and the ROE scope gate. No other users' IDs are ever
probed.

## Acceptance

`tests/test_diffcrawl.py` runs against `tests/testapp/`: an IDOR surface
(`/api/doc/{id}`) must be flagged, a broken endpoint (`/api/admin/config`,
reachable anonymously) must raise `missing_access_control`, and a correctly
enforced endpoint (`/api/admin/users`) must come back `authz_enforced` (PASS).
Module coverage: 85%.
