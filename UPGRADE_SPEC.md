# Phase 7 — Deep Injection Surface + Drupal/University-CMS Module

`engine/inject/` extends injection coverage beyond single-param reflection;
`engine/drupalchain/` adds chains purpose-built for Drupal-based institutions
(the dominant CMS class among PH universities: public file storage,
`/user/{uid}` enumeration, REST/UI module exposure, views/ajax endpoints).

All modules inherit the standing constraints: every request via
`engine.http` (scope gate + rate limiter), confirmation gate applies, no
destructive payloads, no DoS-pattern requests.

---

## Part A — Deep Injection Surface (`engine/inject/`)

### A1. Structural JSON/XML injector (`inject/structural.py`)
For JSON bodies, generate mutated trees and classify via
`semantic_diff` + `mass_assignment` oracle:
- **Duplicate keys**: `{"role":"user","role":"admin"}` → detect server
  last-key-wins vs first-key-wins vs duplicate-rejection.
- **Type juggling**: `"id": {"$ne": null}`, `"id": true`, `"id": []` →
  NoSQL / loose-typing candidates.
- **Deep nesting**: capped at depth 8. Never DoS patterns, never
  billion-laughs expansion — the goal is parser behavior classification,
  not resource exhaustion.
- **Prototype pollution keys**: `__proto__`, `constructor.prototype`
  (Node backends).
Cap: 8 mutations per endpoint, deduped against the paramgraph's
`mutation_candidates`.

### A2. Parser-differential probes (`inject/parserdiff.py`)
Re-send each accepted payload with mismatched Content-Type:
JSON body as `application/x-www-form-urlencoded`, XML with
`text/xml` vs `application/xml`, multipart with two `file` parts sharing a
filename. Divergent responses → WAF/parser bypass candidate.
Cap: 4 variants per endpoint.

### A3. GraphQL depth module (`inject/graphqlx.py`)
Extend `graphql_deep`:
- Introspection dump (if enabled → finding: `graphql_introspection_exposed`).
- Alias batching: 2–4 aliases max, single query — never resource-exhausting.
- Field-suggestion extraction from error messages (`Did you mean …`) →
  hidden field discovery.
- Mutation discovery on endpoints the crawl marked read-only.

### A4. Header-surface injection (`inject/headersurf.py`)
For every discovered endpoint, replay with mutated routing/trust headers:
`X-Forwarded-For: 127.0.0.1`, `X-Original-URL`, `X-Rewrite-URL`,
`X-HTTP-Method-Override`, `X-Forwarded-Host`. Verdict via status +
semantic_diff against baseline. Detects access-control and routing bypasses
that host-based allowlists (common on .edu.ph hosting) mistakenly trust.

---

## Part B — Drupal / University-CMS Chains (`engine/drupalchain/`)

Trigger facts: `framework=drupal`, `has_path:/node/*`, `has_path:/storage/*`,
`has_path:/user/*`, `has_path:/sites/default/files`, or the generic
`/administration/` + `id`-param combination observed in recon.

### B1. `drupal-user-idor-chain`  (priority: highest)
- Probe `/user/1` through `/user/20` (anonymous).
- 200 + profile content on any uid > 0 with usernames/roles visible →
  `user_enumeration` finding (medium→high if admin uid 1 exposes email).
- If a session exists (user_a), repeat and diff: any uid whose profile
  user_a can read but shouldn't → hand to diffcrawl's IDOR confirmation
  gate (`live_confirm`, confidence 0.9).
- Safety: GET only, 20 requests max, rate-limited. No login attempts,
  no password probing.

### B2. `drupal-rest-exposure-chain`
Enumerate known Drupal REST/UI routes anonymously:
`/node/{nid}?_format=api_json`, `/jsonapi`, `/jsonapi/node/*`,
`/rest/session/token`, `/user/register?_format=hal_json`.
- Anonymous JSON:API reads of restricted content types →
  `broken_access_control` finding (high).
- `/rest/session/token` returning 200 anonymously → info (expected
  behavior in Drupal — record as PASS with note, do not flag).

### B3. `drupal-views-ajax-chain`
Probe `/views/ajax`, `/views/ajax?view_name=…` with paramgraph-derived
params. Missing CSRF enforcement or anonymous data dumps from admin views
→ `unauthenticated_data_disclosure` (high).

### B4. `drupal-updatephp-and-install-chain`
GET `/update.php`, `/install.php`, `/core/install.php`, `/core/update.php`.
Any 200 (not 403) → `maintenance_endpoint_exposed` (critical —
update.php without auth = site takeover path). Record-only: never POST,
never execute updates.

### B5. `drupal-file-storage-chain`
From the recon-observed `/storage/113/Administrative-Manual.pdf` pattern:
- Enumerate adjacent document IDs within ±5 of observed IDs, plus common
  sensitive names (`backup`, `sql`, `config`, `credentials`, `payroll`,
  `grades`) via wordlist against the storage base path.
- 200s on non-media files (`.sql`, `.bak`, `.env`, `.xlsx` with
  credential-shaped content per the LLM bundle analyst) →
  `sensitive_file_exposure` finding with Row-2 masked impact evidence.
- Cap: 60 requests per storage base, soft-404 fingerprint applied
  before flagging.

### B6. `drupal-config-exposure-chain`
GET `/sites/default/settings.php`, `/core/config.php`,
`/sites/default/files/.ht.sqlite`, `/.env`, `/composer.json`,
`/core/composer.json`, `/CHANGELOG.txt`.
- `CHANGELOG.txt` present → exact Drupal version disclosure (info) →
  feeds `framework-exploit-chain` with a concrete version instead of
  `Generic (Fallback)` — this directly fixes the fingerprinting gap from
  the last scan.
- `settings.php` readable (should be 403 via .htaccess) → critical
  `config_disclosure` (DB creds exposure).

### B7. `university-org-recon-chain` (support chain, feeds auth)
From `/administration/key-officials` style pages: extract names →
derive candidate email patterns (`f.last@`, `firstlast@`,
`first.last@`) → emit as facts `org_email_patterns` for the auth module
and for the client's phishing-resilience report section (informational
only in the automated report; no email probing, no verification requests
against mail servers).

---

## Verdict & evidence wiring

- All B-chains route findings through the Phase 3 OracleGate
  (negative controls apply: B4/B6 use benign-path 404 controls;
  B2/B3 use soft-404-aware status oracle).
- Confirmed findings map into `capability_map.yaml`:
  - `maintenance_endpoint_exposed` → `escalate_role` edge
  - `config_disclosure` → `obtain_token` edge (DB creds)
  - `user_enumeration` + existing `idor` → strengthens chain findings
  - `sensitive_file_exposure` → `read_data` edge
  so a Drupal config leak + update.php exposure composes into a
  capability-chain finding automatically.

## Acceptance

`tests/test_drupalchain.py` runs against a `tests/testapp/drupal_mimic/`
fixture app implementing: `/user/{uid}` with weak access control,
`/jsonapi/node/secret_content` readable anonymously, `/update.php` at 200,
`/storage/{id}/` with an adjacent `.sql` file, `/CHANGELOG.txt` with a
version string. Asserts: all five surfaces flagged with correct severities,
`framework` fact upgraded from `Generic (Fallback)` to
`drupal <version>`, one capability chain composes
(config_disclosure → obtain_token → write_data), and request counts stay
within per-chain caps. `tests/test_inject.py` covers A1–A4 with mocked
HTTP. Module coverage: ≥ 88%.

## Explicit non-goals

No brute-force login, no password spraying, no resource-exhaustion payloads,
no writes to storage endpoints, no requests to any host outside the ROE
allowlist — including URLs harvested from wayback/CT sources, which must
re-enter the scope gate before probing (the failure mode from the
uncontrolled scan is closed here at the chain level as defense-in-depth).