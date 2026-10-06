# SEC-CHECKER

Black-box security testing platform for web applications.
Pattern-driven, framework-agnostic, evidence-based.

**Version:** 1.2.0
**Last build:** Phase 9 (Confidence-gap fixes + Playwright + IDOR + JWT + CI)
**Tested on:** TAMID member portal (Nuxt + Laravel)

---

## Ano Ito

Isang automated security scanning tool na:

1. **Nag-a-analyze** ng web app externally — walang access sa source code
2. **Nag-dedetect** ng framework (Laravel, Django, Rails, Next.js, atbp.)
3. **Nag-a-auto-discover** ng API backend (runtime config + port scan)
4. **Nag-a-auto-login** gamit ang credentials
5. **Nag-e-execute** ng security patterns (deterministic YAML)
6. **Nag-ge-generate** ng HTML / Markdown / SARIF report na may evidence

Isang command lang:

```cmd
python run.py auto https://target.example.com --auto-baseline
```

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│         CLI (run.py + engine/cli.py)                 │
│         auto | scan | scan-all | profile | ...       │
└────────────────────┬─────────────────────────────────┘
                     │
┌────────────────────▼─────────────────────────────────┐
│              AUTO ORCHESTRATOR                       │
│    Preflight → Detect → Discover → Baseline → Scan   │
└────┬─────────────┬─────────────┬─────────────────────┘
     │             │             │
┌────▼─────┐  ┌────▼─────┐  ┌────▼──────┐
│ ADAPTER  │  │ DISCOVERY│  │  AUTH     │
│ MATCHER  │  │  ENGINE  │  │  FLOW     │
│          │  │          │  │           │
│ 11       │  │ Runtime  │  │ Basic     │
│ adapters │  │ + Port   │  │ Bearer    │
│          │  │  scan    │  │ Cookie    │
│          │  │          │  │ Sanctum   │
└────┬─────┘  └────┬─────┘  └────┬──────┘
     │             │             │
     └─────────────┼─────────────┘
                   │
┌──────────────────▼───────────────────────────────────┐
│              PATTERN ENGINE (parallel)               │
│  YAML patterns → Executor → Oracles → Verdict        │
│                       │                              │
│                  RateLimiter                         │
│                  (token bucket)                      │
└────┬──────────────────────────────┬──────────────────┘
     │                              │
┌────▼─────┐                  ┌─────▼──────┐
│ EVIDENCE │                  │  LEDGER    │
│  store   │                  │  SQLite    │
└──────────┘                  └─────┬──────┘
                                    │
                              ┌─────▼──────┐
                              │  REPORT    │
                              │ HTML/MD/   │
                              │  SARIF     │
                              └────────────┘
```

---

## Components

### Engine Modules

| File                 | Purpose                                                            |
| -------------------- | ------------------------------------------------------------------ |
| `cli.py`             | Command-line interface, argument parsing                           |
| `auto.py`            | Full auto-discovery orchestrator (parallel)                        |
| `adapter_loader.py`  | Loads framework adapters from `adapters/`                          |
| `adapter_matcher.py` | Scores and matches target against adapters                         |
| `discovery.py`       | Framework detection, JS extraction, login probe (throttled)        |
| `api_discovery.py`   | Runtime config parsing, port scan                                  |
| `auth_flow.py`       | Login execution, token extraction                                  |
| `http_client.py`     | HTTP with retry, backoff, UA rotation, ROE check, **rate limiter** |
| `ratelimit.py`       | **NEW** — Token bucket per host+path, global + per-endpoint        |
| `roe_guard.py`       | **Fail-closed** rules of engagement enforcement (glob-aware)       |
| `loader.py`          | Pattern YAML loading and validation                                |
| `executor.py`        | Pattern step execution (sequential, repeat, concurrent)            |
| `oracle.py`          | 17 verdict evaluators (**multi-step aware**)                       |
| `evidence.py`        | Request/response artifact storage                                  |
| `ledger.py`          | SQLite findings and runs database                                  |
| `baseline.py`        | Timing baseline profiler                                           |
| `route_enum.py`      | Path enumeration via wordlist                                      |
| `report.py`          | HTML / Markdown / **SARIF** report generation                      |
| `browser.py`         | **NEW** — Playwright capture (console, JS errors, screenshots)     |
| `idor.py`            | **NEW** — IDOR live probe (ID extraction + neighbor probing)       |
| `util.py`            | `safe_name`, atomic writes                                         |
| `session.py`         | **DEPRECATED** — raises `ImportError` on import                    |

### Adapters (11 frameworks)

| Adapter     | Detection                                                 | Ports                  |
| ----------- | --------------------------------------------------------- | ---------------------- |
| laravel     | X-Powered-By: PHP, laravel_session cookie, csrf-token     | 8000, 8001, 8080       |
| nuxt        | X-Powered-By: Nuxt, `__NUXT__`, `/_nuxt/`                 | 3000, 3001             |
| nextjs      | X-Powered-By: Next.js, `__NEXT_DATA__`, `/_next/`         | 3000, 3001             |
| wordpress   | X-Powered-By: WordPress, `/wp-content/`, wp-json          | 80, 443, 8080          |
| django      | Server: WSGIServer, csrftoken cookie, csrfmiddlewaretoken | 8000, 8080, 8888       |
| rails       | Server: Puma, `_rails_session` cookie, csrf-token         | 3000, 3001             |
| express     | X-Powered-By: Express, connect.sid cookie                 | 3000, 3001, 5000, 8080 |
| spring_boot | X-Application-Context, JSESSIONID, Whitelabel Error Page  | 8080, 8081, 8443, 8000 |
| aspnet      | X-AspNet-Version, ASP.NET_SessionId cookie                | 5000, 5001, 8080       |
| fastapi     | Server: uvicorn, swagger-ui                               | 8000, 8001, 8080       |
| generic     | Fallback                                                  | common ports           |

**Scoring:** +50 header · +30 cookie · +25 meta · +20 HTML · +10 URL marker. Below 30 → `generic`.

---

## Patterns (26 total)

> Phase 9 added `jwt-weak-secret`. Actual count ay **26**.

### Single-request (8)

| Pattern                  | Severity | Detects                                 |
| ------------------------ | -------- | --------------------------------------- |
| security-headers-missing | medium   | Missing HSTS, X-Frame-Options, etc.     |
| server-disclosure        | low      | Server version in headers               |
| cors-wildcard            | high     | CORS `*` misconfiguration               |
| cookie-flags-missing     | medium   | Cookie missing Secure/HttpOnly/SameSite |
| http-methods-allowed     | low      | TRACE/PUT/DELETE allowed                |
| authed-security-headers  | medium   | Auth page missing headers               |
| api-cors-preflight       | high     | CORS via OPTIONS                        |
| api-exposed-headers      | low      | X-Powered-By, X-Debug-Token             |

### Sequence (8)

| Pattern                 | Severity | Detects                                |
| ----------------------- | -------- | -------------------------------------- |
| rate-limit-absent       | high     | No 429 on login flood                  |
| auth-bypass-probe       | high     | Endpoint accessible without auth       |
| user-enumeration-timing | medium   | Timing diff between valid/invalid user |
| idor-sequential         | high     | Sequential ID enumeration              |
| authed-idor             | high     | Authenticated IDOR probe               |
| graphql-introspection   | medium   | GraphQL introspection enabled          |
| api-error-handling      | high     | 500 instead of 401 on missing auth     |
| api-info-disclosure     | medium   | Stack traces, SQL errors in response   |

### Temporal (5)

| Pattern               | Severity | Detects                                |
| --------------------- | -------- | -------------------------------------- |
| race-condition-basic  | high     | Concurrent request state inconsistency |
| race-condition-authed | high     | Same, authenticated endpoint           |
| cache-poisoning-probe | high     | Header injection into cache            |
| idempotency-violation | medium   | Same POST producing different results  |
| timing-vs-baseline    | medium   | Response timing anomaly vs baseline    |

### Content (3)

| Pattern            | Severity | Detects                                    |
| ------------------ | -------- | ------------------------------------------ |
| env-file-exposure  | critical | .env, .env.local, .env.backup accessible   |
| js-bundle-secrets  | high     | AWS keys, Stripe keys, JWT in JS bundles   |
| laravel-debug-mode | critical | Laravel `APP_DEBUG=true` (huge error page) |

### Meta (2)

| Pattern          | Severity | Detects                                      |
| ---------------- | -------- | -------------------------------------------- |
| jwt-analysis     | medium   | JWT structure in responses                   |
| jwt-weak-secret  | critical | HMAC JWT signed with a weak/guessable secret |

---

## Oracles (18 verdict evaluators)

| Oracle                     | Logic                                    | Multi-step?                      |
| -------------------------- | ---------------------------------------- | -------------------------------- |
| `header_absent`            | Missing header                           | ✅ all steps                     |
| `header_value_match`       | Header value matches regex               | ✅ all steps                     |
| `cookie_flags_check`       | Set-Cookie missing flags                 | ✅ all steps                     |
| `status_code_absent`       | Status never seen (e.g., 429)            | ✅ + all-error → UNKNOWN         |
| `status_code_present`      | Status present                           | ✅                               |
| `no_auth_200`              | 200 without auth + 401/403 with bad auth | ✅                               |
| `timing_delta`             | Statistical timing anomaly               | ✅                               |
| `timing_vs_baseline`       | Compare vs stored baseline               | ✅                               |
| `timing_difference`        | Between-step timing difference           | ✅                               |
| `response_differs`         | Bodies differ across steps               | ✅                               |
| `content_length_delta`     | Size ratio anomaly                       | ✅                               |
| `pattern_match`            | Regex match in body                      | ✅ all steps, cites matched step |
| `state_inconsistent`       | Same status, different bodies            | ✅                               |
| `redirect_chain`           | External redirect detection              | ✅ all steps                     |
| `expected_status_mismatch` | 500 when 401 expected                    | ✅ all steps                     |
| `debug_signature`          | Laravel/debug markers + size threshold   | ✅ all steps                     |
| `json_error_field`         | Error message extraction                 | ✅ all steps                     |
| `jwt_weak_secret`          | Brute-forces HMAC JWT secret (wordlist)  | ✅ all steps, bodies + headers   |

---

## Features (Working)

### Discovery

- Framework auto-detection (11 adapters, scored)
- Runtime config parsing (`__NUXT_DATA__`, `__NEXT_DATA__`, regex patterns)
- Port scan for split-backend detection
- API base auto-resolution

### Authentication

- JSON login (email/password)
- Form login
- Token extraction (JSON path: `token`, `access_token`, `data.token`)
- Sanctum token support (`ID|hash` format)
- Session save/reuse (atomic writes)
- Login probe throttled (200 ms default between attempts)

### Scanning

- 25 patterns across 5 categories
- Sequential, repeated, concurrent execution
- **Parallel pattern execution** (build9 — respects `concurrency.max_workers`)
- Per-step auth override (`no_auth: true`)
- Pattern-level auth override (`ignore_default_auth: true`)
- Pattern-level endpoint routing (`endpoint_suffix`)
- Concurrency barrier for race detection
- **Rate limiter** (token bucket, `rate_limit.*` in `engine.yaml`)

### Evidence & Reporting

- Per-scan evidence folder (`summary.json`, `raw.json`)
- SQLite findings ledger with severity-ranked queries
- HTML report (dark theme, autoescaped)
- Markdown report
- **SARIF export** (`--format sarif`)
- WSTG + CWE mapping
- Findings dedup (`pattern_id + verdict + reason[:120]`)

### Safety

- **ROE guard fail-closed** (missing scope = block all)
- **Glob-aware forbidden paths** (`/api/*/drop` matches `/api/v1/drop`)
- Per-request scope validation
- `enforce_scope` / `enforce_methods` flags honored
- Preflight reachability check (fail fast on offline targets)
- **Rate limiter** (global + per-endpoint token buckets, 429 backoff)

### CLI

```
auto          Full pipeline (--auto-baseline available)
adapters      List framework adapters
enumerate     Route enumeration
profile       Timing baseline
login         Session creation
sessions      List sessions
scan          Single pattern
scan-all      All patterns (parallel)
list          List patterns
show          Pattern details
validate      Validate YAML
report        Generate report (html | md | sarif)
browser       Playwright capture (console, JS errors, screenshot)
idor          IDOR live probe (extract ID + probe neighbors)
history       Recent findings
targets       Configured targets
```

### Flags

```
--adapter <id>              Force framework adapter
--min-severity <level>      critical|high|medium|low|info
--session <name>            Use saved session
--auth user:pass|bearer:X   Inline auth
--auto-baseline             Profile target before scanning
--no-discovery              Skip JS/recon phase
--fail-on <level>           Exit 3 if an actionable finding >= level (CI gate)
--category <name>           Limit scan-all to one pattern category
--version                   Print version
```

**`--fail-on`** gates CI: on `scan`, `scan-all`, and `auto`, the process exits
`3` if any VULNERABLE/SUSPICIOUS finding is at or above the given severity,
else `0`. `run.py` also exits `1` on unknown command, `2` on missing `engine/`.

**New commands:**

```cmd
python run.py browser http://localhost:3000
python run.py idor http://localhost:8000/api/me http://localhost:8000/api/users --session local-dev
```

---

## Findings from Real Target (TAMID)

Target: Nuxt frontend (`localhost:3000`) + Laravel API (`localhost:8000`)

| #   | Severity | Pattern                  | Reason                                                |
| --- | -------- | ------------------------ | ----------------------------------------------------- |
| 1   | CRITICAL | laravel-debug-mode       | 860 KB Laravel error page exposed on unauth `/api/me` |
| 2   | HIGH     | api-error-handling       | 500 error instead of 401 on missing auth              |
| 3   | MEDIUM   | api-info-disclosure      | 367 stack trace matches in error page                 |
| 4   | MEDIUM   | security-headers-missing | Missing HSTS, CSP, X-Frame-Options                    |
| 5   | MEDIUM   | authed-security-headers  | Duplicate ng #4                                       |

**Root cause ng #1-3:** `APP_DEBUG=true` sa Laravel `.env`

**Remediation:**

```env
APP_DEBUG=false
APP_ENV=production
```

```cmd
php artisan config:clear
php artisan config:cache
```

**Verify:**

```cmd
curl http://127.0.0.1:8000/api/me
```

Expected: `401 {"message":"Unauthenticated"}` — hindi 860 KB HTML.

---

## Ano'ng Wala Pa (Gaps)

### ✅ Resolved sa build8–11

- ~~Parallel pattern execution~~ (build9)
- ~~Findings deduplication~~ (build9, basic)
- ~~Baseline auto-load~~ (build10, `--auto-baseline`)
- ~~SARIF export~~ (build9)
- ~~Rate limit throttle~~ (build10, token bucket)
- ~~ROE not enforced~~ (build8, fail-closed)
- ~~Multi-step oracle last-step bias~~ (build8)
- ~~XSS sa HTML report~~ (build8, autoescape)
- ~~Report counts PASS as critical~~ (build8)
- ~~Report lookup mismatch~~ (build9, loopback alias)

### 🔴 Detection gaps (hindi pa)

| Kulang                 | Bakit importante                    |
| ---------------------- | ----------------------------------- |
| SQL injection probes   | Classic OWASP Top 1                 |
| XSS probes             | Reflected/stored XSS                |
| SSTI probes            | Template injection                  |
| SSRF probes            | OOB callback required               |
| XXE probes             | XML parsing                         |
| Open redirect          | Redirect chain validation           |
| CSRF token analysis    | Missing/weak CSRF                   |
| File upload bypass     | Content-Type, extension             |
| Mass assignment        | Inject extra fields sa POST         |
| JWT weak secret        | Brute force HMAC secret             |
| IDOR live probe        | Actual ID extraction from `/api/me` |
| Rate limit bypass      | X-Forwarded-For rotation            |
| HTTP request smuggling | CL.TE, TE.CL                        |
| Prototype pollution    | JSON body injection                 |

### 🟠 Engine gaps (hindi pa)

| Kulang                       | Impact                                |
| ---------------------------- | ------------------------------------- |
| Retry budget tuning          | Slow scans on partial failures        |
| Playwright integration       | Console logs, JS errors, screenshots  |
| OOB callback server          | Needed for blind SSRF, blind XSS      |
| Recursive JS crawl           | Nuxt lazy chunks not fully parsed     |
| State machine reconstruction | Implicit state mapping                |
| Combination explorer         | Pairwise input/endpoint/timing combos |
| RL-based adaptive search     | Hypothesis-driven exploration         |

### 🟡 Evidence gaps (hindi pa)

| Kulang                      | Impact                        |
| --------------------------- | ----------------------------- |
| Screenshot capture          | Proof of visual state         |
| Full request/response pairs | Currently only bodies         |
| Diff view between runs      | Trend analysis                |
| Timeline view               | Attack sequence visualization |

### 🟡 Safety gaps (hindi pa)

| Kulang                      | Impact                    |
| --------------------------- | ------------------------- |
| ROE time window enforcement | Flag exists, not enforced |
| Signed ROE tokens           | Centralized authority     |
| Proof-of-work challenge     | Prevent accidental DoS    |

---

## Improvement Roadmap

### Phase 8 ✅ (DONE)

- [x] Parallel pattern execution
- [x] Findings deduplication (basic)
- [x] Baseline auto-load integration (`--auto-baseline`)
- [x] SARIF export
- [x] Rate limiter (token bucket)
- [x] ROE fail-closed
- [x] Multi-step oracle correctness
- [x] HTML report autoescape
- [x] Severity-ranked ledger queries

### Phase 9 (Next — handoff to Claude Code)

- [x] Integration tests (live HTTP target) — `tests/test_integration.py`
- [x] Concurrent rate limiter (see Confidence Gaps #1)
- [x] Race condition patterns rework (see Confidence Gaps #2)
- [x] Playwright integration (console, JS errors, screenshots) — `engine/browser.py`
- [ ] Recursive JS crawl for lazy chunks
- [x] IDOR live probe (extract actual IDs from `/api/me`) — `engine/idor.py`
- [x] JWT weak secret checker — `jwt-weak-secret` pattern + `jwt_weak_secret` oracle
- [x] CI workflow (GitHub Actions + SARIF upload) — `.github/workflows/ci.yml`
- [x] `--fail-on <severity>` exit codes (see Confidence Gaps #10)
- [x] Dead config cleanup (see Config Files)

### Phase 10

- [ ] OOB callback server (Interactsh-style)
- [ ] Blind SSRF/XSS patterns
- [ ] Mass assignment patterns
- [ ] HTTP request smuggling probes

### Phase 11 (Novel)

- [ ] Combination explorer
- [ ] State machine reconstruction
- [ ] Emergent behavior detector
- [ ] Timing correlation matrix

### Phase 12

- [ ] Web UI dashboard
- [ ] Multi-target campaigns
- [ ] Continuous monitoring mode

---

## Pattern Authoring Guide

Bagong pattern = isang YAML file sa `patterns/<category>/`.

```yaml
id: my-pattern
name: Human Readable Name
severity: critical | high | medium | low | info
tags: [category, wstg-xxx-xx, cwe-xxx]
endpoint_suffix: /path # optional — appended to target
ignore_default_auth: true # optional — strip auth headers

inputs:
  target_url:
    type: string
    required: true
  iterations:
    type: int
    default: 10

steps:
  - name: step1
    no_auth: true # optional — skip default auth for this step
    repeat: "{{ inputs.iterations }}"
    concurrency: 5
    request:
      method: POST
      url: "{{ inputs.target_url }}"
      headers:
        X-Custom: "value-{{ loop_index }}"
      json:
        field: "value_{{ loop_index }}"

oracles:
  - type: status_code_present
    code: 200
    verdict: VULNERABLE
```

**Template variables:**

- `{{ inputs.<name> }}` — from inputs section
- `{{ loop_index }}` — current iteration
- `{{ target }}` — scan target URL

**Verdict priority:** `VULNERABLE > SUSPICIOUS > PASS > UNKNOWN`

---

## Config Files

| File                       | Purpose                                   | Enforced?      |
| -------------------------- | ----------------------------------------- | -------------- |
| `configs/engine.yaml`      | HTTP, rate limits, concurrency, ROE flags | ✅ most keys   |
| `configs/targets.yaml`     | Named targets for `login <name>`          | ✅             |
| `configs/credentials.yaml` | Credentials for `auto <url>`              | ✅             |
| `configs/roe.yaml`         | Scope, forbidden paths, allowed methods   | ✅ fail-closed |
| `configs/sessions/*.json`  | Saved sessions                            | ✅             |

### Config cleanup (Phase 9 — done)

**Now implemented (were dead):**

- `engine.yaml` → `evidence.save_raw_bodies` — when false, bodies omitted from `raw.json`
- `engine.yaml` → `evidence.max_body_size_kb` — caps stored body size (prevents 860 KB dumps)
- `engine.yaml` → `report.severity_threshold` — filters report findings below the level

**Removed from `engine.yaml` (truly unused):**

- `report.include_evidence`, `report.default_format`
- `concurrency.race_condition_barrier_ms` (obsoleted by the race bypass in Gap #2)
- `logging.*` (structlog never imported)
- `roe.enforce_time_window`, `roe.enforce_rate_limit` (never read by `ROEGuard`)

**Still documented-only in `roe.yaml`** (listed under its `_documentation_only` key):
`time_window.*`, `rate_limits.*`, `safety.*` — superseded by `engine.yaml` `rate_limit`
or reserved for a future ROE authority.

---

## Usage Examples

**Full auto-scan (rekomendado):**

```cmd
python run.py auto http://localhost:3000 --auto-baseline
```

**Without discovery:**

```cmd
python run.py auto http://localhost:3000 --no-discovery
```

**Force adapter:**

```cmd
python run.py auto http://localhost:3000 --adapter laravel
```

**Single pattern:**

```cmd
python run.py scan laravel-debug-mode http://localhost:8000/api
python run.py scan rate-limit-absent http://localhost:8000/api/login --iter 50
python run.py scan race-condition-basic http://localhost:8000/api/cart --concurrency 30
```

**With saved session:**

```cmd
python run.py login local-dev
python run.py scan-all http://localhost:8000/api --session local-dev
```

**Custom auth:**

```cmd
python run.py scan auth-bypass-probe http://example.com/api/me --auth bearer:TOKEN
python run.py scan-all http://example.com --auth cookie:session=abc123
```

**Profile baseline:**

```cmd
python run.py profile http://localhost:8000/api/login --samples 100
```

**Reports:**

```cmd
python run.py report http://127.0.0.1:8000/api
python run.py report http://127.0.0.1:8000/api --format sarif
python run.py history
python run.py history --target http://127.0.0.1:8000/api
```

---

## File Structure

```
sec-checker/
├── run.py                       CLI entry point
├── README.md                    This file
├── requirements.txt             Runtime deps (incl. playwright)
├── requirements-dev.txt         + pytest, jsonschema
├── .github/workflows/ci.yml     GitHub Actions (pytest + scan + SARIF upload)
├── .gitignore                   Protect credentials + artifacts
├── build*.py                    Build scripts (dev tools, gitignored)
├── a.py                         ROE audit tool (dev, gitignored)
├── engine/
│   ├── cli.py, auto.py, ...
│   ├── browser.py               Playwright capture
│   ├── idor.py                  IDOR live probe
│   ├── util.py                  safe_name, atomic writes
│   ├── ratelimit.py             token bucket (+ shared registry)
│   └── session.py               DEPRECATED stub
├── adapters/                    11 YAML files
├── patterns/
│   ├── single/                  8 patterns
│   ├── sequence/                8 patterns
│   ├── temporal/                5 patterns
│   ├── content/                 3 patterns
│   └── meta/                    2 patterns (jwt-analysis, jwt-weak-secret)
├── configs/
│   ├── engine.yaml
│   ├── targets.yaml             (gitignored)
│   ├── credentials.yaml         (gitignored)
│   ├── roe.yaml                 (gitignored)
│   └── sessions/                (gitignored)
├── wordlists/
│   ├── common_paths.txt
│   ├── sensitive_keys.txt
│   ├── jwt_secrets.txt          JWT brute-force candidates
│   └── user_agents.txt
├── tests/
│   ├── conftest.py              step() / ctx() fixtures
│   ├── test_oracles.py          multi-step oracle tests
│   ├── test_roe_guard.py        fail-closed + glob tests
│   ├── test_integration.py      live HTTP: pipeline, rate limiter, SARIF, fail-on
│   ├── test_jwt_oracle.py       JWT weak-secret cracking
│   ├── test_idor.py             IDOR extraction + live probe
│   ├── test_browser.py          Playwright console/JS-error/screenshot
│   └── test_config_keys.py      evidence + report config keys
├── evidence/                    (gitignored)
├── findings/                    (gitignored)
├── reports/                     (gitignored)
└── logs/                        (gitignored)
```

---

## Dependencies

Runtime — `requirements.txt`:

```
httpx          HTTP client
pyyaml         YAML parsing
rich           CLI tables and colors
jinja2         HTML report templating
beautifulsoup4 HTML parsing
lxml           XML/HTML backend
playwright     Headless browser (console, JS errors, screenshots — Phase 9)
```

> After `pip install -r requirements.txt`, run `python -m playwright install chromium`
> once to fetch the browser binary (the pip package alone does not include it).

**Dev/test — `requirements-dev.txt`:**

```
pytest         unit + integration tests
jsonschema     SARIF schema validation (tests/test_integration.py)
```

**Declared but unused (Phase 9 cleanup — not in requirements.txt):**

```
structlog      Structured logging — never imported
tenacity       Retry logic — hand-rolled in http_client
dnspython      DNS — never imported
```

---

## Known Limitations

- Hindi kaya ang blind vulnerabilities — walang OOB callback server
- Hindi kaya ang SPA-deep crawl — partial JS parsing
- Hindi kaya ang HTTP/2 specific attacks — naka-HTTP/1.1
- Hindi kaya ang binary protocol testing — HTTP lang
- ~~Manual baseline~~ — resolved (`--auto-baseline`)
- ~~Sequential pattern execution~~ — resolved (build9)
- ~~Duplicates sa findings~~ — resolved (build9, basic)
- ~~No visual evidence — walang screenshots~~ — resolved (`browser` command, Playwright)
- ~~Race condition patterns may false-PASS~~ — resolved (Confidence Gap #2, `no_rate_limit` + threshold bypass)
- ~~Rate limiter not truly global~~ — resolved (Confidence Gap #1, shared limiter)
- ~~No integration tests~~ — resolved (`tests/test_integration.py`, live HTTP target)
- ~~No CI/CD workflow~~ — resolved (`.github/workflows/ci.yml`, pytest + scan + SARIF upload)
- Blind SSRF/XSS still need an OOB callback server (Phase 10)

---

## Legal & Ethical Notice

Gamitin lang sa mga system na:

- Pag-aari mo, **O**
- May written authorization ka, **O**
- Public bug bounty program na may defined scope

Bawal gamitin sa:

- Iba pang tao/system na walang pahintulot
- Government systems
- Critical infrastructure
- Systems na wala sa ROE scope

**Ang `configs/roe.yaml` ay fail-closed.** Kung walang `scope.in_scope` list, lahat ng requests ay **blocked**. Hindi default-allow. Legal defense ito — hindi decorative config.

---

## Status

**Version:** 1.2.0
**Last build:** Phase 9 — Confidence-gap fixes + Playwright + IDOR + JWT + CI
**Production-ready para sa:**

- Laravel + Nuxt stacks (verified on TAMID)
- Django, Rails, Next.js, WordPress (initial support)
- Basic API security checks

**Tested on:** TAMID member portal (Nuxt + Laravel)
**Findings discovered:** 5 (3 critical/high from `APP_DEBUG=true`)

---

## Credits

Built iteratively across phases:

| Phase | Focus                                  |
| ----- | -------------------------------------- |
| 1     | Environment setup                      |
| 2     | Core engine + patterns                 |
| 3     | Auth flow + route enum                 |
| 4     | Auto-discovery                         |
| 5     | Redirect handling fixes                |
| 6     | Laravel debug detection                |
| 7     | Framework adapter system               |
| 8     | Audit fixes + parallel + rate limiting |
| 9     | Confidence-gap fixes + Playwright + IDOR + JWT + CI + integration tests |

**Architecture:** Evidence-closure, deterministic oracles, YAML patterns
**Philosophy:** Black-box, no codebase required, reproducible

---

## Handoff to Claude Code

### Setup

```cmd
pip install -r requirements-dev.txt
python -m playwright install chromium
```

### Verify current state

```cmd
python run.py --version            # sec-checker 1.2.0
python run.py validate             # 26 OK, 0 FAIL
python run.py adapters             # 11 adapters
python -m pytest tests/ -q         # 48 passed
python a.py                        # ROE audit: CLEAN, 20/20 guard tests
```

### Live smoke test

```cmd
python run.py auto http://localhost:3000 --min-severity medium --auto-baseline
python run.py report http://localhost:3000
python run.py report http://localhost:3000 --format sarif
```

### Priority tasks for Claude Code

1. **Add integration tests** — `tests/test_integration.py` with a live target. Use `pytest-httpserver` or a small Flask app. Cover: full `auto` pipeline, `scan-all` parallel correctness, SARIF output validity (validate against schema).
2. **Fix concurrent rate limiter** — see Confidence Gap #1.
3. **Fix race condition patterns** — see Confidence Gap #2.
4. **Validate SARIF output** — never run through a real SARIF viewer. Test with `sarif-tools` or GitHub's SARIF validator.
5. **CI workflow** — `.github/workflows/ci.yml` running pytest + a scan on a disposable Flask target + SARIF upload.
6. **Dead config cleanup** — either implement or delete unread keys (see Config Files section).

---

## Confidence Gaps (Honest Assessment)

Ito yung mga bagay na **hindi ako sigurado** — these are the risks I'd want Claude Code to verify first.

### ✅ #1 — Rate limiter now truly global (RESOLVED)

`RateLimiter` was instantiated inside `HttpClient.__init__`, so every pattern in the parallel pool got its own limiter and `global_rps: 10` meant "10 RPS _per pattern_" (~8× the intended rate under 8 workers).

**Fix:** `ratelimit.get_shared_limiter()` is a process-wide registry keyed by the rate-config signature. Every `HttpClient` created with the same `rate_limit.*` config shares one `RateLimiter`, so the global token bucket is enforced across every pattern and worker thread. Per-endpoint buckets stay keyed by URL inside the instance. Pass `shared_rate_limit=False` for an isolated bucket (used by tests).

**Verified:** `tests/test_integration.py::test_global_rate_limiter_is_shared` — 10 requests across 2 parallel patterns at `global_rps=5, burst=1` take ≥1.3 s (a per-pattern limiter would finish in ~0.8 s).

### ✅ #2 — Race condition bypass added (RESOLVED)

The global limiter would serialize a `concurrency: N` burst with token-bucket delays, closing the race window and producing a false `PASS`.

**Fix:** a concurrent step bypasses the limiter when it fires at or above `RACE_CONCURRENCY_THRESHOLD` (10), or when the step sets `no_rate_limit: true`. Below the threshold, and for all `repeat`/single steps, throttling still applies.

**Verified:** `tests/test_integration.py::test_race_step_bypasses_rate_limiter` — 20 concurrent requests at `global_rps=2, burst=1` complete in <4 s (a throttled burst would take ~9.5 s) and all 20 reach the target.

### ✅ #3 — SARIF validated against the official schema (RESOLVED)

The generated SARIF now validates cleanly against `https://json.schemastore.org/sarif-2.1.0.json`. The earlier concerns (missing `$schema`, `ruleIndex`, `http://` URIs) were not actual schema violations — `ruleIndex` is optional and `http` URIs are accepted.

**Verified:** `tests/test_integration.py::test_sarif_output_is_schema_valid` validates real generator output with `jsonschema` (skips only if the schema can't be fetched offline), plus structural assertions that always run.

### ✅ #4 — Baseline filename mismatch fixed (RESOLVED)

`save_baseline` used `util.safe_name` (truncate at 80) while `load_baseline` and `executor._load_baseline_for` used a local helper that truncated at 100. For target URLs longer than 80 chars the two produced different filenames, so the baseline never loaded. Short URLs (e.g. TAMID) coincidentally matched, hiding the bug.

**Fix:** all three paths now use `util.safe_name`.

**Verified:** `python -c` round-trip of a 100+ char URL returns non-None from both `baseline.load_baseline` and `executor._load_baseline_for`.

### ✅ #5 — ROE `enforce_*` flags now honored (RESOLVED)

`execute_pattern` created `ROEGuard()` with no engine config, so `enforce_scope` / `enforce_methods` silently fell back to their hard-coded `True` defaults regardless of `engine.yaml`.

**Fix:** `execute_pattern` now constructs `ROEGuard(engine_cfg=cfg)`. Both call sites (`auto._run_pattern`, `cli._run_single`) already pass the engine config into `execute_pattern`. The `http_client` fallback `ROEGuard()` keeps the fail-closed defaults.

**Verified:** `tests/test_integration.py::test_roe_blocks_out_of_scope_host` and a `ROEGuard(engine_cfg=...)` flag round-trip.

### 🟡 #6 — Parallel `_record` writes

Build9 moved `_record` out of worker threads into the parent loop. Good. But `_record` calls `evidence.save_evidence` (filesystem) and `ledger.record_finding` (SQLite) sequentially per pattern. With 25 patterns, that's 25 filesystem writes + 25 SQLite inserts in series — fast, but not tested under failure conditions (disk full, SQLite locked).

**Fix sketch:** wrap in try/except, log to `logs/` on failure, continue the scan.

### 🟡 #7 — `js-bundle-secrets` override path untested

The pattern now receives `overrides={"target_url": js_url}` for each bundle. If the pattern ever gets an `endpoint_suffix`, the override would append the suffix to a JS URL and fail. Currently `js-bundle-secrets` has no suffix, so it works — but it's a latent trap.

**Fix sketch:** add a comment in the pattern's YAML warning future authors not to add an `endpoint_suffix`.

### 🟡 #8 — Unit tests cover pure functions only

`tests/test_oracles.py` and `tests/test_roe_guard.py` are pure unit tests. No test actually fires an HTTP request, no test exercises `HttpClient` retries, no test covers `execute_pattern`, no test verifies `run_auto` end to end.

**Fix sketch:** `tests/test_integration.py` using `pytest-httpserver` to spin up a fake target and run `run_auto` against it.

### 🟡 #9 — Dedupe reason prefix is fragile

`_dedupe` keys on `(pattern_id, verdict, reason[:120])`. Two legitimately distinct findings that happen to share the first 120 chars of their reason (e.g., two different endpoints with identical error messages) will collapse into one.

**Fix sketch:** include `target` or a hash of `evidence` in the dedupe key.

### ✅ #10 — `run.py` exit codes (RESOLVED)

The CLI now propagates exit codes: `scan`, `scan-all`, and `auto` accept
`--fail-on <severity>` and exit `3` when any VULNERABLE/SUSPICIOUS finding is
at or above that severity. `main()` returns `1` on unknown command; `run.py`
still returns `2` on missing `engine/`.

**Verified:** `tests/test_integration.py` (`test_fail_on_*`, `test_unknown_command_returns_one`) plus process-level checks.

### 🟡 #6–#9 — still open (low priority)

Parallel `_record` failure handling (#6), `js-bundle-secrets` suffix trap (#7),
and the fragile `_dedupe` reason prefix (#9) remain as noted. Unit coverage (#8)
is substantially expanded: 48 tests including live-HTTP integration, Playwright,
IDOR, and JWT suites.

---

## Verification Checklist for Claude Code

Before opening a PR, Claude Code should be able to check off:

- [x] `python run.py --version` prints `1.2.0`
- [x] `python run.py validate` returns 26 OK, 0 FAIL
- [x] `python -m pytest tests/ -q` returns 48 passed
- [x] `python a.py` returns CLEAN and 20/20 guard tests
- [ ] `python run.py auto http://localhost:3000 --auto-baseline` completes without worker errors
- [x] `python run.py report ... --format sarif` produces valid JSON that passes `jsonschema` validation (see `test_sarif_output_is_schema_valid`)
- [x] Confidence Gap #1 (rate limiter) reproduced or fixed
- [x] Confidence Gap #2 (race condition) reproduced or fixed
- [x] At least one integration test exists in `tests/`
- [ ] Dead config keys either implemented or removed

Good luck sa Claude Code. Yung confidence gaps yung pinaka-mahalagang i-verify — yun yung mga bagay na malamang na hindi na-catch ng unit tests at hindi ko pa na-confirm sa live scan.
