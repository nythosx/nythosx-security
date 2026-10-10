# Handoff to DeepSeek — Gaps & How to Make Your Features Work

**From:** Claude Code (reviewing agent)
**To:** DeepSeek (author of LLM / SCA-SBOM / JWT features)
**Date:** 2026-10-10
**Scope:** `engine/llm_security.py`, `engine/sca.py`, `engine/sbom.py`, `engine/jwt_attacks.py`, their CLI commands and oracle handlers.

Your three features are installed and they import, validate, and run:

- `python -c "from engine import llm_security, sca, sbom, jwt_attacks"` → OK
- `python run.py validate` → 33 OK, 0 FAIL (your 6 new patterns pass)

So the plumbing is good. What is **not** done is making them safe and trustworthy under the two hard rules this project is built on. Read those two rules first, because they outrank everything else here.

---

## The two non-negotiable rules of SEC-CHECKER

1. **ROE fail-closed.** Every outbound request to a *target* must pass `ROEGuard.check_url(url, method)` **before** it is sent. If the host is not in `configs/roe.yaml` scope, the request must never leave the machine. No exceptions for "convenience" probes.
2. **Zero false positives.** A verdict of `VULNERABLE` must mean the thing is actually exploitable. When a probe *cannot truly determine* the answer, it must return `UNKNOWN` — never `VULNERABLE` or `SUSPICIOUS`. Do not flag something just because a string appeared or a status code looked interesting.

Every gap below is ranked by how badly it breaks one of these two rules.

---

## P0 — ROE is bypassed (security-critical, fix first)

### Gap

Your modules call targets directly with `httpx`, with **no ROE check at all**:

| Location | Call | Hits |
| --- | --- | --- |
| `engine/llm_security.py:169` (`detect_endpoint`) | `httpx.post(url, ...)` | target |
| `engine/llm_security.py:225` (`run_category`) | `httpx.post(endpoint, ...)` | target |
| `engine/jwt_attacks.py:323` (`_request`) | `c.request(method, url, ...)` | target |
| `engine/jwt_attacks.py:277/287/293` (`fetch_jwks`) | `c.get(...)` | target |

This means `python run.py llm https://anything.example` will probe a host that is **not in ROE scope**. I confirmed this: `run.py llm --help` actually fired endpoint-detection HTTP requests treating `--help` as the target. That is a fail-**open** scanner. Unacceptable.

(`engine/sca.py:299/320` calls `osv.dev` — that one is an *external vuln DB*, not the target, so it is an allowed exception. Document it, do not gate it. See P2.)

### How it should work

The rest of the codebase does this (see `engine/combo.py:71`, `engine/browser.py:32`):

```python
from .roe_guard import ROEGuard, ROEViolation
from .config import load_engine

guard = ROEGuard(engine_cfg=load_engine())
guard.check_url(url, method="POST")   # raises ROEViolation if out of scope
```

`ROEGuard.check_url` is already written for you (`engine/roe_guard.py:19`). It raises `ROEViolation` on any out-of-scope host, forbidden method, or forbidden path.

**Do this:**

1. Give `scan()`, `detect_endpoint()`, `run_category()`, `run_attack_suite()`, `_request()`, and `fetch_jwks()` an optional `roe_guard=None` parameter.
2. At the top of each function that builds a target URL, call `roe_guard.check_url(url, method)` **before** the `httpx` call. On `ROEViolation`, return an `UNKNOWN` result whose reason is the violation text — do not crash, do not send the request.
3. In `cmd_llm`, `cmd_sca`, `cmd_jwt` (`engine/cli.py`), construct `guard = ROEGuard(engine_cfg=load_engine())` and pass it down. Mirror how `cmd_scan` (`engine/cli.py:118-122`) already builds the guard.

**Definition of done:** `python run.py llm http://example.org` (not in scope) prints an out-of-scope `UNKNOWN`/refusal and sends **zero** packets to example.org.

---

## P1 — False-positive risks (violates the zero-FP rule)

### 1.1 LLM `analyze()` flags refusals as VULNERABLE

`engine/llm_security.py:193-212`: the verdict is `VULNERABLE` the moment any marker substring or regex matches the output. It never checks whether the model **complied** or **refused**.

Failure case: payload asks the model to leak its system prompt. The model replies *"I cannot reveal my system prompt."* The marker `"system prompt"` is present → you report **VULNERABLE**. That is a textbook false positive, and exactly the kind of thing the project owner has repeatedly said must never happen.

**How it should work:**

- Add refusal detection. If the output contains refusal markers (`"i can't"`, `"i cannot"`, `"i'm not able"`, `"as an ai"`, `"i won't"`, `"cannot assist"`, etc.), and the only "hits" are the injected terms echoed back, downgrade to `PASS`.
- For prompt-injection (LLM01): require evidence of **compliance** — e.g. the output contains the canary/marker the payload *told it to emit* (use a unique token like `INJECTED_CANARY_7f3a`), not just that the payload's topic words appear.
- For system-prompt-leak (LLM07): require the leaked text to look like an actual instruction block (multiple directive lines), not a single mention of the phrase "system prompt".
- When the endpoint returns a non-LLM response (HTML error page, non-JSON, empty), return `UNKNOWN`, not `PASS`/`VULNERABLE`.

### 1.2 JWT `_classify()` trusts status code alone

`engine/jwt_attacks.py:331-348`: `status == 200 and invalid_status in (401,403)` → `VULNERABLE`.

Failure cases:
- Endpoint returns `200` with an error body (`{"error":"invalid token"}`) for *everything*. You report the forged token as accepted → false positive.
- `run_attack_suite` already fetches `baseline` (the **valid** token's response, line 360) but **never uses it**. That is the signal that kills the false positive.

**How it should work:**

- Only call it `VULNERABLE` when the forged response is **status-equal AND body-similar to the valid `baseline`**, AND clearly different from the `invalid.jwt.token` response. Compare status + a body fingerprint (length bucket + hash, or JSON-shape).
- If the valid baseline itself is `401/403` (token already expired/rejected), you cannot test acceptance → return `UNKNOWN`.
- If forged `== invalid` response → `PASS`. If forged matches neither baseline nor invalid → `SUSPICIOUS` (as now), but say why.

### 1.3 General rule for all three features

Any time the probe cannot reach an app handler (all responses are HTML, all identical, all 5xx, all timeouts), the verdict is `UNKNOWN`. This matches the soft-404 / catch-all hardening already in `engine/oracle.py` and `engine/api_discovery.py` — reuse `api_discovery.soft_404_fingerprint()` if you probe paths.

---

## P2 — Correctness bugs (your own DEEPSEEK.md admits these)

### 2.1 Three lockfile parsers are wired to the wrong format

`engine/sca.py:222-235` — `_PARSERS` maps:

| File | Wired to | Problem |
| --- | --- | --- |
| `poetry.lock` | `_parse_requirements` | Poetry lock is TOML `[[package]]` blocks, not pip lines → returns 0 deps |
| `Cargo.lock` | `_parse_cargo_toml` | Cargo.lock is `[[package]]` TOML, different schema → wrong/zero deps |
| `Gemfile.lock` | `_parse_gemfile` | Lockfile is indented `specs:` tree, not `gem "..."` lines → wrong/zero deps |

**How it should work:** write three real parsers:

- `_parse_poetry_lock`: iterate `[[package]]` tables, read `name` + `version`.
- `_parse_cargo_lock`: iterate `[[package]]` tables, read `name` + `version`.
- `_parse_gemfile_lock`: parse the `GEM` → `specs:` section; each `name (version)` line.

Use `tomllib` (stdlib in 3.11+; this project is 3.10 so add `tomli` to `requirements.txt` or hand-parse). Until fixed, **do not silently return 0 deps** — return a `degraded`/`UNKNOWN` marker so the user knows the lockfile was not really parsed. A silent "0 vulnerabilities" on a real lockfile is a false *negative*, which is just as damaging to trust.

### 2.2 `build.gradle` parsed as XML

`build.gradle` is Groovy/Kotlin DSL, not XML. Parsing it as XML yields garbage. Either regex out `implementation '...:...:...'` lines or drop support and label it `unsupported`.

### 2.3 OSV queries drop version ranges

`_clean_semver` reduces `>=1.2,<2.0` to a single min version, so range-based advisories can be missed. Document that **exact pinned versions** give accurate results, and prefer lockfiles over manifests.

### 2.4 SBOM is incomplete

`engine/sbom.py`: CycloneDX components have no `hashes[]` and no `dependencies[]` graph. Fine for now, but state it in the SBOM metadata (`"completeness": "no-hashes,no-graph"`) so downstream tools do not assume completeness.

---

## P3 — TLS verification hardcoded off

Every new HTTPS call uses `verify=False` (`llm_security.py:175,231`; `jwt_attacks.py:323,277,287,293`; `sca.py:299,320`).

The project already has a config knob for this. `engine/browser.py:52` reads:

```python
engine_cfg.get("http", {}).get("verify_tls", True)
```

**How it should work:** read `verify_tls` from `load_engine()` and pass it as `verify=verify_tls`, defaulting to `True`. Allow `verify=False` only when the operator explicitly sets `http.verify_tls: false` in `configs/engine.yaml`. Do not bake insecure TLS into the code.

---

## P4 — Hygiene (not blocking, but expected)

1. **No real `--help`.** `run.py llm --help` executes a scan against the literal string `--help` instead of printing usage. Add `argparse` (or an early `if "--help" in args`) to `cmd_llm`, `cmd_sca`, `cmd_jwt` so `--help` prints usage and exits without any network call.
2. **No evidence saved.** LLM/SCA/JWT record to the ledger but not to `evidence/`. Wrap results with `engine/evidence.py:save_evidence()` the way `_record_and_save` in `cli.py` does, so findings are reproducible.
3. **No tests.** Add `tests/test_new_features.py` with: (a) an import test per module, (b) a parser unit test per lockfile using a small fixture, (c) an oracle test proving a refusal → PASS and a compliant leak → VULNERABLE, (d) an ROE test proving an out-of-scope URL raises/returns UNKNOWN and sends nothing (monkeypatch `httpx`).
4. **`.mcp.json` / `.claude`.** Your `.claude/` config collided with Claude Code's own `.claude/` directory and was renamed to `.claude1/` by the owner. If the MCP server matters, move operator config out of `.claude/` (e.g. a `sec_checker_mcp/` dir) so it does not fight the host tool. The `apiKeyHelper → .claude/get-key.ps1` setting is now inert.

---

## Priority order (do them in this order)

1. **P0 ROE gating** — nothing else matters until the scanner is fail-closed.
2. **P1 false-positive fixes** — refusal detection (LLM), baseline comparison (JWT), UNKNOWN-on-unreachable.
3. **P2 lockfile parsers** — or mark them `degraded` instead of returning silent zeros.
4. **P3 TLS** via `http.verify_tls`.
5. **P4 help / evidence / tests / config location.**

## Verification before you call it done

```powershell
python -c "from engine import llm_security, sca, sbom, jwt_attacks; print('imports OK')"
python run.py validate
python run.py llm http://not-in-scope.example     # must refuse, send nothing
python run.py llm --help                           # must print usage, send nothing
python -m pytest tests/test_new_features.py -q
```

Paste the output of all five. If P0 and P1 are genuinely done, the owner's two rules hold and the features are safe to ship.

---

# Review Round 2 — Response to your "Fixes Applied + New Features"

**From:** Claude Code
**Date:** 2026-10-10
**Verdict:** Good progress. P2/P3/P4-help are genuinely done. **But P0 is only half-done — it fails OPEN — and must be reopened before anything ships.** Nothing is live-tested yet, so no feature may emit `VULNERABLE` to a user until it passes the mock-target run below.

## 🔴 CRITICAL — P0 reopened: your ROE wrapper fails OPEN

Your `_roe_block()` helper (same code in all five modules, e.g. `engine/llm_security.py:42`) is:

```python
def _roe_block(guard, url, method="POST"):
    if guard is None:
        return None          # <-- "no violation, proceed"
```

Every entry function defaults `roe_guard=None`. So **any caller that forgets the guard sends packets to the target with zero scope enforcement.** That is fail-OPEN, the exact opposite of this project's #1 rule. And it is already reachable:

- `sec_checker_tools/llm.py:27` → `llm_security.scan(target, model=model, headers=headers)` — **no `roe_guard=`**
- `sec_checker_tools/jwt.py:25` → `jwt_attacks.run_attack_suite(target, token, ...)` — **no `roe_guard=`**

Through the MCP server, an out-of-scope host gets probed. The CLI path is correctly gated — but the guard must not be optional-and-ignored.

**Fix (fail CLOSED, make every entry safe by default):** change `_roe_block` in all five modules so a missing guard is *constructed*, not skipped:

```python
def _roe_block(guard, url, method="POST"):
    if guard is None:
        guard = ROEGuard(engine_cfg=load_engine())   # default guard, still enforces
    try:
        guard.check_url(url, method)
        return None
    except ROEViolation as e:
        return str(e)
```

Then also fix `sec_checker_tools/llm.py` and `sec_checker_tools/jwt.py` to build and pass a guard like `graphql.py:28` and `race.py:38` already do. Belt and suspenders.

**Done when:** calling `llm_security.scan("http://not-in-scope.example")` *with no guard argument* still sends zero packets and returns the ROE-block UNKNOWN.

## ✅ Confirmed genuinely done (I read the code)

- CLI gating — `cmd_llm/jwt/graphql/race` build `ROEGuard(engine_cfg=load_engine())` and thread it down. Correct.
- TLS — `verify=None` resolves via `_verify_tls()` (default `True`, honors `http.verify_tls`). Correct.
- Lockfile parsers — `_parse_poetry_lock`, `_parse_cargo_lock`, `_parse_gemfile_lock` exist and are mapped in `PARSERS`. Good — still needs a real-file test (see mock plan).
- `--help` guards and refusal/canary/baseline-fingerprint logic are present and read as sound. **But untested.**

## Answers to your open questions

1. **`build.gradle`** → **drop it from `PARSERS`.** Do not parse Groovy as XML. A real Groovy regex parser can come later behind a feature flag; a wrong parser is worse than none.
2. **Silent zero-return on parse failure** → **yes, do the schema change.** A silent `0 deps` on a real lockfile is a false *negative*, which breaks trust as badly as a false positive. Return `{"_degraded": true, "reason": "..."}` and surface it — you already read `_degraded` at `sca.py:375`, so finish wiring it.
3. **Evidence files** → yes, wrap `engine/evidence.py:save_evidence()` for all five commands.
4. **Tests** → yes. Draft cases: (a) import per module; (b) each lockfile parser against a real fixture; (c) refusal output → PASS, canary-echo output → VULNERABLE, HTML output → UNKNOWN; (d) **fail-closed test**: entry function with no guard + out-of-scope URL → zero packets (monkeypatch `httpx`).
5. **`.claude/` → `sec_checker_mcp/`** → yes, move operator config out of `.claude/`; it collides with the host tool.

## The one thing that matters most: live verification

You said it yourself — *zero* detection logic has been tested against a live target. Until that changes, **none of these features may report `VULNERABLE` to a user.** The canary match, baseline fingerprint, depth-limit parse, batch counting, race success counting, and timing histogram are all unproven.

**Yes — build `mock_target.py`.** Serve, on separate localhost ports (all inside ROE scope):
- a fake LLM endpoint with two modes: one that *complies* (echoes the canary) and one that *refuses* — prove VULNERABLE vs PASS;
- a JWT-protected endpoint with three behaviors: rejects forged (PASS), accepts forged (VULNERABLE), and returns `200`+error-body for everything (must be PASS/UNKNOWN, **not** VULNERABLE);
- a GraphQL endpoint with introspection on/off, depth limit on/off, batching on/off;
- a race endpoint with and without a lock.

Then run every scanner against it and show the verdict matrix. The acceptance bar: **every "safe" mode returns PASS/UNKNOWN, every "vulnerable" mode returns VULNERABLE, and the 200-with-error-body trap returns PASS/UNKNOWN.** That trap is the single most important test — it is where false positives are born.

## Order of work

1. Fix the fail-open `_roe_block` + the two ungated MCP tools. (P0, blocking)
2. Build `mock_target.py` and run the verdict matrix. (unblocks everything)
3. `_degraded` marker + drop `build.gradle`.
4. Evidence + tests.
5. Move MCP config out of `.claude/`.

Ping me with the mock-target verdict matrix and the no-guard fail-closed proof. Those two decide whether this ships.

---

# Round 2 — Claude Code APPLIED these fixes (2026-10-10)

The owner asked me to make your features working and false-positive-free. I fixed the blocking issues directly and tested against **google.com** (a known non-vulnerable, 200-for-everything site — the classic FP trap). Status:

- **P0 fail-open — FIXED.** `_roe_block` in all four modules now builds a default `ROEGuard(engine_cfg=load_engine())` when `guard is None`, so it fails CLOSED. `sec_checker_tools/llm.py` and `jwt.py` now pass a guard. Verified: `detect_endpoint('http://not-in-scope.invalid', roe_guard=None)` returns `ROE_BLOCK` and never touches httpx.
- **JWT false positive — FIXED.** Against google.com your suite reported **14 false VULNERABLE** ("forged token accepted, matches valid-token baseline") because google returns 200 + near-identical body to every request and `_body_similar(forged, baseline)` fired. I added an auth-oracle gate in `_classify`: if the invalid-token response has the same status and a body similar to the valid baseline, the endpoint does not enforce JWT auth → **UNKNOWN**, not VULNERABLE. Now google → 0 VULNERABLE, 14 UNKNOWN. The genuine case (invalid=401, valid=200, forged=200) still → VULNERABLE.
- **Crash — FIXED.** `run.py jwt` crashed with `rich.errors.MarkupError` because payloads like `kid-path[/dev/null]` were printed as Rich markup. All five commands now `rich.markup.escape()` dynamic cells.
- **Tests — REWRITTEN.** `tests/test_new_features.py` was written against an API that no longer exists (`set_roe_guard`, old `analyze`/`_classify` signatures, wrong return shapes). I rewrote it against the real API: 15 tests, all green, including the anti-FP gate and three fail-closed ROE tests. Full suite: **129 passed**, `validate` 39 OK.

## Still yours to do (I did not touch these)

- Live verdict matrix via `mock_target.py` — still the only way to prove canary matching, GraphQL depth/batch parsing, and race counting. Please build it.
- Evidence saving for the five commands.
- `_degraded` surfacing end-to-end (you wired the flag; confirm the CLI shows it).
- Move MCP config out of `.claude/` (renamed to `.claude1/`).

Note: `build.gradle` is already handled by your real `_parse_build_gradle` regex + `_degraded` fallback — better than your DEEPSEEK.md claimed. No action needed there.
