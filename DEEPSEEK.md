Paste this to Claude Code:

---

Hey — landed a big multi-phase upgrade on sec-checker. Below is a file-level diff of what changed. No full-file dumps here to save your tokens; ask me for any specific file and I'll paste just that section. Review for: race conditions, import cycles, dead code, broken invariants, missed callers after signature changes, and integration gaps between the phases. Point at file:line.

## Phase 1 — Foundation

**NEW files:**
- `engine/audit.py` — append-only JSONL (`findings/audit.jsonl`), record/tail/count/enable/disable. Hashes credentials + payloads, redacts URLs and errors before writing.
- `engine/secrets_vault.py` — Fernet wrapper for `configs/credentials.yaml`. Format `SECVAULT1:<token>`. Optional; falls back to plaintext if `cryptography` missing.
- `engine/roe_helper.py` — single `check_roe(guard, url, method)` + lazy default guard. Meant to replace 12 duplicated `_roe_block()` funcs (not migrated yet).
- `engine/cost.py` — `estimate_cost(tool_name, args)` returning relative cost per tool. Has `_TOOL_COSTS` and `_ALIASES` dicts.

**Patched:**
- `engine/version.py` → `2.0.0`
- `engine/contract.py` — `ScanResult` gained `extracted_data, proof_of_impact, reproduction, cvss, asvs_chapters, mitre_techniques` (dataclass fields, `__getitem__`, `__contains__`, `to_dict`).
- `engine/redact.py` — 10 new token patterns (Supabase, Firebase, Sentry, Algolia, Mapbox, Twilio SID+auth, SendGrid, npm, pypi). New `redact_url()` strips token-like query keys.
- `engine/budget.py` — `record(url, weight=1.0)`. Per-host counter now floats.
- `engine/roe_guard.py` — added `check_path_normalized()` (currently just delegates to `check_url`).
- `engine/config.py` — `SCHEMA_VERSION = 2`; `load_engine()` auto-injects `schema_version`; `load_credentials()` now tries `secrets_vault.read_file()` first.
- `engine/schema.py` — `validate_asvs_metadata()`.
- `engine/http.py` — new `CircuitBreaker` class (threshold=5, cooldown=60s) with module-level `_default_breaker`. **Defined but not yet used at this phase.**
- `engine/util.py` — `mask_row(row, ..., mask_emails=True)` masks `local@domain` as `l***@domain`.

## Phase 2 — Content only

**NEW wordlists:** `cloud_bucket_suffixes.txt` (~180), `jailbreak_templates.txt` (~40), `blind_extract_queries.txt` (~30). Expanded `jwt_secrets.txt` to ~250.

**NEW patterns (15):** bola-harvest, unauth-pagination-dump, graphql-data-dump, blind-sqli-extract, blind-xxe-file-read, llm-system-prompt-dump, llm-tool-list-dump, llm-credential-extract, mcp-tool-poisoning, mcp-credential-exposure, ci-cd-config-exposure, npmrc-exposure, firebase-misconfig, session-fixation, postmessage-abuse.

**Patched:** `writeup_library.yaml` (+15 entries), `owasp_2025.py` (+15 PATTERN_MAP, +9 PREFIX_MAP), `coverage.py` (A03/A10 additions), both example configs.

## Phase 3 — Orchestrator

**NEW:** `engine/hooks.py` — four lifecycle points: `register_pre_chain_hook`, `register_post_finding_hook`, `register_post_unknown_hook`, `register_post_chain_hook`, plus `fire_*` counterparts. `fire_post_finding` mutates the result dict with whatever the hooks return (extracted_data, proof_of_impact, cvss, etc.) — **flag if this mutation is unsafe.**

**Patched:**
- `engine/chain_engine.py` — imports hooks; fires at 4 points (before chain, after finding, after unknown, after chain). Added `_run_pending_parallel()` and `run(chains=None, parallel=False)`.
- `engine/http.py` — `Client.request()` now checks `CircuitBreaker.allow()` (raises `ROEBlock("CIRCUIT_OPEN: host")` if tripped), records success/failure, and calls `_write_audit()` for every request. **Audit write is per-request — is the sync I/O a concern?**
- `engine/scoring.py` — `compute_priority()` multiplies by `_cost_factor(chain) = 1/chain_cost`. Chains with expensive tools (browser_capture=20.0) get priority cut 20x. **Too aggressive?**
- `engine/confirm.py` — 7 new `_DISPATCH` entries: bola_harvest, blind_sqli_extract, graphql_data_dump, blind_xxe_file_read, llm_system_prompt_dump, llm_credential_extract, unauth_pagination_dump, mcp_tool_poisoning, mcp_credential_exposure + generic.
- `engine/baseline.py` — `diff_since(target, since_iso)`, `latest_timestamp(target)`.
- `engine/hunt.py` — `_collect_extracted(report)` walks findings + evidence + ledger-record side effect.
- `engine/correlator/auto_chain.py` — +25 composite rules.
- `engine/chain_registry.py` — +10 chains (mcp-security, blind-sqli, blind-xxe, pagination-dump, graphql-dump, llm-prompt-dump, llm-cred-tool, session-fixation, ci-cd-exposure, npmrc).
- `engine/brains/rule_based.py` — `EXTRACTION_TOOLS` list; when `caps < 3` after normal proposal, adds up to 3 extraction hints.

## Phase 4 — New capabilities

**NEW modules (all self-register via `register_tool`):**
- `blind_extract.py` — DBMS fingerprint + binary-search blind SQLi. `_tool_blind_extract`.
- `xxe_harvest.py`, `ssrf_harvest.py`, `ssti_harvest.py` — file read, cloud metadata fetch, RCE.
- `mcp_security.py` — tool poisoning (11 patterns) + credential scan (9 patterns). `_tool_mcp_security`.
- `session_fixation.py`, `postmessage_probe.py`, `ci_cd_probe.py`, `npmrc_probe.py`, `firebase_probe.py`.
- `oracles_phase4.py` — **12 oracle handlers registered by mutating `oracle._HANDLERS` at import time.** Race concern if engine is imported concurrently.

**Patched:**
- `bola_scanner.py` — `harvest_sequential_ids(base, template, token, ...)` walking `{id}` or `/<digits>` paths, owner-field auto-detect from a list of common keys. `_tool_bola_harvest`.
- `data_extractor.py` — `extract_with_pagination()`, follows `Link: rel=next` and `page=`/`offset=` params, dedupes via SHA-256 of JSON body. `_tool_paginated_extract`.
- `graphql_schema.py` — `dump_all_data()` — introspects, then loops queryType fields. `_tool_graphql_dump`.
- `llm_security.py` — `_tool_llm_prompt_dump`, `_tool_llm_cred_extract`, `_tool_llm_tool_list`.
- `engine/__init__.py` — auto-imports 16 modules with `except Exception: pass`. **This silently swallowed a NameError twice; not happy about it.**

## Phase 5A — CLI + Reports + Ledger

- `ledger.py` — new `extracted_data` table; `record_extracted()`, `extracted_for_target()`, `extracted_stats()`.
- `evidence.py` — `bundle_evidence(target)` zips evidence + audit.jsonl + ledger.db into `findings/bundles/`.
- `report.py` — new helpers `_enrich_extracted_from_evidence_json`, `_collect_extracted_for_report`; `_build_context` now emits `extracted_rows`, `total_extracted`, `impact_summary`. HTML/MD templates get PROOF OF IMPACT banner, Extracted Data section, CVSS+ASVS columns.
- `cli.py` — `cmd_extract`, `cmd_bola`, `cmd_blind`, `cmd_mcp_scan`. Registered in `COMMANDS`.
- `hunt.py` — records every extracted batch into the ledger.

## Phase 5B — WebUI + MCP + Narrator

- `narrator.py` — `_narrate_step_done` now handles `extracted_records`, `extracted_value`, `files_read`. 10 new tool→label mappings. Returns enriched fields (`extracted`, `extracted_count`, `extracted_value`, `files_read`) that the webui JS consumes.
- `webui.py` — `_build_result` merges report-derived + ledger-derived `extracted_rows`; `total_extracted`. PAGE template (tty UI, not PAGE_CLASSIC) got `renderExtractedSummary(result)` + `handleLiveExtraction(d)` + `extractedSeen` accumulator; on `done`, `renderExtractedSummary(job.result)` prepends a red PROOF OF IMPACT card to `findingsBody`.
- NEW MCP tools: `sec_checker_tools/extract.py` (`data_extract_paginated`), `blind.py` (`blind_sqli_extract`), `mcp_scan.py` (`mcp_security_scan`), plus `bola_harvest` added to existing `bola.py`.

## What I want you to check

1. **`engine/hooks.py`** — `fire_post_finding` mutates the caller's result dict while hooks are being iterated. Is this safe given `_lock` guards the hook list copy but not the result dict?
2. **`engine/chain_engine.py`** — are the four `hooks.fire_*` call sites inside the right scope? Post-finding is inside `_record_finding`, post-unknown is after unknown classification, post-chain is after `chain_done` emit, pre-chain is in the new sequential and parallel loops. Any missing call sites (e.g. step errors, chain aborts)?
3. **`engine/http.py`** — `_write_audit` opens a JSONL file per request inside `_lock` in `audit.py`. Under a burst (20 concurrent race requests) this serializes. Acceptable or should it batch?
4. **`engine/scoring.py`** — `1/cost` factor. Would `1/sqrt(cost)` be safer to avoid over-penalizing heavy tools that might be the only ones that find the bug?
5. **`engine/oracles_phase4.py`** — mutates `oracle._HANDLERS` at import time. Is `engine.__init__` guaranteed single-threaded at first import? What if two threads trigger `import engine` simultaneously?
6. **`engine/__init__.py`** — the `except Exception: pass` around auto-imports hid a NameError twice already. Should we log the exception name to stderr instead of silent pass?
7. **`engine/bola_scanner.py::harvest_sequential_ids`** — the path-template handling for `<int:id>` vs `{id}` vs `/\d+` feels fragile. Does the regex replacement handle `/api/orders/1/items/2` correctly (last digit gets replaced, not first)?
8. **`engine/data_extractor.py::extract_with_pagination`** — dedupes by SHA-256 of row JSON. If rows carry a `timestamp` or `updated_at` field, the same logical row appears twice with different hashes. Should we exclude volatile fields from the hash?
9. **`engine/confirm.py`** — new `_DISPATCH` entries reference tool names as strings. If Phase 4 registered them under different names (e.g. `blind_extract` vs `blind_sqli_extract`), the dispatch silently misses. Want a startup assertion that every `_DISPATCH` key maps to a registered capability?
10. **`engine/webui.py`** — `_build_result` appends ledger-derived rows to report-derived rows without cross-dedup. Same endpoint seen twice (once via finding evidence, once via ledger) will appear twice in the Extracted Data panel. Should we dedupe by `(endpoint, first_row_hash)`?
11. **`engine/redact.py::redact_url`** — parses query with `parse_qs(keep_blank_values=True)` then re-encodes. Does this preserve duplicate keys and ordering correctly for audit trail purposes?
12. **`engine/util.py::mask_row`** — email detection is `"@" in v and "." in v and " " not in v and len(v) < 254`. `"user.name"` has a dot but no `@`, so fine. But `"foo.bar@x"` (no TLD dot) passes both checks and gets masked as `f***@x`. Good or bug?

Also skim for dead code — I know `roe_helper.py` is written but nothing calls it yet, `check_path_normalized` is a passthrough, and `secrets_vault` is optional-path. Those are intentional but flag if they bother you.

Give me: bugs to fix, invariants I broke, and any of the 12 questions above where you disagree with my read.