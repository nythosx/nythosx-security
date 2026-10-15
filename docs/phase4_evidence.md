# Phase 4 — Evidence Synthesizer

`engine/evidence_synth.py` turns every CONFIRMED finding into a three-row
evidence block that is safe to put in a report.

## Row 1 — Reproduction

`curl_oneliner()` emits a minimal `curl -i` command; `raw_pair()` emits the
raw request/response. Both truncate bodies to 2 KB (`BODY_TRUNCATE`), redact
credentials via `engine.redact`, and additionally mask third-party PII
(`mask_text_pii`) so emails and account numbers in a response body do not leak
even though the pair is "raw".

## Row 2 — Impact

For data-exposure findings: the record **count**, the first two records with
values **masked** — `mask_email` → `j•••@•••.com`, `mask_digits` → digits
replaced with `•` except the last two — and a **SHA-256 of the full
response**. Unmasked third-party data is never written to the report. The full
payload is kept only in the local **Fernet-encrypted** evidence store
(`EncryptedEvidenceStore`, key from `EVIDENCE_KEY`; `generate_key()` mints
one). Without a key the store is unavailable and only masked data is emitted.

## Row 3 — Differential

Baseline vs exploit rendered via the existing `semantic_diff` structural hash
(`engine.diff`), plus a one-line remediation per finding class from
`configs/remediation_map.yaml` (`remediation_for`, with built-in fallbacks and
prefix/substring matching).

## Fix verification

`verify_fix(finding_id, poc_runner)` re-runs the minimal PoC and, on PASS
(no longer VULNERABLE), returns a signed `fixed & verified` record
(timestamp, finding id, verdict, HMAC-SHA256 signature keyed by
`EVIDENCE_KEY`). The CLI command `verify-fix <finding_id> [--json]` loads the
finding from the ledger, rebuilds the PoC through `engine.confirm`, and writes
the signed record to `findings/verified/`.

## Report integration

`engine.report.build_evidence_blocks()` renders the blocks for confirmed
findings into both the Markdown and HTML report templates under an **Evidence**
section.

## Acceptance

`tests/test_evidence_synth.py` includes an end-to-end test that fetches a
record containing an email and an account number from `tests/testapp/`, builds
the block, writes the report, and asserts via regex that all three rows are
present and that no full email or account number leaks into the report file.
Module coverage: 88%.
