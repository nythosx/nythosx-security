sec-checker v2.0 — Full Modification Description
Document type: Engineering change proposal
Version: 1.2.0 → 2.0.0 (breaking changes)
Author: Architecture review
Status: Ready for implementation
Estimated timeline: 6–7 weeks with tests

1. Executive Summary
   Ang v2.0 ay hindi bagong scanner — ito ay architectural upgrade na ginagawang:

Brain-optional — gumagana nang walang AI, pero may pluggable LLM brain

Correlation-aware — hindi lang findings, kundi attack chains

Deterministic — lahat ng user-facing text ay pre-authored, hindi AI-generated

Coverage-honest — sinasabi kung ano ang tine-test at ano ang hindi

Self-describing — capabilities ay may metadata para ma-orchestrate ng AI o rules

Ang core engine primitives ay hindi binabago. Ang mga bagong layer ay nasa ibabaw.

2. Breaking Changes (v1.2 → v2.0)
   Change Impact Migration
   ScanResult uniform contract Bawat \*.scan() returns ScanResult imbes na custom dict Wrapper sa bawat module
   Registry-with-metadata @tool decorator extended Existing @tool calls need cost/destructive/idempotent
   Write-up library required Bawat pattern dapat may entry sa writeup_library.yaml CI gate mag-fail kapag missing
   Correlation chain required Bawat chain prerequisite ay dapat real capability CI gate
   Web UI "Why This Matters" column New column, cannot be disabled Default on
   orchestrator.py replaces auto.py::run_auto() Internal refactor run_auto() becomes a shim
   Backwards compatibility: Yung CLI commands (scan, scan-all, auto) ay same interface. Yung output ay mas structured (may bagong fields) pero existing fields ay intact.

3. New Architecture
   3.1 Layered Stack
   text
   ┌─────────────────────────────────────────────────────────┐
   │ Layer 4: ENTRY POINTS │
   │ CLI · Web UI · MCP · AI-API │
   └────────────────────┬────────────────────────────────────┘
   ▼
   ┌─────────────────────────────────────────────────────────┐
   │ Layer 3: BRAIN (optional, pluggable) │
   │ RuleBasedBrain (default) · LLMBrain (opt-in) · none │
   └────────────────────┬────────────────────────────────────┘
   ▼
   ┌─────────────────────────────────────────────────────────┐
   │ Layer 2: ORCHESTRATOR │
   │ multi-pass · budget · visited set · convergence │
   │ correlator · coverage · write-up resolver │
   └────────────────────┬────────────────────────────────────┘
   ▼
   ┌─────────────────────────────────────────────────────────┐
   │ Layer 1: CAPABILITY REGISTRY │
   │ metadata · manifest · composite/bundle tools │
   └────────────────────┬────────────────────────────────────┘
   ▼
   ┌─────────────────────────────────────────────────────────┐
   │ Layer 0: PRIMITIVES (existing engine/\*) │
   │ bizlogic · jwt · graphql · ssrf · dom_xss · ... │
   └─────────────────────────────────────────────────────────┘
   │
   ▼
   ┌─────────────────────────────────────────────────────────┐
   │ CROSS-CUTTING: ROEGuard · RateLimiter · HttpClient │
   │ single instance · fail-closed · one audit point │
   └─────────────────────────────────────────────────────────┘
   3.2 Core Principles
   AI is above the tool boundary. Nagde-desisyon lang, hindi nagpapadala ng HTTP.

Determinism over improvisation. User-facing text ay pre-authored.

Contract before capability. Uniform ScanResult bago magdagdag ng bagong tool.

Fail-closed by default. ROE check bago lahat.

Budgeted. Bawat scan ay may HTTP cap, time cap, at iteration cap.

4. Phase-by-Phase Implementation
   Phase 1 — Contract Unification
   Goal: Uniform data shape sa lahat ng capabilities.

New files:

engine/contract.py — ScanResult, Finding, ScanBudget, Capability

engine/registry.py — capability manifest

Modified files:

Lahat ng engine/\_.py na may scan() o run\_\_() — wrap return value

engine/cli.py — delete duplicate SEVERITY_RANK, VERDICT_COLOR

engine/auto.py — delete duplicate severity logic

ScanResult shape:

python
@dataclass
class ScanResult:
capability: str
target: str
verdict: Verdict # VULNERABLE | SUSPICIOUS | PASS | UNKNOWN
severity: Severity
confidence: float # NEW: 0.0 - 1.0
confidence_reason: str # NEW
reason: str
evidence: dict
findings: list[Finding]
next_hints: list[str] # NEW: para sa AI chaining
duration_ms: float
cost_used: dict # {http_requests, seconds}
author: str = "system" # NEW: template | llm:gpt-4 | human
Capability metadata:

python
@dataclass
class Capability:
name: str
description: str
params: dict # JSON Schema
required: list[str]
cost: str # low | medium | high
destructive: bool
idempotent: bool
prerequisites: list[str]
produces_verdicts: list[str]
category: str
default_on: bool
examples: list[dict]
Test:

test_contract.py — all scan functions return ScanResult

test_registry.py — all registered capabilities have required fields

Phase 2 — Write-up Library + Gap Explanation
Goal: Bawat finding ay may structured "Why This Matters" — pure lookup, walang AI.

New files:

engine/writeup_library.py — resolver + template renderer

engine/writeup_library.yaml — family + pattern overrides (initial: 15 families)

Structure:

yaml
families:
secrets-exposure:
title: "Secrets Harvesting"
attack: "Attacker downloads secrets directly..."
impact: "Total compromise. {leaked_keys} exposed..."
fix: "Block {file_pattern}..."
refs: {owasp: A02, cwe: [CWE-538], wstg: WSTG-CONF-02}

patterns:
env-file-exposure:
family: secrets-exposure
gap: "Web server serves {file} as static content."
vars:
file: "evidence.url_path"
leaked_keys: "evidence.matched_keys | join(', ')"
Coverage test:

python
def test_every_pattern_has_writeup():
for p in loader.list_patterns():
assert writeup_library.resolve(p["id"]) is not None
Web UI change: Bawat finding row ay may bagong Why This Matters column — 4-part: Attack, Gap, Impact, Fix.

Phase 3 — Brain-Optional Orchestrator
Goal: Pluggable brain, deterministic default, multi-pass adaptive loop.

New files:

engine/orchestrator.py — main loop

engine/brains/**init**.py

engine/brains/base.py — ScanBrain protocol

engine/brains/rule_based.py — deterministic default

engine/brains/llm.py — optional AI brain

engine/state.py — ScanState dataclass

ScanBrain protocol:

python
class ScanBrain(Protocol):
def propose(self, state: ScanState) -> list[Hypothesis]: ...
def triage(self, finding: Finding) -> TriageDecision: ...
def should_stop(self, state: ScanState) -> bool: ...
def can_author_payload(self, capability: str) -> bool: ...
def propose_payload(self, state: ScanState, capability: str) -> str | None: ...
ScanState:

python
@dataclass
class ScanState:
target: str
framework: dict
discovered_endpoints: list[str]
findings: list[ScanResult]
chains: list[AttackChain]
coverage: CoverageReport
visited: set[tuple[str, str]] # (capability, target)
pruned: list[Hypothesis] # negative evidence
budget: ScanBudget
iterations: int
elapsed_seconds: float
executed_capabilities: set[str]
Orchestrator loop:

python
def run(self, target, profile="standard", brain=None):
state = self.\_recon(target)
for iteration in range(self.budget.max_iterations):
hypotheses = brain.propose(state) if brain else self.\_default_hypotheses(state)
hypotheses = self.\_prune_visited(hypotheses, state)
results = self.\_fan_out(hypotheses)
state = self.\_aggregate(state, results)
state.chains = correlator.resolve_chains(state.findings)
if self.\_converged(state):
break
state.coverage = coverage.build_coverage_report(state)
return state
Test:

test_orchestrator_replay.py — fixed HTTP responses produce fixed hypothesis sequence

test_brain_differential.py — RuleBasedBrain vs LLMBrain same coverage on same input

Phase 4 — Cross-Finding Correlation Engine
Goal: Findings → attack chains. Pinakamalaking differentiator.

New files:

engine/correlator/**init**.py

engine/correlator/models.py — AttackChain, ChainRequirement, ChainStep

engine/correlator/library.py — loads YAML

engine/correlator/resolver.py — matches findings

engine/correlator/narrative.py — pure lookup text

engine/correlator/library.yaml — initial 15–20 chains

Initial chains:

laravel-admin-takeover — env-file-exposure + mass-assignment

account-takeover-jwt-idor — jwt-weak-secret + authed-idor

auth-bypass-to-admin — auth-bypass-probe + server-disclosure

credential-stuffing-cascade — lockout-probe + weak-password-policy

cors-data-exfil — cors-wildcard + openapi-fuzz

ssrf-cloud-full-compromise — ssrf-cloud-metadata + env-file-exposure

graphql-dos-takeover — graphql-deep-security + auth-bypass-probe

oauth-token-theft — oauth-redirect-uri + oauth-missing-state

upload-to-rce — upload-probe + server-disclosure

h2-desync-to-cache-poison — http2-desync + cache-poisoning-probe

Chain verdict:

CONFIRMED — all prerequisites VULNERABLE + high confidence

LIKELY — most prerequisites VULNERABLE

THEORETICAL — some prerequisites SUSPICIOUS

INCOMPLETE — missing prerequisites

Output integration:

HTML report: bagong "Attack Chains" section bago ang findings

Web UI: bagong tab

CLI: sec-checker chains <target>

Phase 5 — Weak Password Pack
Goal: Tatlong bagong capabilities para sa auth hardening.

New files:

engine/weak_password_policy.py — self-account change test

engine/lockout_probe.py — no-lockout detection

engine/weak_credential_enum.py — opt-in only, curated wordlist

wordlists/weak_passwords_top100.txt — curated, NOT rockyou

Patterns:

patterns/single/weak-password-policy.yaml

patterns/single/lockout-probe.yaml

patterns/single/weak-credential-enum.yaml (opt-in)

Manifest metadata:

python
"lockout_probe": Capability(
cost="low", destructive=False, idempotent=False, # ← changes state
prerequisites=["known_username"],
default_on=False, # opt-in
category="auth",
),
"weak_credential_enum": Capability(
cost="medium", destructive=True, idempotent=False,
prerequisites=["written_authorization"],
default_on=False, # never in safe bundle
category="auth",
),
Safety:

lockout_probe — stop on 403/423/"locked" detection

weak_credential_enum — separate sec_scan_authorized bundle only

Both marked idempotent=False so AI never retries

Phase 6 — 8 New Attack Capabilities
6.1 Wordlist Intelligence
New files: 11 framework-specific wordlists sa wordlists/.

Adapter changes: Bawat adapters/\*.yaml ay may bagong wordlist: field.

Loader change: route_enum.enumerate_routes() accepts adapter param.

6.2 Injection Family (6 new capabilities)
New files:

engine/injection/**init**.py

engine/injection/ssti.py

engine/injection/xxe.py

engine/injection/nosql.py

engine/injection/crlf.py

engine/injection/open_redirect.py

engine/injection/host_header.py

engine/injection/payloads.py — centralized payloads

Patterns: 6 new YAMLs sa patterns/single/.

6.3 WebSocket Security
New file: engine/websocket_probe.py

Dependency: websockets>=12.0,<13

Probes:

Unauthenticated handshake

Cross-origin (CSWSH)

Message reflection

Discovery: engine/discovery.py — add extract_websocket_urls().

6.4 OAuth/OIDC Flow Testing
New files:

engine/oauth/**init**.py

engine/oauth/discovery.py

engine/oauth/redirect_uri.py

engine/oauth/state_probe.py

engine/oauth/pkce_probe.py

engine/oauth/id_token.py

Probes:

redirect_uri bypass (10+ techniques)

Missing state (CSRF)

PKCE downgrade

IdP mixup

id_token JWT attacks (reuse existing jwt_attacks)

6.5 File Upload Testing
New file: engine/upload_probe.py

Probes:

Extension bypass (10 techniques)

Magic bytes + polyglot

Path traversal in filename

SVG XSS

Safety: destructive=True, opt-in.

6.6 HTTP/2 Probes
New file: engine/http2_probe.py

Probes:

H2.CL desync

H2.TE desync

Rapid Reset (careful, low cap)

HPACK bomb (info only)

Integration: smuggle.py accepts protocol="h2".

6.7 Coverage Reporting
New file: engine/coverage.py

Data:

OWASP Top 10:2025 per-category coverage

Attack surface coverage (REST, GraphQL, WS, OAuth, upload, H2, TLS)

Unrun capabilities list

Untested categories

Integration:

HTML/MD reports: bagong section

Web UI: bagong tab

CLI: sec-checker coverage <target>

Phase 7 — Testing Infrastructure
New tests:

test_correlator.py

test_correlator_library.py — CI gate

test_writeup_coverage.py — CI gate

test_wordlist_per_adapter.py

test_injection_family.py

test_websocket_probe.py

test_oauth.py

test_upload_probe.py

test_http2_probe.py

test_coverage.py

test_orchestrator_replay.py

test_brain_differential.py

test_lockout_probe_integration.py

Benchmark suite:

test-targets/ — DVWA, Juice Shop, WebGoat fixtures

test_benchmark.py — recall ≥ 80%, FP rate ≤ 5%

CI gates (.github/workflows/test.yml):

yaml

- name: Contract compliance
  run: pytest tests/test_contract.py
- name: Correlation library validity
  run: pytest tests/test_correlator_library.py
- name: Write-up coverage
  run: pytest tests/test_writeup_coverage.py
- name: Wordlist sanity
  run: pytest tests/test_wordlists.py

5. File Inventory
   New Files (~40)
   Engine core:

text
engine/contract.py
engine/registry.py
engine/orchestrator.py
engine/state.py
engine/coverage.py
engine/writeup_library.py
engine/writeup_library.yaml
Correlator:

text
engine/correlator/**init**.py
engine/correlator/models.py
engine/correlator/library.py
engine/correlator/library.yaml
engine/correlator/resolver.py
engine/correlator/narrative.py
Brains:

text
engine/brains/**init**.py
engine/brains/base.py
engine/brains/rule_based.py
engine/brains/llm.py
Weak password pack:

text
engine/weak_password_policy.py
engine/lockout_probe.py
engine/weak_credential_enum.py
Injection family:

text
engine/injection/**init**.py
engine/injection/ssti.py
engine/injection/xxe.py
engine/injection/nosql.py
engine/injection/crlf.py
engine/injection/open_redirect.py
engine/injection/host_header.py
engine/injection/payloads.py
New attack domains:

text
engine/websocket_probe.py
engine/upload_probe.py
engine/http2_probe.py
engine/oauth/**init**.py
engine/oauth/discovery.py
engine/oauth/redirect_uri.py
engine/oauth/state_probe.py
engine/oauth/pkce_probe.py
engine/oauth/id_token.py
Wordlists:

text
wordlists/paths_laravel.txt
wordlists/paths_django.txt
wordlists/paths_rails.txt
wordlists/paths_nextjs.txt
wordlists/paths_nuxt.txt
wordlists/paths_wordpress.txt
wordlists/paths_spring.txt
wordlists/paths_graphql.txt
wordlists/paths_aspnet.txt
wordlists/paths_express.txt
wordlists/paths_fastapi.txt
wordlists/weak_passwords_top100.txt
Patterns:

text
patterns/single/ssti-probe.yaml
patterns/single/xxe-probe.yaml
patterns/single/nosql-probe.yaml
patterns/single/crlf-injection.yaml
patterns/single/open-redirect.yaml
patterns/single/host-header-injection.yaml
patterns/single/websocket-cswsh.yaml
patterns/single/oauth-redirect-uri.yaml
patterns/single/oauth-missing-state.yaml
patterns/single/upload-probe.yaml
patterns/single/http2-desync.yaml
patterns/single/weak-password-policy.yaml
patterns/single/lockout-probe.yaml
patterns/single/weak-credential-enum.yaml
Tests (~14 new files):

text
tests/test_contract.py
tests/test_registry.py
tests/test_orchestrator_replay.py
tests/test_brain_differential.py
tests/test_correlator.py
tests/test_correlator_library.py
tests/test_writeup_coverage.py
tests/test_wordlists.py
tests/test_injection_family.py
tests/test_websocket_probe.py
tests/test_oauth.py
tests/test_upload_probe.py
tests/test_http2_probe.py
tests/test_coverage.py
tests/test_lockout_probe_integration.py
tests/test_benchmark.py
Modified Files (~25)
Critical:

engine/auto.py → thin shim over orchestrator.py

engine/cli.py — new commands (chains, coverage), delete duplicate severity

engine/webui.py — add Why This Matters column, chains tab, coverage tab

engine/report.py — add chains + coverage sections

engine/loader.py — enforce write-up library presence

Wrapped:

engine/bizlogic.py

engine/jwt_attacks.py

engine/graphql_security.py

engine/ssrf_cloud.py

engine/dom_xss.py

engine/llm_security.py

engine/openapi_scanner.py

engine/idor.py

engine/ssrf.py

engine/xss.py

engine/smuggle.py

engine/race_advanced.py

engine/sca.py

engine/sbom.py

Config:

configs/engine.yaml — new sections: brain, correlator, coverage, orchestrator.budget

adapters/\*.yaml (10 files) — add wordlist: field

MCP:

sec_checker_mcp.py — expose sec_manifest, composite tools

sec_checker_tools/\*.py — update schemas

Dependencies:

requirements.txt — add websockets, h2, cryptography

6. Migration Path
   v1.2 users
   Update dependencies: pip install -r requirements.txt

No config changes required — engine.yaml defaults are backwards compatible

Optional: add wordlists per adapter (auto-detected)

Optional: enable correlation (correlator.enabled: true)

Breaking: yung --fail-on exit code ay may mas mataas na confidence threshold ngayon. Verify sa CI.

Existing sessions/findings
SQLite schema is additive — new columns: confidence, chain_ids, author

Existing findings load fine, default confidence = 0.5

Ledger preserved

Adapters
Existing adapters work as-is. Yung wordlist: field ay optional — fallback sa generic.

7. Testing Strategy
   Unit tests per module
   Bawat bagong module ay may dedicated test file. Deterministic, fast, no network.

Integration tests
Local mock servers per capability:

WS server (accepts/rejects)

OAuth server (weak/strong redirect_uri check)

Upload endpoint (permissive/strict)

HTTP/2 server (vulnerable/compliant)

Golden trace tests
Record full scan ng isang test target. Assert:

Same hypotheses generated (deterministic brain)

Same verdicts

Same chains resolved

Benchmark suite
Against known-vulnerable apps:

DVWA — XSS, SQLi, file inclusion, CSRF

OWASP Juice Shop — admin bypass, JWT, NoSQL

WebGoat — XXE, SSRF, access control

VulnAPI — REST API flaws

Assert recall ≥ 80%, FP rate ≤ 5%.

CI gates
Walang PR na pwede mag-merge kapag:

May pattern na walang write-up entry

May chain prerequisite na unknown capability

May wordlist na may malformed entry

Bumagsak yung benchmark

8. Success Metrics
   Technical:

100% of capabilities return ScanResult (contract compliance)

100% of patterns have write-up entry

100% of correlation prerequisites exist as capabilities

Test coverage ≥ 80% sa bagong modules

Product:

User can scan a target without AI at makakuha ng full report

User can scan with LLMBrain at makakuha ng adaptive multi-pass scan

User can scan via MCP at makakuha ng granular tool control

Bawat finding ay may actionable "Why This Matters" text

Bawat CONFIRMED chain ay may step-by-step narrative

Operational:

Scan time ≤ 5 min for standard profile

HTTP requests ≤ 500 for standard profile

No ROE violations in any test

No AI-generated text sa user-facing output

9. Risk Register
   Risk Mitigation
   Correlation library drift CI gate: every chain → real capability
   Write-up library stale CI gate: every pattern → write-up entry
   AI brain produces unsafe payloads Capability validation before send, ROE check, charset limits
   Weak credential enum abuse Opt-in only, separate bundle, curated wordlist, written auth prerequisite
   Upload probe leaves files Destructive flag, opt-in, disabled by default
   HTTP/2 probes DoS vulnerable server Low caps, timing-based detection only
   Multi-pass runaway Hard budget: iterations, HTTP, time
   False positives sa correlation Confidence threshold per requirement
10. Timeline
    Week Deliverable
    1–2 Phase 1: Contract + Registry
    2–3 Phase 2: Write-up library + Web UI column
    3–4 Phase 3: Orchestrator + brains
    4–5 Phase 4: Correlator
    5 Phase 5: Weak password pack
    5–6 Phase 6.1–6.4: Wordlists, Injection, WS, OAuth
    6 Phase 6.5–6.7: Upload, HTTP/2, Coverage
    7 Phase 7: Testing + benchmarks
    7 Release candidate, docs, migration guide
    Total: 6–7 weeks with tests. Longer kung may surprises.

11. Deliverables
    Code
    40+ new files

25+ modified files

All tests passing

CI gates active

Documentation
docs/ARCHITECTURE.md — updated with new layers

docs/WRITEUP_LIBRARY.md — how to add entries

docs/CORRELATION.md — how to add chains

docs/BRAIN.md — how to implement a custom brain

docs/COVERAGE.md — interpretation guide

CHANGELOG.md — v2.0.0 entry

Configuration
Updated engine.yaml with new sections

Example roe.yaml with new capabilities in scope

.github/workflows/test.yml with CI gates

12. Ano ang HINDI kasama sa v2.0
    Para sa clarity, ito ay hindi kasama:

Exploit path visualization (Tier 4) — Phase 2 ng v2.x

Comparative scanning (Tier 4) — research tool, hindi production

Auto-generated regression tests (Tier 4) — Phase 3 ng v2.x

Threat model inference (Tier 4) — AI-assisted, hindi priority

Multi-target orchestration (Tier 3) — Phase 2 ng v2.x

WAF detection + adaptive behavior (Tier 3) — Phase 2 ng v2.x

TLS deep analysis — nasa A04 coverage, pero nasa Phase 2 ng v2.x

CSP deep analysis — nasa A02, Phase 2 ng v2.x

Triage state machine (Tier 1) — Phase 2 ng v2.x

Baseline diff (Tier 1) — Phase 2 ng v2.x

Scan profiles (Tier 3) — partial sa v2.0, complete sa v2.1

Ang v2.0 ay focused sa 8 confirmed additions + architecture + weak password pack + write-up library + correlation engine. Yung iba ay v2.x.

13. Acceptance Criteria
    Ang v2.0 ay shippable kapag:

✅ Lahat ng \*.scan() returns ScanResult

✅ Lahat ng 48+ patterns ay may write-up entry

✅ Correlation library ay may 15+ chains, lahat valid

✅ RuleBasedBrain ay gumagana without AI

✅ LLMBrain ay opt-in, at gumagana sa parehong interface

✅ Web UI ay may Why This Matters column

✅ Web UI ay may Attack Chains tab

✅ sec-checker coverage <target> gumagana

✅ 3 weak password capabilities ay safe at tested

✅ 8 new attack capabilities (wordlists, injection x6, WS, OAuth, upload, H2)

✅ Benchmark suite passing (recall ≥ 80%, FP ≤ 5%)

✅ CI gates active

✅ Migration guide published

✅ pip install -r requirements.txt && python run.py auto <url> works with zero config

14. Post-v2.0 Roadmap (v2.x)
    v2.1 (2 weeks):

Scan profiles

Baseline diff

Triage state machine

TLS deep analysis

CSP deep analysis

v2.2 (3 weeks):

Multi-target orchestration

WAF detection + adaptive behavior

Comparative scanning (A/B brain diff)

Report templating (executive vs technical)

v2.3 (3 weeks):

Exploit path visualization (SVG graph)

Auto-generated regression tests

Threat model inference

Attack-chain PoC generation (with safety gate)

v3.0 (long-term):

Distributed scan workers (opt-in)

Machine learning confidence calibration

Persistent learning from triage decisions

Enterprise features (SSO, RBAC, audit log export)

Phase 1 — Contracts & Foundation
Purpose: Uniform ScanResult contract sa lahat ng engine primitives. Registry ng capabilities. Minor capability-enabling edits (para hindi na kailangan balikan sa Phase 4).

CREATE (3 files, final — never edited again)
text
engine/contract.py - ScanResult dataclass (verdict, severity, confidence, confidence_reason,
reason, evidence, findings, next_hints, duration_ms, cost_used, author) - Must support BOTH attr access (result.verdict) and dict access
(result["verdict"]) via **getitem** proxy - Finding dataclass (id, type, severity, title, description, evidence) - ScanBudget dataclass (max_iterations, max_http_requests, max_duration_seconds,
max_hypotheses_per_iter, convergence_window) - Capability dataclass (name, description, params, required, cost, destructive,
idempotent, prerequisites, produces_verdicts, category, default_on, examples) - Verdict enum: VULNERABLE | SUSPICIOUS | PASS | UNKNOWN - Severity enum: critical | high | medium | low | info

engine/state.py - ScanState dataclass (target, framework, discovered_endpoints, findings,
chains, coverage, visited, pruned, budget, iterations, elapsed_seconds,
executed_capabilities)

engine/registry.py - Auto-discovery: pkgutil.iter_modules over engine/ and sec_checker_tools/ - Reads @capability decorators OR static CAPABILITIES dict - Exposes: all_capabilities(), manifest(), get(name) - Composite bundles: safe, auth, recon, full, destructive
EDIT (one-time — do all v2 changes here)
text
engine/bizlogic.py → wrap scan() to return ScanResult
engine/jwt_attacks.py → wrap run_attack_suite()
engine/graphql_security.py → wrap scan()
engine/ssrf_cloud.py → wrap scan()
engine/dom_xss.py → wrap scan()
engine/llm_security.py → wrap scan()
engine/openapi_scanner.py → wrap scan()
engine/idor.py → wrap run_probe()
engine/ssrf.py → wrap probe()
engine/xss.py → wrap probe()
engine/smuggle.py → wrap probe() AND add `protocol="h1"|"h2"` param
(h2 branch calls engine/http2_probe once it exists
in Phase 4; for now, raise NotImplementedError)
engine/race_advanced.py → wrap race_scan()
engine/sca.py → wrap scan_dependencies()
engine/oracle.py → return structured Finding objects (not dicts)
engine/evidence.py → support new ScanResult fields (author, confidence,
chain_ids) in summary.json
engine/route_enum.py → add `adapter` param; framework wordlist lookup
engine/discovery.py → add extract_websocket_urls() function
Test files for this phase
text
tests/test_contract.py → every scan function returns ScanResult;
dict-access AND attr-access work
tests/test_registry.py → all registered capabilities have required fields
After Phase 1 (✅ locked)
Lahat ng file sa itaas ay never na ma-edit pa.

Phase 2 — Content & Data Layer
Purpose: All pre-authored content (write-ups, chains, wordlists) at ang resolver logic para sa kanila. Pure data + deterministic lookup. Walang AI dito.

CREATE
text
engine/writeup_library.py - resolve(pattern_id) -> WriteupEntry (family + gap override merged) - render(entry, evidence) -> {attack, gap, impact, fix} - Pure template interpolation, no AI - Coverage assertion: every pattern has an entry

engine/writeup_library.yaml - families: section (15 initial families) - patterns: section (per-pattern gap override + vars mapping) - Every existing pattern ID must be covered

engine/correlator/**init**.py
engine/correlator/models.py - AttackChain, ChainRequirement, ChainStep dataclasses - ChainVerdict enum: CONFIRMED | LIKELY | THEORETICAL | INCOMPLETE

engine/correlator/library.py - load_chains() from library.yaml

engine/correlator/library.yaml - 15-20 initial attack chains (laravel-admin-takeover,
account-takeover-jwt-idor, etc.)

engine/correlator/resolver.py - resolve_chains(findings) -> list[AttackChain] - Deterministic matching; confidence = geometric mean of prerequisites

engine/correlator/narrative.py - render(chain) -> str (pure lookup, no AI)

engine/coverage.py - OWASP_TO_CAPABILITIES mapping - ATTACK_SURFACES mapping - build_coverage_report(target, findings, executed_caps, profile, duration)

wordlists/paths_laravel.txt
wordlists/paths_django.txt
wordlists/paths_rails.txt
wordlists/paths_nextjs.txt
wordlists/paths_nuxt.txt
wordlists/paths_wordpress.txt
wordlists/paths_spring.txt
wordlists/paths_graphql.txt
wordlists/paths_aspnet.txt
wordlists/paths_express.txt
wordlists/paths_fastapi.txt
wordlists/weak_passwords_top100.txt (curated — NOT rockyou)
EDIT (one-time)
text
adapters/laravel.yaml → add `wordlist: paths_laravel` field
adapters/django.yaml → add `wordlist: paths_django`
adapters/rails.yaml → add `wordlist: paths_rails`
adapters/nextjs.yaml → add `wordlist: paths_nextjs`
adapters/nuxt.yaml → add `wordlist: paths_nuxt`
adapters/wordpress.yaml → add `wordlist: paths_wordpress`
adapters/spring_boot.yaml → add `wordlist: paths_spring`
adapters/express.yaml → add `wordlist: paths_express`
adapters/fastapi.yaml → add `wordlist: paths_fastapi`
adapters/ai_agent.yaml → add `wordlist: paths_graphql`
adapters/aspnet.yaml → add `wordlist: paths_aspnet`

configs/engine.yaml → add sections (all at once):
brain: {enabled, provider, model}
correlator: {enabled, confidence_threshold}
coverage: {enabled, include_untested}
orchestrator: {budget: {...}}
weak_password: {enabled, opt_in_destructive}
injection: {enabled, oob_callback_url}
websocket: {enabled, timeout}
oauth: {enabled, test_origins}
upload: {enabled, opt_in}
http2: {enabled, rapid_reset_max}

requirements.txt → add: websockets>=12.0,<13
h2>=4.1,<5
cryptography>=42.0,<43
Test files
text
tests/test_writeup_library.py → every pattern resolves
tests/test_correlator_library.py → every chain prerequisite is real capability
tests/test_correlator_resolver.py → chain verdict computation
tests/test_coverage.py → untested categories detected
tests/test_wordlists.py → no dupes, valid chars, non-empty
After Phase 2 (✅ locked)
Phase 3 — Orchestrator & Brains
Purpose: The multi-pass loop + pluggable brain. auto.py becomes a thin shim.

CREATE
text
engine/brains/**init**.py
engine/brains/base.py - ScanBrain Protocol with methods:
propose(state) -> list[Hypothesis]
triage(finding) -> TriageDecision
should_stop(state) -> bool
can_author_payload(capability) -> bool
propose_payload(state, capability) -> str | None

engine/brains/rule_based.py - RuleBasedBrain (default) — deterministic heuristics - 8 hypothesis sources: JS bundles, framework adapter, OpenAPI, sibling probe,
auth-derived, error-signature, negative evidence, cross-finding

engine/brains/llm.py - LLMBrain (opt-in) — uses Anthropic/OpenAI API - Never constructs HTTP. Only proposes hypotheses + authors payloads. - Temperature=0, response_format=json_object

engine/orchestrator.py - Orchestrator class with run(target, profile, brain) - Multi-pass loop with convergence check - Integrates: correlator (Phase 2), coverage (Phase 2),
write-up resolver (Phase 2) - Fan-out via ThreadPoolExecutor - Prunes visited (capability, target) pairs - Respects ScanBudget hard caps
EDIT (one-time — do all v2 changes here)
text
engine/auto.py → full rewrite as thin shim:
run_auto(url, ...) → Orchestrator().run(...)
Remove duplicate SEVERITY_RANK, VERDICT_COLOR
Remove hardcoded phase list
Keep public signature for backwards compat
Test files
text
tests/test_orchestrator_replay.py → fixed HTTP responses produce fixed
hypothesis sequence (deterministic)
tests/test_brain_differential.py → RuleBasedBrain vs LLMBrain same coverage
tests/test_orchestrator_budget.py → iterations/http/time caps enforced
After Phase 3 (✅ locked)
Phase 4 — New Capabilities
Purpose: All new scan capabilities. Isolated modules — hindi kailangan baguhin ang existing primitives.

CREATE
Weak Password Pack:

text
engine/weak_password_policy.py → self-account change test
engine/lockout_probe.py → no-lockout detection
engine/weak_credential_enum.py → opt-in only, requires written auth
Injection Family:

text
engine/injection/**init**.py
engine/injection/payloads.py → centralized payload library
engine/injection/ssti.py
engine/injection/xxe.py
engine/injection/nosql.py
engine/injection/crlf.py
engine/injection/open_redirect.py
engine/injection/host_header.py
New Domains:

text
engine/websocket_probe.py → CSWSH, unauth, message reflection
engine/oauth/**init**.py
engine/oauth/discovery.py → OIDC well-known fetch
engine/oauth/redirect_uri.py → 10+ bypass techniques
engine/oauth/state_probe.py → missing state CSRF
engine/oauth/pkce_probe.py → PKCE downgrade
engine/oauth/id_token.py → reuse jwt_attacks on id_token
engine/upload_probe.py → extension, magic bytes, path traversal, SVG
engine/http2_probe.py → H2.CL, H2.TE, rapid reset, HPACK
New Patterns:

text
patterns/single/ssti-probe.yaml
patterns/single/xxe-probe.yaml
patterns/single/nosql-probe.yaml
patterns/single/crlf-injection.yaml
patterns/single/open-redirect.yaml
patterns/single/host-header-injection.yaml
patterns/single/websocket-cswsh.yaml
patterns/single/oauth-redirect-uri.yaml
patterns/single/oauth-missing-state.yaml
patterns/single/upload-probe.yaml
patterns/single/http2-desync.yaml
patterns/single/weak-password-policy.yaml
patterns/single/lockout-probe.yaml
patterns/single/weak-credential-enum.yaml
MCP Tool Wrappers:

text
sec_checker_tools/weak_password.py
sec_checker_tools/injection.py
sec_checker_tools/websocket.py
sec_checker_tools/oauth.py
sec_checker_tools/upload.py
sec_checker_tools/http2.py
sec_checker_tools/correlation.py → new tool: sec_chains
sec_checker_tools/coverage.py → new tool: sec_coverage
sec_checker_tools/orchestrate.py → new tool: sec_orchestrate
EDIT (one-time — all v2 changes to these files happen here)
text
sec_checker_mcp.py → new \_schema_for() that reads proper
JSON Schema from tool metadata
Add sec_manifest tool
Add composite bundle tools

sec_checker_tools/router.py → include new tools in listing
Note: sec_checker_tools/registry.py uses pkgutil.iter_modules — auto-discovers new tool files. No edit needed.

Note: engine/smuggle.py — h2 branch was stubbed in Phase 1. Now in Phase 4, create engine/http2_probe.py. The stub in smuggle.py will resolve the import at runtime. Since smuggle.py was already wrapped in Phase 1, no second edit needed — the import is inside a conditional.

Test files
text
tests/test_weak_password.py
tests/test_injection_family.py → for all 6 injection capabilities
tests/test_websocket_probe.py
tests/test_oauth.py
tests/test_upload_probe.py
tests/test_http2_probe.py
After Phase 4 (✅ locked)
Phase 5 — UI & Reports
Purpose: I-integrate ang lahat ng bagong data (write-ups, chains, coverage) sa user-facing outputs. Only runs after Phases 1-4 are complete.

EDIT (one-time — all v2 changes here)
text
engine/cli.py - Add commands: chains, coverage, weak-password-check, scan --profile - Add --brain flag (rule-based | llm | none) - Remove duplicate SEVERITY_RANK / VERDICT_COLOR - Route scan commands to orchestrator

engine/webui.py - Add "Why This Matters" column (from writeup_library) - Add "Attack Chains" tab (from correlator) - Add "Coverage" tab (from coverage) - Remove duplicate SEVERITY_RANK / VERDICT_COLOR - Add scan profile dropdown

engine/report.py - Add Attack Chains section (before individual findings) - Add Why This Matters to each finding row - Add Coverage section - Remove duplicate SEVERITY_RANK / VERDICT_COLOR

tests/conftest.py - Add fixtures for ScanResult, ScanState, mock chains - Update existing step/ctx fixtures if needed for new contract
Test files
text
tests/test_webui_integration.py → Why This Matters column renders
tests/test_report_sections.py → chains + coverage sections present
tests/test_cli_v2_commands.py → new commands work
After Phase 5 (✅ locked)
Phase 6 — Benchmark Suite & Docs
Purpose: Validation against real targets + documentation. Pure additive.

CREATE
text
test-targets/dvwa/ (docker-compose + setup)
test-targets/juice-shop/
test-targets/webgoat/
test-targets/vulnapi/

tests/test_benchmark.py → scan each target, assert recall ≥ 80%,
FP rate ≤ 5%

tests/test_golden_trace.py → full scan trace, deterministic replay

docs/ARCHITECTURE.md
docs/WRITEUP_LIBRARY.md
docs/CORRELATION.md
docs/BRAIN.md
docs/COVERAGE.md
docs/MIGRATION_v1_to_v2.md

.github/workflows/test.yml → CI gates: - contract compliance - writeup coverage - correlator library validity - wordlist sanity - benchmark
CHANGELOG.md → v2.0.0 entry
After Phase 6 (✅ v2.0 complete)
File-Touch Matrix (Summary)
File Phase Edits Notes
engine/contract.py 1 CREATE Never again
engine/state.py 1 CREATE Never again
engine/registry.py 1 CREATE Never again
engine/bizlogic.py 1 EDIT Wrapper only
engine/jwt*attacks.py 1 EDIT Wrapper only
engine/graphql_security.py 1 EDIT Wrapper only
engine/ssrf_cloud.py 1 EDIT Wrapper only
engine/dom_xss.py 1 EDIT Wrapper only
engine/llm_security.py 1 EDIT Wrapper only
engine/openapi_scanner.py 1 EDIT Wrapper only
engine/idor.py 1 EDIT Wrapper only
engine/ssrf.py 1 EDIT Wrapper only
engine/xss.py 1 EDIT Wrapper only
engine/smuggle.py 1 EDIT Wrapper + h2 stub
engine/race_advanced.py 1 EDIT Wrapper only
engine/sca.py 1 EDIT Wrapper only
engine/oracle.py 1 EDIT Structured findings
engine/evidence.py 1 EDIT New fields
engine/route_enum.py 1 EDIT Adapter wordlist param
engine/discovery.py 1 EDIT WS URL extraction
engine/writeup_library.py 2 CREATE Never again
engine/writeup_library.yaml 2 CREATE Content — can grow without code change
engine/correlator/* 2 CREATE Never again
engine/correlator/library.yaml 2 CREATE Content — can grow
engine/coverage.py 2 CREATE Never again
wordlists/* 2 CREATE Never again
adapters/*.yaml 2 EDIT Add wordlist field
configs/engine.yaml 2 EDIT All sections added
requirements.txt 2 EDIT New deps
engine/brains/* 3 CREATE Never again
engine/orchestrator.py 3 CREATE Never again
engine/auto.py 3 EDIT Full rewrite as shim
engine/weak_password*_.py 4 CREATE Never again
engine/lockout_probe.py 4 CREATE Never again
engine/injection/_ 4 CREATE Never again
engine/websocket_probe.py 4 CREATE Never again
engine/oauth/_ 4 CREATE Never again
engine/upload_probe.py 4 CREATE Never again
engine/http2_probe.py 4 CREATE Never again
patterns/single/_.yaml (new) 4 CREATE Never again
sec_checker_tools/_.py (new) 4 CREATE Never again
sec_checker_mcp.py 4 EDIT New schema fn + manifest tool
engine/cli.py 5 EDIT All new commands + cleanup
engine/webui.py 5 EDIT Column + tabs + cleanup
engine/report.py 5 EDIT Sections + cleanup
tests/conftest.py 5 EDIT New fixtures
tests/_ (all new) varies CREATE Distributed per phase
test-targets/_ 6 CREATE Benchmark fixtures
docs/_ 6 CREATE Documentation
CHANGELOG.md 6 CREATE Never again
