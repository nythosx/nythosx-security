# NythosX Sentinel — Upgrade Documentation

Per-phase algorithm notes for the six-phase upgrade (`UPGRADE_SPEC.md`). All
new network traffic routes through `engine.http` (shared rate limiter + ROE
scope gate); credentials, ROE, evidence keys, and scan output are never
committed.

| Phase | Module | Doc |
|-------|--------|-----|
| 1 | `engine/paramgraph.py` | [Param Context Graph](phase1_paramgraph.md) |
| 2 | `engine/diffcrawl.py` | [Auth-Context Differential Crawler](phase2_diffcrawl.md) |
| 3 | `engine/oracles/controls.py` | [Negative-Control Oracle Gate](phase3_negative_control.md) |
| 4 | `engine/evidence_synth.py` | [Evidence Synthesizer](phase4_evidence.md) |
| 5 | `engine/capgraph.py` | [Capability Graph](phase5_capgraph.md) |
| 6 | `engine/chainscore.py` | [Expected-Value Chain Scoring](phase6_chainscore.md) |
| 7 | `engine/inject/`, `engine/drupalchain/` | [Deep Injection + Drupal/University-CMS](phase7_deep_injection_drupal.md) |

## Config files added

- `configs/diffcrawl.creds.example.yaml` — template for Phase 2 credentials
  (real file `diffcrawl.creds.yaml` is gitignored).
- `configs/remediation_map.yaml` — Phase 4 per-class remediation lines.
- `configs/capability_map.yaml` — Phase 5 finding→capability edges.
- `configs/impact_weights.yaml` — Phase 6 per-class impact dollar weights.

## Config files added

- Phase 7 reuses `capability_map.yaml`, `remediation_map.yaml`, and
  `impact_weights.yaml` with added Drupal finding classes.

## Test apps

`tests/testapp/` is a local app served on 127.0.0.1 (in ROE scope) exposing a
strict-numeric param, a loose-string param, a mass-assignment body, an IDOR
surface, admin-only vs broken-authz endpoints, a weak-JWT token, and
data-exposure records — the shared fixture for Phases 1–6.

`tests/testapp/drupal_mimic/` is the Phase 7 fixture: `/user/{uid}`,
anonymous `/jsonapi/node/secret_content`, `/update.php` at 200,
`/storage/108/backup.sql`, `/CHANGELOG.txt`, and a readable
`/sites/default/settings.php`.
