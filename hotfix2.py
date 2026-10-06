import py_compile
from pathlib import Path

ROOT = Path(__file__).parent.absolute()

ORACLE_FILE = ROOT / "engine" / "oracle.py"
AUTO_FILE = ROOT / "engine" / "auto.py"

OLD_ORACLE = '''def _expected_status_mismatch(oracle, context):
    last = _last_step(context)
    if not last:
        return {"verdict": "UNKNOWN", "reason": "no step", "evidence": {}}
    expected = oracle.get("expected", [])
    actual = last.get("status")
    if actual is None:
        return {"verdict": "UNKNOWN", "reason": "no status", "evidence": {}}
    if actual not in expected and actual >= 500:
        return {
            "verdict": oracle.get("verdict", "VULNERABLE"),
            "reason": f"expected {expected}, got {actual} server error",
            "evidence": {"expected": expected, "actual": actual},
        }
    if actual not in expected and actual not in (401, 403, 200, 204):
        return {
            "verdict": oracle.get("verdict", "SUSPICIOUS"),
            "reason": f"expected {expected}, got {actual}",
            "evidence": {"expected": expected, "actual": actual},
        }
    return {"verdict": "PASS", "reason": f"status {actual} as expected", "evidence": {}}'''

NEW_ORACLE = '''def _expected_status_mismatch(oracle, context):
    last = _last_step(context)
    if not last:
        return {"verdict": "UNKNOWN", "reason": "no step", "evidence": {}}
    expected = oracle.get("expected", [])
    actual = last.get("status")
    if actual is None:
        return {"verdict": "UNKNOWN", "reason": "no status", "evidence": {}}
    if actual == 404:
        return {"verdict": "PASS", "reason": "status 404 (endpoint not found)",
                "evidence": {"actual": actual}}
    if actual == 405:
        return {"verdict": "PASS", "reason": "status 405 (method not allowed)",
                "evidence": {"actual": actual}}
    if actual not in expected and actual >= 500:
        return {
            "verdict": "VULNERABLE",
            "reason": f"expected {expected}, got {actual} server error",
            "evidence": {"expected": expected, "actual": actual},
        }
    if actual not in expected:
        return {
            "verdict": "SUSPICIOUS",
            "reason": f"expected {expected}, got {actual}",
            "evidence": {"expected": expected, "actual": actual},
        }
    return {"verdict": "PASS", "reason": f"status {actual} as expected", "evidence": {}}'''

OLD_RUN_PATTERN = '''def _run_pattern(pid, target, headers=None, cookies=None, overrides=None):
    pattern = loader.load_pattern(pid)
    if not pattern:
        return None
    headers = headers or {}'''

NEW_RUN_PATTERN = '''def _run_pattern(pid, target, headers=None, cookies=None, overrides=None):
    pattern = loader.load_pattern(pid)
    if not pattern:
        return None
    suffix = pattern.get("endpoint_suffix", "")
    if suffix:
        target = target.rstrip("/") + suffix
    headers = headers or {}'''

PATTERNS = {}

PATTERNS["patterns/content/laravel-debug-mode.yaml"] = r'''id: laravel-debug-mode
name: Laravel Debug Mode Enabled (Error Page Disclosure)
severity: critical
tags: [debug, info-disclosure, wstg-conf-02, cwe-209, laravel]
endpoint_suffix: /me

inputs:
  target_url:
    type: string
    required: true

steps:
  - name: no_auth_probe
    request:
      method: GET
      url: "{{ inputs.target_url }}"

oracles:
  - type: debug_signature
    min_size: 100000
    signatures:
      - Laravel
      - stack trace
      - vendor
      - Ignition
      - Whoops
      - bootstrap/app
      - app.php
      - /storage/
    verdict: VULNERABLE
'''

PATTERNS["patterns/sequence/api-error-handling.yaml"] = r'''id: api-error-handling
name: API Error Handling — 500 Instead of 401
severity: high
tags: [auth, error-handling, wstg-athn-04, cwe-755]
endpoint_suffix: /me

inputs:
  target_url:
    type: string
    required: true

steps:
  - name: no_auth
    request:
      method: GET
      url: "{{ inputs.target_url }}"
  - name: bad_token
    request:
      method: GET
      url: "{{ inputs.target_url }}"
      headers:
        Authorization: "Bearer invalid_token_xyz_probe"

oracles:
  - type: expected_status_mismatch
    expected: [200, 401, 403]
'''

PATTERNS["patterns/sequence/api-info-disclosure.yaml"] = r'''id: api-info-disclosure
name: API Error Response Information Disclosure
severity: medium
tags: [info-disclosure, wstg-errh-01, cwe-209]
endpoint_suffix: /me

inputs:
  target_url:
    type: string
    required: true

steps:
  - name: probe
    request:
      method: GET
      url: "{{ inputs.target_url }}"

oracles:
  - type: pattern_match
    regex: '(SQLSTATE|QueryException|Stack trace|vendor/laravel|app\\\\Http|Illuminate\\\\|Symfony\\\\|Doctrine\\\\|\\/app\\/[\\w\\/]+\\.php)'
    verdict: VULNERABLE
  - type: pattern_match
    regex: '(DB_PASSWORD|APP_KEY|AWS_SECRET|MAIL_PASSWORD|REDIS_PASSWORD|SANCTUM)'
    verdict: VULNERABLE
'''

PATTERNS["patterns/sequence/rate-limit-absent.yaml"] = r'''id: rate-limit-absent
name: Rate Limiting Absent on Login Endpoint
severity: high
tags: [rate-limit, wstg-athn-03, cwe-307]
endpoint_suffix: /login

inputs:
  target_url:
    type: string
    required: true
  iterations:
    type: int
    default: 30

steps:
  - name: flood
    repeat: "{{ inputs.iterations }}"
    request:
      method: POST
      url: "{{ inputs.target_url }}"
      json:
        email: "probe_{{ loop_index }}@example.com"
        password: "wrong_pass"

oracles:
  - type: status_code_absent
    code: 429
    verdict: VULNERABLE
'''


def patch_file(path, old, new, label):
    if not path.exists():
        print(f"  [FAIL]  {path.relative_to(ROOT)} not found")
        return False
    text = path.read_text(encoding="utf-8")
    if new.split("\n")[0].strip() in text and label == "oracle":
        print(f"  [SKIP]  {path.relative_to(ROOT)} already patched")
        return True
    if old not in text:
        print(f"  [FAIL]  {path.relative_to(ROOT)} — target block not found")
        return False
    text = text.replace(old, new, 1)
    path.write_text(text, encoding="utf-8")
    print(f"  [ OK ]  Patched: {path.relative_to(ROOT)}")
    return True


def write_patterns():
    for path, content in sorted(PATTERNS.items()):
        p = ROOT / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        print(f"  [ OK ]  {path}")


def verify():
    errors = []
    for path in [ORACLE_FILE, AUTO_FILE]:
        try:
            py_compile.compile(str(path), doraise=True)
        except py_compile.PyCompileError as e:
            errors.append((path, str(e)))
    for path in PATTERNS:
        p = ROOT / path
        if p.suffix == ".py":
            try:
                py_compile.compile(str(p), doraise=True)
            except py_compile.PyCompileError as e:
                errors.append((p, str(e)))
    if errors:
        for p, err in errors:
            print(f"  [FAIL]  {p}")
            print(f"          {err[:200]}")
        return False
    print("  [ OK ]  All Python files compile cleanly")
    return True


def main():
    print()
    print("=" * 62)
    print("  HOTFIX 2  ::  Endpoint suffix + false positive fix")
    print("=" * 62)
    print()
    print("  Patching oracle.py...")
    patch_file(ORACLE_FILE, OLD_ORACLE, NEW_ORACLE, "oracle")
    print()
    print("  Patching auto.py...")
    patch_file(AUTO_FILE, OLD_RUN_PATTERN, NEW_RUN_PATTERN, "auto")
    print()
    print("  Updating patterns with endpoint_suffix...")
    write_patterns()
    print()
    print("  Verifying syntax...")
    ok = verify()
    print()
    print("=" * 62)
    if ok:
        print("  HOTFIX 2 COMPLETE")
        print()
        print("  Run: python run.py auto http://localhost:3000")
    else:
        print("  HOTFIX 2 FAILED")
    print("=" * 62)
    print()


if __name__ == "__main__":
    main()