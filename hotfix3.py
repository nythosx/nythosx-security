import py_compile
from pathlib import Path

ROOT = Path(__file__).parent.absolute()

HTTP_FILE = ROOT / "engine" / "http_client.py"
EXEC_FILE = ROOT / "engine" / "executor.py"
AUTO_FILE = ROOT / "engine" / "auto.py"

HTTP_OLD = '''    def request(self, method, url, headers=None, json=None, data=None, params=None):
        try:
            self.roe_guard.check_url(url, method)
        except ROEViolation as e:
            return {
                "status": None, "headers": {}, "body": "", "body_hash": None,
                "time_ms": 0.0, "url": url, "error": f"ROE_BLOCK: {e}", "attempts": 0,
            }
        merged = self._build_headers(headers)'''

HTTP_NEW = '''    def request(self, method, url, headers=None, json=None, data=None, params=None,
                skip_default_headers=False):
        try:
            self.roe_guard.check_url(url, method)
        except ROEViolation as e:
            return {
                "status": None, "headers": {}, "body": "", "body_hash": None,
                "time_ms": 0.0, "url": url, "error": f"ROE_BLOCK: {e}", "attempts": 0,
            }
        if skip_default_headers:
            merged = dict(headers or {})
            if self.user_agents:
                merged.setdefault("User-Agent", random.choice(self.user_agents))
        else:
            merged = self._build_headers(headers)'''

EXEC_OLD = '''def _execute_one(step, inputs, client, loop_index, target):
    req = step.get("request", {})
    method = render(req.get("method", "GET"), inputs, loop_index, target)
    url = render(req.get("url", ""), inputs, loop_index, target)
    headers = render(req.get("headers", {}) or {}, inputs, loop_index, target)
    json_body = render(req.get("json"), inputs, loop_index, target) if req.get("json") else None
    data_body = render(req.get("data"), inputs, loop_index, target) if req.get("data") else None
    params = render(req.get("params"), inputs, loop_index, target) if req.get("params") else None
    result = client.request(method, url, headers=headers, json=json_body,
                             data=data_body, params=params)
    result["step_name"] = step.get("name", "step")
    result["loop_index"] = loop_index
    return result'''

EXEC_NEW = '''def _execute_one(step, inputs, client, loop_index, target):
    req = step.get("request", {})
    method = render(req.get("method", "GET"), inputs, loop_index, target)
    url = render(req.get("url", ""), inputs, loop_index, target)
    headers = render(req.get("headers", {}) or {}, inputs, loop_index, target)
    json_body = render(req.get("json"), inputs, loop_index, target) if req.get("json") else None
    data_body = render(req.get("data"), inputs, loop_index, target) if req.get("data") else None
    params = render(req.get("params"), inputs, loop_index, target) if req.get("params") else None
    no_auth = bool(step.get("no_auth"))
    result = client.request(method, url, headers=headers, json=json_body,
                             data=data_body, params=params,
                             skip_default_headers=no_auth)
    result["step_name"] = step.get("name", "step")
    result["loop_index"] = loop_index
    result["no_auth"] = no_auth
    return result'''

AUTO_OLD = '''    suffix = pattern.get("endpoint_suffix", "")
    if suffix:
        target = target.rstrip("/") + suffix
    headers = headers or {}'''

AUTO_NEW = '''    suffix = pattern.get("endpoint_suffix", "")
    if suffix:
        target = target.rstrip("/") + suffix
    if pattern.get("ignore_default_auth"):
        headers = {}
        cookies = {}
    headers = headers or {}'''

PATTERNS = {}

PATTERNS["patterns/content/laravel-debug-mode.yaml"] = r'''id: laravel-debug-mode
name: Laravel Debug Mode Enabled (Error Page Disclosure)
severity: critical
tags: [debug, info-disclosure, wstg-conf-02, cwe-209, laravel]
endpoint_suffix: /me
ignore_default_auth: true

inputs:
  target_url:
    type: string
    required: true

steps:
  - name: no_auth_probe
    no_auth: true
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

PATTERNS["patterns/sequence/api-info-disclosure.yaml"] = r'''id: api-info-disclosure
name: API Error Response Information Disclosure
severity: medium
tags: [info-disclosure, wstg-errh-01, cwe-209]
endpoint_suffix: /me
ignore_default_auth: true

inputs:
  target_url:
    type: string
    required: true

steps:
  - name: probe
    no_auth: true
    request:
      method: GET
      url: "{{ inputs.target_url }}"

oracles:
  - type: pattern_match
    regex: '(SQLSTATE|QueryException|Stack trace|vendor/laravel|app\\Http|Illuminate\\|Symfony\\|Doctrine\\|/app/[\w/]+\.php)'
    verdict: VULNERABLE
  - type: pattern_match
    regex: '(DB_PASSWORD|APP_KEY|AWS_SECRET|MAIL_PASSWORD|REDIS_PASSWORD|SANCTUM)'
    verdict: VULNERABLE
  - type: pattern_match
    regex: '(bootstrap/app\.php|/app\.php|storage/framework|storage/logs)'
    verdict: SUSPICIOUS
'''

PATTERNS["patterns/sequence/api-error-handling.yaml"] = r'''id: api-error-handling
name: API Error Handling — 500 Instead of 401
severity: high
tags: [auth, error-handling, wstg-athn-04, cwe-755]
endpoint_suffix: /me
ignore_default_auth: true

inputs:
  target_url:
    type: string
    required: true

steps:
  - name: no_auth
    no_auth: true
    request:
      method: GET
      url: "{{ inputs.target_url }}"
  - name: bad_token
    no_auth: true
    request:
      method: GET
      url: "{{ inputs.target_url }}"
      headers:
        Authorization: "Bearer invalid_token_xyz_probe"

oracles:
  - type: expected_status_mismatch
    expected: [200, 401, 403]
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
    default: 20

steps:
  - name: flood
    no_auth: true
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

PATTERNS["patterns/sequence/auth-bypass-probe.yaml"] = r'''id: auth-bypass-probe
name: Auth Bypass Probe
severity: high
tags: [auth, wstg-athn-04, cwe-287]
endpoint_suffix: /me
ignore_default_auth: true

inputs:
  target_url:
    type: string
    required: true

steps:
  - name: no_auth
    no_auth: true
    request:
      method: GET
      url: "{{ inputs.target_url }}"
  - name: bad_auth
    no_auth: true
    request:
      method: GET
      url: "{{ inputs.target_url }}"
      headers:
        Authorization: "Bearer invalid_token_xyz_123"

oracles:
  - type: status_code_present
    code: 200
    verdict: VULNERABLE
'''


def patch_file(path, old, new, label):
    if not path.exists():
        print(f"  [FAIL]  {path.relative_to(ROOT)} not found")
        return False
    text = path.read_text(encoding="utf-8")
    if new.split("\n")[0].strip() in text and "skip_default_headers" in text:
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
    for path in [HTTP_FILE, EXEC_FILE, AUTO_FILE]:
        try:
            py_compile.compile(str(path), doraise=True)
        except py_compile.PyCompileError as e:
            errors.append((path, str(e)))
    if errors:
        for p, err in errors:
            print(f"  [FAIL]  {p.relative_to(ROOT)}")
            print(f"          {err[:200]}")
        return False
    print("  [ OK ]  All Python files compile cleanly")
    return True


def main():
    print()
    print("=" * 62)
    print("  HOTFIX 3  ::  Per-step no_auth support")
    print("=" * 62)
    print()
    print("  Patching http_client.py...")
    patch_file(HTTP_FILE, HTTP_OLD, HTTP_NEW, "http_client")
    print()
    print("  Patching executor.py...")
    patch_file(EXEC_FILE, EXEC_OLD, EXEC_NEW, "executor")
    print()
    print("  Patching auto.py...")
    patch_file(AUTO_FILE, AUTO_OLD, AUTO_NEW, "auto")
    print()
    print("  Updating patterns...")
    write_patterns()
    print()
    print("  Verifying syntax...")
    ok = verify()
    print()
    print("=" * 62)
    if ok:
        print("  HOTFIX 3 COMPLETE")
        print()
        print("  Run: python run.py auto http://localhost:3000")
    else:
        print("  HOTFIX 3 FAILED")
    print("=" * 62)
    print()


if __name__ == "__main__":
    main()