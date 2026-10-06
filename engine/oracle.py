import re
import hmac
import base64
import hashlib
import json as _json
import statistics
from pathlib import Path

_ROOT = Path(__file__).parent.parent.absolute()
_JWT_SECRETS_FILE = _ROOT / "wordlists" / "jwt_secrets.txt"
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}")
_HMAC_ALGS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
_FALLBACK_JWT_SECRETS = [
    "secret", "password", "123456", "changeme", "admin", "test", "jwt",
    "jwtsecret", "jwt_secret", "your-256-bit-secret", "your_jwt_secret",
    "key", "private", "token", "supersecret", "s3cr3t",
]


def _b64url_decode(seg):
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def _load_jwt_secrets(path=None):
    p = Path(path) if path else _JWT_SECRETS_FILE
    if p.exists():
        try:
            lines = [l.strip() for l in p.read_text(encoding="utf-8").splitlines()]
            words = [l for l in lines if l and not l.startswith("#")]
            if words:
                return words
        except Exception:
            pass
    return list(_FALLBACK_JWT_SECRETS)


def _collect_jwts(steps):
    found = []
    seen = set()
    for s in steps:
        haystack = s.get("body") or ""
        for k, v in (s.get("headers") or {}).items():
            if k.lower() in ("authorization", "set-cookie"):
                haystack += " " + str(v)
        for tok in _JWT_RE.findall(haystack):
            if tok not in seen:
                seen.add(tok)
                found.append((tok, s.get("step_name")))
    return found


def _crack_jwt(token, secrets):
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = _json.loads(_b64url_decode(parts[0]))
    except Exception:
        return None
    alg = str(header.get("alg", "")).upper()
    hfunc = _HMAC_ALGS.get(alg)
    if hfunc is None:
        return {"alg": alg, "crackable": False}
    signing_input = (parts[0] + "." + parts[1]).encode("ascii", "ignore")
    try:
        want = _b64url_decode(parts[2])
    except Exception:
        return {"alg": alg, "crackable": True, "secret": None}
    for secret in secrets:
        computed = hmac.new(secret.encode("utf-8"), signing_input, hfunc).digest()
        if hmac.compare_digest(computed, want):
            return {"alg": alg, "crackable": True, "secret": secret}
    return {"alg": alg, "crackable": True, "secret": None}


def _jwt_weak_secret(oracle, context):
    steps = context.get("steps", [])
    if not steps:
        return {"verdict": "UNKNOWN", "reason": "no steps", "evidence": {}}
    secrets = oracle.get("secrets") or _load_jwt_secrets(oracle.get("wordlist"))
    tokens = _collect_jwts(steps)
    if not tokens:
        return {"verdict": "UNKNOWN", "reason": "no JWT found in responses",
                "evidence": {}}
    hmac_seen = False
    for token, step_name in tokens:
        res = _crack_jwt(token, secrets)
        if res is None:
            continue
        if res.get("crackable"):
            hmac_seen = True
        if res.get("secret") is not None:
            return {
                "verdict": oracle.get("verdict", "VULNERABLE"),
                "reason": f"JWT {res['alg']} signed with weak secret '{res['secret']}'",
                "evidence": {"alg": res["alg"], "secret": res["secret"],
                             "step": step_name, "token_prefix": token[:24]},
            }
    if hmac_seen:
        return {"verdict": "PASS",
                "reason": f"{len(tokens)} JWT(s) found, no weak secret in wordlist",
                "evidence": {"candidates_tried": len(secrets)}}
    return {"verdict": "UNKNOWN",
            "reason": f"{len(tokens)} JWT(s) found but none use HMAC (not crackable)",
            "evidence": {}}


def _last_step(context):
    steps = context.get("steps", [])
    return steps[-1] if steps else None


def _header_absent(oracle, context):
    steps = context.get("steps", [])
    if not steps:
        return {"verdict": "UNKNOWN", "reason": "no steps", "evidence": {}}
    required = [h.lower() for h in oracle.get("headers", [])]
    for s in steps:
        present = {k.lower() for k in (s.get("headers") or {}).keys()}
        missing = [h for h in required if h not in present]
        if missing:
            return {
                "verdict": oracle.get("verdict", "VULNERABLE"),
                "reason": f"missing headers on {s.get('step_name')}: {', '.join(missing)}",
                "evidence": {"missing": missing, "step": s.get("step_name")},
            }
    return {"verdict": "PASS", "reason": "all headers present", "evidence": {}}


def _header_value_match(oracle, context):
    steps = context.get("steps", [])
    if not steps:
        return {"verdict": "UNKNOWN", "reason": "no steps", "evidence": {}}
    target_name = oracle.get("header", "").lower()
    pattern = oracle.get("regex", "")
    for s in steps:
        for k, v in (s.get("headers") or {}).items():
            if k.lower() != target_name:
                continue
            try:
                if re.search(pattern, v, re.IGNORECASE):
                    return {
                        "verdict": oracle.get("verdict", "VULNERABLE"),
                        "reason": f"header {target_name} matched on {s.get('step_name')}",
                        "evidence": {"header": target_name, "value": v[:200],
                                     "step": s.get("step_name")},
                    }
            except re.error:
                continue
    return {"verdict": "PASS", "reason": f"header {target_name} ok", "evidence": {}}


def _cookie_flags_check(oracle, context):
    steps = context.get("steps", [])
    if not steps:
        return {"verdict": "UNKNOWN", "reason": "no steps", "evidence": {}}
    required = oracle.get("required_flags", ["Secure", "HttpOnly", "SameSite"])
    for s in steps:
        set_cookie = ""
        for k, v in (s.get("headers") or {}).items():
            if k.lower() == "set-cookie":
                set_cookie = v
                break
        if not set_cookie:
            continue
        lower = set_cookie.lower()
        missing = [f for f in required if f.lower() not in lower]
        if missing:
            return {
                "verdict": oracle.get("verdict", "VULNERABLE"),
                "reason": f"cookie missing flags on {s.get('step_name')}: {', '.join(missing)}",
                "evidence": {"missing": missing, "cookie": set_cookie[:200],
                             "step": s.get("step_name")},
            }
    return {"verdict": "PASS", "reason": "all flags present", "evidence": {}}


def _status_code_absent(oracle, context):
    steps = context.get("steps", [])
    if not steps:
        return {"verdict": "UNKNOWN", "reason": "no steps", "evidence": {}}
    statuses = [s.get("status") for s in steps if s.get("status") is not None]
    if not statuses:
        return {"verdict": "UNKNOWN", "reason": "all requests failed",
                "evidence": {"total_steps": len(steps)}}
    if all(s >= 500 for s in statuses):
        return {"verdict": "UNKNOWN", "reason": "all responses 5xx",
                "evidence": {"seen": sorted(set(statuses))}}
    target = oracle.get("code")
    if target not in statuses:
        return {
            "verdict": oracle.get("verdict", "VULNERABLE"),
            "reason": f"status {target} never observed",
            "evidence": {"seen": sorted(set(statuses)), "count": len(statuses)},
        }
    return {"verdict": "PASS", "reason": f"status {target} observed", "evidence": {}}


def _status_code_present(oracle, context):
    statuses = [s.get("status") for s in context.get("steps", []) if s.get("status")]
    target = oracle.get("code")
    if target in statuses:
        return {
            "verdict": oracle.get("verdict", "VULNERABLE"),
            "reason": f"status {target} observed",
            "evidence": {"count": statuses.count(target)},
        }
    return {"verdict": "PASS", "reason": f"status {target} not observed", "evidence": {}}


def _no_auth_200(oracle, context):
    steps = context.get("steps", [])
    if len(steps) < 2:
        return {"verdict": "UNKNOWN", "reason": "need 2 steps", "evidence": {}}
    s1, s2 = steps[0], steps[1]
    if s1.get("status") == 200 and s2.get("status") in (401, 403):
        return {
            "verdict": "VULNERABLE",
            "reason": "200 without auth, 401/403 with bad auth",
            "evidence": {"no_auth": s1.get("status"), "bad_auth": s2.get("status")},
        }
    if s1.get("status") == 200:
        return {
            "verdict": "SUSPICIOUS",
            "reason": "200 without auth",
            "evidence": {"no_auth": s1.get("status")},
        }
    return {"verdict": "PASS", "reason": "auth behaving as expected", "evidence": {}}


def _timing_delta(oracle, context):
    timings = [s.get("time_ms") for s in context.get("steps", []) if s.get("time_ms")]
    if len(timings) < 4:
        return {"verdict": "UNKNOWN", "reason": "need >= 4 timings", "evidence": {}}
    mean = statistics.mean(timings)
    stdev = statistics.pstdev(timings)
    sigma = oracle.get("sigma", 3.0)
    max_delta = max(abs(t - mean) for t in timings)
    if stdev > 0 and max_delta > sigma * stdev:
        return {
            "verdict": oracle.get("verdict", "SUSPICIOUS"),
            "reason": f"timing delta {max_delta:.1f}ms > {sigma}sigma",
            "evidence": {"mean_ms": round(mean, 3), "stdev_ms": round(stdev, 3),
                          "max_delta_ms": round(max_delta, 3)},
        }
    return {"verdict": "PASS", "reason": "no timing anomaly",
            "evidence": {"mean_ms": round(mean, 3), "stdev_ms": round(stdev, 3)}}


def _timing_vs_baseline(oracle, context):
    baseline = context.get("baseline")
    if not baseline:
        return {"verdict": "UNKNOWN", "reason": "no baseline", "evidence": {}}
    timings = [s.get("time_ms") for s in context.get("steps", []) if s.get("time_ms")]
    if not timings:
        return {"verdict": "UNKNOWN", "reason": "no timings", "evidence": {}}
    mean = baseline.get("mean_ms", 0)
    stdev = baseline.get("stdev_ms", 0)
    sigma = oracle.get("sigma", 3.0)
    if stdev <= 0:
        return {"verdict": "UNKNOWN", "reason": "baseline stdev=0", "evidence": {}}
    max_delta = max(abs(t - mean) for t in timings)
    if max_delta > sigma * stdev:
        return {
            "verdict": oracle.get("verdict", "SUSPICIOUS"),
            "reason": f"delta {max_delta:.1f}ms > {sigma}sigma baseline",
            "evidence": {"baseline_mean": mean, "baseline_stdev": stdev,
                          "max_delta": round(max_delta, 3)},
        }
    return {"verdict": "PASS", "reason": "within baseline", "evidence": {}}


def _timing_difference(oracle, context):
    steps = context.get("steps", [])
    if len(steps) < 2:
        return {"verdict": "UNKNOWN", "reason": "need >= 2 steps", "evidence": {}}
    step_names = [s.get("step_name") for s in steps]
    unique = list(dict.fromkeys(step_names))
    if len(unique) >= 2:
        batch1 = [s.get("time_ms", 0) for s in steps if s.get("step_name") == unique[0]]
        batch2 = [s.get("time_ms", 0) for s in steps if s.get("step_name") == unique[1]]
    else:
        batch1 = [steps[0].get("time_ms", 0)]
        batch2 = [steps[1].get("time_ms", 0)]
    if not batch1 or not batch2:
        return {"verdict": "UNKNOWN", "reason": "empty batches", "evidence": {}}
    m1 = statistics.mean(batch1)
    m2 = statistics.mean(batch2)
    diff = abs(m1 - m2)
    threshold_ms = oracle.get("threshold_ms", 50)
    if diff > threshold_ms:
        return {
            "verdict": oracle.get("verdict", "SUSPICIOUS"),
            "reason": f"timing diff {diff:.1f}ms > {threshold_ms}ms",
            "evidence": {"batch1_mean": round(m1, 3), "batch2_mean": round(m2, 3),
                          "diff_ms": round(diff, 3)},
        }
    return {"verdict": "PASS", "reason": f"diff {diff:.1f}ms within threshold",
            "evidence": {"diff_ms": round(diff, 3)}}


def _response_differs(oracle, context):
    hashes = [s.get("body_hash") for s in context.get("steps", []) if s.get("body_hash")]
    if len(hashes) < 2:
        return {"verdict": "UNKNOWN", "reason": "need >= 2 responses", "evidence": {}}
    distinct = set(hashes)
    if len(distinct) > 1:
        return {
            "verdict": oracle.get("verdict", "SUSPICIOUS"),
            "reason": f"{len(distinct)} distinct response bodies",
            "evidence": {"distinct_count": len(distinct), "total": len(hashes)},
        }
    return {"verdict": "PASS", "reason": "responses identical", "evidence": {}}


def _pattern_match(oracle, context):
    steps = context.get("steps", [])
    if not steps:
        return {"verdict": "UNKNOWN", "reason": "no steps", "evidence": {}}
    pattern = oracle.get("regex", "")
    all_matches = []
    matched_step = None
    for s in steps:
        body = s.get("body") or ""
        try:
            matches = re.findall(pattern, body, re.IGNORECASE)
        except re.error:
            continue
        if matches:
            all_matches.extend(matches)
            if matched_step is None:
                matched_step = s.get("step_name")
    if all_matches:
        return {
            "verdict": oracle.get("verdict", "VULNERABLE"),
            "reason": f"pattern matched {len(all_matches)} times across {len(steps)} steps",
            "evidence": {
                "sample": [str(m)[:100] for m in all_matches[:5]],
                "matched_step": matched_step,
            },
        }
    return {"verdict": "PASS", "reason": "no pattern match", "evidence": {}}


def _state_inconsistent(oracle, context):
    steps = context.get("steps", [])
    statuses = [s.get("status") for s in steps if s.get("status")]
    hashes = [s.get("body_hash") for s in steps if s.get("body_hash")]
    if len(hashes) < 2:
        return {"verdict": "UNKNOWN", "reason": "need >= 2 responses", "evidence": {}}
    if len(set(statuses)) == 1 and len(set(hashes)) > 1:
        return {
            "verdict": oracle.get("verdict", "SUSPICIOUS"),
            "reason": "same status, different bodies",
            "evidence": {"statuses": sorted(set(statuses)), "distinct_bodies": len(set(hashes))},
        }
    return {"verdict": "PASS", "reason": "state consistent", "evidence": {}}


def _content_length_delta(oracle, context):
    lengths = [len((s.get("body") or "")) for s in context.get("steps", [])]
    if len(lengths) < 2:
        return {"verdict": "UNKNOWN", "reason": "need >= 2 responses", "evidence": {}}
    if max(lengths) == 0:
        return {"verdict": "UNKNOWN", "reason": "empty responses", "evidence": {}}
    min_len = min(lengths)
    max_len = max(lengths)
    ratio = float("inf") if min_len == 0 else max_len / min_len
    threshold = oracle.get("ratio_threshold", 1.5)
    if ratio > threshold:
        return {
            "verdict": oracle.get("verdict", "SUSPICIOUS"),
            "reason": f"content length ratio {ratio:.2f} > {threshold}",
            "evidence": {"min": min_len, "max": max_len, "ratio": round(ratio, 3)},
        }
    return {"verdict": "PASS", "reason": "content lengths stable", "evidence": {}}


def _redirect_chain(oracle, context):
    steps = context.get("steps", [])
    if not steps:
        return {"verdict": "UNKNOWN", "reason": "no steps", "evidence": {}}
    pattern = oracle.get("regex", "")
    for s in steps:
        location = ""
        for k, v in (s.get("headers") or {}).items():
            if k.lower() == "location":
                location = v
                break
        if not location:
            continue
        if pattern:
            try:
                if re.search(pattern, location, re.IGNORECASE):
                    return {
                        "verdict": oracle.get("verdict", "SUSPICIOUS"),
                        "reason": f"external redirect on {s.get('step_name')}: {location}",
                        "evidence": {"location": location[:200],
                                     "step": s.get("step_name")},
                    }
            except re.error:
                continue
    return {"verdict": "PASS", "reason": "no matching redirect", "evidence": {}}


def _expected_status_mismatch(oracle, context):
    steps = context.get("steps", [])
    if not steps:
        return {"verdict": "UNKNOWN", "reason": "no steps", "evidence": {}}
    expected = oracle.get("expected", [])
    suspicious = []
    for s in steps:
        actual = s.get("status")
        if actual is None:
            continue
        if actual not in expected and actual >= 500:
            return {
                "verdict": oracle.get("verdict", "VULNERABLE"),
                "reason": f"expected {expected}, got {actual} on {s.get('step_name')}",
                "evidence": {"expected": expected, "actual": actual,
                             "step": s.get("step_name")},
            }
        if actual not in expected and actual not in (401, 403, 200, 204):
            suspicious.append((actual, s.get("step_name")))
    if suspicious:
        actual, step = suspicious[0]
        return {
            "verdict": oracle.get("verdict", "SUSPICIOUS"),
            "reason": f"expected {expected}, got {actual} on {step}",
            "evidence": {"expected": expected, "actual": actual, "step": step},
        }
    return {"verdict": "PASS", "reason": "all statuses as expected", "evidence": {}}


def _debug_signature(oracle, context):
    steps = context.get("steps", [])
    if not steps:
        return {"verdict": "UNKNOWN", "reason": "no steps", "evidence": {}}
    min_size = oracle.get("min_size", 100000)
    signatures = oracle.get("signatures", ["Laravel", "stack trace", "vendor",
                                            "Whoops", "Ignition", "APP_DEBUG",
                                            ".php", "bootstrap/app"])
    for s in steps:
        status = s.get("status")
        if status is None or status < 500:
            continue
        body = s.get("body") or ""
        size = len(body)
        hits = [sig for sig in signatures if sig.lower() in body.lower()]
        if size > min_size:
            return {
                "verdict": oracle.get("verdict", "VULNERABLE"),
                "reason": f"status {status} with {size}b body (>{min_size}b)",
                "evidence": {"status": status, "size": size,
                             "signatures_found": hits, "step": s.get("step_name")},
            }
        if hits:
            return {
                "verdict": oracle.get("verdict", "SUSPICIOUS"),
                "reason": f"status {status} with debug signatures: {', '.join(hits)}",
                "evidence": {"status": status, "size": size,
                             "signatures_found": hits, "step": s.get("step_name")},
            }
    return {"verdict": "PASS", "reason": "no debug signature", "evidence": {}}


def _json_error_field(oracle, context):
    steps = context.get("steps", [])
    if not steps:
        return {"verdict": "UNKNOWN", "reason": "no steps", "evidence": {}}
    field = oracle.get("field", "message")
    pattern = rf'"{re.escape(field)}"\s*:\s*"([^"]{{0,300}})"'
    for s in steps:
        body = s.get("body") or ""
        m = re.search(pattern, body)
        if m:
            value = m.group(1)
            return {
                "verdict": oracle.get("verdict", "SUSPICIOUS"),
                "reason": f"error field '{field}': {value[:120]}",
                "evidence": {"field": field, "value": value[:300],
                             "step": s.get("step_name")},
            }
    return {"verdict": "PASS", "reason": f"no {field} field", "evidence": {}}


_HANDLERS = {
    "header_absent": _header_absent,
    "header_value_match": _header_value_match,
    "cookie_flags_check": _cookie_flags_check,
    "status_code_absent": _status_code_absent,
    "status_code_present": _status_code_present,
    "no_auth_200": _no_auth_200,
    "timing_delta": _timing_delta,
    "timing_vs_baseline": _timing_vs_baseline,
    "timing_difference": _timing_difference,
    "response_differs": _response_differs,
    "content_length_delta": _content_length_delta,
    "pattern_match": _pattern_match,
    "state_inconsistent": _state_inconsistent,
    "redirect_chain": _redirect_chain,
    "expected_status_mismatch": _expected_status_mismatch,
    "debug_signature": _debug_signature,
    "json_error_field": _json_error_field,
    "jwt_weak_secret": _jwt_weak_secret,
}


def evaluate(oracle, context):
    otype = oracle.get("type")
    handler = _HANDLERS.get(otype)
    if not handler:
        return {"verdict": "UNKNOWN", "reason": f"unknown oracle: {otype}", "evidence": {}}
    try:
        return handler(oracle, context)
    except Exception as e:
        return {"verdict": "UNKNOWN", "reason": f"oracle error: {e}", "evidence": {}}
