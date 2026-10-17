import json
import re
import secrets
import time
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse

import httpx

from .config import load_engine
from .roe_guard import ROEGuard, ROEViolation
from .util import response_is_success
from . import http as _http


CRITICAL_PARAM_NAMES = [
    "price", "amount", "total", "cost", "fee", "charge", "payment",
    "quantity", "qty", "count", "num",
    "discount", "coupon", "promo", "voucher", "giftcard", "credit",
    "role", "is_admin", "is_superuser", "admin", "verified", "is_verified",
    "status", "state", "phase", "step", "stage",
    "user_id", "account_id", "owner_id", "tenant_id",
    "balance", "limit", "quota", "max", "cap",
    "currency", "fx_rate", "exchange_rate",
    "shipment", "shipping", "delivery",
    "plan", "tier", "subscription",
    "kyc_status", "kyc_verified", "entitlement",
]

MASS_ASSIGN_FIELDS = [
    "is_admin", "admin", "is_superuser", "superuser", "role",
    "is_verified", "verified", "email_verified", "kyc_status",
    "account_balance", "balance", "credit", "plan", "tier",
    "subscription", "entitlement", "permissions", "scope",
    "total_override", "admin_price", "is_free", "discount_override",
    "free_shipping", "verified_status", "approved", "active",
]

NUMERIC_TAMPERS = [
    ("zero", 0),
    ("negative_one", -1),
    ("negative_small", -0.01),
    ("tiny_decimal", 0.0001),
    ("int32_max", 2147483647),
    ("int32_overflow", 2147483648),
    ("int64_max", 9223372036854775807),
    ("int64_overflow", 9223372036854775808),
    ("float_nan", "NaN"),
    ("float_inf", "Infinity"),
    ("float_neg_inf", "-Infinity"),
    ("null", None),
    ("empty_string", ""),
    ("type_confusion_str", "not_a_number"),
    ("type_confusion_bool", True),
    ("type_confusion_array", []),
]

STRING_TAMPERS = [
    ("empty", ""),
    ("null_byte", "\x00"),
    ("sql_quote", "'"),
    ("double_quote", '"'),
    ("sql_injection", "' OR 1=1--"),
    ("xss", "<script>alert(1)</script>"),
    ("path_traversal", "../../../etc/passwd"),
    ("admin_override", "admin"),
    ("wildcard", "*"),
    ("boolean_bypass", "true"),
]

ROLE_ESCALATION_VALUES = [
    "admin", "administrator", "root", "superuser", "super_admin",
    "owner", "staff", "internal", "system",
]

WORKFLOW_STEP_PARAMS = [
    "step", "stage", "phase", "state", "status", "next", "redirect",
    "return_to", "continue", "complete",
]

COUPON_PATHS = [
    "/api/cart/apply-coupon", "/api/cart/coupon", "/api/coupon/apply",
    "/api/coupon/validate", "/api/coupon/redeem", "/api/promo/apply",
    "/api/discount/apply", "/apply-coupon", "/coupon/apply",
]

CHECKOUT_PATHS = [
    "/api/checkout", "/api/orders", "/api/order", "/api/cart/checkout",
    "/api/purchase", "/checkout", "/api/cart/pay", "/api/payment",
]

CART_PATHS = [
    "/api/cart/add", "/api/cart/update", "/api/cart", "/api/cart/items",
    "/cart/add", "/cart/update",
]

REFUND_PATHS = [
    "/api/refund", "/api/refunds", "/api/order/refund", "/refund",
]

PASSWORD_RESET_PATHS = [
    "/api/password/reset/confirm", "/api/auth/password/reset",
    "/api/password/reset", "/reset-password", "/auth/password/reset/confirm",
]

VERIFICATION_PATHS = [
    "/api/verify/email", "/api/auth/verify", "/api/account/verify",
    "/verify-email", "/api/email/verify",
]

MFA_PATHS = [
    "/api/auth/mfa/verify", "/api/mfa/verify", "/api/2fa/verify",
    "/mfa/verify",
]

STATE_TERMINAL_VALUES = [
    "shipped", "delivered", "completed", "approved", "paid", "confirmed",
    "active", "verified",
]

HTML_SIGNATURES = ["<!doctype html", "<html", "<head>"]

SUCCESS_MARKERS = [
    '"success":true', '"success": true', '"status":"ok"',
    '"status": "ok"', '"ok":true', '"ok": true',
]


def _verify_tls():
    try:
        cfg = load_engine() or {}
        return bool(cfg.get("http", {}).get("verify_tls", True))
    except Exception:
        return True


def _roe_block(guard, url, method="GET"):
    if guard is None:
        try:
            guard = ROEGuard(engine_cfg=load_engine())
        except Exception as e:
            return f"ROE guard unavailable (fail-closed): {e}"
    try:
        guard.check_url(url, method)
        return None
    except ROEViolation as e:
        return str(e)


def _is_html(text):
    if not text:
        return False
    low = text.lstrip().lower()[:200]
    return any(low.startswith(s) for s in HTML_SIGNATURES)


def _body_hash(text):
    import hashlib
    return hashlib.sha256((text or "").encode("utf-8", "ignore")).hexdigest()[:16]


def _looks_like_success(resp):
    if not resp or resp.get("status") is None:
        return False
    if resp["status"] not in (200, 201, 202, 204):
        return False
    body = (resp.get("body") or "").lower()
    if not body or _is_html(resp.get("body")):
        return False
    for marker in SUCCESS_MARKERS:
        if marker in body:
            return True
    return response_is_success(resp.get("body") or "")


def _request(url, method="GET", headers=None, json_body=None, data=None,
             params=None, timeout=8, verify=None, roe_guard=None):
    if verify is None:
        verify = _verify_tls()
    viol = _roe_block(roe_guard, url, method)
    if viol:
        return {"url": url, "blocked": True, "error": f"ROE_BLOCK: {viol}"}
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            r = c.request(method.upper(), url, headers=headers or {},
                          json=json_body, data=data, params=params)
        return {"url": str(r.url), "status": r.status_code,
                "body": (r.text or "")[:4000],
                "headers": {k.lower(): v for k, v in r.headers.items()},
                "body_hash": _body_hash(r.text)}
    except _http.ConnectError as e:
        return {"url": url, "status": None, "error": f"connection error: {e}"}
    except _http.TimeoutException:
        return {"url": url, "status": None, "error": "timeout"}
    except Exception as e:
        return {"url": url, "status": None,
                "error": f"{type(e).__name__}: {e}"}


def _extract_numeric_params(body):
    if not body:
        return {}
    try:
        data = json.loads(body) if isinstance(body, str) else body
    except Exception:
        return {}
    found = {}
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                found[k] = v
            elif isinstance(v, dict):
                for kk, vv in v.items():
                    if isinstance(vv, (int, float)) and not isinstance(vv, bool):
                        found[f"{k}.{kk}"] = vv
    return found


def _baseline_compare(tampered_resp, baseline_resp, tolerance=0.15):
    if not tampered_resp or not baseline_resp:
        return False
    if tampered_resp.get("status") != baseline_resp.get("status"):
        return False
    tb = tampered_resp.get("body") or ""
    bb = baseline_resp.get("body") or ""
    if not tb or not bb:
        return False
    if abs(len(tb) - len(bb)) > max(50, int(len(bb) * tolerance)):
        return False
    return _body_hash(tb) == _body_hash(bb)


def _find_tamper_effect(tampered_resp, baseline_resp):
    if not tampered_resp or tampered_resp.get("status") is None:
        return "no_response"
    if tampered_resp.get("status") >= 500:
        return "server_error"
    if tampered_resp["status"] in (400, 422):
        return "validation_rejected"
    if tampered_resp["status"] in (401, 403):
        return "auth_rejected"
    if tampered_resp["status"] in (200, 201, 202):
        if baseline_resp and _looks_like_success(tampered_resp) and \
           not _looks_like_success(baseline_resp):
            return "success_where_baseline_failed"
        if baseline_resp and _looks_like_success(tampered_resp) and \
           _looks_like_success(baseline_resp):
            if not _baseline_compare(tampered_resp, baseline_resp):
                return "success_different_from_baseline"
            return "success_same_as_baseline"
    return "unknown"


def probe_price_tampering(endpoint_url, method="POST", baseline_body=None,
                          headers=None, timeout=8, verify=None, roe_guard=None):
    if verify is None:
        verify = _verify_tls()
    out = {"endpoint": endpoint_url, "method": method,
           "tampers": [], "findings": [],
           "verdict": "UNKNOWN", "reason": ""}
    if not baseline_body:
        out["reason"] = "no baseline body provided for price tampering"
        return out
    baseline = _request(endpoint_url, method=method, headers=headers,
                        json_body=baseline_body, timeout=timeout,
                        verify=verify, roe_guard=roe_guard)
    if baseline.get("blocked"):
        out["reason"] = baseline["error"]
        return out
    out["baseline"] = {"status": baseline.get("status"),
                       "body_hash": baseline.get("body_hash")}

    numeric_params = _extract_numeric_params(baseline_body)
    if not numeric_params:
        out["reason"] = "no numeric parameters found in baseline body"
        return out

    for param_name in numeric_params:
        for tamper_name, tamper_value in NUMERIC_TAMPERS:
            value_to_send = tamper_value
            modified = json.loads(json.dumps(baseline_body)) if isinstance(baseline_body, dict) else dict(baseline_body)
            if "." in param_name:
                outer, inner = param_name.split(".", 1)
                if outer in modified and isinstance(modified[outer], dict):
                    modified[outer][inner] = value_to_send
            else:
                modified[param_name] = value_to_send
            r = _request(endpoint_url, method=method, headers=headers,
                         json_body=modified, timeout=timeout,
                         verify=verify, roe_guard=roe_guard)
            entry = {"param": param_name, "tamper": tamper_name,
                     "sent": str(value_to_send)[:80],
                     "status": r.get("status")}
            out["tampers"].append(entry)
            effect = _find_tamper_effect(r, baseline)
            if effect == "success_where_baseline_failed":
                out["findings"].append({
                    "type": "price_tampering",
                    "param": param_name,
                    "tamper": tamper_name,
                    "sent": str(value_to_send)[:80],
                    "evidence": "tampered request succeeded while baseline failed",
                })
            elif effect == "success_different_from_baseline" and \
                 tamper_name in ("zero", "negative_one", "negative_small",
                                 "int32_overflow", "int64_overflow"):
                out["findings"].append({
                    "type": "price_tampering_suspected",
                    "param": param_name,
                    "tamper": tamper_name,
                    "sent": str(value_to_send)[:80],
                    "evidence": "tampered request produced different success response",
                })

    strong = [f for f in out["findings"] if f["type"] == "price_tampering"]
    if strong:
        out["verdict"] = "VULNERABLE"
        out["reason"] = (f"{len(strong)} price tampering vector(s) succeeded where "
                         f"the baseline request failed")
    elif out["findings"]:
        out["verdict"] = "SUSPICIOUS"
        out["reason"] = (f"{len(out['findings'])} tamper(s) produced a different success "
                         f"response; this may be an input echo, not an accepted price "
                         f"change — confirm manually")
    else:
        out["verdict"] = "PASS"
        out["reason"] = f"no price tampering anomalies across {len(out['tampers'])} attempts"
    return out


def probe_mass_assignment(endpoint_url, method="POST", baseline_body=None,
                          headers=None, timeout=8, verify=None, roe_guard=None,
                          expected_role=None):
    if verify is None:
        verify = _verify_tls()
    out = {"endpoint": endpoint_url, "method": method,
           "attempts": [], "findings": [],
           "verdict": "UNKNOWN", "reason": ""}
    if not baseline_body:
        out["reason"] = "no baseline body for mass assignment"
        return out
    baseline = _request(endpoint_url, method=method, headers=headers,
                        json_body=baseline_body, timeout=timeout,
                        verify=verify, roe_guard=roe_guard)
    if baseline.get("blocked"):
        out["reason"] = baseline["error"]
        return out
    if not _looks_like_success(baseline):
        out["reason"] = "baseline request did not succeed; cannot test mass assignment"
        return out

    for field in MASS_ASSIGN_FIELDS:
        modified = json.loads(json.dumps(baseline_body)) if isinstance(baseline_body, dict) else dict(baseline_body)
        if field in ("role", "plan", "tier"):
            modified[field] = "admin"
        elif field in ("verified", "is_verified", "email_verified",
                       "kyc_verified", "approved", "active"):
            modified[field] = True
        elif field in ("balance", "credit", "account_balance"):
            modified[field] = 999999999
        elif field in ("subscription", "entitlement"):
            modified[field] = "enterprise"
        elif field == "permissions":
            modified[field] = ["*"]
        elif field == "scope":
            modified[field] = "admin"
        else:
            modified[field] = True
        r = _request(endpoint_url, method=method, headers=headers,
                     json_body=modified, timeout=timeout,
                     verify=verify, roe_guard=roe_guard)
        entry = {"field": field, "sent": str(modified[field])[:60],
                 "status": r.get("status")}
        out["attempts"].append(entry)
        if r.get("status") in (200, 201, 202) and _looks_like_success(r):
            body = (r.get("body") or "").lower()
            if field.lower() in body:
                out["findings"].append({
                    "type": "mass_assignment",
                    "field": field,
                    "sent": str(modified[field])[:60],
                    "evidence": f"field '{field}' reflected in success response",
                })
    if out["findings"]:
        out["verdict"] = "VULNERABLE"
        out["reason"] = f"mass assignment accepted: {', '.join(f['field'] for f in out['findings'][:3])}"
    else:
        out["verdict"] = "PASS"
        out["reason"] = f"no mass assignment reflection across {len(out['attempts'])} attempts"
    return out


def probe_workflow_bypass(base_url, workflow, headers=None, timeout=8,
                          verify=None, roe_guard=None):
    if verify is None:
        verify = _verify_tls()
    out = {"base_url": base_url, "steps": workflow, "results": [],
           "bypasses": [], "verdict": "UNKNOWN", "reason": ""}
    if len(workflow) < 2:
        out["reason"] = "workflow requires at least 2 steps"
        return out

    step_responses = []
    for step in workflow:
        url = urljoin(base_url.rstrip("/") + "/", step["path"].lstrip("/"))
        r = _request(url, method=step.get("method", "POST"),
                     headers={**(headers or {}), **(step.get("headers") or {})},
                     json_body=step.get("body"), timeout=timeout,
                     verify=verify, roe_guard=roe_guard)
        step_responses.append({"step": step["name"], "status": r.get("status"),
                               "success": _looks_like_success(r),
                               "body_hash": r.get("body_hash")})
    out["results"] = step_responses

    final_step = workflow[-1]
    final_url = urljoin(base_url.rstrip("/") + "/",
                        final_step["path"].lstrip("/"))

    for skip_idx in range(len(workflow) - 1):
        skipped = workflow[skip_idx]
        r = _request(final_url, method=final_step.get("method", "POST"),
                     headers={**(headers or {}),
                              **(final_step.get("headers") or {})},
                     json_body=final_step.get("body"), timeout=timeout,
                     verify=verify, roe_guard=roe_guard)
        if _looks_like_success(r):
            out["bypasses"].append({
                "type": "step_skip",
                "skipped_step": skipped["name"],
                "reached_final": final_step["name"],
                "final_status": r.get("status"),
                "evidence": (f"final step '{final_step['name']}' succeeded "
                             f"without '{skipped['name']}'"),
            })

    for step in workflow:
        path = step["path"]
        if "{" in path:
            continue
        if step.get("method", "POST").upper() == "GET":
            continue
        for terminal in STATE_TERMINAL_VALUES:
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            modified_body = dict(step.get("body") or {})
            if isinstance(modified_body, dict):
                if "status" in modified_body or "state" in modified_body:
                    for k in ("status", "state"):
                        if k in modified_body:
                            modified_body[k] = terminal
                else:
                    modified_body["status"] = terminal
            r = _request(url, method=step.get("method", "POST"),
                         headers=headers, json_body=modified_body,
                         timeout=timeout, verify=verify, roe_guard=roe_guard)
            if _looks_like_success(r):
                body_low = (r.get("body") or "").lower()
                if terminal in body_low:
                    out["bypasses"].append({
                        "type": "state_terminal_set",
                        "step": step["name"],
                        "terminal": terminal,
                        "evidence": f"state set to '{terminal}' directly",
                    })
                    break

    if out["bypasses"]:
        out["verdict"] = "VULNERABLE"
        out["reason"] = (f"{len(out['bypasses'])} workflow bypass vector(s) detected")
    else:
        out["verdict"] = "PASS"
        out["reason"] = "workflow steps enforced in order"
    return out


def probe_race_business(base_url, endpoint_path, body=None, headers=None,
                        count=20, timeout=8, verify=None, roe_guard=None,
                        expected_success=1):
    if verify is None:
        verify = _verify_tls()
    url = urljoin(base_url.rstrip("/") + "/", endpoint_path.lstrip("/"))
    viol = _roe_block(roe_guard, url, "POST")
    if viol:
        return {"url": url, "verdict": "UNKNOWN",
                "reason": f"ROE_BLOCK: {viol}", "evidence": {}}

    import threading
    barrier = threading.Barrier(count, timeout=timeout)
    results = []
    lock = threading.Lock()

    def fire():
        client = _http.Client(timeout=timeout, verify=verify,
                              follow_redirects=False)
        try:
            try:
                client.head(url, timeout=3)
            except Exception:
                pass
            barrier.wait()
            kwargs = {"headers": headers or {}, "skip_rate_limit": True}
            if body is not None:
                if isinstance(body, dict):
                    kwargs["json"] = body
                else:
                    kwargs["data"] = body
            r = client.post(url, **kwargs)
            with lock:
                results.append({"status": r.status_code,
                                "body": (r.text or "")[:400],
                                "body_hash": _body_hash(r.text)})
        except threading.BrokenBarrierError:
            with lock:
                results.append({"status": None, "error": "barrier timeout"})
        except Exception as e:
            with lock:
                results.append({"status": None, "error": f"{type(e).__name__}: {e}"})
        finally:
            client.close()

    threads = [threading.Thread(target=fire, daemon=True) for _ in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=timeout + 5)

    successes = [r for r in results if _looks_like_success(r)]
    distinct_success_hashes = len(set(r["body_hash"] for r in successes
                                      if r.get("body_hash")))
    evidence = {
        "total": len(results),
        "successes": len(successes),
        "distinct_success_hashes": distinct_success_hashes,
        "expected_success": expected_success,
    }
    if len(successes) > expected_success:
        return {"url": url, "verdict": "VULNERABLE",
                "reason": f"{len(successes)}/{count} concurrent requests succeeded "
                          f"(invariant: only {expected_success} should succeed)",
                "evidence": evidence}
    if len(successes) == expected_success and distinct_success_hashes > 1:
        return {"url": url, "verdict": "SUSPICIOUS",
                "reason": f"{len(successes)} success responses with distinct bodies "
                          f"(possible partial state split)",
                "evidence": evidence}
    if len(successes) == 0:
        return {"url": url, "verdict": "UNKNOWN",
                "reason": "no successful responses; cannot verify race",
                "evidence": evidence}
    return {"url": url, "verdict": "PASS",
            "reason": f"exactly {expected_success}/{count} succeeded (properly guarded)",
            "evidence": evidence}


def probe_coupon_abuse(base_url, coupon_code, apply_path="/api/cart/apply-coupon",
                       headers=None, timeout=8, verify=None, roe_guard=None,
                       attempts=5):
    if verify is None:
        verify = _verify_tls()
    url = urljoin(base_url.rstrip("/") + "/", apply_path.lstrip("/"))
    out = {"url": url, "coupon": coupon_code, "attempts": [],
           "verdict": "UNKNOWN", "reason": ""}
    for i in range(attempts):
        r = _request(url, method="POST", headers=headers,
                     json_body={"code": coupon_code},
                     timeout=timeout, verify=verify, roe_guard=roe_guard)
        out["attempts"].append({"attempt": i + 1, "status": r.get("status"),
                                "success": _looks_like_success(r)})
        if i > 0 and _looks_like_success(r):
            pass
    successful = [a for a in out["attempts"] if a["success"]]
    if len(successful) > 1:
        out["verdict"] = "VULNERABLE"
        out["reason"] = (f"coupon applied successfully {len(successful)} times "
                         f"sequentially (should be idempotent)")
    elif len(successful) == 1:
        out["verdict"] = "PASS"
        out["reason"] = "coupon accepted once and rejected on retry"
    else:
        out["verdict"] = "UNKNOWN"
        out["reason"] = f"no successful coupon application in {attempts} attempts"
    return out


def probe_verification_bypass(base_url, protected_path, headers=None,
                              timeout=8, verify=None, roe_guard=None):
    if verify is None:
        verify = _verify_tls()
    url = urljoin(base_url.rstrip("/") + "/", protected_path.lstrip("/"))
    r = _request(url, method="GET", headers=headers, timeout=timeout,
                 verify=verify, roe_guard=roe_guard)
    if r.get("blocked"):
        return {"verdict": "UNKNOWN", "reason": r["error"], "evidence": {}}
    if r.get("status") == 200 and not _is_html(r.get("body")):
        return {"verdict": "SUSPICIOUS",
                "reason": (f"protected path '{protected_path}' returned 200 "
                           f"without verification step"),
                "evidence": {"status": 200, "body_preview": (r.get("body") or "")[:200]}}
    if r.get("status") in (401, 403, 302, 303):
        return {"verdict": "PASS",
                "reason": f"protected path enforced (HTTP {r.get('status')})",
                "evidence": {"status": r.get("status")}}
    return {"verdict": "UNKNOWN",
            "reason": f"unexpected status {r.get('status')} on protected path",
            "evidence": {"status": r.get("status")}}


def _scan_impl(base_url, headers=None, timeout=8, verify=None, roe_guard=None,
         endpoints=None):
    if verify is None:
        verify = _verify_tls()
    out = {
        "base_url": base_url,
        "probes": {},
        "verdict": "UNKNOWN",
        "reason": "",
    }
    if not endpoints:
        out["reason"] = "no endpoints provided"
        return out

    if "price_endpoint" in endpoints:
        ep = endpoints["price_endpoint"]
        out["probes"]["price_tampering"] = probe_price_tampering(
            ep["url"], method=ep.get("method", "POST"),
            baseline_body=ep.get("baseline_body"),
            headers=headers, timeout=timeout, verify=verify, roe_guard=roe_guard)

    if "mass_assign_endpoint" in endpoints:
        ep = endpoints["mass_assign_endpoint"]
        out["probes"]["mass_assignment"] = probe_mass_assignment(
            ep["url"], method=ep.get("method", "POST"),
            baseline_body=ep.get("baseline_body"),
            headers=headers, timeout=timeout, verify=verify, roe_guard=roe_guard)

    if "workflow" in endpoints:
        out["probes"]["workflow_bypass"] = probe_workflow_bypass(
            base_url, endpoints["workflow"], headers=headers,
            timeout=timeout, verify=verify, roe_guard=roe_guard)

    if "race_endpoint" in endpoints:
        ep = endpoints["race_endpoint"]
        out["probes"]["race_business"] = probe_race_business(
            base_url, ep["path"], body=ep.get("body"), headers=headers,
            count=ep.get("count", 20), timeout=timeout, verify=verify,
            roe_guard=roe_guard, expected_success=ep.get("expected_success", 1))

    if "coupon" in endpoints:
        out["probes"]["coupon_abuse"] = probe_coupon_abuse(
            base_url, endpoints["coupon"]["code"],
            apply_path=endpoints["coupon"].get("path", "/api/cart/apply-coupon"),
            headers=headers, timeout=timeout, verify=verify, roe_guard=roe_guard)

    if "protected_path" in endpoints:
        out["probes"]["verification_bypass"] = probe_verification_bypass(
            base_url, endpoints["protected_path"], headers=headers,
            timeout=timeout, verify=verify, roe_guard=roe_guard)

    try:
        from . import llm_service
        from . import bizlogic_llm
        client = llm_service.get_client("bizlogic_llm")
        if client is not None:
            model = bizlogic_llm.infer_app_model(
                client,
                {"base_url": base_url,
                 "endpoints": sorted(endpoints.keys())},
            )
            llm_findings = bizlogic_llm.execute_flaws(
                roe_guard, base_url, model)
            if llm_findings:
                out["probes"]["llm_inferred"] = {
                    "verdict": "VULNERABLE",
                    "reason": f"{len(llm_findings)} LLM-inferred flaw(s) confirmed",
                    "evidence": {"findings": llm_findings,
                                 "flaw_count": len(model.get("flaws") or [])},
                }
            else:
                out["probes"]["llm_inferred"] = {
                    "verdict": "PASS",
                    "reason": (
                        f"no LLM-inferred flaws confirmed "
                        f"({len(model.get('flaws') or [])} proposed)"
                    ),
                    "evidence": {"flaw_count": len(model.get("flaws") or [])},
                }
    except Exception as e:
        out["probes"]["llm_inferred"] = {
            "verdict": "UNKNOWN",
            "reason": f"llm inference failed: {type(e).__name__}: {e}",
            "evidence": {},
        }

    rank = {"VULNERABLE": 3, "SUSPICIOUS": 2, "PASS": 1, "UNKNOWN": 0}
    overall = "UNKNOWN"
    for p in out["probes"].values():
        if rank.get(p.get("verdict"), 0) > rank.get(overall, 0):
            overall = p["verdict"]

    out["verdict"] = overall
    if overall == "VULNERABLE":
        vuln = [k for k, v in out["probes"].items()
                if v.get("verdict") == "VULNERABLE"]
        out["reason"] = f"Business logic flaws: {', '.join(vuln)}"
    elif overall == "SUSPICIOUS":
        susp = [k for k, v in out["probes"].items()
                if v.get("verdict") == "SUSPICIOUS"]
        out["reason"] = f"Suspicious behaviour: {', '.join(susp)}"
    elif overall == "PASS":
        out["reason"] = "no business logic anomalies detected"
    else:
        out["reason"] = "probes did not complete"
    return out

def scan(*args, **kwargs):
    from .contract import make_result
    raw = _scan_impl(*args, **kwargs)
    return make_result(raw, capability="bizlogic", args=args, kwargs=kwargs)
