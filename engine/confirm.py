from __future__ import annotations

from .config import load_engine
from .roe_guard import ROEGuard, ROEViolation
from . import http as _http


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


def _default_headers(headers, cookies):
    h = dict(headers or {})
    if cookies and not any(k.lower() == "cookie" for k in h):
        h["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    return h


def confirm_auth_bypass(target_url, forged_token, headers=None, cookies=None,
                        timeout=8, roe_guard=None):
    verify = _verify_tls()
    viol = _roe_block(roe_guard, target_url, "GET")
    if viol:
        return {"confirmed": False, "reason": f"ROE_BLOCK: {viol}"}
    h = _default_headers(headers, cookies)
    if forged_token:
        h["Authorization"] = f"Bearer {forged_token}"
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            r = c.get(target_url, headers=h)
        if r.status_code in (200, 201, 202):
            return {"confirmed": True,
                    "reason": f"forged token accepted (HTTP {r.status_code})",
                    "evidence": {"status": r.status_code,
                                 "body_preview": (r.text or "")[:200]}}
        return {"confirmed": False,
                "reason": f"forged token rejected (HTTP {r.status_code})"}
    except Exception as e:
        return {"confirmed": False, "reason": f"{type(e).__name__}: {e}"}


def confirm_sqli_reflection(target_url, param, method="GET", headers=None,
                            timeout=8, roe_guard=None):
    verify = _verify_tls()
    marker = "SC_CONFIRM_5121"
    payload = f"' UNION SELECT '{marker}'-- -"
    viol = _roe_block(roe_guard, target_url, method)
    if viol:
        return {"confirmed": False, "reason": f"ROE_BLOCK: {viol}"}
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            if method.upper() == "POST":
                r = c.post(target_url, data={param: payload},
                           headers=headers or {})
            else:
                r = c.get(target_url, params={param: payload},
                          headers=headers or {})
        body = r.text or ""
        if marker in body:
            return {"confirmed": True,
                    "reason": "UNION marker reflected in response",
                    "evidence": {"status": r.status_code,
                                 "preview": body[:300]}}
        return {"confirmed": False,
                "reason": "UNION marker not reflected",
                "evidence": {"status": r.status_code}}
    except Exception as e:
        return {"confirmed": False, "reason": f"{type(e).__name__}: {e}"}


def confirm_idor_neighbor(target_url, own_id, neighbor_id, headers=None,
                          cookies=None, timeout=8, roe_guard=None):
    verify = _verify_tls()
    h = _default_headers(headers, cookies)
    base = target_url.rstrip("/")
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            viol_own = _roe_block(roe_guard, f"{base}/{own_id}", "GET")
            if viol_own:
                return {"confirmed": False, "reason": f"ROE_BLOCK: {viol_own}"}
            r_own = c.get(f"{base}/{own_id}", headers=h)
            viol_nb = _roe_block(roe_guard, f"{base}/{neighbor_id}", "GET")
            if viol_nb:
                return {"confirmed": False,
                        "reason": f"ROE_BLOCK: {viol_nb}"}
            r_nb = c.get(f"{base}/{neighbor_id}", headers=h)
        if (r_own.status_code == 200 and r_nb.status_code == 200
                and r_own.text != r_nb.text):
            return {"confirmed": True,
                    "reason": f"neighbor id {neighbor_id} returned different 200 body",
                    "evidence": {"own_len": len(r_own.text or ""),
                                 "neighbor_len": len(r_nb.text or "")}}
        return {"confirmed": False,
                "reason": f"no distinct neighbor response "
                          f"(own={r_own.status_code}, neighbor={r_nb.status_code})"}
    except Exception as e:
        return {"confirmed": False, "reason": f"{type(e).__name__}: {e}"}


def confirm_ssrf_callback(target_url, param, oob=None, method="GET",
                          headers=None, timeout=8, roe_guard=None,
                          wait=4.0):
    if oob is None:
        try:
            from .oob_registry import get_shared_oob
            oob = get_shared_oob()
        except Exception:
            return {"confirmed": False, "reason": "no OOB available"}
    token, payload_url = oob.payload_url()
    viol = _roe_block(roe_guard, target_url, method)
    if viol:
        return {"confirmed": False, "reason": f"ROE_BLOCK: {viol}"}
    verify = _verify_tls()
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            if method.upper() == "POST":
                c.post(target_url, data={param: payload_url},
                       headers=headers or {})
            else:
                c.get(target_url, params={param: payload_url},
                      headers=headers or {})
    except Exception as e:
        return {"confirmed": False, "reason": f"{type(e).__name__}: {e}"}
    if oob.wait_for_hit(token, timeout=wait):
        return {"confirmed": True,
                "reason": "OOB callback received",
                "evidence": {"token": token}}
    return {"confirmed": False, "reason": "no OOB callback"}


_DISPATCH = {
    "auth_bypass": lambda finding, ctx: confirm_auth_bypass(
        ctx.get("target", ""),
        finding.get("evidence", {}).get("forged_token") or "",
        headers=ctx.get("headers"), cookies=ctx.get("cookies"),
        roe_guard=ctx.get("roe_guard")),
    "sqli_scan": lambda finding, ctx: confirm_sqli_reflection(
        ctx.get("target", ""),
        finding.get("evidence", {}).get("param") or ctx.get("param", ""),
        method=ctx.get("method", "GET"),
        headers=ctx.get("headers"),
        roe_guard=ctx.get("roe_guard")),
    "idor_scan": lambda finding, ctx: confirm_idor_neighbor(
        finding.get("evidence", {}).get("resource_base") or ctx.get("target", ""),
        finding.get("evidence", {}).get("own_id") or 1,
        finding.get("evidence", {}).get("neighbor_id") or 2,
        headers=ctx.get("headers"), cookies=ctx.get("cookies"),
        roe_guard=ctx.get("roe_guard")),
    "ssrf_scan": lambda finding, ctx: confirm_ssrf_callback(
        ctx.get("target", ""),
        ctx.get("param", "url"),
        headers=ctx.get("headers"),
        roe_guard=ctx.get("roe_guard")),
}


def confirm(capability, finding, context=None):
    if not capability:
        return {"confirmed": False, "reason": "no capability"}
    ctx = context or {}
    try:
        cfg = load_engine() or {}
        if not (cfg.get("confirm") or {}).get("enabled", True):
            return {"confirmed": False, "reason": "confirm.enabled=false"}
    except Exception:
        pass
    handler = _DISPATCH.get(capability)
    if handler is None:
        return {"confirmed": False,
                "reason": f"no confirmation handler for {capability}"}
    try:
        return handler(finding or {}, ctx)
    except Exception as e:
        return {"confirmed": False,
                "reason": f"confirmation error: {type(e).__name__}: {e}"}


__all__ = ["confirm", "confirm_auth_bypass", "confirm_sqli_reflection",
           "confirm_idor_neighbor", "confirm_ssrf_callback"]
