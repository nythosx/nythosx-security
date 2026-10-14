"""Oracle handlers for Phase 4 patterns.

Registered into engine.oracle._HANDLERS at import time so that
test_every_pattern_oracle_has_handler goes green without touching
engine/oracle.py (which is Phase 3 territory).
"""

from __future__ import annotations

import json as _json
import re as _re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from . import oracle as _oracle
from . import http as _http


def _step_body(step):
    return step.get("body") or ""


def _looks_json(body):
    if not body:
        return False
    t = body.lstrip()
    return t.startswith("{") or t.startswith("[")


def _try_json(body):
    try:
        return _json.loads(body)
    except Exception:
        return None


def _oracle_bola_harvest(oracle, ctx):
    steps = ctx.get("steps") or []
    if not steps:
        return {"verdict": "UNKNOWN",
                "reason": "no steps to evaluate", "evidence": {}}
    distinct_bodies = set()
    sample = None
    for s in steps:
        if s.get("status") != 200:
            continue
        body = _step_body(s)
        if not _looks_json(body):
            continue
        distinct_bodies.add(s.get("body_hash") or body[:100])
        if sample is None:
            sample = s
    if len(distinct_bodies) >= 2:
        return {"verdict": "VULNERABLE",
                "reason": f"{len(distinct_bodies)} distinct 200 JSON bodies "
                          f"across the same endpoint — cross-user data returned",
                "evidence": {"distinct_bodies": len(distinct_bodies)}}
    if distinct_bodies:
        return {"verdict": "SUSPICIOUS",
                "reason": "single-body 200 response — needs second user to confirm",
                "evidence": {"distinct_bodies": len(distinct_bodies)}}
    return {"verdict": "PASS", "reason": "no JSON bodies returned",
            "evidence": {}}


def _oracle_unauth_pagination_dump(oracle, ctx):
    steps = ctx.get("steps") or []
    total = 0
    pages_with_rows = 0
    for s in steps:
        if s.get("status") != 200:
            continue
        body = _step_body(s)
        data = _try_json(body)
        if data is None:
            continue
        rows = _unwrap(data)
        if rows:
            total += len(rows)
            pages_with_rows += 1
    if pages_with_rows >= 2:
        return {"verdict": "VULNERABLE",
                "reason": (f"unauthenticated pagination returned {total} "
                            f"row(s) across {pages_with_rows} page(s)"),
                "evidence": {"total_rows": total, "pages": pages_with_rows}}
    if total:
        return {"verdict": "SUSPICIOUS",
                "reason": f"{total} row(s) returned from one unauth page",
                "evidence": {"total_rows": total, "pages": pages_with_rows}}
    return {"verdict": "PASS", "reason": "no unauthenticated rows returned",
            "evidence": {}}


def _oracle_graphql_data_dump(oracle, ctx):
    for s in ctx.get("steps") or []:
        body = _step_body(s)
        if "__schema" not in body:
            continue
        data = _try_json(body)
        if not isinstance(data, dict):
            continue
        schema = (data.get("data") or {}).get("__schema") or {}
        if not schema:
            continue
        q = (schema.get("queryType") or {}).get("fields") or []
        return {"verdict": "VULNERABLE" if q else "SUSPICIOUS",
                "reason": f"introspection returned {len(q)} root field(s)",
                "evidence": {"root_fields": [f.get("name") for f in q[:20]]}}
    return {"verdict": "PASS", "reason": "no introspection response returned",
            "evidence": {}}


def _oracle_blind_sqli_extract(oracle, ctx):
    steps = ctx.get("steps") or []
    if not steps:
        return {"verdict": "UNKNOWN", "reason": "no steps", "evidence": {}}
    statuses = [s.get("status") for s in steps if s.get("status") is not None]
    if not statuses:
        return {"verdict": "UNKNOWN",
                "reason": "no live responses", "evidence": {}}
    delays = [s.get("time_ms") for s in steps if s.get("time_ms") is not None]
    if len(delays) >= 2:
        delta = max(delays) - min(delays)
        if delta >= 1500:
            return {"verdict": "SUSPICIOUS",
                    "reason": (f"timing delta {delta:.0f}ms across payloads "
                                f"— blind injection signal"),
                    "evidence": {"timing_delta_ms": round(delta, 1)}}
    return {"verdict": "PASS",
            "reason": "no blind-injection timing signal observed",
            "evidence": {}}


def _oracle_blind_xxe_file_read(oracle, ctx):
    markers = ("root:", "localhost", "[fonts]", "PATH=", "APP_KEY",
                "aws_access_key_id")
    for s in ctx.get("steps") or []:
        body = _step_body(s)
        for m in markers:
            if m in body:
                return {"verdict": "VULNERABLE",
                        "reason": f"XXE file read marker '{m}' in response",
                        "evidence": {"marker": m, "preview": body[:300]}}
    return {"verdict": "PASS",
            "reason": "no file-read markers in XXE responses",
            "evidence": {}}


def _oracle_llm_system_prompt_dump(oracle, ctx):
    for s in ctx.get("steps") or []:
        body = _step_body(s)
        out = _extract_llm_output(body)
        if not out or len(out) < 80:
            continue
        hits = sum(1 for pat in (
            r"you are (?:a|an)",
            r"your (?:role|task|purpose) is",
            r"you (?:must|should|will)",
            r"(?:do not|don't) (?:reveal|share)",
        ) if _re.search(pat, out, _re.IGNORECASE))
        if hits >= 2:
            return {"verdict": "VULNERABLE",
                    "reason": f"system prompt structure leaked "
                              f"({hits} directive patterns)",
                    "evidence": {"preview": out[:500]}}
    return {"verdict": "PASS",
            "reason": "no system prompt leaked across probes",
            "evidence": {}}


def _oracle_llm_tool_list_dump(oracle, ctx):
    for s in ctx.get("steps") or []:
        out = _extract_llm_output(_step_body(s))
        if not out:
            continue
        hits = sum(1 for m in ("function", "tool", "parameter", "argument",
                                "schema", "{") if m in out.lower())
        if hits >= 3 and len(out) > 150:
            return {"verdict": "VULNERABLE",
                    "reason": f"tool list disclosed ({len(out)} chars)",
                    "evidence": {"preview": out[:500]}}
    return {"verdict": "PASS",
            "reason": "no tool list disclosed", "evidence": {}}


def _oracle_llm_credential_extract(oracle, ctx):
    patterns = (r"AKIA[0-9A-Z]{16}", r"sk-[A-Za-z0-9_\-]{20,}",
                 r"ghp_[A-Za-z0-9]{36}", r"AIza[0-9A-Za-z\-_]{35}",
                 r"-----BEGIN [A-Z]+ PRIVATE KEY-----")
    for s in ctx.get("steps") or []:
        out = _extract_llm_output(_step_body(s))
        if not out:
            continue
        for pat in patterns:
            m = _re.search(pat, out)
            if m:
                return {"verdict": "VULNERABLE",
                        "reason": f"credential pattern matched: {pat}",
                        "evidence": {"match": m.group(0)[:60],
                                     "preview": out[:400]}}
    return {"verdict": "PASS",
            "reason": "no credential patterns in LLM output",
            "evidence": {}}


def _oracle_mcp_tool_poisoning(oracle, ctx):
    for s in ctx.get("steps") or []:
        body = _step_body(s)
        if not body:
            continue
        if "mcpServers" in body or "mcp" in body.lower():
            if _re.search(
                r"ignore (?:all )?previous|disregard|you are now|"
                r"read ~?/\.ssh|read ~?/\.aws|exfil",
                body, _re.IGNORECASE,
            ):
                return {"verdict": "VULNERABLE",
                        "reason": "MCP tool description contains "
                                    "poisoning pattern",
                        "evidence": {"preview": body[:400]}}
    return {"verdict": "PASS",
            "reason": "no MCP poisoning pattern in config",
            "evidence": {}}


def _oracle_mcp_credential_exposure(oracle, ctx):
    patterns = (r"AKIA[0-9A-Z]{16}", r"sk-[A-Za-z0-9_\-]{20,}",
                 r"ghp_[A-Za-z0-9]{36}", r"xox[baprs]-[0-9A-Za-z\-]+")
    for s in ctx.get("steps") or []:
        body = _step_body(s)
        for pat in patterns:
            m = _re.search(pat, body)
            if m:
                return {"verdict": "VULNERABLE",
                        "reason": f"credential in MCP config: {pat}",
                        "evidence": {"match": m.group(0)[:60]}}
    return {"verdict": "PASS",
            "reason": "no credentials in MCP config", "evidence": {}}


def _oracle_session_fixation(oracle, ctx):
    steps = ctx.get("steps") or []
    if len(steps) < 2:
        return {"verdict": "UNKNOWN",
                "reason": "need pre-login and post-login responses",
                "evidence": {}}
    pre, post = steps[0], steps[1]
    pre_cookies = _extract_session_cookies(pre.get("headers") or {})
    post_cookies = _extract_session_cookies(post.get("headers") or {})
    if not pre_cookies:
        return {"verdict": "UNKNOWN",
                "reason": "no session cookie issued before login",
                "evidence": {"pre": list(pre_cookies.keys())}}
    unchanged = [k for k in pre_cookies if post_cookies.get(k) == pre_cookies[k]]
    rotated = [k for k in pre_cookies if k in post_cookies
               and post_cookies[k] != pre_cookies[k]]
    if unchanged and not rotated:
        return {"verdict": "VULNERABLE",
                "reason": f"session cookie not rotated: {', '.join(unchanged)}",
                "evidence": {"unchanged": unchanged}}
    if rotated:
        return {"verdict": "PASS",
                "reason": "session cookie rotated on login",
                "evidence": {"rotated": rotated}}
    return {"verdict": "UNKNOWN",
            "reason": "cookie present before but missing after login",
            "evidence": {}}


def _oracle_postmessage_abuse(oracle, ctx):
    add_listener = _re.compile(r"addEventListener\s*\(\s*['\x22]message['\x22]",
                                _re.DOTALL)
    for s in ctx.get("steps") or []:
        body = _step_body(s)
        if not add_listener.search(body):
            continue
        for m in add_listener.finditer(body):
            snippet = body[m.start():m.start() + 300]
            if "event.origin" not in snippet and "e.origin" not in snippet \
                    and "evt.origin" not in snippet and "ev.origin" not in snippet:
                return {"verdict": "SUSPICIOUS",
                        "reason": "message listener does not check event.origin",
                        "evidence": {"snippet": snippet[:200]}}
    return {"verdict": "PASS",
            "reason": "no unguarded message listener found", "evidence": {}}


def _oracle_generic_pattern(oracle, ctx):
    """Fallback for pattern_match-style oracles referencing our new patterns."""
    regex = oracle.get("regex") or ""
    if not regex:
        return {"verdict": "UNKNOWN",
                "reason": "no regex in oracle", "evidence": {}}
    for s in ctx.get("steps") or []:
        body = _step_body(s)
        try:
            m = _re.search(regex, body)
        except _re.error:
            continue
        if m:
            return {"verdict": oracle.get("verdict", "VULNERABLE"),
                    "reason": f"pattern matched: {regex[:80]}",
                    "evidence": {"match": m.group(0)[:120]}}
    return {"verdict": "PASS", "reason": "no pattern match", "evidence": {}}


def _extract_session_cookies(headers):
    out = {}
    for k, v in (headers or {}).items():
        if k.lower() == "set-cookie":
            for chunk in str(v).split(","):
                if "=" in chunk:
                    name, _, rest = chunk.partition("=")
                    name = name.strip()
                    val = rest.split(";")[0].strip()
                    if name:
                        out[name] = val
    return out


def _extract_llm_output(body):
    data = _try_json(body)
    if data is None:
        return body or ""
    paths = [
        ["choices", 0, "message", "content"],
        ["choices", 0, "text"],
        ["content", 0, "text"],
        ["message", "content"],
        ["response"], ["output"], ["text"], ["result"],
    ]
    for path in paths:
        cur = data
        ok = True
        for key in path:
            if isinstance(cur, dict):
                cur = cur.get(key)
            elif isinstance(cur, list) and isinstance(key, int):
                cur = cur[key] if key < len(cur) else None
            else:
                ok = False
                break
            if cur is None:
                ok = False
                break
        if ok and isinstance(cur, str) and cur.strip():
            return cur
    return body or ""


def _unwrap(parsed):
    if isinstance(parsed, list):
        return [r for r in parsed if isinstance(r, dict)]
    if isinstance(parsed, dict):
        for k in ("data", "items", "results", "records", "content",
                   "accounts", "transactions", "customers", "users"):
            v = parsed.get(k)
            if isinstance(v, list):
                return [r for r in v if isinstance(r, dict)]
        return [parsed]
    return []


_oracle._HANDLERS.update({
    "bola_harvest": _oracle_bola_harvest,
    "unauth_pagination_dump": _oracle_unauth_pagination_dump,
    "graphql_data_dump": _oracle_graphql_data_dump,
    "blind_sqli_extract": _oracle_blind_sqli_extract,
    "blind_xxe_file_read": _oracle_blind_xxe_file_read,
    "llm_system_prompt_dump": _oracle_llm_system_prompt_dump,
    "llm_tool_list_dump": _oracle_llm_tool_list_dump,
    "llm_credential_extract": _oracle_llm_credential_extract,
    "mcp_tool_poisoning": _oracle_mcp_tool_poisoning,
    "mcp_credential_exposure": _oracle_mcp_credential_exposure,
    "session_fixation": _oracle_session_fixation,
    "postmessage_abuse": _oracle_postmessage_abuse,
})
