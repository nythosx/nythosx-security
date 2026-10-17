"""WAF retry primitives: extract, substitute, decide.

Pure functions — no HTTP. The HTTP loop lives in engine/http.py Client.
"""
from __future__ import annotations

from urllib.parse import urlparse, parse_qs

WAF_TRIGGER_SUBSTRINGS = (
    "'", '"', "<", ">", "&", ";", "|", "$", "`", "(", ")",
    "../", "..\\", "/etc/", "system(", "sleep(", "waitfor",
    "union", "select", "or 1=1", "<script", "onerror=", "onload=",
    "__proto__", "constructor[", "{{", "}}", "%0d", "%0a",
)

SKIP_LOCATIONS = frozenset(("headers", "cookies"))


def has_waf_triggers(s):
    if not isinstance(s, str) or not s:
        return False
    low = s.lower()
    return any(t in low for t in WAF_TRIGGER_SUBSTRINGS)


def _first_payload_key(d):
    for k, v in d.items():
        if isinstance(v, str) and has_waf_triggers(v):
            return k, v
    return None, None


def extract_payload(method, url, kwargs):
    if not isinstance(kwargs, dict):
        return None
    j = kwargs.get("json")
    if isinstance(j, dict):
        k, v = _first_payload_key(j)
        if k is not None:
            return {"location": "json." + k, "value": v}
    d = kwargs.get("data")
    if isinstance(d, dict):
        k, v = _first_payload_key(d)
        if k is not None:
            return {"location": "data." + k, "value": v}
    c = kwargs.get("content")
    if isinstance(c, (bytes, bytearray)):
        try:
            c = c.decode("utf-8")
        except Exception:
            c = ""
    if isinstance(c, str) and has_waf_triggers(c):
        return {"location": "content", "value": c}
    p = kwargs.get("params")
    if isinstance(p, dict):
        k, v = _first_payload_key(p)
        if k is not None:
            return {"location": "params." + k, "value": v}
    if isinstance(url, str):
        try:
            parsed = urlparse(url)
        except Exception:
            parsed = None
        if parsed and parsed.query:
            q = parse_qs(parsed.query, keep_blank_values=True)
            for k, vals in q.items():
                if isinstance(vals, list) and vals:
                    v = vals[0]
                    if has_waf_triggers(v):
                        return {"location": "url_query." + k, "value": v,
                                "url": url, "parsed": parsed, "q": q}
    return None


def _clone_json(j):
    if isinstance(j, dict):
        return dict(j)
    return j


def substitute(kwargs, new_value, payload_info):
    loc = payload_info.get("location") or ""
    out = dict(kwargs)
    if loc.startswith("json."):
        key = loc[len("json."):]
        j = _clone_json(kwargs.get("json"))
        if isinstance(j, dict):
            j[key] = new_value
            out["json"] = j
        return out
    if loc.startswith("data."):
        key = loc[len("data."):]
        d = dict(kwargs.get("data") or {})
        d[key] = new_value
        out["data"] = d
        return out
    if loc == "content":
        if isinstance(kwargs.get("content"), (bytes, bytearray)):
            out["content"] = new_value.encode("utf-8") if isinstance(new_value, str) else new_value
        else:
            out["content"] = new_value
        return out
    if loc.startswith("params."):
        key = loc[len("params."):]
        p = dict(kwargs.get("params") or {})
        p[key] = new_value
        out["params"] = p
        return out
    if loc.startswith("url_query."):
        key = loc[len("url_query."):]
        q = dict(payload_info.get("q") or {})
        q[key] = [new_value]
        from urllib.parse import urlencode, urlunparse
        parsed = payload_info["parsed"]
        out["_retry_url"] = urlunparse(parsed._replace(query=urlencode(q, doseq=True)))
        return out
    return out


def should_retry(method, url, kwargs, response_status):
    if response_status != 403:
        return False
    return extract_payload(method, url, kwargs) is not None


__all__ = ["extract_payload", "substitute", "should_retry",
           "has_waf_triggers", "WAF_TRIGGER_SUBSTRINGS"]
