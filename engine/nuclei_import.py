from __future__ import annotations

import re
from pathlib import Path

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

_registered = False

_SEV_TO_PRIORITY = {
    "critical": 900,
    "high": 700,
    "medium": 500,
    "low": 300,
    "info": 100,
}


def _request_blocks(template):
    out = []
    for proto in ("http", "requests", "dns", "network",
                  "headless", "javascript"):
        raw = template.get(proto)
        if raw is None:
            continue
        if isinstance(raw, dict):
            raw = [raw]
        if not isinstance(raw, list):
            continue
        for r in raw:
            if isinstance(r, dict):
                out.append((proto, r))
    return out


def _http_block(template):
    return [b for proto, b in _request_blocks(template)
            if proto in ("http", "requests")]


def load_template(path):
    if not HAS_YAML:
        raise RuntimeError("PyYAML not installed")
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(str(p))
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError("template root must be a mapping")
    return data


def _resolve_base(url, target):
    if not url:
        return target
    if "{{BaseURL}}" in url:
        return url.replace("{{BaseURL}}", target)
    if "{{RootURL}}" in url:
        return url.replace("{{RootURL}}", target)
    if url.startswith(("http://", "https://")):
        return url
    if url.startswith("/"):
        return target.rstrip("/") + url
    return target.rstrip("/") + "/" + url


def _matcher_matches(matcher, status, body_text, header_text):
    if not isinstance(matcher, dict):
        return False
    mt = str(matcher.get("type") or "").lower()
    negate = bool(matcher.get("negative"))
    part = str(matcher.get("part") or "body").lower()
    haystack = body_text
    if part == "header":
        haystack = header_text
    elif part == "all":
        haystack = header_text + "\n" + body_text
    inner = str(matcher.get("condition") or "or").lower()
    ok = False
    if mt == "status":
        wanted = matcher.get("status") or []
        try:
            ok = int(status) in [int(x) for x in wanted]
        except Exception:
            ok = False
    elif mt == "word":
        words = [str(w) for w in (matcher.get("words") or [])]
        if not words:
            ok = False
        elif inner == "and":
            ok = all(w in haystack for w in words)
        else:
            ok = any(w in haystack for w in words)
    elif mt == "regex":
        patterns = matcher.get("regex") or matcher.get("regexes") or []
        patterns = [str(p) for p in patterns]
        hits = []
        for p in patterns:
            try:
                hits.append(re.search(p, haystack) is not None)
            except re.error:
                hits.append(False)
        if not hits:
            ok = False
        elif inner == "and":
            ok = all(hits)
        else:
            ok = any(hits)
    else:
        ok = False
    return (not ok) if negate else ok


def _evaluate_matchers(req, status, body_text, header_text):
    matchers = req.get("matchers") or []
    if not matchers:
        return True, []
    cond = str(req.get("matchers-condition") or "or").lower()
    results = [_matcher_matches(m, status, body_text, header_text)
               for m in matchers]
    if cond == "and":
        matched = all(results)
    else:
        matched = any(results)
    return matched, results


def _tool_nuclei_http(orch, args):
    from . import http as _http
    req = args.get("request") or {}
    protocol = str(args.get("protocol") or "http").lower()
    template_id = str(args.get("template_id") or "nuclei")
    if not isinstance(req, dict):
        return {"verdict": "UNKNOWN",
                "reason": "nuclei_http: request block missing"}
    if protocol in ("dns", "network", "headless", "javascript"):
        return {"verdict": "UNKNOWN",
                "reason": (f"nuclei protocol '{protocol}' not yet "
                           f"implemented (template {template_id})"),
                "evidence": {"protocol": protocol,
                             "template_id": template_id,
                             "request": req}}
    paths = req.get("path") or req.get("paths") or []
    if isinstance(paths, str):
        paths = [paths]
    if not paths:
        return {"verdict": "UNKNOWN",
                "reason": "nuclei_http: request has no path"}
    target = orch.target
    url = _resolve_base(str(paths[0]), target)
    method = str(req.get("method") or "GET").upper()
    headers = dict(req.get("headers") or {})
    body = req.get("body")
    kwargs = {"headers": headers, "follow_redirects": False}
    if body is not None:
        if isinstance(body, (list, tuple)):
            body = "\n".join(str(b) for b in body)
        kwargs["content"] = str(body).encode("utf-8")
    try:
        with _http.Client(timeout=12) as c:
            r = c.request(method, url, **kwargs)
    except _http.ROEBlock as e:
        return {"verdict": "UNKNOWN",
                "reason": f"nuclei_http ROE_BLOCK: {e}"}
    except Exception as e:
        return {"verdict": "UNKNOWN",
                "reason": f"nuclei_http error: {type(e).__name__}: {e}"}
    body_text = r.text or ""
    header_text = "\n".join(
        f"{k}: {v}" for k, v in r.headers.items())
    matched, results = _evaluate_matchers(
        req, r.status_code, body_text, header_text)
    preview = body_text[:400]
    if matched:
        return {
            "verdict": "VULNERABLE",
            "reason": (f"nuclei template {template_id} matched "
                        f"at {method} {url} (HTTP {r.status_code})"),
            "evidence": {
                "template_id": template_id,
                "url": url,
                "method": method,
                "status": r.status_code,
                "matcher_results": results,
                "preview": preview,
            },
        }
    return {"verdict": "PASS",
            "reason": (f"nuclei template {template_id} did not match "
                        f"at {method} {url} (HTTP {r.status_code})"),
            "evidence": {"template_id": template_id, "url": url,
                         "status": r.status_code}}


def ensure_registered():
    global _registered
    if _registered:
        return
    try:
        from .chain_engine import register_tool
        register_tool("nuclei_http", _tool_nuclei_http)
    except Exception:
        pass
    _registered = True


def template_to_chain(template, source_path=""):
    tid = str(template.get("id") or "unnamed").strip() or "unnamed"
    info = template.get("info") or {}
    name = str(info.get("name") or tid)
    severity = str(info.get("severity") or "medium").lower()
    priority = _SEV_TO_PRIORITY.get(severity, 500)
    blocks = _request_blocks(template)
    steps = []
    for i, (proto, req) in enumerate(blocks):
        steps.append({
            "id": f"nuclei-{proto}-{i}",
            "tool": "nuclei_http",
            "args": {"request": req, "protocol": proto,
                     "template_id": tid},
            "on_fail": "next",
        })
    chain = {
        "id": f"nuclei-{tid}",
        "name": name,
        "priority": priority,
        "severity": severity,
        "source": str(source_path or ""),
        "trigger": {
            "mode": "any",
            "conditions": [{"fact": "nuclei_enabled"}],
        },
        "steps": steps,
    }
    return chain


try:
    ensure_registered()
except Exception:
    pass


__all__ = [
    "load_template", "template_to_chain",
    "ensure_registered",
]
