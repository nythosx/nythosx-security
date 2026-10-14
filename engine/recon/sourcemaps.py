"""JavaScript source-map mining.

Source maps (.js.map) are frequently shipped to production. They contain
the ORIGINAL source of the application, including parameter names, API
URLs, hardcoded constants, and comments that the minifier stripped from
the shipped bundle.

This module fetches sourcemaps for every JS URL discovered during recon,
parses them, and extracts high-signal strings.

The archive/recon pattern: sourcemap fetches hit the TARGET, so ROE
applies. All requests route through engine.http.Client.
"""
from __future__ import annotations

import json
import re
from urllib.parse import urljoin, urlparse

from .. import http as _http
from ..config import load_engine
from ..roe_guard import ROEGuard, ROEViolation


_URL_RE = re.compile(r"""["'`](https?://[\w\-./?=&%#:]+)["'`]""")
_PATH_RE = re.compile(r"""["'`](/[a-z][\w\-./]{1,120})["'`]""", re.I)
_PARAM_HINT_RE = re.compile(
    r"""(?:params?|query|body|payload)\s*[:=]\s*\{([^}]{0,200})\}""",
    re.I,
)
_FETCH_RE = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|delete|patch)|useFetch|\$fetch)\s*\(\s*["'`]([^"'`]+)["'`]"""
)
_PICK_RE = re.compile(r"""\.(?:pick|select)\s*\(\s*\[([^\]]+)\]""", re.I)
_NAME_RE = re.compile(r"""([a-zA-Z_][a-zA-Z0-9_]{2,})\s*[:=]""")


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


def _fetch(url, timeout, verify, roe_guard):
    viol = _roe_block(roe_guard, url, "GET")
    if viol:
        return {"blocked": True, "error": f"ROE_BLOCK: {viol}"}
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=True) as c:
            r = c.get(url)
        if r.status_code != 200:
            return {"status": r.status_code, "error": "not ok"}
        return {"status": 200, "body": r.text or ""}
    except _http.ConnectError as e:
        return {"status": None, "error": f"connection error: {e}"}
    except _http.TimeoutException:
        return {"status": None, "error": "timeout"}
    except Exception as e:
        return {"status": None, "error": f"{type(e).__name__}: {e}"}


_SOURCEMAP_RE = re.compile(r"""//[#@]\s*sourceMappingURL=([^\s]+)""")


def _candidate_map_urls(js_url, js_body):
    out = []
    if js_body:
        for m in _SOURCEMAP_RE.finditer(js_body):
            url = m.group(1).strip()
            if url.startswith("data:"):
                continue
            out.append(urljoin(js_url, url))
    out.append(js_url.split("?")[0] + ".map")
    seen = set()
    result = []
    for u in out:
        if u not in seen:
            seen.add(u)
            result.append(u)
    return result


def fetch_sourcemap(js_url, js_body=None, timeout=10, roe_guard=None):
    verify = _verify_tls()
    for map_url in _candidate_map_urls(js_url, js_body or ""):
        r = _fetch(map_url, timeout, verify, roe_guard)
        if r.get("blocked"):
            return {"error": r["error"]}
        if r.get("status") != 200:
            continue
        body = (r.get("body") or "").strip()
        if not body.startswith("{"):
            continue
        try:
            data = json.loads(body)
        except Exception:
            continue
        if not isinstance(data, dict) or "version" not in data:
            continue
        data["_source_url"] = map_url
        return data
    return None


def extract_from_sourcemap(sourcemap, max_sources=50, max_chars=400000):
    sources = sourcemap.get("sources") or []
    contents = sourcemap.get("sourcesContent") or []
    urls = set()
    paths = set()
    params = set()
    fetch_calls = set()

    joined_chunks = []
    for i, src in enumerate(sources):
        if i >= max_sources:
            break
        if i >= len(contents):
            continue
        text = contents[i] or ""
        if not isinstance(text, str):
            continue
        joined_chunks.append(text[:max_chars])

    joined = "\n".join(joined_chunks)
    for m in _URL_RE.finditer(joined):
        urls.add(m.group(1))
    for m in _PATH_RE.finditer(joined):
        p = m.group(1)
        if p.startswith(("/api", "/v1", "/v2", "/rest", "/graphql")):
            paths.add(p)
    for m in _PARAM_HINT_RE.finditer(joined):
        for name_m in _NAME_RE.finditer(m.group(1)):
            params.add(name_m.group(1))
    for m in _FETCH_RE.finditer(joined):
        v = m.group(1)
        if v.startswith("/"):
            paths.add(v)
        fetch_calls.add(v)
    for m in _PICK_RE.finditer(joined):
        inner = m.group(1)
        for name_m in _NAME_RE.finditer(inner):
            params.add(name_m.group(1))

    return {
        "source_count": len(sources),
        "sources_parsed": len(joined_chunks),
        "urls": sorted(urls)[:100],
        "paths": sorted(paths)[:100],
        "params": sorted(params)[:100],
        "fetch_calls": sorted(fetch_calls)[:50],
    }


def mine(js_urls, roe_guard=None, timeout=10, max_maps=20):
    results = []
    errors = []
    for js_url in js_urls[:max_maps]:
        if not js_url.startswith(("http://", "https://")):
            continue
        sm = fetch_sourcemap(js_url, timeout=timeout, roe_guard=roe_guard)
        if sm is None:
            continue
        if sm.get("error"):
            errors.append({"url": js_url, "error": sm["error"]})
            continue
        extracted = extract_from_sourcemap(sm)
        extracted["js_url"] = js_url
        extracted["map_url"] = sm.get("_source_url")
        results.append(extracted)
    return {"maps_found": results, "errors": errors}


__all__ = ["fetch_sourcemap", "extract_from_sourcemap", "mine"]
