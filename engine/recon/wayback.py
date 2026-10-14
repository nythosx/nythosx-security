"""Historic URL harvest via Wayback Machine CDX and CommonCrawl.

These are external, public archives — not the scan target — so ROE scope
does not apply here. Same exception class as engine/sca.py (OSV) and
engine/cve_lookup.py (NVD).

What we extract:
  * Distinct paths, prioritised by:
      - looking API-ish (contains /api, /v1, /graphql, etc.)
      - carrying query parameters (historic parameters are gold)
      - containing patterns that hint at sensitive surfaces (admin, debug,
        backup, internal, private, upload, export)
  * Distinct parameter names, which feed the fuzzer.

The CDX response is a JSON array of arrays. The first row is a header.
CommonCrawl returns newline-delimited JSON.
"""
from __future__ import annotations

import json
from collections import Counter
from urllib.parse import urlparse, parse_qs

import httpx

from ..config import load_engine


WAYBACK_CDX = "http://web.archive.org/cdx/search/cdx"
COMMONCRAWL_INDEXES = [
    "CC-MAIN-2024-40",
    "CC-MAIN-2024-33",
    "CC-MAIN-2024-26",
]

_PRIORITY_SUBSTRINGS = [
    "/api", "/v1", "/v2", "/v3", "/graphql", "/gql", "/rest",
    "/admin", "/internal", "/debug", "/backup", "/backups",
    "/private", "/upload", "/export", "/import", "/config",
    "/.env", "/.git", "/swagger", "/openapi",
]


def _cfg():
    try:
        cfg = load_engine() or {}
        return cfg.get("wayback") or {}
    except Exception:
        return {}


def _verify_tls():
    try:
        cfg = load_engine() or {}
        return bool(cfg.get("http", {}).get("verify_tls", True))
    except Exception:
        return True


def _fetch_wayback(domain, limit, timeout):
    params = {
        "url": domain,
        "matchType": "domain",
        "output": "json",
        "collapse": "urlkey",
        "limit": str(limit),
        "fl": "original",
    }
    try:
        with httpx.Client(timeout=timeout, verify=_verify_tls()) as c:
            r = c.get(WAYBACK_CDX, params=params)
        if r.status_code != 200:
            return []
        data = r.json()
    except Exception:
        return []
    if not data or len(data) < 2:
        return []
    header = data[0]
    try:
        idx = header.index("original")
    except ValueError:
        idx = 0
    return [row[idx] for row in data[1:] if len(row) > idx]


def _fetch_commoncrawl(domain, index, limit, timeout):
    url = f"http://index.commoncrawl.org/{index}-index"
    params = {"url": f"{domain}/*", "output": "json", "limit": str(limit)}
    try:
        with httpx.Client(timeout=timeout, verify=_verify_tls()) as c:
            r = c.get(url, params=params)
        if r.status_code != 200:
            return []
        out = []
        for line in (r.text or "").splitlines():
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
                u = obj.get("url")
                if u:
                    out.append(u)
            except Exception:
                continue
        return out
    except Exception:
        return []


def _is_priority(path):
    pl = path.lower()
    return any(s in pl for s in _PRIORITY_SUBSTRINGS)


def harvest(domain, limit=3000, timeout=20):
    """Return {paths, params, sources, sample_urls}."""
    cfg = _cfg()
    if cfg.get("enabled") is False:
        return None
    if isinstance(domain, str) and "://" in domain:
        parsed = urlparse(domain)
        domain = parsed.hostname or domain

    all_urls = []
    sources = []
    wb = _fetch_wayback(domain, limit, timeout)
    if wb:
        sources.append(f"wayback:{len(wb)}")
        all_urls.extend(wb)
    if cfg.get("commoncrawl", True):
        for index in COMMONCRAWL_INDEXES:
            cc = _fetch_commoncrawl(domain, index, limit // len(COMMONCRAWL_INDEXES), timeout)
            if cc:
                sources.append(f"{index}:{len(cc)}")
                all_urls.extend(cc)
            if len(all_urls) >= limit * 2:
                break

    if not all_urls:
        return None

    paths = Counter()
    params = Counter()
    for raw in all_urls:
        try:
            p = urlparse(raw)
        except Exception:
            continue
        if not p.path or p.path == "/":
            continue
        paths[p.path] += 1
        for k in parse_qs(p.query).keys():
            params[k] += 1

    ranked = sorted(
        paths.items(),
        key=lambda kv: (-_is_priority(kv[0]), -kv[1], kv[0]),
    )
    top_paths = [p for p, _ in ranked[:200]]
    top_params = [k for k, _ in params.most_common(100)]

    return {
        "domain": domain,
        "sources": sources,
        "total_urls_seen": len(all_urls),
        "paths": top_paths,
        "priority_paths": [p for p in top_paths if _is_priority(p)][:50],
        "params": top_params,
        "sample_urls": all_urls[:20],
    }


__all__ = ["harvest"]
