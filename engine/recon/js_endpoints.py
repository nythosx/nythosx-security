from __future__ import annotations

import hashlib
import re
import sys
import uuid
from urllib.parse import urljoin, urlparse

from .. import http as _http


_SCRIPT_SRC_RE = re.compile(
    r"""<(?:script|link)[^>]+(?:src|href)\s*=\s*["']([^"']+?\.(?:js|mjs))["']""",
    re.I,
)
_MODULEPRELOAD_RE = re.compile(
    r"""["']([^"']+?\.(?:js|mjs))["']""",
    re.I,
)
_PATH_RE = re.compile(r"""["'`](/(?:api|rest|graphql|v\d|admin|internal|auth|oauth)[\w\-./]{0,160})["'`]""", re.I)
_GENERIC_PATH_RE = re.compile(r"""["'`](/[a-z][\w\-]{1,40}(?:/[\w\-.:${}]{1,40}){0,6})["'`]""", re.I)
_ABS_URL_RE = re.compile(r"""["'`](https?://[\w\-.]+(?::\d+)?/[\w\-./?=&%#:]{0,200})["'`]""")
_FETCH_RE = re.compile(
    r"""(?:fetch|axios(?:\.(?:get|post|put|delete|patch))?|\$fetch|useFetch|request)\s*\(\s*["'`]([^"'`]+)["'`]""",
    re.I,
)

_IGNORE_EXT = (".css", ".png", ".jpg", ".jpeg", ".svg", ".gif", ".webp",
               ".woff", ".woff2", ".ttf", ".ico", ".map", ".json.map")
_IGNORE_HOST_HINT = ("w3.org", "schema.org", "reactjs.org", "reactrouter.com",
                     "googletagmanager.com", "github.com", "cloudflare.com",
                     "localhost", "127.0.0.1", "example.com")


def _same_host(u, host):
    try:
        return urlparse(u).hostname == host
    except Exception:
        return False


def _clean(path):
    path = path.strip()
    if any(h in path for h in _IGNORE_HOST_HINT):
        return None
    if path.lower().endswith(_IGNORE_EXT):
        return None
    if "${" in path or path.endswith("/"):
        path = re.sub(r"\$\{[^}]*\}", "{id}", path)
    return path or None


def _fetch(url, headers=None):
    try:
        r = _http.get(url, headers=headers or {})
        return getattr(r, "status_code", None), (getattr(r, "text", "") or "")
    except Exception as e:
        return None, f"__ERROR__{type(e).__name__}: {e}"


def extract_from_js(text, base_url):
    host = urlparse(base_url).hostname
    paths = set()
    for rx in (_PATH_RE, _GENERIC_PATH_RE):
        for m in rx.findall(text):
            c = _clean(m)
            if c:
                paths.add(c)
    for m in _FETCH_RE.findall(text):
        if m.startswith("/"):
            c = _clean(m)
            if c:
                paths.add(c)
        elif m.startswith("http") and _same_host(m, host):
            p = urlparse(m).path
            c = _clean(p)
            if c:
                paths.add(c)
    abs_urls = set()
    for m in _ABS_URL_RE.findall(text):
        if _same_host(m, host) and not m.lower().endswith(_IGNORE_EXT):
            abs_urls.add(m)
    return paths, abs_urls


def find_bundles(html, base_url):
    bundles = []
    seen = set()
    for m in _SCRIPT_SRC_RE.findall(html):
        u = urljoin(base_url, m)
        if u not in seen:
            seen.add(u)
            bundles.append(u)
    for m in _MODULEPRELOAD_RE.findall(html):
        if m.lower().endswith((".js", ".mjs")) and (m[:1] in ("/", ".") or m.startswith("http")):
            u = urljoin(base_url, m)
            if u not in seen:
                seen.add(u)
                bundles.append(u)
    return bundles


def soft_404_baseline(base_url, headers=None):
    probe = urljoin(base_url.rstrip("/") + "/", "zzz-" + uuid.uuid4().hex[:12])
    status, body = _fetch(probe, headers=headers)
    h = hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()[:16] if body else ""
    return {"status": status, "len": len(body or ""), "hash": h, "probe_url": probe}


def discover(base_url, headers=None, max_bundles=12):
    base_url = base_url.rstrip("/")
    result = {
        "base_url": base_url,
        "bundles": [],
        "paths": [],
        "abs_urls": [],
        "soft_404": None,
        "errors": [],
    }
    status, html = _fetch(base_url + "/", headers=headers)
    if html.startswith("__ERROR__"):
        result["errors"].append(f"homepage: {html[9:]}")
        return result
    result["soft_404"] = soft_404_baseline(base_url, headers=headers)
    bundles = find_bundles(html, base_url)[:max_bundles]
    result["bundles"] = bundles
    all_paths = set()
    all_abs = set()
    hp, ha = extract_from_js(html, base_url)
    all_paths |= hp
    all_abs |= ha
    for b in bundles:
        st, body = _fetch(b, headers=headers)
        if body.startswith("__ERROR__"):
            result["errors"].append(f"{b}: {body[9:]}")
            continue
        p, a = extract_from_js(body, base_url)
        all_paths |= p
        all_abs |= a
    result["paths"] = sorted(all_paths)
    result["abs_urls"] = sorted(all_abs)
    return result


def probe_routes(base_url, paths, headers=None):
    base_url = base_url.rstrip("/")
    baseline = soft_404_baseline(base_url, headers=headers)
    live = []
    for p in paths:
        url = urljoin(base_url + "/", p.lstrip("/"))
        status, body = _fetch(url, headers=headers)
        if body.startswith("__ERROR__"):
            continue
        blen = len(body or "")
        bhash = hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()[:16] if body else ""
        is_soft = (status == baseline["status"]
                   and (bhash == baseline["hash"] or blen == baseline["len"]))
        real = (status is not None and status not in (404,) and not is_soft)
        live.append({
            "path": p,
            "url": url,
            "status": status,
            "len": blen,
            "soft_404": is_soft,
            "real": real,
            "body_preview": (body or "")[:160],
        })
    return {"baseline": baseline, "routes": live}


def _main(argv):
    if not argv:
        print("usage: python -m engine.recon.js_endpoints <base_url> [--probe]")
        return 2
    base = argv[0]
    do_probe = "--probe" in argv
    res = discover(base)
    print(f"base_url : {res['base_url']}")
    print(f"bundles  : {len(res['bundles'])}")
    for b in res["bundles"]:
        print(f"    {b}")
    if res["soft_404"]:
        s = res["soft_404"]
        print(f"soft_404 : status={s['status']} len={s['len']} hash={s['hash']}")
    print(f"paths    : {len(res['paths'])}")
    for p in res["paths"]:
        print(f"    {p}")
    if res["abs_urls"]:
        print(f"abs_urls : {len(res['abs_urls'])}")
        for u in res["abs_urls"]:
            print(f"    {u}")
    if res["errors"]:
        print("errors   :")
        for e in res["errors"]:
            print(f"    {e}")
    if do_probe and res["paths"]:
        print("\n--- probing discovered routes ---")
        pr = probe_routes(base, res["paths"])
        b = pr["baseline"]
        print(f"baseline : status={b['status']} len={b['len']}")
        for r in pr["routes"]:
            tag = "REAL" if r["real"] else ("soft404" if r["soft_404"] else "---")
            print(f"  [{str(r['status']):>4}] {tag:<7} len={r['len']:<6} {r['path']}")
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
