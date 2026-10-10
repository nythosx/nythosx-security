import re
import time
from urllib.parse import urljoin, urlparse
import httpx
from bs4 import BeautifulSoup
from . import adapter_matcher
from . import progress


def fetch(url, headers=None, timeout=15, method="GET", json_body=None, data=None,
          follow=True):
    try:
        with httpx.Client(timeout=timeout, follow_redirects=follow, verify=False) as c:
            return c.request(method, url, headers=headers or {}, json=json_body, data=data)
    except Exception:
        return None


def is_spa_redirect(r):
    if r is None:
        return False
    if r.status_code not in (301, 302, 303, 307, 308):
        return False
    text = r.text or ""
    if "http-equiv=\"refresh\"" in text and "/login" in text:
        return True
    loc = r.headers.get("Location", "")
    return loc in ("/login", "/signin")


def is_html(r):
    if r is None:
        return False
    ct = r.headers.get("Content-Type", "").lower()
    if "text/html" in ct:
        return True
    text = (r.text or "").lstrip().lower()
    return text.startswith("<!doctype") or text.startswith("<html")


def is_json_response(r):
    if r is None:
        return False
    ct = r.headers.get("Content-Type", "").lower()
    if "application/json" in ct:
        return True
    text = (r.text or "").lstrip()
    if text.startswith("{") or text.startswith("["):
        try:
            import json
            json.loads(text)
            return True
        except Exception:
            return False
    return False


def get_first_html(base_url):
    candidates = ["/", "/login", "/signin", "/dashboard", "/home", "/index.html"]
    for path in candidates:
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        r = fetch(url, follow=True)
        if r and r.status_code == 200 and is_html(r):
            return url, r
    return None, None


def detect_framework(url):
    progress.activity("Fingerprinting framework (headers, cookies, markup)",
                      stage="framework")
    match_result = adapter_matcher.match(url)
    adapter = match_result["adapter"]
    obs = match_result.get("observations")
    return {
        "framework": adapter.get("id", "generic"),
        "name": adapter.get("name", "Generic"),
        "adapter": adapter,
        "score": match_result["score"],
        "evidence": match_result["evidence"],
        "alternatives": match_result.get("alternatives", []),
        "landing_url": (obs or {}).get("url", url),
        "server": ((obs or {}).get("headers") or {}).get("server", ""),
        "powered_by": ((obs or {}).get("headers") or {}).get("x-powered-by", ""),
        "observations": obs,
    }


def extract_js_urls(url):
    landing, r = get_first_html(url)
    if not r:
        r = fetch(url, follow=True)
        if not r:
            return []
    try:
        soup = BeautifulSoup(r.text or "", "lxml")
    except Exception:
        return []
    base = str(r.url)
    urls = []
    for s in soup.find_all("script"):
        src = s.get("src")
        if src and not src.startswith("data:"):
            urls.append(urljoin(base, src))
    for link in soup.find_all("link"):
        rel = link.get("rel")
        href = link.get("href")
        as_attr = link.get("as")
        if not href:
            continue
        rels = [x.lower() for x in rel] if isinstance(rel, list) else [str(rel).lower()]
        if "modulepreload" in rels or ("preload" in rels and as_attr == "script"):
            urls.append(urljoin(base, href))
    seen = set()
    out = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def fetch_js_text(url, max_size=2_000_000):
    r = fetch(url, timeout=20, follow=True)
    if not r or r.status_code != 200:
        return ""
    text = r.text or ""
    return text[:max_size] if len(text) > max_size else text


def extract_api_paths_from_js(js_text, adapter):
    hints = adapter.get("api_hints") or ["api", "auth", "login", "token", "user",
                                           "account", "session", "me", "profile"]
    hint_re = "|".join(re.escape(h) for h in hints)
    path_re = re.compile(
        rf"""["'`](/[\w\-\./]*(?:{hint_re})[\w\-\./]*)["'`]""",
        re.IGNORECASE,
    )
    generic_re = re.compile(r"""["'`](/api/[\w\-\./]+)["'`]""")
    fetch_re = re.compile(r"""\$fetch\s*\(\s*["'`]([^"'`]+)["'`]""")
    axios_re = re.compile(r"""axios\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*["'`]([^"'`]+)["'`]""")
    use_fetch_re = re.compile(r"""useFetch\s*\(\s*["'`]([^"'`]+)["'`]""")

    paths = set()
    for pattern in (path_re, generic_re):
        for m in pattern.finditer(js_text):
            paths.add(m.group(1))
    for pattern in (fetch_re, axios_re, use_fetch_re):
        for m in pattern.finditer(js_text):
            v = m.group(1)
            if v.startswith("/"):
                paths.add(v)

    cleaned = []
    for p in paths:
        p = p.split("?")[0]
        if "${" in p or "`" in p:
            continue
        if len(p) < 200 and " " not in p and "{" not in p:
            cleaned.append(p)
    return sorted(set(cleaned))


_CHUNK_RE = re.compile(r"""["'`]([\w\-./]+?\.m?js)(?:\?[\w=&.]*)?["'`]""")


def _same_host(u1, u2):
    return urlparse(u1).netloc == urlparse(u2).netloc


def extract_chunk_urls(js_text, bundle_url, root_url):
    refs = set()
    for m in _CHUNK_RE.finditer(js_text):
        name = m.group(1)
        if name.startswith(("http://", "https://")):
            if not _same_host(name, root_url):
                continue
            resolved = name
        else:
            resolved = urljoin(bundle_url, name)
        if _same_host(resolved, root_url):
            refs.add(resolved.split("?")[0])
    return refs


def crawl_js_for_paths(base_url, js_urls, adapter, max_bundles=40,
                       recursive=True, max_rounds=3):
    all_paths = set()
    fetched = []
    visited = set()
    queue = list(js_urls)
    rounds = 0
    while queue and len(fetched) < max_bundles:
        next_queue = []
        for u in queue:
            if len(fetched) >= max_bundles:
                break
            if u in visited:
                continue
            visited.add(u)
            progress.activity(f"Fetching JS bundle {u.rsplit('/', 1)[-1][:48]}",
                              stage="discovery", i=len(fetched) + 1, n=max_bundles)
            text = fetch_js_text(u)
            if not text:
                continue
            fetched.append({"url": u, "size": len(text)})
            for p in extract_api_paths_from_js(text, adapter):
                all_paths.add(p)
            if recursive:
                for c in extract_chunk_urls(text, u, base_url):
                    if c not in visited:
                        next_queue.append(c)
        rounds += 1
        if not recursive or rounds >= max_rounds:
            break
        queue = next_queue
    return sorted(all_paths), fetched


def _extract_token(body, token_paths):
    import json
    try:
        data = json.loads(body)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    for path in token_paths or ["token", "access_token", "data.token"]:
        parts = path.split(".")
        cur = data
        for p in parts:
            if isinstance(cur, dict):
                cur = cur.get(p)
            else:
                cur = None
                break
        if isinstance(cur, str) and len(cur) > 15:
            return {"path": path, "token": cur}
    return None


def find_login_endpoint(base_url, adapter, discovered_paths=None, username="", password=""):
    auth_cfg = adapter.get("auth", {}) or {}
    candidates = list(auth_cfg.get("login_paths") or [
        "/api/login", "/api/auth/login", "/login", "/auth/login",
    ])
    field_candidates = list(auth_cfg.get("login_fields") or [
        "email", "username", "identifier",
    ])
    token_paths = auth_cfg.get("token_paths") or ["token", "access_token", "data.token"]

    if discovered_paths:
        for p in discovered_paths:
            pl = p.lower()
            if any(k in pl for k in ("login", "signin", "auth", "token", "session")):
                if p not in candidates:
                    candidates.insert(0, p)

    probe_delay_ms = int((auth_cfg.get("probe_delay_ms") or 200))
    best = None
    for pidx, path in enumerate(candidates, 1):
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        progress.activity(f"Trying login endpoint {path}",
                          stage="login", i=pidx, n=len(candidates))
        for field in field_candidates:
            for ptype in ("json", "form"):
                if probe_delay_ms > 0:
                    time.sleep(probe_delay_ms / 1000.0)
                payload = {field: username, "password": password}
                if ptype == "json":
                    r = fetch(url, method="POST", json_body=payload, follow=False)
                else:
                    r = fetch(url, method="POST", data=payload, follow=False)
                if not r:
                    continue
                if is_spa_redirect(r):
                    continue
                if is_html(r):
                    continue
                status = r.status_code
                if status in (401, 403):
                    if best is None:
                        best = {"url": url, "path": path, "fields": payload,
                                "type": ptype, "status": status,
                                "note": "endpoint exists, credentials rejected"}
                    continue
                if status in (400, 422):
                    return {"url": url, "path": path, "fields": payload,
                            "type": ptype, "status": status,
                            "note": "endpoint exists, field mismatch"}
                if status in (200, 201) and is_json_response(r):
                    tok = _extract_token(r.text or "", token_paths)
                    return {"url": url, "path": path, "fields": payload,
                            "type": ptype, "status": status, "note": "success",
                            "token": tok, "raw": (r.text or "")[:500],
                            "cookies": dict(r.cookies)}
    return best

def extract_websocket_urls(url_or_html):
    import re as _re
    text = url_or_html or ""
    base = ""
    if isinstance(text, str) and text.startswith(("http://", "https://")):
        base = text
        r = fetch(base, follow=True)
        if r is not None:
            text = r.text or ""
    if not isinstance(text, str):
        text = ""
    pattern = _re.compile(
        r'''["'`]((?:ws|wss)://[^"'`\s<>]+)["'`]''',
        _re.IGNORECASE,
    )
    found = set()
    for m in pattern.finditer(text):
        found.add(m.group(1).rstrip(".,;)"))
    if base:
        from urllib.parse import urljoin as _urljoin
        return sorted(_urljoin(base, u) if u.startswith("ws") else u for u in found)
    return sorted(found)
