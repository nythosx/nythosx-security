import re
import time
from urllib.parse import urljoin, urlparse
import httpx
from bs4 import BeautifulSoup
from . import adapter_matcher
from . import progress
from . import http as _http
from urllib.parse import urljoin as _urljoin


from .budget import is_dead as _budget_dead


def fetch(url, headers=None, timeout=15, method="GET", json_body=None, data=None,
          follow=True):
    try:
        with _http.Client(timeout=timeout, follow_redirects=follow, verify=False) as c:
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



_PARAM_OBJ_RE = re.compile(
    r"""(?:axios|client|api|http|\$fetch|useFetch)\s*
        (?:\.\s*\w+\s*)?\(\s*
        ["'`]([^"'`]+)["'`]\s*,\s*\{[^}]*?params\s*:\s*\{([^}]*)\}""",
    re.S | re.X,
)

_PARAM_QUERY_RE = re.compile(r"""["'`]([^"'`\s?]+)\?([^"'`\s]+)["'`]""")

_PARAM_PATH_RE = re.compile(
    r"""["'`]([^"'`\s]*\{([a-zA-Z_][a-zA-Z0-9_]*)\}[^"'`\s]*)["'`]"""
)

_PARAM_NAME_RE = re.compile(r"""([a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]""")


def _split_query_params(qs):
    names = []
    for part in qs.split("&"):
        if not part:
            continue
        name = part.split("=", 1)[0].strip()
        if name:
            names.append(name)
    return names


def extract_api_params_from_js(js_text):
    """Return {path: {"query": [...], "path": [...]}} parsed from JS."""
    out = {}

    def _add(path, kind, names):
        if not path or not path.startswith("/"):
            return
        if "${" in path or "`" in path:
            return
        entry = out.setdefault(path, {"query": [], "path": []})
        for n in names:
            if n and n not in entry[kind]:
                entry[kind].append(n)

    for m in _PARAM_OBJ_RE.finditer(js_text):
        path = m.group(1).split("?")[0]
        names = _PARAM_NAME_RE.findall(m.group(2) or "")
        _add(path, "query", names)

    for m in _PARAM_QUERY_RE.finditer(js_text):
        path = m.group(1)
        _add(path, "query", _split_query_params(m.group(2)))

    for m in _PARAM_PATH_RE.finditer(js_text):
        _add(m.group(1), "path", [m.group(2)])

    return out


def crawl_js_for_paths_and_params(base_url, js_urls, adapter,
                                  max_bundles=40, recursive=True,
                                  max_rounds=3):
    """Like crawl_js_for_paths but also returns a {path: {query, path}} map."""
    paths, fetched = crawl_js_for_paths(
        base_url, js_urls, adapter,
        max_bundles=max_bundles, recursive=recursive, max_rounds=max_rounds,
    )
    params = {}
    for entry in fetched:
        text = fetch_js_text(entry["url"])
        if not text:
            continue
        for path, spec in extract_api_params_from_js(text).items():
            cur = params.setdefault(path, {"query": [], "path": []})
            for n in spec["query"]:
                if n not in cur["query"]:
                    cur["query"].append(n)
            for n in spec["path"]:
                if n not in cur["path"]:
                    cur["path"].append(n)
    return paths, params, fetched


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


_ID_LEAF_RE = re.compile(r'^(?:[0-9]+|[0-9a-fA-F]{8,}|[0-9a-fA-F-]{20,})$')

_MISS_VERDICTS = ("not_found", "catch_all", "unreachable")
_FAMILY_SKIP_AFTER = 3


def _path_family(path):
    # API-ish paths are where the real, heterogeneous endpoints live (one
    # missing /api/v1/x says nothing about /api/v1/y), so each gets its own
    # family and is never pruned. Everything else (e.g. /admin/*, /_next/*)
    # is grouped by its first segment — those tend to exist or not exist as
    # a whole namespace, so repeated misses there are a real signal.
    pl = path.lower()
    if pl.startswith(("/api", "/v1", "/v2", "/rest")) or "graphql" in pl:
        return path
    parts = [p for p in path.strip("/").split("/") if p]
    return parts[0] if parts else "/"


def _looks_like_id_leaf(path):
    leaf = path.rstrip("/").rsplit("/", 1)[-1]
    return bool(_ID_LEAF_RE.match(leaf))


def _probe_one(origin, path, neg, timeout):
    url = urljoin(origin + "/", path.lstrip("/"))
    r = fetch(url, timeout=timeout, follow=True)
    if r is None:
        return {"path": path, "url": url, "status": None, "verdict": "unreachable"}
    body = r.text or ""
    ct = r.headers.get("Content-Type", "").lower()
    json_resp = is_json_response(r)
    catch_all = (
        neg is not None and r.status_code == neg["status"]
        and "text/html" in ct and not json_resp
        and abs(len(body) - neg["size"]) <= max(80, int(neg["size"] * 0.15))
    )
    if r.status_code == 404:
        verdict = "not_found"
    elif catch_all:
        verdict = "catch_all"
    elif json_resp:
        verdict = "live_api"
    elif r.status_code in (401, 403):
        verdict = "auth_required"
    elif 200 <= r.status_code < 300:
        verdict = "exists"
    else:
        verdict = "other"
    return {"path": path, "url": url, "status": r.status_code,
            "verdict": verdict, "json": json_resp, "size": len(body)}


async def probe_paths_async(base_url, paths, limit=80, timeout=8):
    import asyncio
    from urllib.parse import urlparse as _urlparse
    from .http_async import AsyncClient

    parsed = _urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    neg = None
    import random
    import string as _string
    rand_path = ("/zzz-" + "".join(
        random.choices(_string.ascii_lowercase + _string.digits, k=20)))
    try:
        async with AsyncClient(timeout=timeout, follow_redirects=True) as c:
            r = await c.get(origin + rand_path)
        body = r.text or ""
        neg = {
            "status": r.status_code,
            "is_html": "text/html" in r.headers.get("Content-Type", "").lower(),
            "size": len(body),
        }
    except Exception as e:
        import sys as _sys
        _sys.stderr.write(
            f"[probe_paths_async soft-404] {origin}{rand_path}: "
            f"{type(e).__name__}: {e}\n")
        neg = None

    uniq = sorted(set(p for p in paths if p))[:limit]
    total = len(uniq)
    family_misses = {}
    skipped_families = set()
    results = []
    sem = asyncio.Semaphore(20)

    async def _one(client, path):
        async with sem:
            url = _urljoin(origin + "/", path.lstrip("/"))
            try:
                r = await client.get(url)
            except Exception as e:
                import sys as _sys
                _sys.stderr.write(
                    f"[probe_paths_async] {url}: {type(e).__name__}: {e}\n")
                return {"path": path, "url": url,
                        "status": None, "verdict": "unreachable",
                        "error": f"{type(e).__name__}: {e}"}
            body = r.text or ""
            ct = r.headers.get("Content-Type", "").lower()
            json_resp = is_json_response(r)
            catch_all = (
                neg is not None and r.status_code == neg["status"]
                and "text/html" in ct and not json_resp
                and abs(len(body) - neg["size"]) <= max(80, int(neg["size"] * 0.15))
            )
            if r.status_code == 404:
                verdict = "not_found"
            elif catch_all:
                verdict = "catch_all"
            elif json_resp:
                verdict = "live_api"
            elif r.status_code in (401, 403):
                verdict = "auth_required"
            elif 200 <= r.status_code < 300:
                verdict = "exists"
            else:
                verdict = "other"
            return {"path": path, "url": str(r.url), "status": r.status_code,
                    "verdict": verdict, "json": json_resp, "size": len(body)}

    try:
        async with AsyncClient(timeout=timeout, follow_redirects=True) as c:
            tasks = []
            for path in uniq:
                fam = _path_family(path)
                if family_misses.get(fam, 0) >= _FAMILY_SKIP_AFTER:
                    if fam not in skipped_families:
                        skipped_families.add(fam)
                    results.append({"path": path,
                                    "url": _urljoin(origin + "/", path.lstrip("/")),
                                    "status": None, "verdict": "skipped",
                                    "reason": f"{_FAMILY_SKIP_AFTER} misses under /{fam}"})
                    continue
                tasks.append((path, _one(c, path)))
            if tasks:
                entries = await asyncio.gather(
                    *[t for _, t in tasks], return_exceptions=True)
                for (path, _), entry in zip(tasks, entries):
                    if isinstance(entry, BaseException):
                        entry = {"path": path,
                                 "url": _urljoin(origin + "/", path.lstrip("/")),
                                 "status": None, "verdict": "unreachable",
                                 "error": f"{type(entry).__name__}: {entry}"}
                    fam = _path_family(path)
                    family_misses[fam] = (
                        family_misses.get(fam, 0) + 1
                        if entry.get("verdict") in _MISS_VERDICTS else 0
                    )
                    results.append(entry)
                    try:
                        progress.emit(progress.active_job(), "endpoint_probe", entry)
                    except Exception:
                        pass
    except Exception as e:
        import sys as _sys
        _sys.stderr.write(
            f"[probe_paths_async] {type(e).__name__}: {e}\n")
    return results


def probe_paths(base_url, paths, limit=80, timeout=8):
    from .http_async import run_sync
    return run_sync(probe_paths_async(base_url, paths, limit=limit, timeout=timeout))


def _probe_paths_sync_original(base_url, paths, limit=80, timeout=8):
    """HTTP-probe each JS-extracted candidate path for real.

    extract_api_paths_from_js only finds *string literals* that look like
    API paths — plenty of those are webpack chunk names or dead code, not
    real backend routes. This turns each candidate into a verified result
    (status, verdict) instead of a guess, and is itself subject to ROE /
    rate-limit / budget enforcement via discovery.fetch -> http.Client.

    Two heuristics make this cheaper and more useful than a flat probe:
    - Family pruning: paths are grouped by their first two segments
      (e.g. "/admin/login" -> "admin/login", "/api/v1/x" -> "api/v1"). After
      _FAMILY_SKIP_AFTER consecutive misses (404 / catch-all / unreachable)
      in the same family, the rest of that family is skipped without an
      HTTP request — one bad guess under /admin/* makes the next ones
      unlikely too, and this keeps the request budget for paths that still
      have a real chance.
    - ID follow-up: a path that resolves (200/JSON, not already ID-shaped)
      gets one extra probe at "<path>/1" to check for a nested detail route
      (list endpoint -> single-resource endpoint), which is exactly the
      shape IDOR-style findings need a real URL for.
    """
    import random
    import string as _string

    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    neg = None
    rand_path = ("/zzz-" + "".join(
        random.choices(_string.ascii_lowercase + _string.digits, k=20)))
    try:
        r = fetch(origin + rand_path, timeout=timeout)
    except Exception:
        r = None
    if r is not None:
        body = r.text or ""
        neg = {
            "status": r.status_code,
            "is_html": "text/html" in r.headers.get("Content-Type", "").lower(),
            "size": len(body),
        }

    uniq = sorted(set(p for p in paths if p))[:limit]
    total = len(uniq)
    results = []
    family_misses = {}
    skipped_families = set()

    def _emit(entry):
        results.append(entry)
        try:
            progress.emit(progress.active_job(), "endpoint_probe", entry)
        except Exception:
            pass

    for i, path in enumerate(uniq, 1):
        if _budget_dead():
            results.append({"path": path,
                            "url": urljoin(origin + "/", path.lstrip("/")),
                            "status": None, "verdict": "budget_exhausted",
                            "reason": "duration or request budget exhausted"})
            continue
        fam = _path_family(path)
        if family_misses.get(fam, 0) >= _FAMILY_SKIP_AFTER:
            if fam not in skipped_families:
                skipped_families.add(fam)
                progress.activity(
                    f"No luck under /{fam} after {_FAMILY_SKIP_AFTER} tries "
                    "— skipping similar paths", stage="discovery", i=i, n=total)
            results.append({"path": path, "url": urljoin(origin + "/", path.lstrip("/")),
                             "status": None, "verdict": "skipped",
                             "reason": f"{_FAMILY_SKIP_AFTER} consecutive misses under /{fam}"})
            continue
        progress.activity(f"Probing endpoint {path}", stage="discovery", i=i, n=total)
        entry = _probe_one(origin, path, neg, timeout)
        family_misses[fam] = (family_misses.get(fam, 0) + 1
                              if entry["verdict"] in _MISS_VERDICTS else 0)
        _emit(entry)
        if entry["verdict"] in ("live_api", "exists") and not _looks_like_id_leaf(path):
            id_path = path.rstrip("/") + "/1"
            progress.activity(f"{path} looks real — trying {id_path} for a detail route",
                              stage="discovery", i=i, n=total)
            id_entry = _probe_one(origin, id_path, neg, timeout)
            id_entry["id_guess_for"] = path
            _emit(id_entry)
    return results


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


_DEFAULT_LOGIN_PATHS = [
    "/api/login", "/api/auth/login", "/api/v1/login", "/api/v1/auth/login",
    "/login", "/signin", "/sign-in", "/sign_in",
    "/auth/login", "/auth/signin", "/account/login", "/user/login",
    "/users/sign_in", "/wp-login.php", "/admin/login", "/session/new",
    "/session", "/sessions",
]

_LOGIN_LINK_RE = re.compile(r"\b(log[\s_-]?in|sign[\s_-]?in)\b", re.I)
_LOGOUT_WORD_RE = re.compile(r"\b(log[\s_-]?out|sign[\s_-]?out)\b", re.I)


def _find_login_links(base_url, timeout=8):
    """Follow the site's own navigation to its login page instead of only
    guessing path strings — a real "Sign in" link/button is a stronger
    signal than any fixed wordlist, and works on any target's own layout."""
    r = fetch(base_url, timeout=timeout, follow=True)
    if not r or not is_html(r):
        return []
    try:
        soup = BeautifulSoup(r.text or "", "lxml")
    except Exception:
        return []
    base = str(r.url)
    found = []
    seen = set()
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if href.startswith(("mailto:", "tel:", "javascript:", "#")):
            continue
        text = a.get_text(" ", strip=True) or ""
        if _LOGOUT_WORD_RE.search(text) or _LOGOUT_WORD_RE.search(href):
            continue
        if _LOGIN_LINK_RE.search(text) or _LOGIN_LINK_RE.search(href):
            abs_url = urljoin(base, href)
            if abs_url not in seen:
                seen.add(abs_url)
                found.append(abs_url)
    return found


def _extract_login_form(html, page_url):
    """Parse a real <form> containing a password field instead of guessing
    field names — picks up the actual field names and any hidden/CSRF
    tokens the server expects, generically, on whatever markup the target
    happens to use."""
    try:
        soup = BeautifulSoup(html or "", "lxml")
    except Exception:
        return None
    for form in soup.find_all("form"):
        pwd = form.find("input", attrs={"type": re.compile("^password$", re.I)})
        if not pwd or not pwd.get("name"):
            continue
        hidden = {}
        user_field = None
        for inp in form.find_all("input"):
            name = inp.get("name")
            if not name:
                continue
            itype = (inp.get("type") or "text").lower()
            if itype == "password":
                continue
            if itype == "hidden":
                hidden[name] = inp.get("value", "")
            elif user_field is None and itype in ("text", "email", "tel"):
                user_field = name
        if not user_field:
            continue
        action = urljoin(page_url, form.get("action") or page_url)
        method = (form.get("method") or "POST").upper()
        return {"action": action, "method": method,
                "username_field": user_field, "password_field": pwd["name"],
                "hidden": hidden}
    return None


def _try_html_login(page_url, username, password, timeout=8, verify=False):
    """GET the candidate page, parse its real login form (if any), then POST
    to it reusing the SAME client so any session/CSRF cookie set on the GET
    rides along on the POST — two separate short-lived clients would drop
    that cookie and make every CSRF-protected form look broken."""
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=True) as c:
            get_r = c.get(page_url)
            if "text/html" not in get_r.headers.get("content-type", "").lower():
                return None
            form = _extract_login_form(get_r.text or "", str(get_r.url))
            if not form:
                return None
            payload = dict(form["hidden"])
            payload[form["username_field"]] = username
            payload[form["password_field"]] = password
            post_r = c.request(form["method"], form["action"], data=payload,
                               headers={"Referer": str(get_r.url)},
                               follow_redirects=False)
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}

    location = post_r.headers.get("location", "")
    still_has_form = _extract_login_form(post_r.text or "", str(post_r.url)) is not None
    redirected_away = (post_r.status_code in (301, 302, 303, 307, 308)
                      and not _LOGIN_LINK_RE.search(location))
    cookies = dict(post_r.cookies)
    success = bool(cookies) and (redirected_away or not still_has_form)
    return {
        "url": form["action"], "path": urlparse(form["action"]).path,
        "fields": {form["username_field"]: username,
                  "password_field": form["password_field"]},
        "type": "html_form", "status": post_r.status_code,
        "note": "success" if success else "endpoint exists, credentials rejected",
        "token": None, "cookies": cookies, "raw": (post_r.text or "")[:500],
    }


def find_login_endpoint(base_url, adapter, discovered_paths=None, username="", password=""):
    auth_cfg = adapter.get("auth", {}) or {}
    candidates = list(auth_cfg.get("login_paths") or _DEFAULT_LOGIN_PATHS)
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

    for link in _find_login_links(base_url):
        if link not in candidates:
            candidates.insert(0, link)

    probe_delay_ms = int((auth_cfg.get("probe_delay_ms") or 200))
    best = None
    for pidx, path in enumerate(candidates, 1):
        url = path if path.startswith(("http://", "https://")) else \
            urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        progress.activity(f"Trying login endpoint {path}",
                          stage="login", i=pidx, n=len(candidates))

        html_result = _try_html_login(url, username, password, timeout=8)
        if html_result and not html_result.get("error"):
            if html_result["note"] == "success":
                return html_result
            if best is None:
                best = html_result

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


_ROBOTS_DISALLOW_RE = re.compile(r"^\s*Disallow:\s*(\S+)", re.M | re.I)
_SITEMAP_LOC_RE = re.compile(r"<loc>([^<]+)</loc>", re.I)


def extract_from_robots(base_url, timeout=8):
    """Return paths discovered in robots.txt Disallow lines and sitemap.xml."""
    from urllib.parse import urlparse as _urlparse
    out = set()
    robots_url = urljoin(base_url.rstrip("/") + "/", "robots.txt")
    r = fetch(robots_url, timeout=timeout, follow=True)
    if r is not None and r.status_code == 200:
        for m in _ROBOTS_DISALLOW_RE.finditer(r.text or ""):
            p = m.group(1).strip()
            if p and p != "/" and not p.startswith(("http://", "https://")):
                out.add(p)
    sitemap_url = urljoin(base_url.rstrip("/") + "/", "sitemap.xml")
    r = fetch(sitemap_url, timeout=timeout, follow=True)
    if r is not None and r.status_code == 200:
        for m in _SITEMAP_LOC_RE.finditer(r.text or ""):
            p = _urlparse(m.group(1)).path
            if p and p != "/":
                out.add(p)
    return sorted(out)


def extract_all_forms(url, timeout=8):
    """Return every HTML form on the page as a structured dict.

    Unlike _extract_login_form (which is login-specific), this returns all
    forms so the fuzzer and mass-assignment probes can use real fields
    instead of guessing.
    """
    r = fetch(url, timeout=timeout, follow=True)
    if r is None or not is_html(r):
        return []
    try:
        soup = BeautifulSoup(r.text or "", "lxml")
    except Exception:
        return []
    base = str(r.url)
    out = []
    for form in soup.find_all("form"):
        action = form.get("action") or ""
        method = (form.get("method") or "GET").upper()
        action_url = urljoin(base, action) if action else base
        fields = {}
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            itype = (inp.get("type") or "text").lower()
            if itype == "submit":
                continue
            fields[name] = {
                "type": itype,
                "value": inp.get("value", ""),
            }
        if fields:
            out.append({
                "action": action_url,
                "method": method,
                "fields": fields,
            })
    return out
