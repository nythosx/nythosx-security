import re
import json
import random
import string
import hashlib
from urllib.parse import urljoin, urlparse
import httpx

from . import progress
from . import http as _http


COMMON_API_PORTS = [
    443, 8443, 3000, 3001, 3002, 4000, 4001, 5000, 5001, 5173, 5174,
    8000, 8001, 8080, 8081, 9000, 9001, 10000,
]

DEFAULT_SCHEMES = ["https", "http"]
DEFAULT_BASE_PATHS = ["", "/api", "/api/v1", "/api/v2", "/api/latest",
                      "/v1", "/v2", "/rest", "/graphql"]
DEFAULT_CONFIRM_SUBPATHS = ["", "/health", "/healthz", "/status", "/ping", "/version"]


def _cfg(config):
    config = config or {}
    return {
        "prefer_https": config.get("prefer_https", True),
        "schemes": config.get("schemes") or DEFAULT_SCHEMES,
        "base_paths": config.get("base_paths") or DEFAULT_BASE_PATHS,
        "confirm_subpaths": config.get("confirm_subpaths") or DEFAULT_CONFIRM_SUBPATHS,
        "reject_redirect_only": config.get("reject_redirect_only", True),
        "follow_redirects": config.get("follow_redirects", True),
        "timeout": float(config.get("probe_timeout_seconds", 6)),
    }


def _fetch(url, timeout=10, follow=True):
    try:
        with _http.Client(timeout=timeout, follow_redirects=follow, verify=False) as c:
            return c.get(url)
    except Exception:
        return None


def _extract_config_from_html(html, patterns):
    found = []
    for pat in patterns or []:
        try:
            compiled = re.compile(pat)
        except Exception:
            continue
        for m in compiled.finditer(html):
            value = m.group(1) if m.groups() else m.group(0)
            if value and len(value) < 300:
                found.append({"pattern": pat, "value": value})
    return found


def _extract_from_json_script(html, script_id):
    pat = re.compile(
        r'<script[^>]+id="' + re.escape(script_id) + r'"[^>]*>(.*?)</script>',
        re.DOTALL,
    )
    m = pat.search(html)
    if not m:
        return None
    try:
        return json.loads(m.group(1).strip())
    except Exception:
        return None


def _find_urls_in_structure(obj, depth=0, max_depth=8):
    if depth > max_depth:
        return []
    results = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            kl = str(k).lower()
            if isinstance(v, str) and v.startswith(("http://", "https://", "/")):
                if any(h in kl for h in ("api", "url", "base", "endpoint", "host")):
                    results.append({"key": k, "value": v})
            else:
                results.extend(_find_urls_in_structure(v, depth + 1, max_depth))
    elif isinstance(obj, list):
        for item in obj[:50]:
            results.extend(_find_urls_in_structure(item, depth + 1, max_depth))
    return results


def detect_api_base_from_runtime(url, adapter=None):
    r = _fetch(url)
    if r is None or r.status_code != 200:
        return None
    html = r.text or ""
    runtime_cfg = (adapter or {}).get("runtime_config", {}) or {}
    html_patterns = runtime_cfg.get("html_patterns") or [
        r'apiBase\s*[:=]\s*["\']([^"\']+)["\']',
        r'baseURL\s*[:=]\s*["\']([^"\']+)["\']',
        r'apiUrl\s*[:=]\s*["\']([^"\']+)["\']',
        r'API_URL\s*[:=]\s*["\']([^"\']+)["\']',
    ]
    hits = _extract_config_from_html(html, html_patterns)
    if hits:
        for h in hits:
            v = h["value"]
            if v.startswith(("http://", "https://")):
                return {"base": v.rstrip("/"), "source": "html_pattern", "raw": v}
            if v.startswith("/"):
                return {"base": urljoin(str(r.url), v).rstrip("/"),
                        "source": "html_pattern", "raw": v}

    script_ids = runtime_cfg.get("json_scripts") or ["__NUXT_DATA__", "__NEXT_DATA__"]
    for sid in script_ids:
        data = _extract_from_json_script(html, sid)
        if data is None:
            continue
        urls = _find_urls_in_structure(data)
        for entry in urls:
            v = entry.get("value", "")
            if isinstance(v, str) and v.startswith(("http://", "https://")):
                return {"base": v.rstrip("/"), "source": f"json:{sid}.{entry['key']}",
                        "raw": v}
    return None


def _origin_of(url):
    p = urlparse(url)
    host = p.hostname or "localhost"
    netloc = host + (f":{p.port}" if p.port else "")
    return f"{p.scheme or 'https'}://{netloc}"


def soft_404_fingerprint(url, cfg=None):
    cfg = cfg or _cfg(None)
    origin = _origin_of(url)
    rand = "/zzz-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=20)) + "/does-not-exist"
    r = _fetch(origin + rand, timeout=cfg["timeout"], follow=cfg["follow_redirects"])
    if r is None:
        return None
    body = r.text or ""
    ct = r.headers.get("Content-Type", "").lower()
    return {
        "status": r.status_code,
        "is_html": "text/html" in ct,
        "json": _is_json_response(r),
        "size": len(body),
        "body_hash": hashlib.sha256(body.encode("utf-8", "ignore")).hexdigest()[:16],
        "catch_all": r.status_code == 200 and "text/html" in ct and not _is_json_response(r),
    }


def _matches_fingerprint(status, is_html, size, neg):
    if not neg:
        return False
    if neg.get("json"):
        return False
    if status != neg.get("status"):
        return False
    if not (is_html and neg.get("is_html")):
        return False
    nsize = neg.get("size") or 0
    if not nsize:
        return True
    return abs(size - nsize) <= max(80, int(nsize * 0.15))


def _is_json_response(r):
    if r is None:
        return False
    ct = r.headers.get("Content-Type", "").lower()
    if "application/json" in ct:
        return True
    body = (r.text or "").lstrip()
    if body.startswith(("{", "[")):
        try:
            json.loads(body)
            return True
        except Exception:
            return False
    return False


def _join(base, suffix):
    if not suffix:
        return base or "/"
    return (base.rstrip("/") + "/" + suffix.lstrip("/")) if base else suffix


def _probe(url, timeout, follow):
    req_host = (urlparse(url).hostname or "").lower()
    r = _fetch(url, timeout=timeout, follow=follow)
    if r is None:
        return None
    final = urlparse(str(r.url))
    final_host = (final.hostname or "").lower()
    return {
        "requested": url,
        "final_url": str(r.url),
        "final_scheme": final.scheme,
        "final_netloc": final.netloc,
        "status": r.status_code,
        "json": _is_json_response(r),
        "is_html": "text/html" in r.headers.get("Content-Type", "").lower(),
        "off_host": bool(final_host) and final_host != req_host,
        "is_redirect": 300 <= r.status_code < 400,
        "server": r.headers.get("Server", ""),
        "powered_by": r.headers.get("X-Powered-By", ""),
        "size": len(r.text or ""),
    }


def _api_ish_path(path):
    pl = path.lower()
    return pl.startswith(("/api", "/v1", "/v2", "/rest")) or "graphql" in pl


def _score_candidate(c):
    score = 0
    if c["json"]:
        score += 100
    if c["api_ish"]:
        score += 40
    if c["status"] in (200, 401, 403, 405, 422):
        score += 20
    elif c["status"] in (400, 404):
        score += 8
    if c["scheme"] == "https":
        score += 15
    score += min(len(c["base_path"]), 12)
    return score


def _confirm_base(scheme, netloc, base_path, cfg, neg=None):
    best = None
    for sub in cfg["confirm_subpaths"]:
        url = f"{scheme}://{netloc}" + _join(base_path, sub)
        info = _probe(url, cfg["timeout"], cfg["follow_redirects"])
        if info is None:
            continue
        if info["off_host"] and cfg["reject_redirect_only"]:
            continue
        if info["is_redirect"] and cfg["reject_redirect_only"]:
            continue
        if not info["json"] and _matches_fingerprint(
                info["status"], info.get("is_html", False),
                info.get("size", 0), neg):
            continue
        cand = {
            "scheme": info["final_scheme"] or scheme,
            "netloc": info["final_netloc"] or netloc,
            "base_path": base_path,
            "status": info["status"],
            "json": info["json"],
            "api_ish": _api_ish_path(base_path),
            "final_url": info["final_url"],
            "server": info["server"],
            "powered_by": info["powered_by"],
            "sub": sub,
        }
        if best is None or _score_candidate(cand) > _score_candidate(best):
            best = cand
    return best


def discover_same_origin(base_url, cfg):
    parsed = urlparse(base_url)
    host = parsed.hostname or "localhost"
    netloc_with_port = parsed.netloc or host

    origin_scheme = parsed.scheme or ("https" if cfg["prefer_https"] else "http")
    schemes = list(dict.fromkeys(
        ([origin_scheme] + list(cfg["schemes"])) if not cfg["prefer_https"]
        else (["https"] + [s for s in cfg["schemes"] if s != "https"] + [origin_scheme])
    ))

    candidates = []
    base_paths = cfg["base_paths"]
    total = len(schemes) * len(base_paths)
    step = 0
    neg_by_scheme = {}
    for scheme in schemes:
        netloc = netloc_with_port if scheme == origin_scheme else host
        if scheme not in neg_by_scheme:
            neg_by_scheme[scheme] = soft_404_fingerprint(f"{scheme}://{netloc}", cfg)
        neg = neg_by_scheme[scheme]
        if neg and neg.get("catch_all"):
            progress.activity(
                f"{scheme}://{netloc} serves a catch-all page for unknown paths "
                f"(soft-404) — looking for JSON API paths that differ from it",
                stage="discovery")
        for base_path in base_paths:
            step += 1
            progress.activity(
                f"Probing {scheme}://{netloc}{base_path or '/'}",
                stage="discovery", i=step, n=total)
            cand = _confirm_base(scheme, netloc, base_path, cfg, neg=neg)
            if cand is not None:
                candidates.append(cand)
                progress.activity(
                    f"Candidate {cand['scheme']}://{cand['netloc']}{cand['base_path'] or '/'}"
                    f" HTTP {cand['status']}" + (" JSON" if cand["json"] else ""),
                    stage="discovery", i=step, n=total)
        if any(c["json"] or c["api_ish"] for c in candidates):
            break
        if neg and neg.get("catch_all"):
            break
    if not candidates:
        return None
    candidates.sort(key=_score_candidate, reverse=True)
    return candidates[0]


def port_scan(host, ports=None, timeout=2, cfg=None):
    cfg = cfg or _cfg(None)
    ports = ports or COMMON_API_PORTS
    parsed = urlparse(host)
    hostname = parsed.hostname or "localhost"
    current_port = parsed.port
    alive = []
    total = len(ports)
    for idx, port in enumerate(ports, 1):
        if current_port and port == current_port:
            continue
        progress.activity(f"Port scan {hostname}:{port}",
                          stage="discovery", i=idx, n=total)
        schemes = ["https", "http"] if port in (443, 8443) else ["http", "https"]
        if cfg["prefer_https"] and "https" in schemes:
            schemes = ["https"] + [s for s in schemes if s != "https"]
        found = None
        for scheme in schemes:
            for suffix in ("/api", "/"):
                probe_url = f"{scheme}://{hostname}:{port}{suffix}"
                info = _probe(probe_url, cfg["timeout"], cfg["follow_redirects"])
                if info is None:
                    continue
                if info["off_host"] and cfg["reject_redirect_only"]:
                    continue
                if info["is_redirect"] and cfg["reject_redirect_only"]:
                    continue
                found = {
                    "port": port,
                    "scheme": info["final_scheme"] or scheme,
                    "url": info["final_url"],
                    "status": info["status"],
                    "content_type": "",
                    "server": info["server"],
                    "powered_by": info["powered_by"],
                    "json": info["json"],
                    "size": info["size"],
                }
                break
            if found:
                break
        if found:
            alive.append(found)
    alive.sort(key=lambda x: (not x["json"], x["scheme"] != "https", x["port"]))
    return alive


def discover(base_url, adapter=None, config=None):
    cfg = _cfg(config)
    neg = soft_404_fingerprint(base_url, cfg)
    result = {
        "frontend": base_url,
        "runtime_config": None,
        "port_scan": [],
        "candidate_api_base": None,
        "source": None,
        "adapter": (adapter or {}).get("id", "generic"),
        "catch_all": bool(neg and neg.get("catch_all")),
        "soft_404": neg,
    }

    progress.activity("Reading runtime config from landing page", stage="discovery")
    runtime = detect_api_base_from_runtime(base_url, adapter)
    if runtime:
        confirmed = _probe(_join(runtime["base"], "health"), cfg["timeout"],
                           cfg["follow_redirects"]) or _probe(
            runtime["base"], cfg["timeout"], cfg["follow_redirects"])
        if confirmed and not confirmed["off_host"]:
            result["runtime_config"] = runtime
            result["candidate_api_base"] = runtime["base"]
            result["source"] = f"runtime:{runtime['source']}"
            return result

    progress.activity("Checking same-origin API paths", stage="discovery")
    same = discover_same_origin(base_url, cfg)
    # An api_ish path that only returns a 4xx/5xx HTML error page is not a real
    # API surface (e.g. a CDN 404) — accept a non-JSON candidate only when it
    # answered with a real, non-error status.
    api_path_ok = (same is not None and same["api_ish"]
                   and same.get("status") in (200, 201, 202, 401, 403, 405, 422))
    if same is not None and (same["json"] or api_path_ok):
        base = f"{same['scheme']}://{same['netloc']}{same['base_path']}"
        result["candidate_api_base"] = base.rstrip("/") or base
        result["source"] = ("same-origin"
                            + (":json" if same["json"] else ":path"))
        return result

    parsed = urlparse(base_url)
    host = f"{parsed.scheme}://{parsed.hostname}"
    if parsed.port:
        host = f"{host}:{parsed.port}"

    if result["catch_all"]:
        progress.activity("Catch-all site — skipping port scan, using frontend URL",
                          stage="discovery")
        result["candidate_api_base"] = base_url.rstrip("/")
        result["source"] = "catch-all:frontend"
        return result

    progress.activity("No same-origin API — scanning common ports", stage="discovery")
    adapter_ports = (adapter or {}).get("ports")
    alive = port_scan(host, ports=adapter_ports, cfg=cfg) if adapter_ports else []
    if not alive:
        alive = port_scan(host, cfg=cfg)
    result["port_scan"] = alive

    for entry in alive:
        if entry["json"]:
            result["candidate_api_base"] = f"{entry['scheme']}://{parsed.hostname}:{entry['port']}/api"
            result["source"] = f"portscan:{entry['scheme']}:{entry['port']}"
            return result
    for entry in alive:
        result["candidate_api_base"] = f"{entry['scheme']}://{parsed.hostname}:{entry['port']}/api"
        result["source"] = f"portscan:{entry['scheme']}:{entry['port']}"
        return result

    if same is not None:
        base = f"{same['scheme']}://{same['netloc']}{same['base_path']}"
        result["candidate_api_base"] = base.rstrip("/") or base
        result["source"] = "same-origin:fallback"
    return result
