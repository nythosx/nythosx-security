from .chain_engine import register_tool
from .config import load_engine
from .contract import DataRow
from .util import extract_json_path, unwrap_rows
from . import http as _http


def _verify_tls():
    try:
        cfg = load_engine() or {}
        return bool(cfg.get("http", {}).get("verify_tls", True))
    except Exception:
        return True


def _banking_cfg():
    try:
        cfg = load_engine() or {}
        return cfg.get("banking") or {}
    except Exception:
        return {}


def _headers_for(token, header="Authorization", prefix="Bearer "):
    h = {"Accept": "application/json"}
    if token:
        h[header] = f"{prefix}{token}"
    return h


def extract_endpoint(url, token=None, method="GET", roe_guard=None,
                     timeout=10, max_rows=5, auth_label=None):
    verify = _verify_tls()
    headers = _headers_for(token)
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            r = c.request(method.upper(), url, headers=headers)
    except _http.ROEBlock as e:
        return None, f"ROE_BLOCK: {e}", "roe_block"
    except _http.ConnectError as e:
        return None, f"connect_error: {e}", "connect_error"
    except _http.TimeoutException:
        return None, "timeout", "timeout"
    except Exception as e:
        return None, f"{type(e).__name__}: {e}", "error"

    ct = (r.headers.get("Content-Type") or "").lower()
    if r.status_code != 200:
        return None, f"HTTP {r.status_code}", "status"
    if "json" not in ct:
        return None, f"non-JSON content-type: {ct[:40]}", "content_type"

    try:
        parsed = r.json()
    except Exception:
        return None, "JSON parse failed", "parse"

    rows = unwrap_rows(parsed)
    if not rows:
        return None, "no rows", "empty"

    masked_rows = [DataRow(
        endpoint=url,
        method=method.upper(),
        status=r.status_code,
        total_rows=len(rows),
        extracted=min(len(rows), max_rows),
        rows=rows[:max_rows],
        raw_rows=rows[:max_rows],
        auth_used=auth_label,
    )]
    return masked_rows[0], None, None


def _tool_data_extract(orch, args):
    url = args.get("url") or args.get("endpoint")
    if not url:
        base = orch.get_fact("api_base") or orch.target
        path = args.get("path") or "/api/v1/me"
        url = base.rstrip("/") + path if path.startswith("/") else base + "/" + path

    token = args.get("token") or orch.get_context("jwt_token") or None
    max_rows = int(args.get("max_rows") or 5)
    method = args.get("method") or "GET"

    row, err, kind = extract_endpoint(
        url, token=token, method=method,
        roe_guard=orch.roe_guard, max_rows=max_rows,
        auth_label="authenticated" if token else "unauthenticated",
    )

    if row is None:
        verdict = "UNKNOWN" if kind in ("roe_block", "connect_error",
                                         "timeout", "error") else "PASS"
        return {"verdict": verdict, "reason": err,
                "evidence": {"url": url, "kind": kind}}

    return {
        "verdict": "SUSPICIOUS",
        "reason": f"{row.extracted}/{row.total_rows} row(s) extracted from {url}",
        "evidence": {"url": url, "total_rows": row.total_rows,
                     "extracted": row.extracted,
                     "rows": row.rows,
                     "auth_used": row.auth_used},
        "data_rows": [row.to_dict()],
    }


register_tool("data_extract", _tool_data_extract)


def _parse_link_header(link_header):
    import re as _re
    if not link_header:
        return None
    m = _re.search(r'<([^>]+)>;\s*rel="next"', link_header)
    return m.group(1) if m else None


def extract_with_pagination(url, token=None, method="GET", max_pages=50,
                             headers=None, timeout=10, verify=None,
                             roe_guard=None, max_rows=5):
    """Follow pagination links/params and collect rows from every page."""
    from urllib.parse import urlparse, urlencode, urlunparse, parse_qs
    if verify is None:
        try:
            from .config import load_engine
            verify = bool((load_engine() or {}).get(
                "http", {}).get("verify_tls", True))
        except Exception:
            verify = True
    all_rows = []
    seen_hashes = set()
    pages_fetched = 0
    current = url
    for page in range(max_pages):
        h = {"Accept": "application/json"}
        if token:
            h["Authorization"] = "Bearer " + token
        if headers:
            h.update(headers)
        try:
            with _http.Client(timeout=timeout, verify=verify,
                              follow_redirects=False) as c:
                r = c.get(current, headers=h)
        except Exception as e:
            return {"rows": all_rows, "pages_fetched": pages_fetched,
                    "error": f"{type(e).__name__}: {e}"}
        if r.status_code != 200:
            break
        pages_fetched += 1
        try:
            parsed = r.json()
        except Exception:
            break
        rows = unwrap_rows(parsed)
        if not rows:
            break
        new_rows = 0
        for row in rows:
            key = _row_hash(row)
            if key in seen_hashes:
                continue
            seen_hashes.add(key)
            all_rows.append(row)
            new_rows += 1
        if new_rows == 0:
            break
        nxt = _parse_link_header(r.headers.get("Link", ""))
        if nxt:
            current = nxt
            continue
        p = urlparse(url)
        q = parse_qs(p.query)
        next_page = page + 1
        if "page" in q:
            q["page"] = [str(next_page + 1)]
        elif "offset" in q:
            try:
                cur_off = int(q["offset"][0])
            except (ValueError, IndexError):
                cur_off = 0
            q["offset"] = [str(cur_off + len(rows))]
        else:
            q["page"] = [str(next_page + 1)]
        current = urlunparse(p._replace(query=urlencode(q, doseq=True)))
    return {"rows": all_rows, "pages_fetched": pages_fetched}


_VOLATILE_HASH_FIELDS = frozenset((
    "updated_at", "updatedat", "modified_at", "modifiedat", "timestamp",
    "ts", "_ts", "last_seen", "lastseen", "last_modified", "etag",
    "server_time", "fetched_at", "retrieved_at",
))


def _stable_id_for_hash(row):
    if not isinstance(row, dict):
        return None
    for k in row:
        if str(k).lower() in ("id", "_id", "uuid", "guid", "pk", "slug"):
            v = row.get(k)
            if isinstance(v, (str, int)) and str(v):
                return f"{str(k).lower()}={v}"
    return None


def _strip_volatile(obj, depth=0, max_depth=10):
    if depth > max_depth:
        return obj
    if isinstance(obj, dict):
        return {k: _strip_volatile(v, depth + 1, max_depth)
                for k, v in obj.items()
                if str(k).lower() not in _VOLATILE_HASH_FIELDS}
    if isinstance(obj, list):
        return [_strip_volatile(item, depth + 1, max_depth) for item in obj]
    return obj


def _row_hash(row):
    import hashlib, json as _json
    stable = _stable_id_for_hash(row)
    if stable is not None:
        return hashlib.sha256(stable.encode()).hexdigest()[:16]
    try:
        payload = _strip_volatile(row) if isinstance(row, dict) else row
        s = _json.dumps(payload, sort_keys=True, default=str)
        return hashlib.sha256(s.encode()).hexdigest()[:16]
    except Exception:
        return str(row)[:64]


def _tool_paginated_extract(orch, args):
    url = args.get("url") or orch.get_fact("api_base") or orch.target
    token = args.get("token") or orch.get_context("jwt_token")
    max_pages = int(args.get("max_pages") or 50)
    max_rows = int(args.get("max_rows") or 100)
    result = extract_with_pagination(
        url, token=token, max_pages=max_pages, roe_guard=orch.roe_guard,
    )
    rows = result.get("rows") or []
    if not rows:
        return {"verdict": "PASS",
                "reason": f"no rows recovered across {result.get('pages_fetched', 0)} page(s)",
                "evidence": {"url": url, "pages": result.get("pages_fetched", 0)}}
    sample = rows[:max_rows]
    return {
        "verdict": "VULNERABLE" if not token else "SUSPICIOUS",
        "reason": (f"{len(rows)} row(s) recovered across "
                    f"{result.get('pages_fetched', 0)} page(s) "
                    + ("(unauthenticated)" if not token else "(authenticated)")),
        "evidence": {"url": url,
                     "total_rows": len(rows),
                     "extracted": len(sample),
                     "pages": result.get("pages_fetched", 0),
                     "auth_used": "authenticated" if token else "unauthenticated",
                     "rows": sample},
    }


register_tool("unauth_pagination", _tool_paginated_extract)
