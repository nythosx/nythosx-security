"""Shared probe helper for framework detection modules.

Each module exports PROBES (a list of spec dicts) and calls probe_specs()
to run them all through a single client.
"""
from __future__ import annotations


def _looks_html(body):
    low = (body or "").lstrip().lower()[:200]
    return low.startswith("<!doctype") or low.startswith("<html") or "<body" in low


def _matches_neg_fp(body, neg_fp):
    if not neg_fp:
        return False
    nsize = neg_fp.get("size") or 0
    if not nsize:
        return False
    return abs(len(body or "") - nsize) <= max(80, int(nsize * 0.15))


def _match(spec, status, body, neg_fp=None):
    if "status_in" in spec and status not in spec["status_in"]:
        return False
    if "status_not_in" in spec and status in spec["status_not_in"]:
        return False
    for m in (spec.get("body_not_contains") or []):
        if m in body:
            return False
    needles_all = spec.get("body_contains_all") or []
    if needles_all and not all(m in body for m in needles_all):
        return False
    needles = spec.get("body_contains") or []
    has_marker = bool(needles) or bool(needles_all)
    if needles and not any(m in body for m in needles):
        return False
    json_markers = [m for m in (needles + needles_all) if '"' in m]
    if json_markers and not spec.get("allow_html") and _looks_html(body):
        return False
    if _matches_neg_fp(body, neg_fp):
        return False
    if not has_marker and _looks_html(body):
        return False
    return True


def probe_specs(base_url, specs, roe_guard=None, timeout=8,
                max_body=8000, headers=None, neg_fp=None):
    from .. import http as _http
    base = base_url.rstrip("/")
    probes = []
    findings = []
    try:
        with _http.Client(timeout=timeout, follow_redirects=False) as c:
            for spec in specs:
                url = base + spec["path"]
                method = spec.get("method", "GET").upper()
                kwargs = {}
                for key in ("json", "data", "content"):
                    if spec.get(key) is not None:
                        kwargs[key] = spec[key]
                if spec.get("headers"):
                    kwargs["headers"] = dict(spec["headers"])
                try:
                    r = c.request(method, url, **kwargs)
                except Exception as e:
                    probes.append({
                        "probe": spec["name"],
                        "url": url,
                        "error": f"{type(e).__name__}: {str(e)[:140]}",
                    })
                    continue
                body = (r.text or "")[:max_body]
                matched = _match(spec, r.status_code, body, neg_fp=neg_fp)
                probe = {
                    "probe": spec["name"],
                    "url": url,
                    "method": method,
                    "status": r.status_code,
                    "matched": bool(matched),
                }
                probes.append(probe)
                if matched:
                    findings.append({
                        "probe": spec["name"],
                        "url": url,
                        "method": method,
                        "status": r.status_code,
                        "severity": spec.get("severity", "medium"),
                        "reason": spec.get("reason", ""),
                        "cve": spec.get("cve", ""),
                        "preview": body[:300],
                    })
    except _http.ROEBlock as e:
        return {"probes": probes, "findings": findings,
                "error": f"ROE_BLOCK: {e}"}
    except Exception as e:
        return {"probes": probes, "findings": findings,
                "error": f"{type(e).__name__}: {e}"}
    return {"probes": probes, "findings": findings}


__all__ = ["probe_specs"]
