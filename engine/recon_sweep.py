from __future__ import annotations

from urllib.parse import urljoin

from . import triage as _triage


def _extract_rows(url, token, rows):
    try:
        from .data_extractor import extract_endpoint
    except Exception:
        return None
    try:
        row, err, kind = extract_endpoint(url, token=token, max_rows=rows)
    except Exception:
        return None
    if row is None:
        return None
    try:
        data = row.masked_json_rows() if hasattr(row, "masked_json_rows") else row.rows
    except Exception:
        data = getattr(row, "rows", [])
    return {
        "total_rows": getattr(row, "total_rows", len(data or [])),
        "extracted": getattr(row, "extracted", len(data or [])),
        "auth_used": getattr(row, "auth_used", "unauth"),
        "rows": data or [],
    }


def deep_recon(base_url, token=None, headers=None, do_extract=True,
               do_idor=True, rows=5):
    from .recon.js_endpoints import discover, probe_routes
    base_url = base_url.rstrip("/")
    out = {
        "base_url": base_url,
        "soft_404": None,
        "bundles": [],
        "inventory": [],
        "idor": None,
        "summary": {"endpoints": 0, "live": 0, "with_data": 0,
                    "by_category": {}, "idor_candidates": 0},
        "errors": [],
    }
    disc = discover(base_url, headers=headers)
    if disc.get("error"):
        out["errors"].append(disc["error"])
    out["soft_404"] = disc.get("soft_404")
    out["bundles"] = disc.get("bundles") or []
    paths = disc.get("paths") or []
    out["errors"].extend(disc.get("errors") or [])

    probed = probe_routes(base_url, paths, headers=headers)
    cat_counts = {}
    for r in probed.get("routes") or []:
        det = _triage.classify_detailed(r["path"])
        category = det["category"]
        cat_counts[category] = cat_counts.get(category, 0) + 1
        item = {
            "path": r["path"],
            "status": r["status"],
            "real": r["real"],
            "soft_404": r["soft_404"],
            "length": r["len"],
            "category": category,
            "by_design": category in _triage.BY_DESIGN_CATEGORIES,
            "confidence": det["confidence"],
            "data": None,
        }
        if do_extract and r["real"] and r["status"] == 200:
            url = urljoin(base_url + "/", r["path"].lstrip("/"))
            d = _extract_rows(url, token, rows)
            if d and d["rows"]:
                item["data"] = d
                det2 = _triage.classify_detailed(
                    r["path"], sorted(d["rows"][0].keys())
                    if isinstance(d["rows"][0], dict) else None)
                item["category"] = det2["category"]
                item["by_design"] = det2["category"] in _triage.BY_DESIGN_CATEGORIES
                item["confidence"] = det2["confidence"]
        out["inventory"].append(item)

    out["summary"]["endpoints"] = len(out["inventory"])
    out["summary"]["live"] = sum(1 for i in out["inventory"] if i["real"])
    out["summary"]["with_data"] = sum(1 for i in out["inventory"] if i["data"])
    out["summary"]["by_category"] = cat_counts

    if do_idor:
        try:
            from . import idor_sweep
            bases = idor_sweep.item_bases_from_paths(paths)
            for p in paths:
                if p.startswith("/api") and not idor_sweep._PLACEHOLDER_RE.search(p):
                    b = p.rstrip("/")
                    if b not in bases:
                        bases.append(b)
            idor_res = idor_sweep.scan(base_url, endpoints=bases, token=token,
                                       headers=headers)
            out["idor"] = idor_res
            out["summary"]["idor_candidates"] = len(
                idor_res.get("idor_candidates") or [])
        except Exception as e:
            out["errors"].append(f"idor: {type(e).__name__}: {e}")
    return out


__all__ = ["deep_recon"]
