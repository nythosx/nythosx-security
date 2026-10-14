from __future__ import annotations

import hashlib
import json as _json
import re
import sys
from urllib.parse import urljoin, urlparse

from . import http as _http
from . import triage as _triage


_PLACEHOLDER_RE = re.compile(r"(\{[^}]+\}|:[A-Za-z_][A-Za-z0-9_]*)")
_TRAILING_ID_RE = re.compile(r"/\d+/?$")

SENSITIVE_KEYS = ("email", "phone", "ssn", "token", "password", "secret",
                  "address", "name", "username", "user", "account", "balance",
                  "card", "iban", "dob", "owner", "ip", "session")

_SEV_FROM_CATEGORY = {
    "sensitive": "high",
    "content": "low",
    "telemetry": "info",
    "form": "low",
    "unknown": "medium",
}


def _fetch(url, token=None, headers=None):
    h = {"Accept": "application/json"}
    if headers:
        h.update(headers)
    if token:
        h["Authorization"] = "Bearer " + token
    try:
        r = _http.get(url, headers=h)
    except Exception as e:
        return {"status": None, "error": f"{type(e).__name__}: {e}", "body": "", "ct": ""}
    body = getattr(r, "text", "") or ""
    ct = ""
    try:
        ct = (r.headers.get("content-type") or "").lower()
    except Exception:
        pass
    return {"status": getattr(r, "status_code", None), "error": None, "body": body, "ct": ct}


def _json_obj(resp):
    if resp["status"] != 200 or "json" not in resp["ct"]:
        return None
    try:
        data = _json.loads(resp["body"])
    except Exception:
        return None
    if isinstance(data, dict) and isinstance(data.get("data"), (dict, list)):
        return data["data"]
    return data


def _hash(obj):
    try:
        return hashlib.sha256(
            _json.dumps(obj, sort_keys=True, default=str).encode("utf-8", "replace")
        ).hexdigest()[:16]
    except Exception:
        return ""


def _sensitive_keys_present(obj):
    found = set()
    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if any(s in str(k).lower() for s in SENSITIVE_KEYS):
                    found.add(str(k))
                walk(v)
        elif isinstance(o, list):
            for v in o[:20]:
                walk(v)
    walk(obj)
    return sorted(found)


def item_bases_from_paths(paths):
    bases = []
    seen = set()
    for p in paths or []:
        if not p.startswith("/"):
            continue
        if _PLACEHOLDER_RE.search(p):
            base = _PLACEHOLDER_RE.split(p)[0].rstrip("/")
        elif _TRAILING_ID_RE.search(p):
            base = _TRAILING_ID_RE.sub("", p)
        else:
            continue
        if base and base not in seen:
            seen.add(base)
            bases.append(base)
    return bases


def _diff_sequence(base, results_unauth):
    objs = [(i, r) for i, r in results_unauth if r.get("obj") is not None]
    distinct = {}
    for i, r in objs:
        distinct.setdefault(r["hash"], []).append(i)
    enumerable = len(objs) >= 2 and len(distinct) >= 2
    sample_keys = set()
    for _, r in objs:
        o = r.get("obj")
        if isinstance(o, dict):
            sample_keys.update(o.keys())
        elif isinstance(o, list):
            for it in o[:3]:
                if isinstance(it, dict):
                    sample_keys.update(it.keys())
    det = _triage.classify_detailed(base, sorted(sample_keys))
    category = det["category"]
    sens = set()
    for _, r in objs:
        sens |= set(r.get("sensitive_keys") or [])
    severity = _SEV_FROM_CATEGORY.get(category, "medium")
    if enumerable and category == "unknown" and sens:
        severity = "high"
    return {
        "enumerable_unauth": enumerable,
        "distinct_objects": len(distinct),
        "readable_ids": [i for i, _ in objs],
        "category": category,
        "by_design": category in _triage.BY_DESIGN_CATEGORIES,
        "sensitive_keys": sorted(sens),
        "severity": severity,
        "confidence": det["confidence"],
        "basis": det["basis"],
    }


def scan_endpoint(base_url, base_path, ids, token=None, headers=None):
    results_unauth = []
    results_auth = []
    for i in ids:
        url = urljoin(base_url.rstrip("/") + "/", base_path.lstrip("/") + "/" + str(i))
        ru = _fetch(url, token=None, headers=headers)
        obj = _json_obj(ru)
        results_unauth.append((i, {
            "url": url,
            "status": ru["status"],
            "obj": obj,
            "hash": _hash(obj) if obj is not None else "",
            "sensitive_keys": _sensitive_keys_present(obj) if obj is not None else [],
        }))
        if token:
            ra = _fetch(url, token=token, headers=headers)
            aobj = _json_obj(ra)
            results_auth.append((i, {
                "url": url,
                "status": ra["status"],
                "hash": _hash(aobj) if aobj is not None else "",
            }))
    summary = _diff_sequence(base_path, results_unauth)
    auth_gap = None
    if token:
        exposed = []
        amap = {i: r for i, r in results_auth}
        for i, ru in results_unauth:
            ra = amap.get(i)
            if ru.get("obj") is not None and ra is not None and ru["hash"] == ra["hash"]:
                exposed.append(i)
        auth_gap = {
            "unauth_equals_auth_ids": exposed,
            "data_readable_without_auth": bool(exposed),
        }
    return {
        "endpoint": base_path,
        "ids_probed": list(ids),
        "summary": summary,
        "auth_gap": auth_gap,
        "detail_unauth": [{"id": i, "status": r["status"], "hash": r["hash"],
                           "sensitive_keys": r["sensitive_keys"]}
                          for i, r in results_unauth],
    }


def _seed_identifiers(base_url, base_path, headers=None, cap=4):
    url = urljoin(base_url.rstrip("/") + "/", base_path.lstrip("/"))
    obj = _json_obj(_fetch(url, headers=headers))
    rows = obj if isinstance(obj, list) else ([obj] if isinstance(obj, dict) else [])
    ids = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        for key in ("slug", "id", "uuid", "_id", "code", "ref"):
            v = row.get(key)
            if isinstance(v, (str, int)) and not isinstance(v, bool):
                s = str(v)
                if s and s not in ids:
                    ids.append(s)
    numeric = [int(i) for i in ids if str(i).isdigit()]
    if numeric:
        neighbor = str(min(numeric) + 1)
        if neighbor not in ids:
            ids.append(neighbor)
    return ids[:cap]


def scan(base_url, endpoints=None, ids=(1, 2, 3), token=None, headers=None, seed=True):
    base_url = base_url.rstrip("/")
    if not endpoints:
        try:
            from .recon.js_endpoints import discover
            disc = discover(base_url, headers=headers)
            paths = disc.get("paths") or []
            bases = item_bases_from_paths(paths)
            for p in paths:
                if p.startswith("/api") and not _PLACEHOLDER_RE.search(p):
                    b = p.rstrip("/")
                    if b not in bases:
                        bases.append(b)
            endpoints = bases
        except Exception as e:
            return {"base_url": base_url, "error": f"discovery failed: {e}", "findings": []}
    findings = []
    for base_path in endpoints:
        probe_ids = ids
        if seed:
            seeded = _seed_identifiers(base_url, base_path, headers=headers)
            if seeded:
                probe_ids = seeded
        findings.append(scan_endpoint(base_url, base_path, probe_ids, token=token, headers=headers))
    real = [f for f in findings
            if f["summary"]["enumerable_unauth"]
            and f["summary"]["severity"] in ("medium", "high", "critical")]
    return {
        "base_url": base_url,
        "endpoints_tested": len(findings),
        "findings": findings,
        "idor_candidates": [f["endpoint"] for f in real],
    }


def _main(argv):
    if not argv:
        print("usage: python -m engine.idor_sweep <base_url> [--token T] [--ids 1,2,3] [--endpoints /a,/b]")
        return 2
    base = argv[0]
    token = None
    ids = (1, 2, 3)
    endpoints = None
    for i, a in enumerate(argv):
        if a == "--token" and i + 1 < len(argv):
            token = argv[i + 1]
        elif a == "--ids" and i + 1 < len(argv):
            ids = tuple(int(x) for x in argv[i + 1].split(",") if x.strip().isdigit())
        elif a == "--endpoints" and i + 1 < len(argv):
            endpoints = [e.strip() for e in argv[i + 1].split(",") if e.strip()]
    res = scan(base, endpoints=endpoints, ids=ids, token=token)
    if res.get("error"):
        print("error: " + res["error"])
        return 1
    print(f"base_url : {res['base_url']}")
    print(f"tested   : {res['endpoints_tested']} item endpoint(s), ids={list(ids)}")
    for f in res["findings"]:
        s = f["summary"]
        if s["enumerable_unauth"] and s["severity"] in ("medium", "high", "critical"):
            tag = "IDOR?"
        elif s["enumerable_unauth"]:
            tag = "enum/pub"
        elif s["by_design"]:
            tag = "by-design"
        else:
            tag = "---"
        print(f"  [{s['severity']:<6}] {tag:<9} {s['category']:<10} conf={s.get('confidence','?'):<6} {f['endpoint']}"
              f"  distinct={s['distinct_objects']} ids={s['readable_ids']}")
        if s["sensitive_keys"]:
            print(f"      sensitive keys: {', '.join(s['sensitive_keys'][:12])}")
        if f["auth_gap"] and f["auth_gap"]["data_readable_without_auth"]:
            print(f"      ** readable WITHOUT auth (same as authed) ids={f['auth_gap']['unauth_equals_auth_ids']}")
    if res["idor_candidates"]:
        print("\nIDOR candidates (non-by-design, enumerable unauth):")
        for e in res["idor_candidates"]:
            print("  !! " + e)
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
