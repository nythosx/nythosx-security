import itertools
from collections import Counter

from .http_client import HttpClient
from .config import load_engine
from .roe_guard import ROEGuard


def cartesian(dimensions):
    if not dimensions:
        return []
    keys = list(dimensions.keys())
    value_lists = [dimensions[k] for k in keys]
    out = []
    for combo in itertools.product(*value_lists):
        out.append(dict(zip(keys, combo)))
    return out


def pairwise(dimensions):
    keys = [k for k, v in dimensions.items() if v]
    if len(keys) <= 1:
        return cartesian(dimensions)

    required = set()
    for a, b in itertools.combinations(keys, 2):
        for va in dimensions[a]:
            for vb in dimensions[b]:
                required.add(((a, va), (b, vb)))

    full = cartesian(dimensions)
    chosen = []
    covered = set()

    def pairs_of(combo):
        items = [(k, combo[k]) for k in keys]
        return set(itertools.combinations(items, 2))

    while required - covered:
        best = None
        best_gain = -1
        for combo in full:
            gain = len((pairs_of(combo) & required) - covered)
            if gain > best_gain:
                best_gain = gain
                best = combo
        if best is None or best_gain <= 0:
            break
        chosen.append(best)
        covered |= pairs_of(best)
    return chosen


def build_request(combo, base_url):
    method = combo.get("method", "GET")
    path = combo.get("path", "")
    url = base_url.rstrip("/") + path if path else base_url
    headers = {}
    params = {}
    for k, v in combo.items():
        if k.startswith("header:"):
            headers[k[7:]] = v
        elif k.startswith("param:"):
            params[k[6:]] = v
    return method, url, headers, params


def explore(base_url, dimensions, strategy="pairwise", engine_cfg=None,
            headers=None, cookies=None, max_combos=200):
    engine_cfg = engine_cfg if engine_cfg is not None else load_engine()
    guard = ROEGuard(engine_cfg=engine_cfg)
    http_cfg = engine_cfg.get("http", {})
    rl = engine_cfg.get("rate_limit", {}) or {}
    combos = (pairwise(dimensions) if strategy == "pairwise"
              else cartesian(dimensions))[:max_combos]
    client = HttpClient(
        default_headers=headers or {},
        timeout=http_cfg.get("timeout_seconds", 15),
        verify=http_cfg.get("verify_tls", True),
        roe_guard=guard,
        cookies=cookies or {},
        rate_limit_global_rps=rl.get("global_rps", 10),
        rate_limit_per_endpoint_rps=rl.get("per_endpoint_rps", 5),
        rate_limit_burst=rl.get("burst", 20),
    )
    results = []
    try:
        for combo in combos:
            method, url, extra_headers, params = build_request(combo, base_url)
            r = client.request(method, url, headers=extra_headers or None,
                               params=params or None)
            results.append({"combo": combo, "status": r.get("status"),
                            "body_hash": r.get("body_hash"), "error": r.get("error")})
    finally:
        client.close()
    return {"combos_run": len(results), "results": results,
            "analysis": analyze(results)}


def analyze(results, outlier_threshold=0.25):
    statuses = [r["status"] for r in results if r["status"] is not None]
    if len(statuses) < 3:
        return {"verdict": "UNKNOWN", "reason": "need >= 3 successful combos",
                "evidence": {}}
    counts = Counter(statuses)
    total = len(statuses)
    outliers = []
    for r in results:
        st = r["status"]
        if st is None:
            continue
        frac = counts[st] / total
        if frac <= outlier_threshold and st < 500:
            outliers.append({"combo": r["combo"], "status": st})
    if outliers:
        return {
            "verdict": "SUSPICIOUS",
            "reason": f"{len(outliers)} combination(s) produced an outlier status "
                      f"(distribution: {dict(counts)})",
            "evidence": {"outliers": outliers[:10], "distribution": dict(counts)},
        }
    return {"verdict": "PASS",
            "reason": f"uniform behavior across {total} combinations",
            "evidence": {"distribution": dict(counts)}}
