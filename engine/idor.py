import json

from .http_client import HttpClient
from .config import load_engine
from .roe_guard import ROEGuard

_ID_FIELDS = ("id", "user_id", "userid", "uuid", "account_id", "accountid",
              "customer_id", "profile_id")


def extract_ids(body):
    try:
        data = json.loads(body)
    except Exception:
        return []
    found = []

    def walk(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k.lower() in _ID_FIELDS and isinstance(v, (int, str)):
                    found.append((k, v))
                walk(v)
        elif isinstance(obj, list):
            for item in obj[:20]:
                walk(item)

    walk(data)
    return found


def neighbor_ids(value):
    try:
        n = int(value)
    except (ValueError, TypeError):
        return []
    return [x for x in (n - 1, n + 1) if x > 0]


def _triage_evidence(self_probe, offenders, resource_base):
    try:
        from . import triage as _triage
    except Exception:
        return None
    keys = set()
    for probe in [self_probe] + list(offenders or []):
        for k, _ in extract_ids(probe.get("body") or ""):
            keys.add(k)
        try:
            data = json.loads(probe.get("body") or "")
        except Exception:
            data = None
        if isinstance(data, dict):
            inner = data.get("data") if isinstance(data.get("data"), dict) else data
            if isinstance(inner, dict):
                keys.update(inner.keys())
    det = _triage.classify_detailed(resource_base or "", sorted(keys))
    return {
        "category": det["category"],
        "severity_hint": _triage.WRITE_SEVERITY.get(det["category"], ("medium", ""))[0].lower(),
        "confidence": det["confidence"],
        "basis": det["basis"],
        "by_design": det["category"] in _triage.BY_DESIGN_CATEGORIES,
    }


def analyze(self_probe, neighbor_probes, resource_base=None):
    self_hash = self_probe.get("body_hash")
    offenders = []
    for np in neighbor_probes:
        if np.get("status") == 200 and np.get("body_hash") \
                and np.get("body_hash") != self_hash \
                and len((np.get("body") or "").strip()) > 2:
            offenders.append(np)
    from .bola_confirm import _same_body
    _self_body = self_probe.get("body") or ""
    _filtered = []
    for _np in offenders:
        if _same_body(_self_body, _np.get("body") or ""):
            continue
        _filtered.append(_np)
    offenders = _filtered
    if offenders:
        evidence = {"offender_ids": [o["id"] for o in offenders],
                    "self_id": self_probe.get("id")}
        tri = _triage_evidence(self_probe, offenders, resource_base)
        if tri:
            evidence["triage"] = tri
        return {
            "verdict": "VULNERABLE",
            "reason": f"{len(offenders)} neighbor ID(s) returned a distinct 200 body "
                      f"(accessed another record)",
            "evidence": evidence,
        }
    seen_200 = [np for np in neighbor_probes if np.get("status") == 200]
    if seen_200:
        return {
            "verdict": "SUSPICIOUS",
            "reason": f"{len(seen_200)} neighbor ID(s) returned 200 (body identical "
                      f"to self — possible shared/empty response)",
            "evidence": {"neighbor_ids": [o["id"] for o in seen_200]},
        }
    return {"verdict": "PASS",
            "reason": "no neighbor record accessible",
            "evidence": {"self_id": self_probe.get("id")}}


def _run_cross_user_probe(identity_url, resource_base, token_a, token_b,
                          headers=None, cookies=None, engine_cfg=None,
                          roe_guard=None):
    from .bola_confirm import classify, CONFIRMED, REFUTED, INCONCLUSIVE
    engine_cfg = engine_cfg if engine_cfg is not None else load_engine()
    guard = roe_guard or ROEGuard(engine_cfg=engine_cfg)
    http_cfg = engine_cfg.get("http", {})
    rl_cfg = engine_cfg.get("rate_limit", {}) or {}
    base_headers = dict(headers or {})
    base_cookies = dict(cookies or {})

    def _client_for(token):
        h = dict(base_headers)
        if token:
            h["Authorization"] = f"Bearer {token}"
        return HttpClient(
            default_headers=h,
            timeout=http_cfg.get("timeout_seconds", 30),
            verify=http_cfg.get("verify_tls", True),
            roe_guard=guard,
            cookies=base_cookies,
            rate_limit_global_rps=rl_cfg.get("global_rps", 10),
            rate_limit_per_endpoint_rps=rl_cfg.get("per_endpoint_rps", 5),
            rate_limit_burst=rl_cfg.get("burst", 20),
        )

    out = {"identity_url": identity_url, "resource_base": resource_base,
           "ids_found": [], "result": None, "error": None,
           "mode": "cross_user"}
    client_a = _client_for(token_a)
    client_b = _client_for(token_b)
    try:
        me = client_a.request("GET", identity_url)
        if me.get("error"):
            out["error"] = me["error"]
            out["result"] = {"verdict": "UNKNOWN",
                             "reason": me["error"], "evidence": {}}
            return out
        ids = extract_ids(me.get("body") or "")
        out["ids_found"] = [{"field": f, "value": v} for f, v in ids]
        base = resource_base.rstrip("/")
        paths = []
        seen = set()
        for _, v in ids:
            try:
                n = int(v)
            except (TypeError, ValueError):
                continue
            for cand in (n, n + 1, n + 2):
                if cand <= 0:
                    continue
                p = f"{base}/{cand}"
                if p not in seen:
                    seen.add(p)
                    paths.append(p)
            if len(paths) >= 6:
                break
        if not paths:
            paths = [f"{base}/1", f"{base}/2"]

        responses_a = {}
        responses_b = {}
        for url in paths:
            ra = client_a.request("GET", url)
            rb = client_b.request("GET", url)
            responses_a[url] = {"status": ra.get("status"),
                                "body": ra.get("body") or ""}
            responses_b[url] = {"status": rb.get("status"),
                                "body": rb.get("body") or ""}
        decision = classify(responses_a, responses_b, paths)
        verdict_map = {CONFIRMED: "VULNERABLE",
                       REFUTED: "PASS",
                       INCONCLUSIVE: "UNKNOWN"}
        out["result"] = {
            "verdict": verdict_map.get(decision.status, "UNKNOWN"),
            "reason": decision.reason,
            "evidence": {"proof": decision.proof,
                         "status": decision.status,
                         "mode": "cross_user"},
        }
    finally:
        try:
            client_a.close()
        except Exception:
            pass
        try:
            client_b.close()
        except Exception:
            pass
    return out


def _run_probe_impl(identity_url, resource_base, headers=None, cookies=None,
                    engine_cfg=None, roe_guard=None,
                    token_a=None, token_b=None):
    if token_b and token_a:
        return _run_cross_user_probe(
            identity_url, resource_base, token_a, token_b,
            headers=headers, cookies=cookies,
            engine_cfg=engine_cfg, roe_guard=roe_guard)
    engine_cfg = engine_cfg if engine_cfg is not None else load_engine()
    guard = roe_guard or ROEGuard(engine_cfg=engine_cfg)
    http_cfg = engine_cfg.get("http", {})
    rl_cfg = engine_cfg.get("rate_limit", {}) or {}
    client = HttpClient(
        default_headers=headers or {},
        timeout=http_cfg.get("timeout_seconds", 30),
        verify=http_cfg.get("verify_tls", True),
        roe_guard=guard,
        cookies=cookies or {},
        rate_limit_global_rps=rl_cfg.get("global_rps", 10),
        rate_limit_per_endpoint_rps=rl_cfg.get("per_endpoint_rps", 5),
        rate_limit_burst=rl_cfg.get("burst", 20),
    )
    out = {"identity_url": identity_url, "resource_base": resource_base,
           "ids_found": [], "self": None, "neighbors": [], "result": None,
           "error": None}
    try:
        me = client.request("GET", identity_url)
        if me.get("error"):
            out["error"] = me["error"]
            out["result"] = {"verdict": "UNKNOWN", "reason": me["error"], "evidence": {}}
            return out
        ids = extract_ids(me.get("body") or "")
        out["ids_found"] = [{"field": f, "value": v} for f, v in ids]
        numeric = next(((f, v) for f, v in ids if neighbor_ids(v)), None)
        if not numeric:
            out["result"] = {"verdict": "UNKNOWN",
                             "reason": "no numeric ID found in identity response",
                             "evidence": {"ids_found": out["ids_found"]}}
            return out
        _, self_id = numeric
        base = resource_base.rstrip("/")
        self_resp = client.request("GET", f"{base}/{self_id}")
        self_probe = {"id": self_id, "status": self_resp.get("status"),
                      "body_hash": self_resp.get("body_hash"),
                      "body": self_resp.get("body")}
        out["self"] = self_probe
        neighbor_probes = []
        for nid in neighbor_ids(self_id):
            r = client.request("GET", f"{base}/{nid}")
            neighbor_probes.append({"id": nid, "status": r.get("status"),
                                    "body_hash": r.get("body_hash"),
                                    "body": r.get("body")})
        out["neighbors"] = neighbor_probes
        out["result"] = analyze(self_probe, neighbor_probes, resource_base=base)
    finally:
        client.close()
    return out

def run_probe(*args, **kwargs):
    from .contract import make_result
    raw = _run_probe_impl(*args, **kwargs)
    return make_result(raw, capability="idor", args=args, kwargs=kwargs)
