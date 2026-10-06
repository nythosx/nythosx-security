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


def analyze(self_probe, neighbor_probes):
    self_hash = self_probe.get("body_hash")
    offenders = []
    for np in neighbor_probes:
        if np.get("status") == 200 and np.get("body_hash") \
                and np.get("body_hash") != self_hash \
                and len((np.get("body") or "").strip()) > 2:
            offenders.append(np)
    if offenders:
        return {
            "verdict": "VULNERABLE",
            "reason": f"{len(offenders)} neighbor ID(s) returned a distinct 200 body "
                      f"(accessed another record)",
            "evidence": {"offender_ids": [o["id"] for o in offenders],
                         "self_id": self_probe.get("id")},
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


def run_probe(identity_url, resource_base, headers=None, cookies=None,
              engine_cfg=None, roe_guard=None):
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
        out["result"] = analyze(self_probe, neighbor_probes)
    finally:
        client.close()
    return out
