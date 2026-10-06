from .http_client import HttpClient
from .config import load_engine
from .roe_guard import ROEGuard
from .oob import OOBServer

COMMON_SSRF_PARAMS = ["url", "uri", "link", "callback", "webhook", "next",
                      "redirect", "redirect_uri", "dest", "destination",
                      "image", "img", "fetch", "proxy", "target", "feed",
                      "source", "data", "domain", "host"]

COMMON_SSRF_HEADERS = ["X-Forwarded-For", "X-Forwarded-Host", "Referer",
                       "True-Client-IP", "X-Real-IP"]


def _make_client(headers, cookies, engine_cfg, guard):
    http_cfg = engine_cfg.get("http", {})
    rl = engine_cfg.get("rate_limit", {}) or {}
    return HttpClient(
        default_headers=headers or {},
        timeout=http_cfg.get("timeout_seconds", 15),
        verify=http_cfg.get("verify_tls", True),
        roe_guard=guard,
        cookies=cookies or {},
        rate_limit_global_rps=rl.get("global_rps", 10),
        rate_limit_per_endpoint_rps=rl.get("per_endpoint_rps", 5),
        rate_limit_burst=rl.get("burst", 20),
    )


def probe(target_url, oob_server=None, method="GET", params=None, headers=None,
          cookies=None, engine_cfg=None, wait_timeout=5.0):
    engine_cfg = engine_cfg if engine_cfg is not None else load_engine()
    guard = ROEGuard(engine_cfg=engine_cfg)
    own_oob = oob_server is None
    oob = oob_server or OOBServer().start()
    out = {"target": target_url, "oob_base": oob.base_url, "injected": [],
           "callbacks": [], "result": None}
    client = _make_client(headers, cookies, engine_cfg, guard)
    token_map = {}
    try:
        for p in (params or COMMON_SSRF_PARAMS):
            token, url = oob.payload_url()
            token_map[token] = {"vector": f"param:{p}"}
            out["injected"].append({"vector": f"param:{p}", "token": token})
            client.request(method, target_url, params={p: url})
        for h in COMMON_SSRF_HEADERS:
            token, url = oob.payload_url()
            token_map[token] = {"vector": f"header:{h}"}
            out["injected"].append({"vector": f"header:{h}", "token": token})
            client.request(method, target_url, headers={h: url})

        tokens = list(token_map.keys())
        _wait_any(oob, tokens, wait_timeout)
        for token, meta in token_map.items():
            hits = oob.interactions(token)
            if hits:
                out["callbacks"].append({"vector": meta["vector"], "token": token,
                                         "hits": len(hits)})
    finally:
        client.close()
        if own_oob:
            oob.stop()

    if out["callbacks"]:
        vectors = ", ".join(c["vector"] for c in out["callbacks"])
        out["result"] = {"verdict": "VULNERABLE",
                         "reason": f"out-of-band callback received via {vectors}",
                         "evidence": {"callbacks": out["callbacks"]}}
    else:
        out["result"] = {"verdict": "PASS",
                         "reason": "no out-of-band callback observed",
                         "evidence": {"vectors_tried": len(out["injected"])}}
    return out


def _wait_any(oob, tokens, timeout):
    import time
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if any(oob.hit_count(t) > 0 for t in tokens):
            return True
        time.sleep(0.1)
    return False
