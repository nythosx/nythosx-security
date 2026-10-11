import re
import json
import concurrent.futures
from pathlib import Path
from .http_client import HttpClient
from .roe_guard import ROEGuard
from .util import safe_name

_TEMPLATE_RE = re.compile(r"\{\{\s*([^}]+?)\s*\}\}")
ROOT = Path(__file__).parent.parent.absolute()
BASELINE_DIR = ROOT / "findings"

# Steps that fire at or above this concurrency are race probes: bypass the
# rate limiter so token-bucket delays don't serialize the burst and close the
# race window (Confidence Gap #2). A step may also opt out with
# `no_rate_limit: true`.
RACE_CONCURRENCY_THRESHOLD = 10


def _load_baseline_for(target_url):
    # Must use the same safe_name() (and maxlen) as baseline.save_baseline,
    # otherwise long target URLs serialize to a different filename and the
    # baseline never loads (Confidence Gap #4).
    safe = safe_name(target_url)
    p = BASELINE_DIR / f"baseline_{safe}.json"
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data.get("endpoints", {}).get(target_url)
    except Exception:
        return None


def _resolve(key, inputs, loop_index, target):
    key = key.strip()
    if key == "loop_index":
        return str(loop_index)
    if key == "target":
        return target
    if key.startswith("inputs."):
        path = key[7:]
        v = inputs.get(path)
        return "" if v is None else str(v)
    return ""


def render(value, inputs, loop_index=0, target=""):
    if isinstance(value, dict):
        return {k: render(v, inputs, loop_index, target) for k, v in value.items()}
    if isinstance(value, list):
        return [render(v, inputs, loop_index, target) for v in value]
    if isinstance(value, str):
        return _TEMPLATE_RE.sub(
            lambda m: _resolve(m.group(1), inputs, loop_index, target), value
        )
    return value


def _execute_one(step, inputs, client, loop_index, target, skip_rate_limit=False):
    req = step.get("request", {})
    method = render(req.get("method", "GET"), inputs, loop_index, target)
    url = render(req.get("url", ""), inputs, loop_index, target)
    headers = render(req.get("headers", {}) or {}, inputs, loop_index, target)
    json_body = render(req.get("json"), inputs, loop_index, target) if req.get("json") else None
    data_body = render(req.get("data"), inputs, loop_index, target) if req.get("data") else None
    params = render(req.get("params"), inputs, loop_index, target) if req.get("params") else None
    no_auth = bool(step.get("no_auth"))
    follow_redirects = bool(req.get("follow_redirects", False))
    result = client.request(method, url, headers=headers, json=json_body,
                             data=data_body, params=params,
                             skip_default_headers=no_auth,
                             skip_cookies=no_auth,
                             skip_rate_limit=skip_rate_limit,
                             follow_redirects=follow_redirects)
    result["step_name"] = step.get("name", "step")
    result["loop_index"] = loop_index
    result["no_auth"] = no_auth
    return result


def execute_pattern(pattern, inputs, target, default_headers=None, engine_config=None,
                    cookies=None, negative_baseline=None):
    cfg = engine_config or {}
    http_cfg = cfg.get("http", {})
    # Pass engine config so roe.enforce_scope / enforce_methods flags are
    # honored instead of silently defaulting (Confidence Gap #5).
    roe_guard = ROEGuard(engine_cfg=cfg)
    rl_cfg = cfg.get("rate_limit", {}) or {}
    client = HttpClient(
        default_headers=default_headers,
        timeout=http_cfg.get("timeout_seconds", 30),
        verify=http_cfg.get("verify_tls", True),
        roe_guard=roe_guard,
        rotate_ua=http_cfg.get("user_agent_rotation", False),
        max_retries=http_cfg.get("max_retries", 3),
        backoff_base_ms=http_cfg.get("backoff_base_ms", 500),
        cookies=cookies,
        rate_limit_global_rps=rl_cfg.get("global_rps", 10),
        rate_limit_per_endpoint_rps=rl_cfg.get("per_endpoint_rps", 5),
        rate_limit_burst=rl_cfg.get("burst", 20),
        rate_limit_on_429_ms=rl_cfg.get("on_429_backoff_ms", 5000),
    )
    steps_results = []
    try:
        for step in pattern.get("steps", []):
            if step.get("concurrency"):
                n = int(render(str(step["concurrency"]), inputs, 0, target))
                n = max(1, min(n, 200))
                # A genuine concurrent burst must not be serialized by the
                # token bucket, or the race window closes (Confidence Gap #2).
                skip_rl = bool(step.get("no_rate_limit")) or n >= RACE_CONCURRENCY_THRESHOLD
                with concurrent.futures.ThreadPoolExecutor(max_workers=n) as pool:
                    futures = [pool.submit(_execute_one, step, inputs, client, i, target, skip_rl)
                                for i in range(n)]
                    for f in concurrent.futures.as_completed(futures):
                        steps_results.append(f.result())
            elif step.get("repeat"):
                n = int(render(str(step["repeat"]), inputs, 0, target))
                n = max(1, min(n, 500))
                skip_rl = bool(step.get("no_rate_limit"))
                for i in range(n):
                    steps_results.append(_execute_one(step, inputs, client, i, target, skip_rl))
            else:
                skip_rl = bool(step.get("no_rate_limit"))
                steps_results.append(_execute_one(step, inputs, client, 0, target, skip_rl))
    finally:
        client.close()
    context = {"steps": steps_results, "inputs": inputs, "target": target,
               "negative_baseline": negative_baseline}
    if any((o.get("type") == "timing_vs_baseline") for o in pattern.get("oracles", [])):
        baseline = _load_baseline_for(target)
        if baseline:
            context["baseline"] = baseline
    return context
