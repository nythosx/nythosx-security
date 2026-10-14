import random

from .chain_engine import register_tool
from .config import load_engine
from .util import unwrap_rows
from . import http as _http

BYPASS_HEADERS = [
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Originating-IP",
    "X-Remote-IP",
    "X-Client-IP",
    "X-Forwarded-Host",
    "True-Client-IP",
    "CF-Connecting-IP",
    "X-Cluster-Client-IP",
]


def _verify_tls():
    try:
        cfg = load_engine() or {}
        return bool(cfg.get("http", {}).get("verify_tls", True))
    except Exception:
        return False


def _fake_ip(i):
    return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{i % 255}"


def test_bypass(url, roe_guard=None, count=30, timeout=8,
                method="GET", token=None):
    verify = _verify_tls()
    statuses = []
    bodies = []
    for i in range(count):
        headers = {"Accept": "application/json"}
        ip = _fake_ip(i)
        for h in BYPASS_HEADERS:
            headers[h] = ip
        if token:
            headers["Authorization"] = f"Bearer {token}"
        try:
            with _http.Client(timeout=timeout, verify=verify,
                              follow_redirects=False) as c:
                r = c.request(method.upper(), url, headers=headers)
        except _http.ROEBlock as e:
            return {"verdict": "UNKNOWN", "reason": f"ROE_BLOCK: {e}",
                    "evidence": {}}
        except Exception:
            statuses.append(None)
            bodies.append("")
            continue
        statuses.append(r.status_code)
        bodies.append(r.text or "")

    real = [s for s in statuses if s is not None]
    if not real:
        return {"verdict": "UNKNOWN",
                "reason": f"all {count} rotated-IP requests failed",
                "evidence": {"statuses": statuses}}

    success = [s for s in real if s in (200, 201, 202)]
    limited = [s for s in real if s == 429]
    if len(success) >= count * 0.9 and not limited:
        return {
            "verdict": "VULNERABLE",
            "reason": f"rotated forwarded-IP bypass: {len(success)}/{count} requests succeeded, 0 rate-limited",
            "evidence": {"statuses": statuses, "bypass_headers": BYPASS_HEADERS},
        }
    if limited:
        return {
            "verdict": "PASS",
            "reason": f"rate limit enforced ({len(limited)} x HTTP 429 across {count} rotated-IP requests)",
            "evidence": {"statuses": statuses},
        }
    return {
        "verdict": "PASS",
        "reason": f"rotated-IP requests did not all succeed ({len(success)}/{count})",
        "evidence": {"statuses": statuses},
    }


def _tool_rate_limit_bypass(orch, args):
    url = args.get("url")
    if not url:
        base = orch.get_fact("api_base") or orch.target
        path = args.get("path") or "/api/v1/accounts"
        url = base.rstrip("/") + path if path.startswith("/") else base + "/" + path

    token = args.get("token") or orch.get_context("jwt_token") or None
    result = test_bypass(
        url, roe_guard=orch.roe_guard,
        count=int(args.get("count") or 30),
        timeout=int(args.get("timeout") or 8),
        method=args.get("method") or "GET",
        token=token,
    )
    return {
        "verdict": result.get("verdict", "UNKNOWN"),
        "reason": result.get("reason", ""),
        "evidence": result.get("evidence") or {},
    }


register_tool("rate_limit_bypass", _tool_rate_limit_bypass)
