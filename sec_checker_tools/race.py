from claude_agent_sdk import tool
from engine import race_advanced
from engine.roe_guard import ROEGuard
from engine.config import load_engine


@tool(
    "race_scan",
    "Run advanced race condition testing against a URL. Techniques: "
    "(1) barrier-synchronized burst via threading.Barrier, "
    "(2) HTTP/2 single-packet attack (Kettle 2023, withholds END_STREAM "
    "then releases all final frames in one TCP packet), "
    "(3) response-timing histogram analysis (bimodal distribution detection), "
    "(4) state-machine replay (idempotency check). Use when the target has "
    "state-changing endpoints (coupon redeem, transfer, checkout, refund, "
    "password reset) and you suspect a TOCTOU or limit-overrun flaw. "
    "WARNING: this sends real requests. Ensure the target is in scope and "
    "the endpoint is safe to test concurrently.",
    {
        "target_url": str,
        "method": str,
        "body_json": str,
        "count": int,
    },
)
async def tool_race_scan(args):
    target = args["target_url"]
    method = (args.get("method") or "POST").upper()
    body = None
    if args.get("body_json"):
        try:
            import json as _json
            body = _json.loads(args["body_json"])
        except Exception:
            body = args["body_json"]
    count = int(args.get("count") or 20)
    try:
        guard = ROEGuard(engine_cfg=load_engine())
        out = race_advanced.race_scan(target, method=method, body=body,
                                       count=count, roe_guard=guard)
    except Exception as e:
        return {
            "content": [{"type": "text",
                         "text": f"race_scan failed: {type(e).__name__}: {e}"}],
            "isError": True,
        }
    lines = [f"Race scan: {target}",
             f"Method: {method}  Count: {count}",
             f"Overall: {out.get('overall')}",
             ""]
    for key, r in (out.get("results") or {}).items():
        lines.append(f"[{r.get('verdict')}] {key}: {r.get('reason', '')[:150]}")
    return {
        "content": [{"type": "text", "text": "\n".join(lines)}],
        "structuredContent": out,
    }
