from claude_agent_sdk import tool

from engine import differential
from engine.config import load_engine
from engine.roe_guard import ROEGuard


@tool(
    "differential_scan",
    "Cross-auth differential scan. Attempts to establish two user sessions "
    "(via signup auto-discovery or provided credentials), probes every known "
    "endpoint as {anonymous, user_a, user_b}, and structurally diffs the "
    "responses. Finds BOLA (broken object-level authorization), missing auth, "
    "and admin-path exposure that pattern-based scanners miss.",
    {"base_url": str, "endpoints_csv": str},
)
async def tool_differential_scan(args):
    endpoints = None
    if args.get("endpoints_csv"):
        endpoints = [e.strip() for e in args["endpoints_csv"].split(",") if e.strip()]
    try:
        guard = ROEGuard(engine_cfg=load_engine())
        r = differential.scan(args["base_url"], endpoints=endpoints, roe_guard=guard)
    except Exception as e:
        return {"content": [{"type": "text",
                             "text": f"differential error: {type(e).__name__}: {e}"}],
                "isError": True}
    return {"content": [{"type": "text",
                         "text": f"{r['verdict']}: {r.reason}"}],
            "structuredContent": r.to_dict()}
