from claude_agent_sdk import tool

from engine import http2_probe
from engine.config import load_engine
from engine.roe_guard import ROEGuard
from engine import registry


try:
    registry.register(http2_probe.CAPABILITY)
except Exception:
    pass


@tool(
    "http2_scan",
    "HTTP/2 desync probes: H2.CL, H2.TE. Requires the h2 library.",
    {"target_url": str, "method": str},
)
async def tool_http2_scan(args):
    try:
        guard = ROEGuard(engine_cfg=load_engine())
        r = http2_probe.scan(args["target_url"],
                             method=(args.get("method") or "POST").upper(),
                             roe_guard=guard)
    except Exception as e:
        return {"content": [{"type": "text",
                             "text": f"http2_scan error: {type(e).__name__}: {e}"}],
                "isError": True}
    return {"content": [{"type": "text",
                         "text": f"{r['verdict']}: {r.reason}"}],
            "structuredContent": r.to_dict()}
