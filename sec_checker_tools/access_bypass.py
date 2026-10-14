from claude_agent_sdk import tool

from engine.config import load_engine
from engine.injection import access_bypass
from engine.roe_guard import ROEGuard


@tool(
    "access_bypass_scan",
    "Test a 403/401-gated URL for bypass via header overrides "
    "(X-Original-URL, X-Rewrite-URL, X-Forwarded-For) and path mutations "
    "(trailing slash, encoded dot, ..;/). Reports VULNERABLE if any attempt "
    "flips the gate to 200.",
    {"target_url": str},
)
async def tool_access_bypass(args):
    try:
        guard = ROEGuard(engine_cfg=load_engine())
        r = access_bypass.scan(args["target_url"], roe_guard=guard)
    except Exception as e:
        return {"content": [{"type": "text",
                             "text": f"access_bypass error: {type(e).__name__}: {e}"}],
                "isError": True}
    return {"content": [{"type": "text",
                         "text": f"{r['verdict']}: {r.reason}"}],
            "structuredContent": r.to_dict()}
