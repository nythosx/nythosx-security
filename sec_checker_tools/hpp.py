from claude_agent_sdk import tool

from engine.config import load_engine
from engine.injection import hpp
from engine.roe_guard import ROEGuard


@tool(
    "hpp_scan",
    "Test HTTP Parameter Pollution. For each parameter, sends single, "
    "duplicate, comma-separated, and array forms, then checks whether the "
    "response reflects the last value only (last-wins), which can bypass "
    "WAF matching or authorization checks that inspect only the first value.",
    {"target_url": str, "params_csv": str},
)
async def tool_hpp_scan(args):
    params = None
    if args.get("params_csv"):
        params = [p.strip() for p in args["params_csv"].split(",") if p.strip()]
    try:
        guard = ROEGuard(engine_cfg=load_engine())
        r = hpp.scan(args["target_url"], params=params, roe_guard=guard)
    except Exception as e:
        return {"content": [{"type": "text",
                             "text": f"hpp error: {type(e).__name__}: {e}"}],
                "isError": True}
    return {"content": [{"type": "text",
                         "text": f"{r['verdict']}: {r.reason}"}],
            "structuredContent": r.to_dict()}
