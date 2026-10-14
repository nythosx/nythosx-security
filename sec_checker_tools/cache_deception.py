from claude_agent_sdk import tool

from engine.config import load_engine
from engine.injection import cache_deception
from engine.roe_guard import ROEGuard


@tool(
    "cache_deception_scan",
    "Test a sensitive 200 endpoint for web cache deception. Appends cacheable "
    "extensions (.css, .js, .svg, etc.) and checks whether a CDN caches the "
    "private response (X-Cache: HIT on a second request with identical body).",
    {"target_url": str},
)
async def tool_cache_deception(args):
    try:
        guard = ROEGuard(engine_cfg=load_engine())
        r = cache_deception.scan(args["target_url"], roe_guard=guard)
    except Exception as e:
        return {"content": [{"type": "text",
                             "text": f"cache_deception error: {type(e).__name__}: {e}"}],
                "isError": True}
    return {"content": [{"type": "text",
                         "text": f"{r['verdict']}: {r.reason}"}],
            "structuredContent": r.to_dict()}
