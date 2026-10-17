from claude_agent_sdk import tool
from engine.intelligent_discovery import intelligent_endpoint_discovery
from engine.brains.llm import make_brain_from_config, LLMBrain
from engine.config import load_engine
from engine.roe_guard import ROEGuard

@tool(
    "intelligent_discover",
    "Use LLM-guided inference to discover hidden API endpoints (like chatbots, admin panels) "
    "that standard wordlists miss. Provide the base URL and optionally the detected framework.",
    {"url": str, "framework": (str, True), "max_suggestions": (int, True)},
)
async def tool_intelligent_discover(args):
    url = args.get("url")
    if not url:
        return {"content": [{"type": "text", "text": "url is required"}], "isError": True}

    framework = args.get("framework") or "generic"
    max_suggestions = int(args.get("max_suggestions") or 15)

    engine_cfg = load_engine()
    brain = make_brain_from_config(engine_cfg.get("brain"))
    llm_client = brain.client if isinstance(brain, LLMBrain) else None

    try:
        guard = ROEGuard(engine_cfg=engine_cfg)
        results = intelligent_endpoint_discovery(
            base_url=url,
            valid_paths=[],
            failed_paths=[],
            llm_client=llm_client,
            timeout=10,
            roe_guard=guard
        )
    except Exception as e:
        return {"content": [{"type": "text", "text": f"discovery failed: {type(e).__name__}: {e}"}], "isError": True}

    if not results:
        return {"content": [{"type": "text", "text": "No new endpoints discovered."}], "structuredContent": {"endpoints": []}}

    lines = [f"Intelligent Discovery for {url} ({len(results)} found):"]
    for r in results:
        lines.append(f"  [{r.get('status')}] {r.get('path')} ({r.get('content_type', '')[:30]})")

    return {
        "content": [{"type": "text", "text": "\n".join(lines)}],
        "structuredContent": {"endpoints": results}
    }
