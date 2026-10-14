from claude_agent_sdk import tool

from engine.recon import wayback


@tool(
    "wayback_harvest",
    "Harvest historic URLs for a domain from the Wayback Machine (CDX) and "
    "CommonCrawl. Returns ranked paths (priority: API-ish, parameterised, "
    "sensitive-looking) and the distinct parameter names ever seen. Historic "
    "URLs frequently expose endpoints the current site no longer links.",
    {"domain": str},
)
async def tool_wayback_harvest(args):
    try:
        result = wayback.harvest(args["domain"])
    except Exception as e:
        return {"content": [{"type": "text",
                             "text": f"wayback error: {type(e).__name__}: {e}"}],
                "isError": True}
    if not result:
        return {"content": [{"type": "text", "text": "no historic URLs found"}],
                "structuredContent": {}}
    lines = [
        f"Historic URLs for {result['domain']}",
        f"Sources: {', '.join(result['sources'])}",
        f"Total URLs seen: {result['total_urls_seen']}",
        f"Distinct paths: {len(result['paths'])}",
        f"Priority paths: {len(result['priority_paths'])}",
        f"Distinct params: {len(result['params'])}",
        "",
        "Top priority paths:",
    ]
    for p in result["priority_paths"][:20]:
        lines.append(f"  {p}")
    return {"content": [{"type": "text", "text": "\n".join(lines)}],
            "structuredContent": result}
