from claude_agent_sdk import tool

from engine.config import load_engine
from engine.recon import sourcemaps, ct_logs
from engine.roe_guard import ROEGuard


@tool(
    "sourcemap_mine",
    "Fetch JavaScript source maps (.js.map) for one or more JS URLs, parse "
    "sourcesContent, and extract original parameter names, internal paths, "
    "URLs, and fetch() calls. Source maps leak what the minifier stripped.",
    {"js_urls_csv": str},
)
async def tool_sourcemap_mine(args):
    urls = [u.strip() for u in (args.get("js_urls_csv") or "").split(",")
            if u.strip()]
    if not urls:
        return {"content": [{"type": "text", "text": "no JS URLs provided"}],
                "isError": True}
    try:
        guard = ROEGuard(engine_cfg=load_engine())
        r = sourcemaps.mine(urls, roe_guard=guard)
    except Exception as e:
        return {"content": [{"type": "text",
                             "text": f"sourcemap error: {type(e).__name__}: {e}"}],
                "isError": True}
    maps = r.get("maps_found") or []
    lines = [f"Source maps found: {len(maps)}"]
    for m in maps[:10]:
        lines.append(f"  {m['map_url']}")
        lines.append(f"    params: {m.get('params', [])[:10]}")
        lines.append(f"    paths: {m.get('paths', [])[:10]}")
    return {"content": [{"type": "text", "text": "\n".join(lines)}],
            "structuredContent": r}


@tool(
    "ct_subdomain",
    "Enumerate subdomains for a domain via Certificate Transparency logs "
    "(crt.sh). Optionally resolve each subdomain to confirm it is live.",
    {"domain": str},
)
async def tool_ct_subdomain(args):
    try:
        r = ct_logs.harvest(args["domain"])
    except Exception as e:
        return {"content": [{"type": "text",
                             "text": f"ct_subdomain error: {type(e).__name__}: {e}"}],
                "isError": True}
    if not r:
        return {"content": [{"type": "text",
                             "text": "crt.sh unreachable or no certificates found"}],
                "structuredContent": {}}
    lines = [f"Domain: {r['domain']}",
             f"Subdomains in CT logs: {r['count']}",
             f"Live (resolved): {len(r.get('live') or [])}",
             ""]
    for s in (r.get("subdomains") or [])[:40]:
        lines.append(f"  {s}")
    return {"content": [{"type": "text", "text": "\n".join(lines)}],
            "structuredContent": r}
