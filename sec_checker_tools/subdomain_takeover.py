from claude_agent_sdk import tool

from engine import subdomain_takeover
from engine.config import load_engine
from engine.roe_guard import ROEGuard


@tool(
    "subdomain_takeover",
    "Detect subdomain takeover. Fetches each URL and matches the response "
    "body against fingerprints of 18 known-vulnerable services (Heroku, "
    "GitHub Pages, S3, Azure, Shopify, Tumblr, Bitbucket, Fastly, Surge, "
    "Netlify, Vercel, Ghost, Zendesk, Pantheon, and more).",
    {"urls_csv": str},
)
async def tool_subdomain_takeover(args):
    urls = [u.strip() for u in (args.get("urls_csv") or "").split(",")
            if u.strip()]
    if not urls:
        return {"content": [{"type": "text", "text": "no URLs provided"}],
                "isError": True}
    try:
        guard = ROEGuard(engine_cfg=load_engine())
        r = subdomain_takeover.scan(urls, roe_guard=guard)
    except Exception as e:
        return {"content": [{"type": "text",
                             "text": f"subdomain_takeover error: {type(e).__name__}: {e}"}],
                "isError": True}
    return {"content": [{"type": "text",
                         "text": f"{r['verdict']}: {r.reason}"}],
            "structuredContent": r.to_dict()}
