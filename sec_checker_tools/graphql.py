from claude_agent_sdk import tool
from engine import graphql_security
from engine.roe_guard import ROEGuard
from engine.config import load_engine


@tool(
    "graphql_scan",
    "Run deep GraphQL security testing against a GraphQL endpoint. Tests: "
    "(1) query depth limit bypass (100+ nested queries), "
    "(2) array batching rate-limit bypass, "
    "(3) alias batching rate-limit bypass, "
    "(4) CSRF via application/x-www-form-urlencoded, "
    "(5) Apollo Federation interface access control bypass (CVE-2025-64530), "
    "(6) field-suggestion schema leak when introspection is disabled. "
    "Use when the target exposes a GraphQL API.",
    {
        "target_url": str,
        "max_depth": int,
        "batch_size": int,
    },
)
async def tool_graphql_scan(args):
    target = args["target_url"]
    max_depth = int(args.get("max_depth") or 110)
    batch_size = int(args.get("batch_size") or 50)
    try:
        guard = ROEGuard(engine_cfg=load_engine())
        out = graphql_security.scan(target, roe_guard=guard,
                                    max_depth=max_depth,
                                    batch_size=batch_size)
    except Exception as e:
        return {
            "content": [{"type": "text",
                         "text": f"graphql_scan failed: {type(e).__name__}: {e}"}],
            "isError": True,
        }
    if not out.get("endpoint"):
        return {"content": [{"type": "text",
                             "text": f"No GraphQL endpoint: {out.get('reason', '')}"}]}
    lines = [f"GraphQL Deep Scan: {out['endpoint']}",
             f"Overall: {out.get('verdict')}", ""]
    for key, r in (out.get("results") or {}).items():
        if isinstance(r, dict) and "verdict" in r:
            lines.append(f"[{r['verdict']}] {key}: {r.get('reason', '')[:120]}")
    return {
        "content": [{"type": "text", "text": "\n".join(lines)}],
        "structuredContent": out,
    }
