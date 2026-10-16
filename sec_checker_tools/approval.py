from claude_agent_sdk import tool

from engine import registry


@tool(
    "sec_requires_approval",
    "Check whether a SEC-CHECKER capability requires explicit human "
    "approval for the given URL under the current registry policy. "
    "Call this before invoking any destructive capability. Returns "
    "'requires_approval=true' when the capability is destructive or "
    "opt-in and the URL is inside an approval-required scope, and "
    "'requires_approval=false' otherwise. Never invokes any tool.",
    {"capability": str, "url": str},
)
async def tool_sec_requires_approval(args):
    cap = (args.get("capability") or "").strip()
    url = (args.get("url") or "").strip()
    if not cap:
        return {"content": [{"type": "text",
                             "text": "capability is required"}],
                "isError": True}
    try:
        required = bool(registry.requires_approval(cap, url))
    except Exception as e:
        return {"content": [{"type": "text",
                             "text": f"error: {type(e).__name__}: {e}"}],
                "isError": True}
    text = ("requires_approval=true" if required
            else "requires_approval=false")
    return {
        "content": [{"type": "text", "text": text}],
        "structuredContent": {
            "capability": cap,
            "url": url,
            "required": required,
        },
    }
