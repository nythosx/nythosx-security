from claude_agent_sdk import tool
from engine import idor


@tool(
    "idor_scan",
    "Run an IDOR probe. Fetches the caller's identity from an identity endpoint, "
    "extracts numeric IDs, then requests neighbouring IDs from a resource base to "
    "check whether other users' records are accessible. Use for object-level "
    "authorization testing.",
    {
        "identity_url": str,
        "resource_base": str,
    },
)
async def tool_idor_scan(args):
    identity = args["identity_url"]
    resource = args["resource_base"]
    try:
        out = idor.run_probe(identity, resource)
    except Exception as e:
        return {
            "content": [{"type": "text", "text": f"idor_scan failed: {type(e).__name__}: {e}"}],
            "isError": True,
        }
    r = out.get("result") or {"verdict": "UNKNOWN", "reason": "no result"}
    text = (
        f"IDOR probe: identity={identity}  resource={resource}\n"
        f"Verdict: {r['verdict']}\n"
        f"Reason: {r.get('reason', '')}\n"
        f"IDs found: {out.get('ids_found', [])}"
    )
    return {
        "content": [{"type": "text", "text": text}],
        "structuredContent": {"verdict": r["verdict"], "evidence": r.get("evidence", {})},
    }
