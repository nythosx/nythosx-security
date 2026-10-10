from claude_agent_sdk import tool
from engine import smuggle


@tool(
    "smuggle_scan",
    "Run a non-destructive HTTP request smuggling timing probe. Sends CL.TE and "
    "TE.CL payloads and measures response delays versus a baseline. Does not smuggle "
    "a second request into another client's stream. Use when a proxy/CDN sits in "
    "front of the target.",
    {
        "target_url": str,
        "timeout": float,
        "threshold_ms": float,
    },
)
async def tool_smuggle_scan(args):
    target = args["target_url"]
    timeout = float(args.get("timeout") or 5.0)
    threshold = float(args.get("threshold_ms") or 3000.0)
    try:
        out = smuggle.probe(target, timeout=timeout, threshold_ms=threshold)
    except Exception as e:
        return {
            "content": [{"type": "text", "text": f"smuggle_scan failed: {type(e).__name__}: {e}"}],
            "isError": True,
        }
    r = out["result"]
    text = (
        f"Smuggling probe: {target}\n"
        f"Verdict: {r['verdict']}\n"
        f"Reason: {r.get('reason', '')}"
    )
    return {
        "content": [{"type": "text", "text": text}],
        "structuredContent": {"verdict": r["verdict"], "evidence": r.get("evidence", {})},
    }
