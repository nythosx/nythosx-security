from claude_agent_sdk import tool
from engine import ssrf


@tool(
    "ssrf_scan",
    "Run a blind SSRF probe against a URL. Injects out-of-band callback URLs into "
    "common SSRF parameters (url, uri, callback, webhook, next, redirect, dest, image, "
    "proxy, etc.) and common headers (X-Forwarded-For, Referer). Use when the target "
    "fetches remote resources on behalf of the user.",
    {
        "target_url": str,
        "method": str,
    },
)
async def tool_ssrf_scan(args):
    target = args["target_url"]
    method = args.get("method") or "GET"
    try:
        out = ssrf.probe(target, method=method)
    except Exception as e:
        return {
            "content": [{"type": "text", "text": f"ssrf_scan failed: {type(e).__name__}: {e}"}],
            "isError": True,
        }
    r = out["result"]
    text = (
        f"SSRF probe: {target}\n"
        f"Verdict: {r['verdict']}\n"
        f"Reason: {r.get('reason', '')}\n"
        f"Vectors injected: {len(out['injected'])}\n"
        f"Callbacks: {len(out['callbacks'])}"
    )
    return {
        "content": [{"type": "text", "text": text}],
        "structuredContent": {"verdict": r["verdict"], "callbacks": out["callbacks"]},
    }
