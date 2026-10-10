from claude_agent_sdk import tool
from engine import xss


@tool(
    "xss_scan",
    "Run a blind/reflected XSS probe against a URL parameter. Injects script payloads "
    "that call back to an out-of-band listener, then loads the URL in a headless "
    "browser to confirm execution. Use when user input is reflected into HTML.",
    {
        "target_url": str,
        "param": str,
    },
)
async def tool_xss_scan(args):
    target = args["target_url"]
    param = args["param"]
    try:
        out = xss.probe(target, param)
    except Exception as e:
        return {
            "content": [{"type": "text", "text": f"xss_scan failed: {type(e).__name__}: {e}"}],
            "isError": True,
        }
    r = out["result"]
    text = (
        f"XSS probe: {target}  param={param}\n"
        f"Verdict: {r['verdict']}\n"
        f"Reason: {r.get('reason', '')}\n"
        f"Callbacks: {len(out['callbacks'])}"
    )
    return {
        "content": [{"type": "text", "text": text}],
        "structuredContent": {"verdict": r["verdict"], "callbacks": out["callbacks"]},
    }
