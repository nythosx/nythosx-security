from claude_agent_sdk import tool
from engine import dom_xss
from engine.roe_guard import ROEGuard
from engine.config import load_engine


@tool(
    "domxss_scan",
    "Run DOM-based XSS detection with source→sink taint tracking. Uses "
    "Playwright to hook dangerous JavaScript sinks (innerHTML, outerHTML, "
    "eval, Function, document.write, setAttribute(on*), insertAdjacentHTML, "
    "iframe.srcdoc, string setTimeout/setInterval) and injects unique markers "
    "through DOM sources (location.hash, location.search, document.referrer, "
    "window.name). Also checks Trusted Types enforcement (CSP "
    "require-trusted-types-for 'script') and runs mXSS round-trip probes. "
    "Use when the page runs client-side JavaScript and you need to catch "
    "DOM XSS that reflected/stored scanners miss. Requires playwright "
    "chromium installed.",
    {
        "target_url": str,
        "include_mxss": bool,
        "timeout_ms": int,
    },
)
async def tool_domxss_scan(args):
    target = args["target_url"]
    include_mxss = bool(args.get("include_mxss", True))
    timeout_ms = int(args.get("timeout_ms") or 15000)
    try:
        guard = ROEGuard(engine_cfg=load_engine())
        out = dom_xss.scan(target, timeout_ms=timeout_ms, roe_guard=guard,
                           include_mxss=include_mxss)
    except Exception as e:
        return {
            "content": [{"type": "text",
                         "text": f"domxss_scan failed: {type(e).__name__}: {e}"}],
            "isError": True,
        }
    lines = [
        f"DOM XSS scan: {target}",
        f"Verdict: {out.get('verdict')}",
        f"Reason: {out.get('reason', '')}",
        "",
    ]
    results = out.get("results") or {}
    for f in results.get("flow_findings") or []:
        lines.append(f"[{f['kind']}] source={f['source']} sinks={f.get('sinks')}")
    if results.get("mxss"):
        lines.append(f"mXSS confirmed: {len(results['mxss'])} payload(s)")
    csp = results.get("csp") or {}
    if csp:
        lines.append(f"Trusted Types: {'enforced' if csp.get('enforced') else 'not enforced'}")
    return {
        "content": [{"type": "text", "text": "\n".join(lines)}],
        "structuredContent": out,
    }
