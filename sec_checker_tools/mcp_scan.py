from claude_agent_sdk import tool

from engine.mcp_security import _tool_mcp_security


class _StubOrch:
    def __init__(self, target):
        self.target = target
        self.roe_guard = None


@tool(
    "mcp_security_scan",
    "Scan an MCP configuration file for tool poisoning and credential "
    "exposure. Detects hidden instructions in tool descriptions that would "
    "redirect the agent, and hardcoded AWS/OpenAI/Anthropic/GitHub/Google/"
    "Slack tokens in the config.",
    {
        "config_path": str,
        "check": (str, True),
    },
)
async def tool_mcp_security_scan(args):
    config_path = args.get("config_path")
    if not config_path:
        return {"content": [{"type": "text", "text": "config_path is required"}],
                "isError": True}
    check = (args.get("check") or "poisoning").lower()
    try:
        result = _tool_mcp_security(_StubOrch(config_path),
                                     {"config_path": config_path,
                                      "check": check})
    except Exception as e:
        return {"content": [{"type": "text",
                             "text": f"mcp scan failed: {type(e).__name__}: {e}"}],
                "isError": True}
    v = result.get("verdict", "UNKNOWN")
    reason = result.get("reason", "")
    lines = [f"MCP scan: {config_path} ({check})",
             f"Verdict: {v}",
             f"Reason: {reason}"]
    for h in (result.get("evidence") or {}).get("hits") or []:
        lines.append(f"  [{h.get('severity')}] {h.get('where')}: {h.get('match')}")
    for c in (result.get("evidence") or {}).get("credentials") or []:
        lines.append(f"  [credential] {c.get('type')}: {c.get('match')}")
    return {"content": [{"type": "text", "text": "\n".join(lines)}],
            "structuredContent": result}
