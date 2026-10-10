from claude_agent_sdk import tool
from sec_checker_tools.registry import all_tools


@tool(
    "sec_route",
    "Universal SEC-CHECKER entrypoint. Given a free-text description of what you "
    "want to test, returns the list of available SEC-CHECKER tools with their "
    "descriptions, so you can choose the right one. Use this when you are unsure "
    "which specific scan tool to call.",
    {},
)
async def tool_sec_route(args):
    lines = ["Available SEC-CHECKER tools:", ""]
    for t in all_tools():
        name = getattr(t, "_tool_name", None) or t.__name__
        desc = getattr(t, "__doc__", "") or ""
        if hasattr(t, "_tool_description"):
            desc = t._tool_description
        lines.append(f"  {name}")
        lines.append(f"      {desc}")
        lines.append("")
    return {"content": [{"type": "text", "text": "\n".join(lines)}]}
