import asyncio
import os
import sys
from pathlib import Path

ROOT = Path(__file__).parent.absolute()
sys.path.insert(0, str(ROOT))

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from sec_checker_tools import all_tools
from sec_checker_tools.schemas import schema_for as _schema_for
from engine import redact


server = Server("sec-checker")


@server.list_tools()
async def list_tools():
    tools = []
    for fn in all_tools():
        name = getattr(fn, "_tool_name", None) or fn.__name__
        desc = getattr(fn, "_tool_description", None) or (fn.__doc__ or "")
        tools.append(
            Tool(
                name=name,
                description=desc.strip(),
                inputSchema=_schema_for(fn),
            )
        )
    return tools


@server.call_tool()
async def call_tool(name, arguments):
    if name == "sec_manifest":
        from engine import registry
        import json as _json
        return [TextContent(type="text",
                             text=_json.dumps(registry.manifest(), indent=2))]
    fn = None
    for t in all_tools():
        if (getattr(t, "_tool_name", None) or t.__name__) == name:
            fn = t
            break
    if fn is None:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]
    result = await fn(arguments)
    result = redact.redact_dict(result)
    blocks = result.get("content") or []
    out = []
    for b in blocks:
        if b.get("type") == "text":
            out.append(TextContent(type="text", text=b.get("text", "")))
    if not out:
        out.append(TextContent(type="text", text="(no output)"))
    return out


async def main():
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
