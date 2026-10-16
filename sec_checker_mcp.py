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
from engine import audit


_TOOL_SCOPES = {
    "sec_route": "scan:read",
    "sec_manifest": "scan:read",
    "sec_requires_approval": "scan:read",
    "sec_scan": "scan:read",
    "sec_list_patterns": "scan:read",
    "sec_chains": "scan:read",
    "sec_coverage": "scan:read",
    "sec_orchestrate": "scan:read",
    "jwt_attack": "scan:read",
    "jwt_decode": "scan:read",
    "graphql_scan": "scan:read",
    "graphql_schema_walk": "scan:read",
    "llm_scan": "scan:read",
    "domxss_scan": "scan:read",
    "idor_scan": "scan:read",
    "combo_explore": "scan:read",
    "owasp_compliance": "scan:read",
    "owasp_map_pattern": "scan:read",
    "cve_correlation": "scan:read",
    "wayback_harvest": "scan:read",
    "sourcemap_mine": "scan:read",
    "ct_subdomain": "scan:read",
    "framework_probe": "scan:read",
    "openapi_scan": "scan:read",
    "smuggle_scan": "scan:read",
    "ssrf_scan": "scan:read",
    "ssrf_cloud_scan": "scan:read",
    "sca_scan": "scan:read",
    "sbom_generate": "scan:read",
    "xss_scan": "scan:read",
    "data_extract": "scan:read",
    "data_extract_paginated": "scan:read",
    "mcp_security_scan": "scan:read",
    "deserialization_scan": "scan:read",
    "differential_scan": "scan:read",
    "cache_deception_scan": "scan:read",
    "access_bypass_scan": "scan:read",
    "hpp_scan": "scan:read",
    "http2_scan": "scan:read",
    "websocket_scan": "scan:read",
    "subdomain_takeover": "scan:read",
    "cloud_storage_enum": "scan:read",
    "hunt": "scan:destructive",
    "banking_hunt": "scan:destructive",
    "race_scan": "scan:destructive",
    "upload_scan": "scan:destructive",
    "weak_password_scan": "scan:destructive",
    "lockout_probe": "scan:destructive",
    "weak_credential_enum": "scan:destructive",
    "workflow_record": "scan:destructive",
    "workflow_list_params": "scan:read",
    "workflow_replay": "scan:destructive",
    "workflow_tamper": "scan:destructive",
    "bola_scan": "scan:read",
    "bola_harvest": "scan:destructive",
    "blind_sqli_extract": "scan:destructive",
    "timing_robust": "scan:destructive",
}


def _granted_scopes():
    import os
    raw = os.environ.get("SEC_CHECKER_MCP_SCOPES", "scan:read")
    return frozenset(s.strip() for s in raw.split(",") if s.strip())


def authorize(tool_name, granted):
    required = _TOOL_SCOPES.get(tool_name)
    if required is None:
        return True, None
    if required in granted:
        return True, None
    return False, (
        f"tool '{tool_name}' requires scope '{required}'; "
        f"granted scopes: {sorted(granted)}"
    )


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
    granted = _granted_scopes()
    ok, reason = authorize(name, granted)
    if not ok:
        try:
            audit.record("mcp_call_denied", error=reason,
                         extra={"tool": name})
        except Exception:
            pass
        return [TextContent(type="text",
                             text=f"permission denied: {reason}")]
    try:
        audit.record("mcp_call", extra={
            "tool": name,
            "args": redact.redact_dict(arguments or {}),
        })
    except Exception:
        pass
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
