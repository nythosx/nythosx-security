from claude_agent_sdk import tool

from engine.config import load_engine
from engine.injection import ssti, xxe, nosql, crlf, open_redirect, host_header
from engine.roe_guard import ROEGuard
from engine import registry


for _cap in (ssti.CAPABILITY, xxe.CAPABILITY, nosql.CAPABILITY,
              crlf.CAPABILITY, open_redirect.CAPABILITY,
              host_header.CAPABILITY):
    try:
        registry.register(_cap)
    except Exception:
        pass


def _fmt(r):
    return {"content": [{"type": "text",
                         "text": f"{r['verdict']}: {r.reason}"}],
            "structuredContent": r.to_dict()}


@tool(
    "ssti_scan",
    "Server-Side Template Injection probe across common params.",
    {"target_url": str, "param": str, "method": str},
)
async def tool_ssti_scan(args):
    try:
        guard = ROEGuard(engine_cfg=load_engine())
        r = ssti.scan(args["target_url"],
                      param=args.get("param") or None,
                      method=(args.get("method") or "GET").upper(),
                      roe_guard=guard)
        return _fmt(r)
    except Exception as e:
        return {"content": [{"type": "text", "text": f"ssti_scan error: {e}"}],
                "isError": True}


@tool(
    "xxe_scan",
    "XML External Entity injection probe (file read + optional OOB).",
    {"target_url": str, "oob_url": str},
)
async def tool_xxe_scan(args):
    try:
        guard = ROEGuard(engine_cfg=load_engine())
        r = xxe.scan(args["target_url"],
                     oob_url=args.get("oob_url") or None,
                     roe_guard=guard)
        return _fmt(r)
    except Exception as e:
        return {"content": [{"type": "text", "text": f"xxe_scan error: {e}"}],
                "isError": True}


@tool(
    "nosql_scan",
    "NoSQL injection via JSON operator injection against a login endpoint.",
    {"login_url": str, "username_field": str, "password_field": str},
)
async def tool_nosql_scan(args):
    try:
        guard = ROEGuard(engine_cfg=load_engine())
        r = nosql.scan(args["login_url"],
                       username_field=args.get("username_field") or "username",
                       password_field=args.get("password_field") or "password",
                       roe_guard=guard)
        return _fmt(r)
    except Exception as e:
        return {"content": [{"type": "text", "text": f"nosql_scan error: {e}"}],
                "isError": True}


@tool(
    "crlf_scan",
    "CRLF injection / HTTP response splitting probe.",
    {"target_url": str, "param": str},
)
async def tool_crlf_scan(args):
    try:
        guard = ROEGuard(engine_cfg=load_engine())
        r = crlf.scan(args["target_url"],
                      param=args.get("param") or None,
                      roe_guard=guard)
        return _fmt(r)
    except Exception as e:
        return {"content": [{"type": "text", "text": f"crlf_scan error: {e}"}],
                "isError": True}


@tool(
    "open_redirect_scan",
    "Open redirect probe across common redirect params.",
    {"target_url": str, "param": str},
)
async def tool_open_redirect_scan(args):
    try:
        guard = ROEGuard(engine_cfg=load_engine())
        r = open_redirect.scan(args["target_url"],
                               param=args.get("param") or None,
                               roe_guard=guard)
        return _fmt(r)
    except Exception as e:
        return {"content": [{"type": "text", "text": f"open_redirect_scan error: {e}"}],
                "isError": True}


@tool(
    "host_header_scan",
    "Host header injection / reflection probe.",
    {"target_url": str},
)
async def tool_host_header_scan(args):
    try:
        guard = ROEGuard(engine_cfg=load_engine())
        r = host_header.scan(args["target_url"], roe_guard=guard)
        return _fmt(r)
    except Exception as e:
        return {"content": [{"type": "text", "text": f"host_header_scan error: {e}"}],
                "isError": True}
