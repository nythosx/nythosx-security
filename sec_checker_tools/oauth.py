from claude_agent_sdk import tool

from engine.config import load_engine
from engine.oauth import discovery, redirect_uri, state_probe, pkce_probe, id_token
from engine.roe_guard import ROEGuard
from engine import registry


for _cap in (discovery.CAPABILITY, redirect_uri.CAPABILITY,
              state_probe.CAPABILITY, pkce_probe.CAPABILITY,
              id_token.CAPABILITY):
    try:
        registry.register(_cap)
    except Exception:
        pass


def _fmt(r):
    return {"content": [{"type": "text",
                         "text": f"{r['verdict']}: {r.reason}"}],
            "structuredContent": r.to_dict()}


@tool(
    "oauth_discovery",
    "Fetch the OIDC .well-known/openid-configuration document.",
    {"base_url": str},
)
async def tool_oauth_discovery(args):
    try:
        guard = ROEGuard(engine_cfg=load_engine())
        r = discovery.scan(args["base_url"], roe_guard=guard)
        return _fmt(r)
    except Exception as e:
        return {"content": [{"type": "text", "text": f"oauth_discovery error: {e}"}],
                "isError": True}


@tool(
    "oauth_redirect_uri_scan",
    "OAuth redirect_uri bypass probe across 12 techniques.",
    {"auth_endpoint": str, "target_host": str},
)
async def tool_oauth_redirect_uri(args):
    try:
        guard = ROEGuard(engine_cfg=load_engine())
        r = redirect_uri.scan(args["auth_endpoint"],
                              target_host=args.get("target_host") or None,
                              roe_guard=guard)
        return _fmt(r)
    except Exception as e:
        return {"content": [{"type": "text", "text": f"oauth_redirect_uri error: {e}"}],
                "isError": True}


@tool(
    "oauth_state_scan",
    "Check whether the authorization endpoint requires the state parameter.",
    {"auth_endpoint": str},
)
async def tool_oauth_state(args):
    try:
        guard = ROEGuard(engine_cfg=load_engine())
        r = state_probe.scan(args["auth_endpoint"], roe_guard=guard)
        return _fmt(r)
    except Exception as e:
        return {"content": [{"type": "text", "text": f"oauth_state_scan error: {e}"}],
                "isError": True}


@tool(
    "oauth_pkce_scan",
    "PKCE downgrade / absence probe.",
    {"auth_endpoint": str},
)
async def tool_oauth_pkce(args):
    try:
        guard = ROEGuard(engine_cfg=load_engine())
        r = pkce_probe.scan(args["auth_endpoint"], roe_guard=guard)
        return _fmt(r)
    except Exception as e:
        return {"content": [{"type": "text", "text": f"oauth_pkce_scan error: {e}"}],
                "isError": True}


@tool(
    "oauth_id_token_scan",
    "Reuse the JWT attack suite against an OAuth id_token.",
    {"target_url": str, "id_token": str, "method": str},
)
async def tool_oauth_id_token(args):
    try:
        guard = ROEGuard(engine_cfg=load_engine())
        r = id_token.scan(args["target_url"], args["id_token"],
                          method=(args.get("method") or "GET").upper(),
                          roe_guard=guard)
        return _fmt(r)
    except Exception as e:
        return {"content": [{"type": "text", "text": f"oauth_id_token error: {e}"}],
                "isError": True}
