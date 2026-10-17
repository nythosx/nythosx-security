"""Tier-2 Phase 4 wiring: Auth T2 + GraphQL T2 tools & oracles."""
from .chain_engine import register_tool
from . import oracle as _oracle

# --- Tools ---
def _tool_jwt_pubkey_confusion(orch, args):
    from .auth_t2 import jwt_pubkey_confusion
    return jwt_pubkey_confusion.scan(args["jwks_url"], args["target_url"], args["token"], roe_guard=orch.roe_guard)

def _tool_session_fixation_chain(orch, args):
    from .auth_t2 import session_chain
    return session_chain.run_chain(args["login_url"], args["protected_url"], roe_guard=orch.roe_guard)

def _tool_oauth_mix_up(orch, args):
    from .auth_t2 import oauth_t2
    return oauth_t2.probe_mix_up(args["auth_endpoint"], args["client_id"], args["redirect_uri"], roe_guard=orch.roe_guard)

def _tool_cookie_dup_matrix(orch, args):
    from .auth_t2 import cookie_matrix
    return cookie_matrix.scan(args["url"], args["cookie_name"], roe_guard=orch.roe_guard)

def _tool_graphql_batch_alias(orch, args):
    from .graphql_t2 import batch_alias
    return batch_alias.scan(args["endpoint"], args["tenant_id"], roe_guard=orch.roe_guard)

def _tool_graphql_field_brute(orch, args):
    from .graphql_t2 import field_brute
    return field_brute.scan(args["endpoint"], roe_guard=orch.roe_guard)

def _tool_graphql_dataloader(orch, args):
    from .graphql_t2 import dataloader_probe
    return dataloader_probe.scan(args["endpoint"], roe_guard=orch.roe_guard)

def _tool_graphql_apq(orch, args):
    from .graphql_t2 import apq_downgrade
    return apq_downgrade.scan(args["endpoint"], roe_guard=orch.roe_guard)

def _tool_graphql_ws_sub(orch, args):
    from .graphql_t2 import ws_subscription
    return ws_subscription.scan(args["ws_url"], roe_guard=orch.roe_guard)

register_tool("jwt_pubkey_confusion", _tool_jwt_pubkey_confusion)
register_tool("session_fixation_chain", _tool_session_fixation_chain)
register_tool("oauth_mix_up", _tool_oauth_mix_up)
register_tool("cookie_dup_matrix", _tool_cookie_dup_matrix)
register_tool("graphql_batch_alias", _tool_graphql_batch_alias)
register_tool("graphql_field_brute", _tool_graphql_field_brute)
register_tool("graphql_dataloader", _tool_graphql_dataloader)
register_tool("graphql_apq_downgrade", _tool_graphql_apq)
register_tool("graphql_ws_subscription", _tool_graphql_ws_sub)

# --- Oracles ---
def _oracle_pubkey_confusion(oracle, context):
    for s in context.get("steps", []):
        if "HS256 accepted with JWKS" in (s.get("body") or ""):
            return {"verdict": "VULNERABLE", "reason": "Pubkey confusion confirmed"}
    return {"verdict": "PASS", "reason": "No pubkey confusion"}

def _oracle_session_survived(oracle, context):
    for s in context.get("steps", []):
        if "Session ID survived login" in (s.get("body") or ""):
            return {"verdict": "VULNERABLE", "reason": "Session fixation confirmed"}
    return {"verdict": "PASS", "reason": "Session rotated"}

def _oracle_cookie_precedence(oracle, context):
    for s in context.get("steps", []):
        if "Last-wins precedence" in (s.get("body") or ""):
            return {"verdict": "VULNERABLE", "reason": "Cookie precedence bypass"}
    return {"verdict": "PASS", "reason": "Cookie precedence safe"}

def _oracle_graphql_batch(oracle, context):
    for s in context.get("steps", []):
        if "Batch alias bypass" in (s.get("body") or ""):
            return {"verdict": "VULNERABLE", "reason": "Batch alias rate limit bypass"}
    return {"verdict": "PASS", "reason": "Batch aliases limited"}

def _oracle_graphql_ws(oracle, context):
    for s in context.get("steps", []):
        if "Anonymous WS subscription" in (s.get("body") or ""):
            return {"verdict": "VULNERABLE", "reason": "Unauth WS subscription"}
    return {"verdict": "PASS", "reason": "WS auth enforced"}

_oracle._HANDLERS.update({
    "pubkey_confusion_confirmed": _oracle_pubkey_confusion,
    "session_survived_login": _oracle_session_survived,
    "cookie_precedence_bypass": _oracle_cookie_precedence,
    "graphql_batch_confirmed": _oracle_graphql_batch,
    "graphql_ws_unauth": _oracle_graphql_ws,
})
