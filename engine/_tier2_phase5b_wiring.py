"""Tier-2 Phase 5b wiring: Tenant + Runtime Escapes + Campaign tools & oracles."""
from .chain_engine import register_tool
from . import oracle as _oracle

def _tool_tenant_multi(orch, args):
    from .tenant import multi_tenant
    return multi_tenant.sweep(args["base_url"], args["token_a"], args["token_b"], roe_guard=orch.roe_guard)

def _tool_tenant_reg(orch, args):
    from .tenant import registration
    return registration.probe_signup(args["base_url"], roe_guard=orch.roe_guard)

def _tool_tenant_reset(orch, args):
    from .tenant import password_reset_matrix
    return password_reset_matrix.probe_entropy(args["base_url"], args["email"], roe_guard=orch.roe_guard)

def _tool_runtime_escape(orch, args):
    from . import runtime_escape
    return runtime_escape.probe(args["url"], allow_destructive=orch.allow_destructive, roe_guard=orch.roe_guard)

def _tool_campaign(orch, args):
    from . import campaign
    return campaign.run(args["target"], roe_guard=orch.roe_guard, allow_destructive=orch.allow_destructive)

def _tool_csd(orch, args):
    from .desync import csd
    return csd.browser_proof(args["url"], roe_guard=orch.roe_guard)

def _tool_cache_compose(orch, args):
    from .desync import cache_compose
    return cache_compose.compose(args["url"], roe_guard=orch.roe_guard)

register_tool("tenant_multi_sweep", _tool_tenant_multi)
register_tool("tenant_registration_probe", _tool_tenant_reg)
register_tool("tenant_reset_matrix", _tool_tenant_reset)
register_tool("runtime_escape_probe", _tool_runtime_escape)
register_tool("campaign_run", _tool_campaign)
register_tool("csd_browser_proof", _tool_csd)
register_tool("cache_compose", _tool_cache_compose)

def _oracle_tenant_breach(oracle, context):
    for s in context.get("steps", []):
        if "Cross-tenant BOLA" in (s.get("body") or ""):
            return {"verdict": "VULNERABLE", "reason": "Tenant breach confirmed"}
    return {"verdict": "PASS", "reason": "No tenant breach"}

def _oracle_mass_assign_signup(oracle, context):
    for s in context.get("steps", []):
        if "role=admin accepted" in (s.get("body") or ""):
            return {"verdict": "VULNERABLE", "reason": "Mass assignment at signup"}
    return {"verdict": "PASS", "reason": "Signup safe"}

def _oracle_reset_entropy(oracle, context):
    for s in context.get("steps", []):
        if "Low entropy" in (s.get("body") or ""):
            return {"verdict": "SUSPICIOUS", "reason": "Weak reset tokens"}
    return {"verdict": "PASS", "reason": "Reset tokens strong"}

def _oracle_runtime_escape(oracle, context):
    for s in context.get("steps", []):
        if "Runtime escape confirmed" in (s.get("body") or ""):
            return {"verdict": "VULNERABLE", "reason": "RCE/SSTI confirmed"}
    return {"verdict": "PASS", "reason": "No escape"}

def _oracle_campaign(oracle, context):
    for s in context.get("steps", []):
        if "Campaign completed" in (s.get("body") or ""):
            return {"verdict": "VULNERABLE", "reason": "Campaign chain verified"}
    return {"verdict": "PASS", "reason": "No campaign"}

def _oracle_cache_compose(oracle, context):
    for s in context.get("steps", []):
        if "PERSISTENT_CACHE_POISON" in (s.get("body") or ""):
            return {"verdict": "VULNERABLE", "reason": "Cache poisoned"}
    return {"verdict": "PASS", "reason": "Cache safe"}

_oracle._HANDLERS.update({
    "tenant_breach_confirmed": _oracle_tenant_breach,
    "mass_assignment_signup": _oracle_mass_assign_signup,
    "reset_entropy_low": _oracle_reset_entropy,
    "runtime_escape_confirmed": _oracle_runtime_escape,
    "campaign_verified": _oracle_campaign,
    "persistent_cache_poison": _oracle_cache_compose,
})
