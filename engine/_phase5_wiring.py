"""Phase 5 wiring: register Phase 1-4 modules as chain tools."""
from .chain_engine import register_tool


def _wrap(result):
    if hasattr(result, "to_dict"):
        d = result.to_dict()
    elif isinstance(result, dict):
        d = result
    else:
        return {"verdict": "UNKNOWN",
                "reason": f"unexpected result type: {type(result).__name__}"}
    v = d.get("verdict", "UNKNOWN")
    if hasattr(v, "value"):
        v = v.value
    return {
        "verdict": str(v),
        "reason": d.get("reason", "") or "",
        "evidence": d.get("evidence") or {},
    }


def _tool_cmdi_scan(orch, args):
    try:
        from .injection import cmdi
    except Exception as e:
        return {"verdict": "UNKNOWN",
                "reason": f"cmdi import failed: {type(e).__name__}: {e}"}
    url = args.get("url") or orch.target
    param = args.get("param") or None
    method = (args.get("method") or "GET").upper()
    try:
        return _wrap(cmdi.scan(url, param=param, method=method,
                                roe_guard=orch.roe_guard))
    except Exception as e:
        return {"verdict": "UNKNOWN",
                "reason": f"cmdi failed: {type(e).__name__}: {e}"}


def _tool_lfi_scan(orch, args):
    try:
        from .injection import lfi
    except Exception as e:
        return {"verdict": "UNKNOWN",
                "reason": f"lfi import failed: {type(e).__name__}: {e}"}
    url = args.get("url") or orch.target
    param = args.get("param") or None
    try:
        return _wrap(lfi.scan(url, param=param,
                               roe_guard=orch.roe_guard))
    except Exception as e:
        return {"verdict": "UNKNOWN",
                "reason": f"lfi failed: {type(e).__name__}: {e}"}


def _tool_ldap_scan(orch, args):
    try:
        from .injection import ldap
    except Exception as e:
        return {"verdict": "UNKNOWN",
                "reason": f"ldap import failed: {type(e).__name__}: {e}"}
    url = args.get("login_url") or args.get("url") or orch.target
    try:
        return _wrap(ldap.scan(url, roe_guard=orch.roe_guard))
    except Exception as e:
        return {"verdict": "UNKNOWN",
                "reason": f"ldap failed: {type(e).__name__}: {e}"}


def _tool_password_reset_scan(orch, args):
    try:
        from .injection import password_reset
    except Exception as e:
        return {"verdict": "UNKNOWN",
                "reason": f"password_reset import failed: {type(e).__name__}: {e}"}
    url = args.get("url") or orch.get_fact("api_base") or orch.target
    try:
        return _wrap(password_reset.scan(url, roe_guard=orch.roe_guard))
    except Exception as e:
        return {"verdict": "UNKNOWN",
                "reason": f"password_reset failed: {type(e).__name__}: {e}"}


def _tool_saml_discovery(orch, args):
    try:
        from .saml import discovery
    except Exception as e:
        return {"verdict": "UNKNOWN",
                "reason": f"saml.discovery import failed: {type(e).__name__}: {e}"}
    url = args.get("url") or orch.get_fact("api_base") or orch.target
    try:
        return _wrap(discovery.scan(url, roe_guard=orch.roe_guard))
    except Exception as e:
        return {"verdict": "UNKNOWN",
                "reason": f"saml.discovery failed: {type(e).__name__}: {e}"}


def _tool_saml_xsw(orch, args):
    try:
        from .saml import xsw
    except Exception as e:
        return {"verdict": "UNKNOWN",
                "reason": f"saml.xsw import failed: {type(e).__name__}: {e}"}
    acs_url = args.get("acs_url") or orch.get_context("saml_acs_url")
    saml_response = (args.get("saml_response")
                      or orch.get_context("saml_response"))
    if not acs_url or not saml_response:
        return {"verdict": "UNKNOWN",
                "reason": ("saml_xsw requires acs_url and saml_response "
                            "(supply via context or args)")}
    try:
        return _wrap(xsw.scan(acs_url, saml_response,
                                roe_guard=orch.roe_guard))
    except Exception as e:
        return {"verdict": "UNKNOWN",
                "reason": f"saml.xsw failed: {type(e).__name__}: {e}"}


def _tool_mfa_bypass(orch, args):
    try:
        from . import mfa_probe
    except Exception as e:
        return {"verdict": "UNKNOWN",
                "reason": f"mfa_probe import failed: {type(e).__name__}: {e}"}
    url = (args.get("mfa_url") or orch.get_context("mfa_url")
           or args.get("url"))
    if not url:
        return {"verdict": "UNKNOWN",
                "reason": "mfa_bypass requires mfa_url (args or context)"}
    base_body = args.get("base_body") or orch.get_context("mfa_base_body")
    try:
        return _wrap(mfa_probe.scan(url, base_body=base_body,
                                     authorized=bool(orch.allow_destructive),
                                     roe_guard=orch.roe_guard))
    except Exception as e:
        return {"verdict": "UNKNOWN",
                "reason": f"mfa_bypass failed: {type(e).__name__}: {e}"}


def _tool_bizlogic_dynamic(orch, args):
    try:
        from . import bizlogic
    except Exception as e:
        return {"verdict": "UNKNOWN",
                "reason": f"bizlogic import failed: {type(e).__name__}: {e}"}
    endpoints = (args.get("endpoints")
                 or orch.get_context("workflow_endpoints")
                 or {})
    if not endpoints:
        return {"verdict": "UNKNOWN",
                "reason": "no workflow endpoints discovered",
                "evidence": {}}
    base = (args.get("base_url") or orch.get_fact("api_base")
            or orch.target)
    try:
        out = bizlogic.scan(base, roe_guard=orch.roe_guard,
                             endpoints=endpoints)
    except Exception as e:
        return {"verdict": "UNKNOWN",
                "reason": f"bizlogic_dynamic failed: {type(e).__name__}: {e}"}
    return {
        "verdict": out.get("verdict", "UNKNOWN"),
        "reason": out.get("reason", ""),
        "evidence": out.get("probes", {}),
    }


register_tool("cmdi_scan", _tool_cmdi_scan)
register_tool("lfi_scan", _tool_lfi_scan)
register_tool("ldap_scan", _tool_ldap_scan)
register_tool("password_reset_scan", _tool_password_reset_scan)
register_tool("saml_discovery", _tool_saml_discovery)
register_tool("saml_xsw", _tool_saml_xsw)
register_tool("mfa_bypass", _tool_mfa_bypass)
register_tool("bizlogic_dynamic", _tool_bizlogic_dynamic)
