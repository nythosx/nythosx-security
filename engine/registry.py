from __future__ import annotations

import importlib
import pkgutil
import threading
from pathlib import Path

from .contract import Capability


_LOCK = threading.Lock()
_REGISTRY = {}
_DISCOVERED = False


def _cap(name, description, category, cost="low", destructive=False,
         idempotent=True, prerequisites=None, default_on=True, params=None,
         required=None, examples=None, opt_in=False, destructive_reason=""):
    return Capability(
        name=name,
        description=description,
        category=category,
        cost=cost,
        destructive=destructive,
        idempotent=idempotent,
        prerequisites=list(prerequisites or []),
        default_on=default_on,
        params=params or {},
        required=list(required or []),
        examples=list(examples or []),
        opt_in=opt_in,
        destructive_reason=destructive_reason,
    )


_STATIC = {
    "sec_route": _cap(
        "sec_route",
        "List all SEC-CHECKER tools with descriptions. Use when you are unsure which scan tool to call.",
        "meta",
    ),
    "sec_scan": _cap(
        "sec_scan",
        "Run a single SEC-CHECKER pattern against a target URL.",
        "meta",
        params={"pattern_id": {"type": "string"}, "target_url": {"type": "string"}, "auth_header": {"type": "string"}},
        required=["pattern_id", "target_url"],
    ),
    "sec_list_patterns": _cap(
        "sec_list_patterns",
        "List every SEC-CHECKER pattern available to scan, grouped by category.",
        "meta",
    ),
    "bizlogic_scan": _cap(
        "bizlogic_scan",
        "Business logic flaw detection (price, mass assignment, workflow, race, coupon, verification).",
        "business-logic",
        cost="high",
        idempotent=False,
    ),
    "combo_explore": _cap(
        "combo_explore",
        "Pairwise or cartesian combination explorer across methods and paths.",
        "recon",
        cost="medium",
    ),
    "owasp_compliance": _cap(
        "owasp_compliance",
        "Generate an OWASP Top 10:2025 compliance report for a scanned target.",
        "reporting",
    ),
    "owasp_map_pattern": _cap(
        "owasp_map_pattern",
        "Map a SEC-CHECKER pattern ID to its OWASP Top 10:2025 category.",
        "reporting",
    ),
    "domxss_scan": _cap(
        "domxss_scan",
        "DOM XSS source-sink taint tracking with mXSS and Trusted Types checks.",
        "injection",
        cost="high",
    ),
    "graphql_scan": _cap(
        "graphql_scan",
        "Deep GraphQL testing: depth limit, batching, CSRF, Apollo Federation bypass, field suggestion.",
        "injection",
        cost="medium",
    ),
    "idor_scan": _cap(
        "idor_scan",
        "IDOR live probe against a resource base using identity endpoint.",
        "access-control",
        cost="medium",
    ),
    "jwt_attack": _cap(
        "jwt_attack",
        "JWT attack suite: alg:none, algorithm confusion, kid injection, embedded JWK, weak secret.",
        "auth",
        cost="medium",
    ),
    "jwt_decode": _cap(
        "jwt_decode",
        "Decode a JWT and report red flags.",
        "auth",
    ),
    "llm_scan": _cap(
        "llm_scan",
        "OWASP LLM Top 10 security scan: prompt injection, sensitive disclosure, output handling, excessive agency.",
        "llm",
        cost="medium",
    ),
    "openapi_scan": _cap(
        "openapi_scan",
        "OpenAPI/Swagger discovery plus schema-driven fuzzing.",
        "recon",
        cost="high",
    ),
    "race_scan": _cap(
        "race_scan",
        "Advanced race condition testing: barrier, HTTP/2 single-packet, timing histogram, replay.",
        "temporal",
        cost="high",
        idempotent=False,
    ),
    "sca_scan": _cap(
        "sca_scan",
        "Software composition analysis against OSV.dev.",
        "supply-chain",
        cost="medium",
    ),
    "sbom_generate": _cap(
        "sbom_generate",
        "Generate a CycloneDX or SPDX SBOM from a local project directory.",
        "supply-chain",
    ),
    "smuggle_scan": _cap(
        "smuggle_scan",
        "Non-destructive HTTP request smuggling timing probe (CL.TE / TE.CL).",
        "temporal",
        cost="medium",
    ),
    "ssrf_scan": _cap(
        "ssrf_scan",
        "Blind SSRF probe with out-of-band callback listener.",
        "ssrf",
        cost="medium",
    ),
    "ssrf_cloud_scan": _cap(
        "ssrf_cloud_scan",
        "Cloud metadata SSRF probe: AWS IMDS, GCP, Azure, DO, Alibaba, Oracle, K8s.",
        "ssrf",
        cost="high",
    ),
    "workflow_record": _cap(
        "workflow_record",
        "Record a multi-step browser workflow. Requires interactive stdin.",
        "business-logic",
        cost="high",
        idempotent=False,
    ),
    "workflow_list_params": _cap(
        "workflow_list_params",
        "List modifiable parameters from a recorded workflow JSON.",
        "business-logic",
    ),
    "workflow_replay": _cap(
        "workflow_replay",
        "Replay a recorded workflow with parameter substitutions.",
        "business-logic",
        cost="high",
        idempotent=False,
    ),
    "workflow_tamper": _cap(
        "workflow_tamper",
        "Auto-tamper business-critical parameters and replay a workflow.",
        "business-logic",
        cost="high",
        idempotent=False,
        destructive=True,
        default_on=False,
    ),
    "xss_scan": _cap(
        "xss_scan",
        "Blind or reflected XSS probe with OOB callback and headless browser confirmation.",
        "injection",
        cost="medium",
    ),
}


_BUNDLES = {
    "safe": lambda c: c.default_on and not c.destructive,
    "auth": lambda c: c.category in ("auth", "access-control"),
    "recon": lambda c: c.category in ("recon", "meta", "reporting", "supply-chain"),
    "full": lambda c: True,
    "destructive": lambda c: c.destructive,
}


def register(capability):
    if not isinstance(capability, Capability):
        raise TypeError("register expects Capability")
    with _LOCK:
        _REGISTRY[capability.name] = capability


def _safe_import(module_name, package):
    try:
        return importlib.import_module(f"{package}.{module_name}")
    except Exception:
        return None


def _absorb_module(mod, source):
    if mod is None:
        return
    single = getattr(mod, "CAPABILITY", None)
    if isinstance(single, Capability):
        with _LOCK:
            _REGISTRY.setdefault(single.name, single)
    many = getattr(mod, "CAPABILITIES", None)
    if isinstance(many, dict):
        for k, v in many.items():
            if isinstance(v, Capability):
                with _LOCK:
                    _REGISTRY.setdefault(k, v)
    for attr in dir(mod):
        if not attr.startswith("tool_"):
            continue
        fn = getattr(mod, attr, None)
        if fn is None:
            continue
        tname = getattr(fn, "_tool_name", None) or attr
        if tname in _STATIC:
            continue
        with _LOCK:
            if tname in _REGISTRY:
                continue
        desc = getattr(fn, "_tool_description", None) or (fn.__doc__ or "")
        with _LOCK:
            _REGISTRY.setdefault(tname, _cap(
                tname, desc.strip(), source, cost="low",
            ))


def _discover():
    global _DISCOVERED
    if _DISCOVERED:
        return
    _DISCOVERED = True
    here = Path(__file__).parent
    tools_dir = here.parent / "sec_checker_tools"
    skip_engine = {"contract", "state", "registry"}
    for info in pkgutil.iter_modules([str(here)]):
        if info.name.startswith("_") or info.name in skip_engine:
            continue
        _absorb_module(_safe_import(info.name, "engine"), "engine")
    if tools_dir.exists():
        for info in pkgutil.iter_modules([str(tools_dir)]):
            if info.name.startswith("_") or info.name == "registry":
                continue
            _absorb_module(_safe_import(info.name, "sec_checker_tools"), "mcp")


_DESTRUCTIVE_OVERRIDES = {
    "weak_password_scan": "Attempts to change the authenticated user's password to weak values.",
    "lockout_probe": "Sends repeated failed logins that can lock out real accounts.",
    "weak_credential_enum": "Attempts real credentials against the login endpoint.",
    "upload_scan": "Writes files to the target via upload endpoints.",
    "race_scan": "Sends real concurrent state-changing requests.",
    "bizlogic_scan": "Exercises checkout, coupon, and transfer flows with tampered values.",
    "workflow_tamper": "Replays recorded workflows with tampered business values.",
    "timing_sqli": "Sends time-delay SQL payloads that consume server CPU.",
    "timing_ssti": "Sends CPU-heavy template payloads.",
    "timing_xxe": "Sends external-entity XML payloads.",
    "second_order_xss": "Stores probe markers on the target for cross-endpoint checks.",
}


def _apply_destructive_overrides(caps):
    for name, reason in _DESTRUCTIVE_OVERRIDES.items():
        cap = caps.get(name)
        if cap is None:
            continue
        cap.destructive = True
        cap.default_on = False
        cap.opt_in = True
        if not cap.destructive_reason:
            cap.destructive_reason = reason
    return caps


def all_capabilities():
    _discover()
    with _LOCK:
        caps = dict(_STATIC)
        caps.update(_REGISTRY)
    return _apply_destructive_overrides(caps)


def get(name):
    return all_capabilities().get(name)


def manifest():
    caps = all_capabilities()
    return {name: cap.to_dict() for name, cap in caps.items()}


def get_bundle(name):
    fn = _BUNDLES.get(name)
    if fn is None:
        return []
    return sorted([c.name for c in all_capabilities().values() if fn(c)])


def bundles():
    return {name: get_bundle(name) for name in _BUNDLES}


def reset():
    global _DISCOVERED
    with _LOCK:
        _REGISTRY.clear()
    _DISCOVERED = False


__all__ = [
    "register", "all_capabilities", "get", "manifest",
    "get_bundle", "bundles", "reset",
]
