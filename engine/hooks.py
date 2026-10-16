from __future__ import annotations

import threading

_lock = threading.Lock()
_post_finding_hooks = []
_post_unknown_hooks = []
_post_chain_hooks = []
_pre_chain_hooks = []


def register_post_finding_hook(fn):
    with _lock:
        if fn not in _post_finding_hooks:
            _post_finding_hooks.append(fn)
    return fn


def register_post_unknown_hook(fn):
    with _lock:
        if fn not in _post_unknown_hooks:
            _post_unknown_hooks.append(fn)
    return fn


def register_post_chain_hook(fn):
    with _lock:
        if fn not in _post_chain_hooks:
            _post_chain_hooks.append(fn)
    return fn


def register_pre_chain_hook(fn):
    with _lock:
        if fn not in _pre_chain_hooks:
            _pre_chain_hooks.append(fn)
    return fn


def fire_post_finding(orch, chain_id, step, result):
    with _lock:
        fns = list(_post_finding_hooks)
    for fn in fns:
        try:
            r = fn(orch, chain_id, step, result)
        except Exception as e:
            try:
                orch._diag("hooks", "warning",
                           f"post_finding hook {fn.__name__} failed: "
                           f"{type(e).__name__}: {e}")
            except Exception:
                pass
            continue
        if isinstance(r, dict):
            for k, v in r.items():
                if k == "extracted_data":
                    existing = result.get("extracted_data") or []
                    result["extracted_data"] = existing + list(v or [])
                elif k in ("proof_of_impact", "reproduction"):
                    if v:
                        result[k] = v
                elif k in ("cvss", "confidence_breakdown"):
                    if v:
                        existing = result.get(k) or {}
                        if isinstance(existing, dict) and isinstance(v, dict):
                            result[k] = {**existing, **v}
                        else:
                            result[k] = v
                elif k == "asvs_chapters":
                    existing = result.get("asvs_chapters") or []
                    result["asvs_chapters"] = sorted(set(existing) | set(v or []))
                elif k == "mitre_techniques":
                    existing = result.get("mitre_techniques") or []
                    result["mitre_techniques"] = sorted(set(existing) | set(v or []))
                else:
                    if k not in result or not result[k]:
                        result[k] = v
        # Also fold into evidence for downstream report
        try:
            ev = result.get("evidence") or {}
            if "extracted_data" in result and result["extracted_data"]:
                ev["extracted_data"] = result["extracted_data"]
            if "proof_of_impact" in result and result["proof_of_impact"]:
                ev["proof_of_impact"] = result["proof_of_impact"]
            result["evidence"] = ev
        except Exception:
            pass
    return result


def fire_post_unknown(orch, chain_id, step, result):
    with _lock:
        fns = list(_post_unknown_hooks)
    for fn in fns:
        try:
            fn(orch, chain_id, step, result)
        except Exception:
            pass
    return result


def fire_post_chain(orch, chain_result):
    with _lock:
        fns = list(_post_chain_hooks)
    for fn in fns:
        try:
            fn(orch, chain_result)
        except Exception:
            pass
    return chain_result


def fire_pre_chain(orch, chain):
    with _lock:
        fns = list(_pre_chain_hooks)
    for fn in fns:
        try:
            allowed = fn(orch, chain)
        except Exception:
            continue
        if allowed is False:
            return False
    return True


def clear_hooks():
    with _lock:
        _post_finding_hooks.clear()
        _post_unknown_hooks.clear()
        _post_chain_hooks.clear()
        _pre_chain_hooks.clear()


_DEFAULTS_INSTALLED = False


def _default_post_finding(orch, chain_id, step, result):
    try:
        tool = step.get("tool") or step.get("id") or ""
    except Exception:
        tool = ""
    if not isinstance(result, dict):
        return None
    verdict = result.get("verdict")
    if hasattr(verdict, "value"):
        verdict = verdict.value
    if verdict != "VULNERABLE":
        return None
    target = getattr(orch, "target", "") or ""
    evidence = result.get("evidence") or {}
    outcome = result.get("outcome") or "NONE"
    if hasattr(outcome, "value"):
        outcome = outcome.value
    try:
        from . import artifacts
        artifacts.write(
            target=target,
            kind=tool or "finding",
            value=evidence,
            chain_id=chain_id,
            outcome=str(outcome),
        )
    except Exception:
        pass
    try:
        from . import capgraph
        caps = capgraph.granted_capabilities({
            "verdict": "VULNERABLE",
            "capability": tool,
            "pattern_id": tool,
        })
    except Exception:
        caps = []
    for cap in caps or []:
        fk = capgraph.capability_to_fact(cap)
        if not fk:
            continue
        try:
            fs = getattr(orch, "fact_store", None)
            if fs is not None:
                fs.add(fk, True, source="capgraph", confidence=0.9)
        except Exception:
            pass
        try:
            orch.add_fact(fk, True, source="capgraph")
        except Exception:
            pass
    return None


def install_default_hooks():
    global _DEFAULTS_INSTALLED
    if _DEFAULTS_INSTALLED:
        return
    register_post_finding_hook(_default_post_finding)
    _DEFAULTS_INSTALLED = True


def list_hooks():
    with _lock:
        return {
            "post_finding": [getattr(f, "__name__", "?") for f in _post_finding_hooks],
            "post_unknown": [getattr(f, "__name__", "?") for f in _post_unknown_hooks],
            "post_chain": [getattr(f, "__name__", "?") for f in _post_chain_hooks],
            "pre_chain": [getattr(f, "__name__", "?") for f in _pre_chain_hooks],
        }


__all__ = [
    "register_post_finding_hook", "register_post_unknown_hook",
    "install_default_hooks",
    "register_post_chain_hook", "register_pre_chain_hook",
    "fire_post_finding", "fire_post_unknown", "fire_post_chain",
    "fire_pre_chain", "clear_hooks", "list_hooks",
]
