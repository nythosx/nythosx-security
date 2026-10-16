from __future__ import annotations

import time


def should_pause(step, obj=None):
    if obj is None:
        return False
    if not getattr(obj, "approval_mode", False):
        return False
    if not isinstance(step, dict):
        return False
    tool = step.get("tool")
    if not tool:
        return False
    try:
        from . import registry
        checker = getattr(registry, "requires_approval", None)
        if callable(checker):
            url = ""
            args = step.get("args") or {}
            if isinstance(args, dict):
                url = args.get("url") or args.get("target") or ""
            return bool(checker(tool, url))
    except Exception:
        pass
    try:
        from .chain_engine import ChainOrchestrator
        return tool in ChainOrchestrator._DESTRUCTIVE_TOOLS
    except Exception:
        return False


def record_pending(obj, chain_id, step):
    if obj is None or not isinstance(step, dict):
        return None
    try:
        pending = getattr(obj, "pending_approval", None)
        if pending is None:
            pending = []
            setattr(obj, "pending_approval", pending)
        entry = {
            "chain": str(chain_id or ""),
            "step": step.get("id") or step.get("step"),
            "tool": step.get("tool"),
            "args": step.get("args") or {},
            "ts": time.time(),
            "approved": False,
        }
        pending.append(entry)
        return entry
    except Exception:
        return None


def is_approved(obj, chain_id, step_id):
    if obj is None:
        return False
    pending = getattr(obj, "pending_approval", None) or []
    for p in pending:
        if not isinstance(p, dict):
            continue
        if p.get("chain") == chain_id and p.get("step") == step_id:
            return bool(p.get("approved"))
    return False


def mark_approved(obj, chain_id, step_id):
    if obj is None:
        return False
    pending = getattr(obj, "pending_approval", None) or []
    for p in pending:
        if not isinstance(p, dict):
            continue
        if p.get("chain") == chain_id and p.get("step") == step_id:
            p["approved"] = True
            return True
    return False


__all__ = [
    "should_pause", "record_pending", "is_approved", "mark_approved",
]
