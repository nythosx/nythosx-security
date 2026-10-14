from __future__ import annotations

from .config import load_engine
from .roe_guard import ROEGuard, ROEViolation

_default_guard = None


def _get_guard(guard=None):
    global _default_guard
    if guard is not None:
        return guard
    if _default_guard is None:
        try:
            _default_guard = ROEGuard(engine_cfg=load_engine())
        except Exception:
            return None
    return _default_guard


def check_roe(guard, url, method="GET"):
    g = _get_guard(guard)
    if g is None:
        return "ROE guard unavailable (fail-closed)"
    try:
        g.check_url(url, method)
        return None
    except ROEViolation as e:
        return str(e)


def reset_default_guard():
    global _default_guard
    _default_guard = None


__all__ = ["check_roe", "reset_default_guard"]
