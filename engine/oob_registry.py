"""Shared OOB listener.

The whole process uses one OOBServer. Its mode is decided once, from
configs/engine.yaml:

    oob:
      external_enabled: true
      callback_url: ''

When external_enabled is true and callback_url is set, payloads point at
the external service and no local listener is bound.
"""
import threading

from .oob import OOBServer

_SHARED = None
_LOCK = threading.Lock()


def _read_external_from_config():
    try:
        from .config import load_engine
        cfg = load_engine() or {}
        oob_cfg = cfg.get("oob") or {}
        if not oob_cfg.get("external_enabled"):
            return None
        url = (oob_cfg.get("callback_url") or "").strip()
        return url or None
    except Exception:
        return None


def get_shared_oob():
    global _SHARED
    with _LOCK:
        if _SHARED is None:
            external = _read_external_from_config()
            _SHARED = OOBServer(external_url=external).start()
        return _SHARED


def stop_shared_oob():
    global _SHARED
    with _LOCK:
        if _SHARED is not None:
            try:
                _SHARED.stop()
            except Exception:
                pass
            _SHARED = None


def reset_shared_oob():
    stop_shared_oob()


def shared_oob_base():
    try:
        return get_shared_oob().base_url
    except Exception:
        return ""


__all__ = [
    "get_shared_oob", "stop_shared_oob", "reset_shared_oob",
    "shared_oob_base",
]
