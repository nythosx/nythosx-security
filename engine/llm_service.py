from __future__ import annotations

import threading

_clients = {}
_lock = threading.Lock()
_DISABLED = ("rule_based", "rule", "none", "", "llm")


def _brain_cfg():
    try:
        from .config import load_engine
        return (load_engine() or {}).get("brain") or {}
    except Exception:
        return {}


def resolve(capability=None, cfg=None):
    bcfg = cfg if cfg is not None else _brain_cfg()
    if not bcfg.get("enabled", True):
        return None
    universal = bcfg.get("llm") or {}
    tools = bcfg.get("tools") or {}
    override = (tools.get(capability) or {}) if capability else {}
    provider = (override.get("provider") or universal.get("provider") or "").lower()
    if not provider or provider in _DISABLED:
        return None
    return {
        "provider": provider,
        "model": (override.get("model") or universal.get("model")
                  or "gpt-4o-mini"),
        "base_url": override.get("base_url") or universal.get("base_url") or None,
        "api_key_env": (override.get("api_key_env")
                        or universal.get("api_key_env") or None),
    }


def get_client(capability=None, cfg=None):
    key = capability or "__default__"
    if cfg is None:
        with _lock:
            if key in _clients:
                return _clients[key]
    resolved = resolve(capability, cfg)
    client = None
    if resolved:
        try:
            from .brains.llm import make_llm_client, _read_api_key
            if _read_api_key(None, resolved.get("api_key_env")):
                client = make_llm_client(
                    provider=resolved["provider"],
                    model=resolved["model"],
                    base_url=resolved.get("base_url"),
                    env_name=resolved.get("api_key_env"),
                )
        except Exception:
            client = None
    if cfg is None:
        with _lock:
            _clients[key] = client
    return client


def is_enabled(capability=None, cfg=None):
    return get_client(capability, cfg) is not None


def complete(prompt, capability=None, cfg=None, default=None):
    client = get_client(capability, cfg)
    if client is None:
        return default
    try:
        return client(prompt)
    except Exception:
        return default


def reset_cache():
    with _lock:
        _clients.clear()


__all__ = ["resolve", "get_client", "is_enabled", "complete", "reset_cache"]
