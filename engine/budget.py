"""Shared outbound request budget across the whole process.

Counts every HTTP request made by the scanner against the engagement's
limits:
  - max_requests (roe.yaml safety.max_requests_per_scan or
                  engine.yaml budget.max_http_requests)
  - max_requests_per_host (engine.yaml budget.max_requests_per_host)
  - max_duration_seconds (roe.yaml safety.max_scan_duration_seconds or
                          engine.yaml budget.max_duration_seconds)

Enforced by engine.http.Client and engine.http_client.HttpClient.
"""
import threading
import time
from urllib.parse import urlparse


class BudgetExceeded(RuntimeError):
    pass


_lock = threading.Lock()
_state = {
    "enabled": True,
    "requests": 0,
    "per_host": {},
    "started_at": None,
    "max_requests": None,
    "max_per_host": None,
    "max_duration_seconds": None,
}


def configure(max_requests=None, max_per_host=None,
              max_duration_seconds=None):
    """Reset and configure the budget. Idempotent."""
    with _lock:
        _state["enabled"] = True
        _state["requests"] = 0
        _state["per_host"] = {}
        _state["started_at"] = time.monotonic()
        _state["max_requests"] = max_requests
        _state["max_per_host"] = max_per_host
        _state["max_duration_seconds"] = max_duration_seconds


def disable():
    with _lock:
        _state["enabled"] = False


def enable():
    with _lock:
        _state["enabled"] = True


def is_configured():
    with _lock:
        return _state["started_at"] is not None


def snapshot():
    with _lock:
        return {
            "requests": _state["requests"],
            "per_host": dict(_state["per_host"]),
            "max_requests": _state["max_requests"],
            "max_per_host": _state["max_per_host"],
            "max_duration_seconds": _state["max_duration_seconds"],
            "started_at_monotonic": _state["started_at"],
        }


def record(url):
    """Record one outbound request. Raise BudgetExceeded if any cap hit."""
    if not _state.get("enabled", True):
        return
    host = urlparse(str(url)).hostname or ""
    with _lock:
        st = _state
        if st["max_requests"] is not None and \
                st["requests"] >= st["max_requests"]:
            raise BudgetExceeded(
                f"request budget exceeded "
                f"({st['requests']}/{st['max_requests']})"
            )
        if st["max_per_host"] is not None:
            cur = st["per_host"].get(host, 0)
            if cur >= st["max_per_host"]:
                raise BudgetExceeded(
                    f"host budget exceeded for {host} "
                    f"({cur}/{st['max_per_host']})"
                )
        if st["max_duration_seconds"] is not None \
                and st["started_at"] is not None:
            elapsed = time.monotonic() - st["started_at"]
            if elapsed > st["max_duration_seconds"]:
                raise BudgetExceeded(
                    f"duration budget exceeded "
                    f"({elapsed:.0f}s/{st['max_duration_seconds']}s)"
                )
        st["requests"] += 1
        st["per_host"][host] = st["per_host"].get(host, 0) + 1


def auto_configure_from_configs():
    """Read roe.yaml + engine.yaml and configure the budget.

    roe.yaml values (if present) take precedence over engine.yaml values,
    since roe.yaml is engagement-specific.
    """
    try:
        from .config import load_roe, load_engine
        roe = load_roe() or {}
        eng = load_engine() or {}
    except Exception:
        return
    safety = roe.get("safety") or {}
    budget_cfg = eng.get("budget") or {}
    configure(
        max_requests=(safety.get("max_requests_per_scan")
                      or budget_cfg.get("max_http_requests")),
        max_per_host=budget_cfg.get("max_requests_per_host"),
        max_duration_seconds=(safety.get("max_scan_duration_seconds")
                              or budget_cfg.get("max_duration_seconds")),
    )


__all__ = [
    "BudgetExceeded", "configure", "disable", "enable", "is_configured",
    "record", "snapshot", "auto_configure_from_configs",
]
