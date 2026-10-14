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
    "phase": "chains",
    "recon_frac": 0.5,
}


def configure(max_requests=None, max_per_host=None,
              max_duration_seconds=None, recon_frac=None):
    """Reset and configure the budget. Idempotent."""
    with _lock:
        _state["enabled"] = True
        _state["requests"] = 0
        _state["per_host"] = {}
        _state["started_at"] = time.monotonic()
        _state["max_requests"] = max_requests
        _state["max_per_host"] = max_per_host
        _state["max_duration_seconds"] = max_duration_seconds
        _state["phase"] = "chains"
        if recon_frac is not None:
            try:
                _state["recon_frac"] = max(0.05, min(0.95, float(recon_frac)))
            except (TypeError, ValueError):
                pass


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
            "phase": _state.get("phase", "chains"),
            "recon_frac": _state.get("recon_frac", 0.5),
            "effective_max_requests": _effective_max_requests(),
        }


def set_phase(phase):
    with _lock:
        _state["phase"] = "recon" if phase == "recon" else "chains"


def _effective_max_requests():
    st = _state
    max_r = st["max_requests"]
    if max_r is None:
        return None
    if st.get("phase") == "recon":
        frac = st.get("recon_frac", 0.5)
        return max(10, int(max_r * frac))
    return max_r


def record(url, weight=1.0):
    """Record one outbound request. Raise BudgetExceeded if any cap hit."""
    if not _state.get("enabled", True):
        return
    try:
        weight = float(weight)
    except (TypeError, ValueError):
        weight = 1.0
    if weight <= 0:
        weight = 1.0
    host = urlparse(str(url)).hostname or ""
    with _lock:
        st = _state
        eff = _effective_max_requests()
        if eff is not None and st["requests"] >= eff:
            label = ("recon" if st.get("phase") == "recon" else "request")
            raise BudgetExceeded(
                f"{label} budget exceeded "
                f"({st['requests']}/{eff}, total cap {st['max_requests']})"
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
        st["requests"] += weight
        st["per_host"][host] = st["per_host"].get(host, 0) + weight


def raise_duration_ceiling(seconds):
    if seconds is None:
        return
    with _lock:
        cur = _state["max_duration_seconds"]
        if cur is None or seconds > cur:
            _state["max_duration_seconds"] = seconds


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


def snapshot_human():
    snap = snapshot()
    max_req = snap.get("max_requests")
    max_dur = snap.get("max_duration_seconds")
    started = snap.get("started_at_monotonic")
    elapsed = None
    if started is not None:
        import time as _t
        elapsed = round(_t.monotonic() - started, 1)
    reason = None
    eff = _effective_max_requests()
    if eff is not None and int(snap.get("requests") or 0) >= int(eff):
        label = "recon" if snap.get("phase") == "recon" else "request"
        reason = (f"{label} budget exhausted "
                  f"({snap.get('requests')}/{eff}, total {max_req})")
    elif max_dur is not None and elapsed is not None and elapsed > float(max_dur):
        reason = f"duration budget exhausted ({elapsed}s/{max_dur}s)"
    return {
        "requests": snap.get("requests", 0),
        "max": max_req,
        "per_host": snap.get("per_host", {}),
        "max_per_host": snap.get("max_per_host"),
        "elapsed_seconds": elapsed,
        "max_duration_seconds": max_dur,
        "reason": reason,
        "phase": snap.get("phase", "chains"),
        "recon_frac": snap.get("recon_frac", 0.5),
        "effective_max_requests": snap.get("effective_max_requests"),
    }


__all__ = [
    "BudgetExceeded", "configure", "disable", "enable", "is_configured",
    "record", "set_phase", "snapshot", "snapshot_human",
    "auto_configure_from_configs",
]
