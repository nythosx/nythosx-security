import json
import yaml
from pathlib import Path
from .util import atomic_write_json

ROOT = Path(__file__).parent.parent.absolute()
CONFIGS = ROOT / "configs"
SESSIONS = CONFIGS / "sessions"

DISCOVERY_DEFAULTS = {
    "prefer_https": True,
    "schemes": ["https", "http"],
    "base_paths": ["", "/api", "/api/v1", "/api/v2", "/api/latest",
                   "/v1", "/v2", "/rest", "/graphql"],
    "confirm_subpaths": ["", "/health", "/healthz", "/status", "/ping", "/version"],
    "reject_redirect_only": True,
    "follow_redirects": True,
    "probe_timeout_seconds": 6,
}


def _load(name, default=None):
    p = CONFIGS / name
    if not p.exists():
        return default or {}
    try:
        return yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except Exception:
        return default or {}


def load_engine():
    return _load("engine.yaml", {
        "http": {"timeout_seconds": 30, "follow_redirects": False, "verify_tls": True,
                 "max_retries": 3, "backoff_base_ms": 500,
                 "default_user_agent": "sec-checker/1.0"},
        "rate_limit": {"global_rps": 10, "per_endpoint_rps": 5, "burst": 20},
        "discovery": DISCOVERY_DEFAULTS,
        "roe": {"enabled": True, "enforce_scope": True, "enforce_methods": True,
                "enforce_rate_limit": True},
    })


def discovery_config():
    eng = load_engine()
    cfg = dict(DISCOVERY_DEFAULTS)
    cfg.update(eng.get("discovery") or {})
    return cfg


def load_targets():
    return _load("targets.yaml", {"targets": {}})


def load_roe():
    return _load("roe.yaml", {})


def get_target(name):
    return load_targets().get("targets", {}).get(name)


def save_session(name, data):
    SESSIONS.mkdir(parents=True, exist_ok=True)
    p = SESSIONS / f"{name}.json"
    atomic_write_json(p, data)
    return str(p)


def load_session(name):
    p = SESSIONS / f"{name}.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def list_sessions():
    if not SESSIONS.exists():
        return []
    return sorted(p.stem for p in SESSIONS.glob("*.json"))
