import json
import yaml
from pathlib import Path
from .util import atomic_write_json
import copy
from . import schema
from .util import strict_yaml_load

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


_ENGINE_DEFAULTS = {
    "http": {"timeout_seconds": 30, "follow_redirects": False,
             "verify_tls": True, "max_retries": 3, "backoff_base_ms": 500,
             "default_user_agent": "sec-checker/1.0"},
    "rate_limit": {"global_rps": 10, "per_endpoint_rps": 5, "burst": 20},
    "discovery": DISCOVERY_DEFAULTS,
    "roe": {"enabled": True, "enforce_scope": True, "enforce_methods": True,
            "enforce_rate_limit": True},
    "budget": {"max_http_requests": 5000,
               "max_duration_seconds": 1800,
               "max_requests_per_host": 500},
    "oob": {"callback_url": "", "external_enabled": False},
    "redaction": {"enabled": True, "extra_patterns": [],
                  "allow_patterns": []},
    "ssrf_cloud": {"allow_scanner_self_probe": False},
    "baseline": {"enabled": True, "samples": 10, "cache_ttl_seconds": 3600},
    "diff": {"signal_threshold": 0.8, "pass_threshold": 0.4},
    "scoring": {"enabled": True, "history_window": 20},
    "triage": {"enabled": True, "borderline_low": 0.4, "borderline_high": 0.8},
    "waf": {"enabled": True, "fingerprint_depth": 3, "max_encodings": 20},
    "iteration": {"enabled": False, "max_sweeps": 3, "min_budget_remaining": 0.2},
    "confirm": {"enabled": True, "max_attempts": 3, "read_only": True},
}


def _load(name, default=None, strict=False, validate=None):
    p = CONFIGS / name
    if not p.exists():
        return copy.deepcopy(default) if default is not None else {}
    try:
        text = p.read_text(encoding="utf-8")
    except Exception as e:
        if strict:
            raise RuntimeError(f"cannot read {name}: {e}") from e
        return copy.deepcopy(default) if default is not None else {}
    try:
        data = strict_yaml_load(text) if strict else yaml.safe_load(text)
    except yaml.YAMLError as e:
        if strict:
            raise RuntimeError(f"config parse error in {name}: {e}") from e
        return copy.deepcopy(default) if default is not None else {}
    if data is None:
        return copy.deepcopy(default) if default is not None else {}
    if validate is not None:
        try:
            validate(data, name)
        except schema.SchemaError as e:
            if strict:
                raise RuntimeError(f"config schema error in {name}: {e}") from e
            return copy.deepcopy(default) if default is not None else {}
    return data


def load_engine():
    data = _load("engine.yaml", default=_ENGINE_DEFAULTS,
                 strict=True, validate=schema.validate_engine)
    for key, val in _ENGINE_DEFAULTS.items():
        if key not in data:
            data[key] = copy.deepcopy(val)
    return data


def discovery_config():
    eng = load_engine()
    cfg = dict(DISCOVERY_DEFAULTS)
    cfg.update(eng.get("discovery") or {})
    return cfg


def load_targets():
    return _load("targets.yaml", {"targets": {}}, strict=True,
                 validate=schema.validate_targets)


def load_roe():
    return _load("roe.yaml", {}, strict=True, validate=schema.validate_roe)


def load_credentials():
    return _load("credentials.yaml", {"credentials": {}}, strict=True,
                 validate=schema.validate_credentials)


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
