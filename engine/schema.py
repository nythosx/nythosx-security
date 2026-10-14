"""Lightweight schema validation for config and pattern files.

No pydantic dependency. Validates shape (types + required fields) and
raises SchemaError on the first problem.
"""


class SchemaError(ValueError):
    pass


class FieldSpec:
    __slots__ = ("type", "required", "allow_none")

    def __init__(self, type=object, required=False, allow_none=True):
        self.type = type
        self.required = required
        self.allow_none = allow_none


def _type_name(t):
    if isinstance(t, tuple):
        return " | ".join(getattr(x, "__name__", str(x)) for x in t)
    return getattr(t, "__name__", str(t))


def _coerce_field_spec(fs):
    if isinstance(fs, FieldSpec):
        return fs
    if isinstance(fs, dict):
        return FieldSpec(**fs)
    if fs is None:
        return FieldSpec(object, required=False)
    if isinstance(fs, type) or isinstance(fs, tuple):
        return FieldSpec(fs, required=False)
    raise SchemaError(f"invalid FieldSpec: {fs!r}")


def validate_shape(data, spec, where):
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise SchemaError(
            f"{where}: expected mapping, got {type(data).__name__}"
        )
    for key, raw_fs in spec.items():
        fs = _coerce_field_spec(raw_fs)
        if key not in data:
            if fs.required:
                raise SchemaError(f"{where}: missing required field '{key}'")
            continue
        val = data[key]
        if val is None and fs.allow_none:
            continue
        if fs.type is not None and not isinstance(val, fs.type):
            raise SchemaError(
                f"{where}.{key}: expected {_type_name(fs.type)}, "
                f"got {type(val).__name__}"
            )


def validate_engine(data, where="engine.yaml"):
    validate_shape(data, {
        "http": dict,
        "rate_limit": dict,
        "discovery": dict,
        "concurrency": dict,
        "evidence": dict,
        "report": dict,
        "roe": dict,
        "ssrf_cloud": dict,
        "brain": dict,
        "correlator": dict,
        "coverage": dict,
        "orchestrator": dict,
        "weak_password": dict,
        "injection": dict,
        "websocket": dict,
        "oauth": dict,
        "upload": dict,
        "http2": dict,
        "budget": dict,
        "oob": dict,
        "redaction": dict,
        "baseline": dict,
        "diff": dict,
        "scoring": dict,
        "triage": dict,
        "waf": dict,
        "iteration": dict,
        "confirm": dict,
        "banking": dict,
    }, where)
    if data.get("banking") is not None:
        validate_banking(data["banking"], where + ".banking")
    http = data.get("http")
    if isinstance(http, dict):
        v = http.get("verify_tls")
        if v is not None and not isinstance(v, bool):
            raise SchemaError(f"{where}.http.verify_tls: expected bool")
        t = http.get("timeout_seconds")
        if t is not None and (not isinstance(t, (int, float))
                                or isinstance(t, bool) or t <= 0):
            raise SchemaError(
                f"{where}.http.timeout_seconds: expected positive number")
        mr = http.get("max_retries")
        if mr is not None and (not isinstance(mr, int)
                                or isinstance(mr, bool) or mr < 0):
            raise SchemaError(
                f"{where}.http.max_retries: expected non-negative int")
    rl = data.get("rate_limit")
    if isinstance(rl, dict):
        for key in ("global_rps", "per_endpoint_rps", "burst"):
            v = rl.get(key)
            if v is None:
                continue
            if isinstance(v, bool) or not isinstance(v, (int, float)) or v <= 0:
                raise SchemaError(
                    f"{where}.rate_limit.{key}: expected positive number")


_BROAD_WILDCARD_EXACT = {"*", "*.*", "0.0.0.0/0"}
_BROAD_WILDCARD_TLDS = {"com", "net", "org", "io", "dev", "co", "ai",
                        "gov", "mil", "edu", "info", "biz", "us", "uk"}
_BROAD_WILDCARD_RANGES = {"10.*", "192.168.*", "172.16.*", "172.17.*",
                          "172.18.*", "172.19.*"}


def is_broad_scope_wildcard(pattern):
    if not pattern or not isinstance(pattern, str):
        return False
    if pattern in _BROAD_WILDCARD_EXACT:
        return True
    if pattern.startswith("*.") and pattern[2:].lower() in _BROAD_WILDCARD_TLDS:
        return True
    if pattern.endswith("/0"):
        return True
    if pattern in _BROAD_WILDCARD_RANGES:
        return True
    return False


def find_broad_scope_wildcards(roe):
    if not isinstance(roe, dict):
        return []
    scope = roe.get("scope") or {}
    in_scope = scope.get("in_scope") or []
    return [p for p in in_scope if is_broad_scope_wildcard(p)]


def validate_roe(data, where="roe.yaml"):
    validate_shape(data, {
        "enabled": bool,
        "scope": dict,
        "rate_limits": dict,
        "time_window": dict,
        "safety": dict,
    }, where)
    scope = data.get("scope")
    if scope is not None:
        validate_shape(scope, {
            "in_scope": list,
            "out_of_scope": list,
            "allowed_methods": list,
            "forbidden_paths": list,
        }, where + ".scope")
        in_scope = scope.get("in_scope") or []
        for item in in_scope:
            if item is not None and not isinstance(item, str):
                raise SchemaError(
                    f"{where}.scope.in_scope: entries must be strings")
        allowed = scope.get("allowed_methods") or []
        for m in allowed:
            if not isinstance(m, str):
                raise SchemaError(
                    f"{where}.scope.allowed_methods: entries must be strings")
        safety = data.get("safety") or {}
        if not safety.get("allow_broad_scope", False):
            broad = [p for p in in_scope if is_broad_scope_wildcard(p)]
            if broad:
                import sys as _sys
                _sys.stderr.write(
                    f"[roe-warn] {where}.scope.in_scope contains broad "
                    f"wildcard(s): {broad}. Set safety.allow_broad_scope: "
                    f"true to silence.\n")


def validate_targets(data, where="targets.yaml"):
    if not isinstance(data, dict):
        raise SchemaError(f"{where}: expected mapping")
    targets = data.get("targets")
    if targets is None:
        return
    if not isinstance(targets, dict):
        raise SchemaError(f"{where}.targets: expected mapping")
    for name, spec in targets.items():
        if not isinstance(spec, dict):
            raise SchemaError(
                f"{where}.targets.{name}: expected mapping")
        if "url" in spec and spec["url"] is not None \
                and not isinstance(spec["url"], str):
            raise SchemaError(
                f"{where}.targets.{name}.url: expected string")


def validate_credentials(data, where="credentials.yaml"):
    if not isinstance(data, dict):
        raise SchemaError(f"{where}: expected mapping")
    creds = data.get("credentials")
    if creds is None:
        return
    if not isinstance(creds, dict):
        raise SchemaError(f"{where}.credentials: expected mapping")


def validate_banking(data, where="banking"):
    if not isinstance(data, dict):
        raise SchemaError(f"{where}: expected mapping")
    for key in ("endpoints_authenticated", "endpoints_unauthenticated"):
        v = data.get(key)
        if v is None:
            continue
        if not isinstance(v, list):
            raise SchemaError(f"{where}.{key}: expected list")
        for item in v:
            if not isinstance(item, str):
                raise SchemaError(f"{where}.{key}: entries must be strings")
    mc = data.get("mask_chars")
    if mc is not None:
        if isinstance(mc, bool) or not isinstance(mc, int) or mc < 0:
            raise SchemaError(f"{where}.mask_chars: expected non-negative int")
    cipher = data.get("cipher")
    if cipher is not None and not isinstance(cipher, str):
        raise SchemaError(f"{where}.cipher: expected string")


def validate_pattern(data, where="pattern"):
    if not isinstance(data, dict):
        raise SchemaError(f"{where}: expected mapping")
    for key in ("id", "name"):
        v = data.get(key)
        if not isinstance(v, str) or not v:
            raise SchemaError(f"{where}: missing or invalid '{key}'")
    sev = data.get("severity")
    if sev not in ("critical", "high", "medium", "low", "info"):
        raise SchemaError(f"{where}: invalid severity {sev!r}")
    if not isinstance(data.get("steps"), list):
        raise SchemaError(f"{where}: 'steps' must be a list")
    if not isinstance(data.get("oracles"), list):
        raise SchemaError(f"{where}: 'oracles' must be a list")
    return True


def validate_adapter(data, where="adapter"):
    if not isinstance(data, dict):
        raise SchemaError(f"{where}: expected mapping")
    if not isinstance(data.get("id"), str) or not data["id"]:
        raise SchemaError(f"{where}: missing 'id'")
    if "detect" in data and data["detect"] is not None \
            and not isinstance(data["detect"], dict):
        raise SchemaError(f"{where}.detect: expected mapping")
    return True


def validate_chain(data, where="chain"):
    if not isinstance(data, dict):
        raise SchemaError(f"{where}: expected mapping")
    for key in ("id", "name"):
        v = data.get(key)
        if not isinstance(v, str) or not v:
            raise SchemaError(f"{where}: missing or invalid '{key}'")
    if not isinstance(data.get("trigger"), dict):
        raise SchemaError(f"{where}: 'trigger' must be a mapping")
    if not isinstance(data.get("steps"), list):
        raise SchemaError(f"{where}: 'steps' must be a list")
    return True


def validate_correlator_chain(data, where="correlator-chain"):
    if not isinstance(data, dict):
        raise SchemaError(f"{where}: expected mapping")
    for key in ("id", "name"):
        v = data.get(key)
        if not isinstance(v, str) or not v:
            raise SchemaError(f"{where}: missing or invalid '{key}'")
    if not isinstance(data.get("prerequisites"), list):
        raise SchemaError(f"{where}: 'prerequisites' must be a list")
    return True


def validate_asvs_metadata(data, where="asvs"):
    if not isinstance(data, dict):
        raise SchemaError(f"{where}: expected mapping")
    chapters = data.get("chapters")
    if chapters is not None and not isinstance(chapters, list):
        raise SchemaError(f"{where}.chapters: expected list")
    return True


def validate_writeup_family(data, where="writeup-family"):
    if not isinstance(data, dict):
        raise SchemaError(f"{where}: expected mapping")


def validate_writeup_pattern(data, where="writeup-pattern"):
    if not isinstance(data, dict):
        raise SchemaError(f"{where}: expected mapping")
    if "family" not in data:
        raise SchemaError(f"{where}: missing 'family'")


__all__ = [
    "SchemaError", "FieldSpec", "validate_shape",
    "validate_engine", "validate_roe", "validate_targets",
    "validate_credentials", "validate_pattern", "validate_adapter",
    "validate_chain", "validate_correlator_chain",
    "validate_writeup_family", "validate_writeup_pattern",
    "validate_banking", "validate_asvs_metadata",
]
