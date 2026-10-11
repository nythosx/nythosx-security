"""Central redaction for anything that leaves the process.

Everything that is written to disk (evidence, ledger, reports) or returned
to an external caller (web UI JSON, MCP tool output) passes through here
first. The goal is to keep credentials, session tokens, and provider keys
out of evidence and reports even when a probe echoes them back.

Design:
  - header blocklist (Authorization, Cookie, X-API-Key, ...)
  - token regex list (JWT, AWS, GitHub, Stripe, OpenAI, Google, Slack,
    Laravel Sanctum, private keys, generic Bearer)
  - sensitive key names: exact or known suffix (_token, _secret, _password)
    -> scalar values replaced with <REDACTED>
"""
import re


PLACEHOLDER = "<REDACTED>"


SENSITIVE_HEADERS = {
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "x-auth-token", "x-csrf-token", "x-xsrf-token",
    "x-session-token", "x-access-token",
}


_SENSITIVE_KEY_EXACT = {
    "password", "passwd", "pwd",
    "secret", "client_secret", "app_secret",
    "api_key", "apikey", "apisecret",
    "access_token", "refresh_token", "auth_token", "id_token",
    "token", "jwt", "bearer",
    "private_key", "session", "sessionid", "session_id", "session_key",
    "csrf_token", "xsrf_token", "csrf",
}

_SENSITIVE_KEY_SUFFIXES = (
    "_token", "_secret", "_password", "_passwd",
    "_api_key", "_apikey", "_api-key",
    "_private_key", "_credential", "_credentials",
    "_session", "_sessionid", "_session_id",
)


TOKEN_PATTERNS = [
    ("private_key",
     re.compile(r"-----BEGIN [A-Z0-9 ]+PRIVATE KEY-----.*?"
                r"-----END [A-Z0-9 ]+PRIVATE KEY-----", re.S)),
    ("jwt",
     re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}"
                r"\.[A-Za-z0-9_\-]+")),
    ("aws_access_key",
     re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_pat",
     re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("github_oauth",
     re.compile(r"\bgho_[A-Za-z0-9]{36}\b")),
    ("github_fine",
     re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b")),
    ("openai",
     re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b")),
    ("stripe_live",
     re.compile(r"\bsk_live_[A-Za-z0-9]{24,}\b")),
    ("stripe_test",
     re.compile(r"\bsk_test_[A-Za-z0-9]{24,}\b")),
    ("google_api",
     re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("slack",
     re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]+\b")),
    ("laravel_sanctum",
     re.compile(r"\b\d+\|[A-Za-z0-9]{40,}\b")),
    ("bearer_header",
     re.compile(r"\bBearer\s+[A-Za-z0-9\-_\.=]{16,}", re.I)),
    ("basic_header",
     re.compile(r"\bBasic\s+[A-Za-z0-9+/=]{16,}", re.I)),
]


def _norm_key(k):
    return str(k).lower().replace("-", "_")


def _is_sensitive_key(k):
    nk = _norm_key(k)
    if nk in _SENSITIVE_KEY_EXACT:
        return True
    for suf in _SENSITIVE_KEY_SUFFIXES:
        if nk.endswith(suf):
            return True
    return False


def redact_text(s):
    """Redact token patterns from a string. Idempotent."""
    if not isinstance(s, str) or not s:
        return s
    for _name, pat in TOKEN_PATTERNS:
        s = pat.sub(PLACEHOLDER, s)
    return s


def redact_headers(headers):
    """Redact sensitive header values, keep other headers readable."""
    if not headers:
        return headers
    out = {}
    for k, v in headers.items():
        if isinstance(k, str) and k.lower() in SENSITIVE_HEADERS:
            out[k] = PLACEHOLDER
        else:
            out[k] = redact_text(v) if isinstance(v, str) else v
    return out


def redact_dict(obj, _depth=0):
    """Recursively redact a nested dict/list/str structure."""
    if _depth > 14:
        return obj
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(k, str) and k.lower() in SENSITIVE_HEADERS:
                out[k] = PLACEHOLDER
            elif _is_sensitive_key(k) and isinstance(v, (str, int, float)) \
                    and not isinstance(v, bool):
                out[k] = PLACEHOLDER if v else v
            else:
                out[k] = redact_dict(v, _depth + 1)
        return out
    if isinstance(obj, list):
        return [redact_dict(v, _depth + 1) for v in obj]
    if isinstance(obj, tuple):
        return tuple(redact_dict(v, _depth + 1) for v in obj)
    if isinstance(obj, str):
        return redact_text(obj)
    return obj


__all__ = [
    "redact_text", "redact_headers", "redact_dict", "PLACEHOLDER",
    "SENSITIVE_HEADERS", "TOKEN_PATTERNS",
]
