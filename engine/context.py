"""Path-aware severity adjustment.

A pattern declares a base severity. This module adjusts it based on the URL
being tested: a 403 bypass on /health is info, the same bypass on
/api/admin/users is critical. The higher of the two wins.
"""
import re
from urllib.parse import urlparse


SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


SENSITIVE_PATTERNS = [
    ("critical", [
        r"/admin(?:\b|/|$)",
        r"/api/admin(?:\b|/|$)",
        r"/internal(?:\b|/|$)",
        r"/api/keys?(?:\b|/|$)",
        r"/billing(?:\b|/|$)",
        r"/payment(?:\b|/|$)",
        r"/transfer(?:\b|/|$)",
        r"/withdraw(?:\b|/|$)",
        r"/delete(?:\b|/|$)",
        r"/sudo(?:\b|/|$)",
    ]),
    ("high", [
        r"/api/users?(?:\b|/|$)",
        r"/api/me(?:\b|/|$)",
        r"/api/account(?:\b|/|$)",
        r"/orders?(?:\b|/|$)",
        r"/profile(?:\b|/|$)",
        r"/settings(?:\b|/|$)",
        r"/api/token(?:\b|/|$)",
        r"/api/auth(?:\b|/|$)",
        r"/oauth(?:\b|/|$)",
        r"/session(?:\b|/|$)",
        r"/password(?:\b|/|$)",
    ]),
    ("medium", [
        r"/api(?:\b|/|$)",
        r"/graphql(?:\b|/|$)",
        r"/upload(?:\b|/|$)",
        r"/search(?:\b|/|$)",
        r"/query(?:\b|/|$)",
        r"/filter(?:\b|/|$)",
    ]),
    ("low", [
        r"/health(?:\b|/|$)",
        r"/healthz(?:\b|/|$)",
        r"/status(?:\b|/|$)",
        r"/ping(?:\b|/|$)",
        r"/version(?:\b|/|$)",
        r"/metrics(?:\b|/|$)",
        r"/robots\.txt",
        r"/favicon\.ico",
    ]),
]


def _rank(sev):
    try:
        return SEVERITY_ORDER.index((sev or "info").lower())
    except ValueError:
        return 0


def _path_severity(path):
    p = (path or "/").lower()
    for level, pats in SENSITIVE_PATTERNS:
        for pat in pats:
            if re.search(pat, p):
                return level
    return None


def context_severity(url, pattern_severity):
    try:
        path = urlparse(url).path
    except Exception:
        path = url or "/"
    ctx = _path_severity(path)
    if ctx is None:
        return pattern_severity
    if _rank(ctx) > _rank(pattern_severity):
        return ctx
    return pattern_severity


__all__ = ["context_severity", "SENSITIVE_PATTERNS", "SEVERITY_ORDER"]
