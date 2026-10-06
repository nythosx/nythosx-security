import fnmatch
from urllib.parse import urlparse
from .config import load_roe


class ROEViolation(Exception):
    pass


class ROEGuard:
    def __init__(self, roe=None, engine_cfg=None):
        self.roe = roe or load_roe()
        self.engine_cfg = engine_cfg or {}
        self.enforce = self.engine_cfg.get("roe", {}) or {}

    def _host_matches(self, host, pattern):
        return fnmatch.fnmatch(host, pattern)

    def check_url(self, url, method="GET"):
        if self.roe.get("enabled") is False:
            return True
        scope = self.roe.get("scope")
        if not scope:
            raise ROEViolation("ROE not configured: missing scope block")
        in_scope = scope.get("in_scope") or []
        if not in_scope:
            raise ROEViolation("ROE not configured: in_scope is empty")
        parsed = urlparse(url)
        host = parsed.hostname or ""
        for blocked in scope.get("out_of_scope", []):
            if self._host_matches(host, blocked):
                raise ROEViolation(f"OUT OF SCOPE: {host} matches {blocked}")
        if self.enforce.get("enforce_scope", True):
            allowed = any(self._host_matches(host, p) for p in in_scope)
            if not allowed:
                raise ROEViolation(f"NOT IN SCOPE: {host}")
        if self.enforce.get("enforce_methods", True):
            allowed_methods = scope.get("allowed_methods", [])
            if allowed_methods and method.upper() not in allowed_methods:
                raise ROEViolation(f"METHOD NOT ALLOWED: {method}")
        forbidden = scope.get("forbidden_paths", [])
        path = parsed.path or "/"
        for fp in forbidden:
            if any(c in fp for c in "*?["):
                if fnmatch.fnmatch(path, fp):
                    raise ROEViolation(f"FORBIDDEN PATH: {path} matches {fp}")
            elif path.startswith(fp):
                raise ROEViolation(f"FORBIDDEN PATH: {path}")
        return True
