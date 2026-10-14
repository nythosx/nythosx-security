"""ROE guard — fail-closed scope enforcement.

Every outbound request should call check_url() first. If scope is
unconfigured or empty, we refuse. If the host matches out_of_scope, we
refuse. If the method is not allowed, we refuse. If the path matches a
forbidden pattern (after percent-decoding, slash-collapsing, and
dot-segment resolution), we refuse. If a time window is configured and
we are outside it, we refuse.

The path normalisation closes the classic bypasses:
  /admin/../admin   -> /admin
  /admin//          -> /admin
  /%2fadmin         -> /admin
  /admin%2f         -> /admin/
"""
import fnmatch
import posixpath
import re
from datetime import datetime, time as dtime, timezone
from urllib.parse import urlparse, unquote

from .config import load_roe


class ROEViolation(Exception):
    pass


class ROEGuard:
    def __init__(self, roe=None, engine_cfg=None):
        self.roe = roe if roe is not None else load_roe()
        self.engine_cfg = engine_cfg or {}
        self.enforce = self.engine_cfg.get("roe", {}) or {}

    @staticmethod
    def _normalize_host(host):
        if not host:
            return ""
        return host.rstrip(".").lower()

    @staticmethod
    def _normalize_path(path):
        """Return (raw, normalized) path forms."""
        raw = path or "/"
        try:
            dec = unquote(raw)
        except Exception:
            dec = raw
        dec = re.sub(r"/+", "/", dec)
        try:
            dec = posixpath.normpath(dec)
        except Exception:
            pass
        if not dec.startswith("/"):
            dec = "/" + dec
        return raw, dec

    def _host_matches(self, host, pattern):
        return fnmatch.fnmatch(self._normalize_host(host),
                                self._normalize_host(pattern))

    def _check_time_window(self):
        tw = self.roe.get("time_window") or {}
        if not tw.get("enabled"):
            return
        start = tw.get("start") or ""
        end = tw.get("end") or ""
        if not (start and end):
            return
        try:
            sh, sm = (int(x) for x in start.split(":")[:2])
            eh, em = (int(x) for x in end.split(":")[:2])
        except Exception:
            return
        now = datetime.now(timezone.utc).time()
        s = dtime(sh, sm)
        e = dtime(eh, em)
        if s <= e:
            inside = s <= now <= e
        else:
            inside = now >= s or now <= e
        if not inside:
            raise ROEViolation(
                f"TIME WINDOW: current time {now} is outside "
                f"{start}-{end} UTC"
            )

    def check_url(self, url, method="GET"):
        if self.roe.get("enabled") is False:
            return True
        scope = self.roe.get("scope")
        if not scope:
            raise ROEViolation("ROE not configured: missing scope block")
        in_scope = scope.get("in_scope") or []
        if not in_scope:
            raise ROEViolation("ROE not configured: in_scope is empty")

        self._check_time_window()

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
        if forbidden:
            raw_path, norm_path = self._normalize_path(parsed.path)
            raw_l = raw_path.lower()
            norm_l = norm_path.lower()
            for fp in forbidden:
                fp_l = fp.lower()
                if any(c in fp for c in "*?["):
                    if (fnmatch.fnmatch(norm_path, fp)
                            or fnmatch.fnmatch(raw_path, fp)
                            or fnmatch.fnmatch(norm_l, fp_l)
                            or fnmatch.fnmatch(raw_l, fp_l)):
                        raise ROEViolation(
                            f"FORBIDDEN PATH: {raw_path} matches {fp}")
                else:
                    if (norm_path.startswith(fp)
                            or raw_path.startswith(fp)
                            or norm_l.startswith(fp_l)
                            or raw_l.startswith(fp_l)):
                        raise ROEViolation(f"FORBIDDEN PATH: {raw_path}")
        return True

    def check_path_normalized(self, url, method="GET"):
        return self.check_url(url, method)

    def walkthrough(self, url, method="GET"):
        try:
            self.check_url(url, method)
            return True, "allowed"
        except ROEViolation as e:
            return False, str(e)


__all__ = ["ROEGuard", "ROEViolation"]
