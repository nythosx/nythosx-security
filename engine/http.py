"""Central HTTP client.

Every outbound request from a scanner module should go through here so that
ROE, the shared rate limiter, TLS verification, and the global request
budget are enforced uniformly.

The Client class is a drop-in replacement for httpx.Client for the subset
of the API the scanner uses: .get, .post, .put, .patch, .delete, .head,
.request, context manager, .close.

Redirects are followed only to same-origin URLs, and each hop is checked
against ROE, the rate limiter, and the budget. Off-origin redirects are
returned as-is (not followed) so callers see the original Location header.
"""
import threading

import httpx as _httpx

from . import budget
from .config import load_engine
from .ratelimit import get_shared_limiter
from .roe_guard import ROEGuard, ROEViolation


# Re-exports so callers don't need to import httpx just for exceptions.
ConnectError = _httpx.ConnectError
TimeoutException = _httpx.TimeoutException
NetworkError = _httpx.NetworkError
RequestError = _httpx.RequestError
HTTPError = _httpx.HTTPError
HTTPStatusError = _httpx.HTTPStatusError
InvalidURL = _httpx.InvalidURL


class ROEBlock(RuntimeError):
    """Raised when the ROE guard refuses a request."""


_config_lock = threading.Lock()
_configured = False


def ensure_configured():
    """Configure the budget from configs once per process."""
    global _configured
    if _configured:
        return
    with _config_lock:
        if _configured:
            return
        try:
            budget.auto_configure_from_configs()
        except Exception:
            pass
        _configured = True


class Client:
    """Central HTTP client. Use as a context manager."""

    def __init__(self, *args, **kwargs):
        ensure_configured()
        cfg = load_engine() or {}
        http_cfg = cfg.get("http") or {}
        rl_cfg = cfg.get("rate_limit") or {}

        # Optional per-instance rate limit overrides. If a caller passes
        # rate_limit_* explicitly, honor them; otherwise fall back to config.
        _rl_global = kwargs.pop("rate_limit_global_rps", None)
        _rl_per_ep = kwargs.pop("rate_limit_per_endpoint_rps", None)
        _rl_burst = kwargs.pop("rate_limit_burst", None)
        _rl_on_429 = kwargs.pop("rate_limit_on_429_ms", None)

        # Config-driven defaults
        kwargs.setdefault("timeout", http_cfg.get("timeout_seconds", 30))
        if "verify" not in kwargs:
            kwargs["verify"] = bool(http_cfg.get("verify_tls", True))

        # Pull follow_redirects — handled by us, not httpx, so we can
        # enforce ROE on every hop.
        self._follow_default = bool(kwargs.pop("follow_redirects", False))

        # Ensure headers dict + default UA
        headers = kwargs.pop("headers", None) or {}
        headers = dict(headers)
        ua = http_cfg.get("default_user_agent")
        if ua and not any(k.lower() == "user-agent" for k in headers):
            headers["User-Agent"] = ua
        self._default_headers = headers

        self._client = _httpx.Client(*args, **kwargs)
        self._roe = ROEGuard(engine_cfg=cfg)
        self._limiter = get_shared_limiter(
            global_rps=(_rl_global if _rl_global is not None
                        else rl_cfg.get("global_rps", 10)),
            per_endpoint_rps=(_rl_per_ep if _rl_per_ep is not None
                              else rl_cfg.get("per_endpoint_rps", 5)),
            burst=(_rl_burst if _rl_burst is not None
                   else rl_cfg.get("burst", 20)),
            on_429_backoff_ms=(_rl_on_429 if _rl_on_429 is not None
                               else rl_cfg.get("on_429_backoff_ms", 5000)),
        )
        self._closed = False

    # -- enforcement ------------------------------------------------------
    def _pre(self, method, url, skip_rate_limit=False):
        try:
            self._roe.check_url(str(url), method)
        except ROEViolation as e:
            raise ROEBlock(f"ROE_BLOCK: {e}") from e
        if not skip_rate_limit:
            self._limiter.acquire(str(url))
        budget.record(str(url))

    def _follow(self, r, max_hops=5, headers=None, method="GET",
                body_kwargs=None):
        from urllib.parse import urljoin, urlparse
        hops = 0
        body_kwargs = body_kwargs or {}
        while 300 <= r.status_code < 400 and hops < max_hops:
            loc = r.headers.get("location")
            if not loc:
                break
            nxt = urljoin(str(r.url), loc)
            if (urlparse(nxt).hostname or "") != \
                    (urlparse(str(r.url)).hostname or ""):
                break
            preserve = r.status_code in (307, 308)
            next_method = method if preserve else "GET"
            try:
                self._roe.check_url(nxt, next_method)
            except ROEViolation:
                break
            self._limiter.acquire(nxt)
            budget.record(nxt)
            req_kwargs = dict(body_kwargs) if preserve else {}
            r = self._client.request(next_method, nxt, follow_redirects=False,
                                     headers=headers or {}, **req_kwargs)
            hops += 1
        return r

    # -- httpx-compatible surface ----------------------------------------
    def request(self, method, url, **kwargs):
        skip_rate_limit = kwargs.pop("skip_rate_limit", False)
        skip_default_headers = kwargs.pop("skip_default_headers", False)
        follow = kwargs.pop("follow_redirects", self._follow_default)

        self._pre(method, url, skip_rate_limit=skip_rate_limit)

        req_headers = dict(kwargs.pop("headers", None) or {})
        if not skip_default_headers:
            for k, v in self._default_headers.items():
                req_headers.setdefault(k, v)

        body_kwargs = {}
        for key in ("json", "data", "content"):
            if key in kwargs:
                body_kwargs[key] = kwargs[key]

        r = self._client.request(method, url,
                                 headers=req_headers or None,
                                 follow_redirects=False, **kwargs)
        if r.status_code == 429:
            self._limiter.on_429()
        if follow:
            r = self._follow(r, headers=req_headers or None,
                             method=method, body_kwargs=body_kwargs)
        return r

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)

    def put(self, url, **kwargs):
        return self.request("PUT", url, **kwargs)

    def patch(self, url, **kwargs):
        return self.request("PATCH", url, **kwargs)

    def delete(self, url, **kwargs):
        return self.request("DELETE", url, **kwargs)

    def head(self, url, **kwargs):
        return self.request("HEAD", url, **kwargs)

    def options(self, url, **kwargs):
        return self.request("OPTIONS", url, **kwargs)

    def close(self):
        if not self._closed:
            try:
                self._client.close()
            except Exception:
                pass
            self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


# Convenience helpers (module level). Each creates a short-lived Client.
def request(method, url, **kwargs):
    with Client() as c:
        return c.request(method, url, **kwargs)


def get(url, **kwargs):
    with Client() as c:
        return c.get(url, **kwargs)


def post(url, **kwargs):
    with Client() as c:
        return c.post(url, **kwargs)


__all__ = [
    "Client", "ROEBlock", "ensure_configured",
    "get", "post", "request",
    "ConnectError", "TimeoutException", "NetworkError",
    "RequestError", "HTTPError", "HTTPStatusError", "InvalidURL",
]
