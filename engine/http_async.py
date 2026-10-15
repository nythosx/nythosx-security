import asyncio
import threading
from urllib.parse import urljoin, urlparse

import httpx as _httpx

from . import budget
from .config import load_engine
from .http import _get_breaker
from .ratelimit import get_shared_limiter
from .roe_guard import ROEGuard, ROEViolation


ConnectError = _httpx.ConnectError
TimeoutException = _httpx.TimeoutException
NetworkError = _httpx.NetworkError
RequestError = _httpx.RequestError
HTTPError = _httpx.HTTPError
HTTPStatusError = _httpx.HTTPStatusError
InvalidURL = _httpx.InvalidURL


class ROEBlock(RuntimeError):
    pass


_config_lock = threading.Lock()
_configured = False


def ensure_configured():
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


class AsyncClient:
    def __init__(self, *args, **kwargs):
        ensure_configured()
        cfg = load_engine() or {}
        http_cfg = cfg.get("http") or {}
        rl_cfg = cfg.get("rate_limit") or {}

        _rl_global = kwargs.pop("rate_limit_global_rps", None)
        _rl_per_ep = kwargs.pop("rate_limit_per_endpoint_rps", None)
        _rl_burst = kwargs.pop("rate_limit_burst", None)
        _rl_on_429 = kwargs.pop("rate_limit_on_429_ms", None)

        kwargs.setdefault("timeout", http_cfg.get("timeout_seconds", 30))
        if "verify" not in kwargs:
            kwargs["verify"] = bool(http_cfg.get("verify_tls", True))

        self._follow_default = bool(kwargs.pop("follow_redirects", False))

        headers = kwargs.pop("headers", None) or {}
        headers = dict(headers)
        ua = http_cfg.get("default_user_agent")
        if ua and not any(k.lower() == "user-agent" for k in headers):
            headers["User-Agent"] = ua
        self._default_headers = headers

        self._client = _httpx.AsyncClient(*args, **kwargs)
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

    def _pre(self, method, url, skip_rate_limit=False):
        try:
            self._roe.check_url(str(url), method)
        except ROEViolation as e:
            raise ROEBlock(f"ROE_BLOCK: {e}") from e
        if not skip_rate_limit:
            self._limiter.acquire(str(url))
        budget.record(str(url))

    async def _follow(self, r, max_hops=5, headers=None, method="GET",
                       body_kwargs=None):
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
            r = await self._client.request(next_method, nxt,
                                            follow_redirects=False,
                                            headers=headers or {},
                                            **req_kwargs)
            hops += 1
        return r

    async def request(self, method, url, **kwargs):
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

        host = urlparse(str(url)).netloc or ""
        breaker = _get_breaker()
        if not breaker.allow(host):
            raise ROEBlock(f"CIRCUIT_OPEN: {host}")

        try:
            r = await self._client.request(method, url,
                                            headers=req_headers or None,
                                            follow_redirects=False, **kwargs)
        except (ConnectError, TimeoutException, NetworkError):
            breaker.record_failure(host)
            raise
        except Exception:
            raise

        breaker.record_success(host)

        if r.status_code == 429:
            self._limiter.on_429()
        if follow:
            r = await self._follow(r, headers=req_headers or None,
                                    method=method, body_kwargs=body_kwargs)
        return r

    async def get(self, url, **kwargs):
        return await self.request("GET", url, **kwargs)

    async def post(self, url, **kwargs):
        return await self.request("POST", url, **kwargs)

    async def put(self, url, **kwargs):
        return await self.request("PUT", url, **kwargs)

    async def patch(self, url, **kwargs):
        return await self.request("PATCH", url, **kwargs)

    async def delete(self, url, **kwargs):
        return await self.request("DELETE", url, **kwargs)

    async def head(self, url, **kwargs):
        return await self.request("HEAD", url, **kwargs)

    async def options(self, url, **kwargs):
        return await self.request("OPTIONS", url, **kwargs)

    async def close(self):
        if not self._closed:
            try:
                await self._client.aclose()
            except Exception:
                pass
            self._closed = True

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.close()
        return False


async def request(method, url, **kwargs):
    async with AsyncClient() as c:
        return await c.request(method, url, **kwargs)


async def get(url, **kwargs):
    async with AsyncClient() as c:
        return await c.get(url, **kwargs)


async def post(url, **kwargs):
    async with AsyncClient() as c:
        return await c.post(url, **kwargs)


def run_sync(coro):
    """Run an async coroutine from sync code, even if a loop is already running.

    If the caller is inside a running event loop, spawn a helper thread with
    its own event loop and block on the result. Otherwise use asyncio.run().
    """
    import asyncio
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


__all__ = [
    "AsyncClient", "ROEBlock", "ensure_configured", "run_sync",
    "get", "post", "request",
    "ConnectError", "TimeoutException", "NetworkError",
    "RequestError", "HTTPError", "HTTPStatusError", "InvalidURL",
]
