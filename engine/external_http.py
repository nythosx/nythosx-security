"""HTTP client for external, non-target services.

Explicitly NOT routed through engine.http.Client because:

  - ROE scope does not apply. OSV.dev, NVD, web.archive.org, crt.sh,
    cloud-provider storage endpoints, and LLM provider APIs are not the
    scan target. Their hostnames are not, and should not be, entries in
    configs/roe.yaml scope.in_scope.
  - The engagement budget counts requests to the target. External calls
    must not consume that allowance.

What IS enforced here:

  - TLS verification from configs/engine.yaml (http.verify_tls).
  - A shared external rate limiter (3 rps, burst 6), independent of the
    target's limiter.
  - A per-host circuit breaker (5 consecutive failures -> 60s open),
    independent of the target's breaker.
  - Retry with exponential backoff on transient network errors.
  - An async variant for callers that already run in an event loop.

Client and AsyncClient WRAP httpx.Client / httpx.AsyncClient instead of
inheriting from them. Composition, not inheritance, is required because
tests monkeypatch httpx.Client globally; a subclass resolves its base
class at import time and would silently skip the fake, issuing real
network traffic inside a test.
"""
import threading
import time
from urllib.parse import urlparse

import httpx

from .config import load_engine
from .ratelimit import RateLimiter

DEFAULT_TIMEOUT = 20.0
DEFAULT_RETRIES = 2
DEFAULT_BACKOFF_MS = 400
EXTERNAL_RATE_RPS = 3.0
EXTERNAL_BURST = 6
CIRCUIT_THRESHOLD = 5
CIRCUIT_COOLDOWN = 60.0


class ExternalCircuitOpen(httpx.ConnectError):
    """Raised when the per-host breaker is open. Subclasses ConnectError so
    every existing `except httpx.ConnectError` block catches it unchanged.
    """


_lock = threading.Lock()
_state = {}


class _Breaker:
    __slots__ = ("failures", "opened_at")

    def __init__(self):
        self.failures = 0
        self.opened_at = 0.0


def _verify_tls():
    try:
        cfg = load_engine() or {}
        return bool(cfg.get("http", {}).get("verify_tls", True))
    except Exception:
        return True


def _host_of(url):
    try:
        return (urlparse(str(url)).hostname or "").lower()
    except Exception:
        return ""


_external_limiter = RateLimiter(
    global_rps=EXTERNAL_RATE_RPS,
    per_endpoint_rps=EXTERNAL_RATE_RPS,
    burst=EXTERNAL_BURST,
    on_429_backoff_ms=1000,
)


def _breaker_allow(host):
    with _lock:
        st = _state.get(host)
        if st is None:
            st = _Breaker()
            _state[host] = st
        if st.failures < CIRCUIT_THRESHOLD:
            return True
        if time.monotonic() - st.opened_at >= CIRCUIT_COOLDOWN:
            st.failures = 0
            st.opened_at = 0.0
            return True
        return False


def _breaker_fail(host):
    with _lock:
        st = _state.get(host)
        if st is None:
            st = _Breaker()
            _state[host] = st
        st.failures += 1
        if st.failures >= CIRCUIT_THRESHOLD:
            st.opened_at = time.monotonic()


def _breaker_ok(host):
    with _lock:
        st = _state.get(host)
        if st is not None:
            st.failures = 0
            st.opened_at = 0.0


def breaker_snapshot():
    """Test helper: return a copy of the current breaker state."""
    with _lock:
        return {
            h: {"failures": s.failures, "opened_at": s.opened_at}
            for h, s in _state.items()
        }


def reset_breaker_state():
    """Test helper: clear all breaker state."""
    with _lock:
        _state.clear()


class Client:
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
        if "verify" not in kwargs:
            kwargs["verify"] = _verify_tls()
        self._retries = int(kwargs.pop("retries", DEFAULT_RETRIES))
        self._backoff_ms = int(kwargs.pop("backoff_ms", DEFAULT_BACKOFF_MS))
        self._inner = httpx.Client(*args, **kwargs)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        inner_exit = getattr(self._inner, "__exit__", None)
        if callable(inner_exit):
            return inner_exit(*exc)
        return False

    def close(self):
        closer = getattr(self._inner, "close", None)
        if callable(closer):
            return closer()
        return None

    def __getattr__(self, name):
        if name == "_inner":
            raise AttributeError(name)
        return getattr(self._inner, name)

    def _with_protection(self, fn, url):
        host = _host_of(url)
        if not _breaker_allow(host):
            raise ExternalCircuitOpen(
                f"external circuit open for {host}")
        _external_limiter.acquire(str(url))
        attempt = 0
        while True:
            try:
                r = fn()
            except (httpx.ConnectError, httpx.TimeoutException,
                    httpx.NetworkError):
                _breaker_fail(host)
                if attempt >= self._retries:
                    raise
                attempt += 1
                delay = (self._backoff_ms * (2 ** (attempt - 1))) / 1000.0
                time.sleep(delay)
                continue
            _breaker_ok(host)
            if getattr(r, "status_code", None) == 429:
                _external_limiter.on_429()
            return r

    def get(self, url, **kwargs):
        return self._with_protection(
            lambda: self._inner.get(url, **kwargs), url)

    def post(self, url, **kwargs):
        return self._with_protection(
            lambda: self._inner.post(url, **kwargs), url)

    def put(self, url, **kwargs):
        return self._with_protection(
            lambda: self._inner.put(url, **kwargs), url)

    def patch(self, url, **kwargs):
        return self._with_protection(
            lambda: self._inner.patch(url, **kwargs), url)

    def delete(self, url, **kwargs):
        return self._with_protection(
            lambda: self._inner.delete(url, **kwargs), url)

    def head(self, url, **kwargs):
        return self._with_protection(
            lambda: self._inner.head(url, **kwargs), url)

    def options(self, url, **kwargs):
        return self._with_protection(
            lambda: self._inner.options(url, **kwargs), url)

    def request(self, method, url, **kwargs):
        return self._with_protection(
            lambda: self._inner.request(method, url, **kwargs), url)


class AsyncClient:
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
        if "verify" not in kwargs:
            kwargs["verify"] = _verify_tls()
        self._retries = int(kwargs.pop("retries", DEFAULT_RETRIES))
        self._backoff_ms = int(kwargs.pop("backoff_ms", DEFAULT_BACKOFF_MS))
        self._inner = httpx.AsyncClient(*args, **kwargs)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        inner_aexit = getattr(self._inner, "__aexit__", None)
        if callable(inner_aexit):
            return await inner_aexit(*exc)
        return False

    async def aclose(self):
        closer = getattr(self._inner, "aclose", None)
        if callable(closer):
            return await closer()
        return None

    def __getattr__(self, name):
        if name == "_inner":
            raise AttributeError(name)
        return getattr(self._inner, name)

    async def _with_protection(self, fn, url):
        import asyncio
        host = _host_of(url)
        if not _breaker_allow(host):
            raise ExternalCircuitOpen(
                f"external circuit open for {host}")
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None, _external_limiter.acquire, str(url))
        attempt = 0
        while True:
            try:
                r = await fn()
            except (httpx.ConnectError, httpx.TimeoutException,
                    httpx.NetworkError):
                _breaker_fail(host)
                if attempt >= self._retries:
                    raise
                attempt += 1
                delay = (self._backoff_ms * (2 ** (attempt - 1))) / 1000.0
                await asyncio.sleep(delay)
                continue
            _breaker_ok(host)
            if getattr(r, "status_code", None) == 429:
                _external_limiter.on_429()
            return r

    async def get(self, url, **kwargs):
        return await self._with_protection(
            lambda: self._inner.get(url, **kwargs), url)

    async def post(self, url, **kwargs):
        return await self._with_protection(
            lambda: self._inner.post(url, **kwargs), url)

    async def put(self, url, **kwargs):
        return await self._with_protection(
            lambda: self._inner.put(url, **kwargs), url)

    async def patch(self, url, **kwargs):
        return await self._with_protection(
            lambda: self._inner.patch(url, **kwargs), url)

    async def delete(self, url, **kwargs):
        return await self._with_protection(
            lambda: self._inner.delete(url, **kwargs), url)

    async def head(self, url, **kwargs):
        return await self._with_protection(
            lambda: self._inner.head(url, **kwargs), url)

    async def options(self, url, **kwargs):
        return await self._with_protection(
            lambda: self._inner.options(url, **kwargs), url)

    async def request(self, method, url, **kwargs):
        return await self._with_protection(
            lambda: self._inner.request(method, url, **kwargs), url)


__all__ = [
    "Client", "AsyncClient", "ExternalCircuitOpen",
    "breaker_snapshot", "reset_breaker_state",
    "DEFAULT_TIMEOUT", "DEFAULT_RETRIES",
]
