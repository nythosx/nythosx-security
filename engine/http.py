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


_circuit_breaker_lock = threading.Lock()
_circuit_breaker_state = {}


class CircuitBreaker:
    def __init__(self, threshold=5, cooldown_seconds=60.0):
        self.threshold = int(threshold)
        self.cooldown_seconds = float(cooldown_seconds)

    def allow(self, host):
        import time as _t
        with _circuit_breaker_lock:
            entry = _circuit_breaker_state.get(host)
            if not entry:
                return True
            failures, until = entry
            if failures < self.threshold:
                return True
            if _t.monotonic() >= until:
                _circuit_breaker_state.pop(host, None)
                return True
            return False

    def record_failure(self, host):
        import time as _t
        with _circuit_breaker_lock:
            failures, _ = _circuit_breaker_state.get(host, (0, 0.0))
            failures += 1
            until = _t.monotonic() + self.cooldown_seconds
            _circuit_breaker_state[host] = (failures, until)

    def record_success(self, host):
        with _circuit_breaker_lock:
            _circuit_breaker_state.pop(host, None)


_cb_cfg_lock = threading.Lock()
_cb_cfg = None


def _cb_config():
    global _cb_cfg
    if _cb_cfg is not None:
        return _cb_cfg
    with _cb_cfg_lock:
        if _cb_cfg is not None:
            return _cb_cfg
        try:
            cfg = load_engine() or {}
            cb = cfg.get("circuit_breaker") or {}
            _cb_cfg = {
                "threshold": int(cb.get("failures_threshold", 5)),
                "cooldown_seconds": float(cb.get("cooldown_seconds", 60.0)),
            }
        except Exception:
            _cb_cfg = {"threshold": 5, "cooldown_seconds": 60.0}
        return _cb_cfg


_cb_params = _cb_config()
_default_breaker = CircuitBreaker(
    threshold=_cb_params["threshold"],
    cooldown_seconds=_cb_params["cooldown_seconds"],
)


def _get_breaker():
    return _default_breaker


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
        _waf_cfg = cfg.get("waf") or {}
        self._waf_retry_on_403 = bool(_waf_cfg.get("retry_on_403", True))
        try:
            self._waf_retry_max = max(1, int(_waf_cfg.get("retry_max", 6)))
        except (TypeError, ValueError):
            self._waf_retry_max = 6
        self._closed = False

    # -- enforcement ------------------------------------------------------
    def _pre(self, method, url, skip_rate_limit=False):
        try:
            self._roe.check_url(str(url), method)
        except ROEViolation as e:
            try:
                from . import progress as _prog
                _prog.diagnostic("roe", "warning",
                                 f"{method} {url}: {e}",
                                 url=str(url), method=method)
            except Exception:
                pass
            raise ROEBlock(f"ROE_BLOCK: {e}") from e
        if not skip_rate_limit:
            self._limiter.acquire(str(url))
        try:
            budget.record(str(url))
        except budget.BudgetExceeded as e:
            try:
                from . import progress as _prog
                _prog.diagnostic("budget", "warning",
                                 f"{method} {url}: {e}",
                                 url=str(url), method=method)
            except Exception:
                pass
            raise

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
        no_waf_retry = kwargs.pop("no_waf_retry", False)

        self._pre(method, url, skip_rate_limit=skip_rate_limit)

        req_headers = dict(kwargs.pop("headers", None) or {})
        if not skip_default_headers:
            for k, v in self._default_headers.items():
                req_headers.setdefault(k, v)

        if isinstance(kwargs.get("data"), (str, bytes, bytearray)):
            kwargs["content"] = kwargs.pop("data")

        body_kwargs = {}
        for key in ("json", "data", "content"):
            if key in kwargs:
                body_kwargs[key] = kwargs[key]

        from urllib.parse import urlparse as _urlparse
        _host = _urlparse(str(url)).netloc or ""
        _breaker = _get_breaker()
        if not _breaker.allow(_host):
            raise ROEBlock(f"CIRCUIT_OPEN: {_host}")

        import time as _time
        _t0 = _time.monotonic()
        try:
            r = self._client.request(method, url,
                                     headers=req_headers or None,
                                     follow_redirects=False, **kwargs)
        except (ConnectError, TimeoutException, NetworkError) as _e:
            _breaker.record_failure(_host)
            self._write_audit(method, url, None, _e, _t0)
            raise
        except Exception as _e:
            self._write_audit(method, url, None, _e, _t0)
            raise

        _breaker.record_success(_host)
        self._write_audit(method, url, r, None, _t0)

        if r.status_code == 429:
            self._limiter.on_429()
        
        no_mutator_retry = kwargs.get("no_mutator_retry", False)
        if r.status_code in (403, 406, 419) and not no_mutator_retry:
            try:
                from .transport_mutator import TransportMutator
                mutator = TransportMutator()
                mut_res = mutator.run(method, url, headers=req_headers, 
                                      json_body=body_kwargs.get("json"), 
                                      data=body_kwargs.get("content") or body_kwargs.get("data"), 
                                      params=kwargs.get("params"))
                if mut_res.get("status") and mut_res["status"] not in (403, 406, 419, 429, 503):
                    class MutResp:
                        pass
                    mr = MutResp()
                    mr.status_code = mut_res["status"]
                    mr.text = mut_res["body"]
                    mr.headers = mut_res["headers"]
                    mr.url = r.url
                    mr.cookies = r.cookies
                    r = mr
            except Exception:
                pass

        if (not no_waf_retry and self._waf_retry_on_403
                and r.status_code == 403):
            try:
                r = self._waf_retry(method, url, kwargs, r,
                                    skip_rate_limit, req_headers)
            except Exception:
                pass
        if follow:
            r = self._follow(r, headers=req_headers or None,
                             method=method, body_kwargs=body_kwargs)
        return r

    def _write_audit(self, method, url, response, error, t0):
        try:
            from . import audit as _audit
        except Exception:
            return
        try:
            import time as _time
            dur = (_time.monotonic() - t0) * 1000.0
        except Exception:
            dur = None
        status = None
        if response is not None:
            try:
                status = response.status_code
            except Exception:
                status = None
        try:
            _audit.record("http_request", method=method, url=str(url),
                          status=status, duration_ms=dur,
                          error=str(error) if error else None)
        except Exception:
            pass

    def _waf_retry(self, method, url, original_kwargs, initial_response,
                   skip_rate_limit, req_headers):
        from .waf import probe
        from .waf.encoder import adaptive_encode
        from .waf.fingerprint import identify
        payload_info = probe.extract_payload(method, url, original_kwargs)
        if not payload_info:
            return initial_response
        payload = payload_info["value"]
        fp = identify({
            "headers": dict(initial_response.headers),
            "body": (initial_response.text or "")[:4000],
        })
        waf_name = fp.get("waf")
        attempts = [{"encoding": "raw",
                     "status": initial_response.status_code}]
        _preferred = ()
        try:
            from .program_memory import get_waf_bypasses
            _preferred = tuple(get_waf_bypasses(waf_name or "unknown"))
        except Exception:
            pass

        cached = {"response": None}

        def _feedback(mutated):
            retry_kwargs = probe.substitute(original_kwargs, mutated,
                                             payload_info)
            retry_url = retry_kwargs.pop("_retry_url", url)
            if not skip_rate_limit:
                try:
                    self._limiter.acquire(str(retry_url))
                except Exception:
                    return 0, ""
            try:
                budget.record(str(retry_url))
            except budget.BudgetExceeded:
                return 0, ""
            try:
                r2 = self._client.request(method, retry_url,
                                           headers=req_headers or None,
                                           follow_redirects=False,
                                           **retry_kwargs)
            except Exception as e:
                attempts.append({"encoding": "?",
                                 "error": str(e)[:120]})
                return 0, ""
            attempts.append({"encoding": "?",
                             "status": r2.status_code})
            if r2.status_code and r2.status_code not in (
                    403, 406, 419, 429, 503):
                cached["response"] = r2
            return r2.status_code or 0, r2.text or ""

        name, _mutated = adaptive_encode(
            payload, waf=waf_name,
            feedback_fn=_feedback,
            max_rounds=self._waf_retry_max,
            preferred_order=_preferred,
        )
        if name and cached["response"] is not None:
            r2 = cached["response"]
            attempts.append({"encoding": name,
                             "status": r2.status_code})
            try:
                from .program_memory import record_waf_bypass
                record_waf_bypass(waf_name or "unknown", name, success=True)
            except Exception:
                pass
            try:
                r2.headers["X-SC-WAF-Bypass"] = name
                r2.headers["X-SC-WAF-Vendor"] = waf_name or "unknown"
            except Exception:
                pass
            return r2
        if initial_response.status_code == 403:
            try:
                from .waf.rag_mutator import llm_mutate
                from . import llm_service
                _client = llm_service.get_client("waf_mutator")
                if _client is not None:
                    _block_body = (initial_response.text or "")[:500]
                    _novel = llm_mutate(_client, payload,
                                         waf_name or "unknown", _block_body)
                    for _idx, _variant in enumerate(_novel):
                        if not isinstance(_variant, str) or _variant == payload:
                            continue
                        _retry_kwargs = probe.substitute(
                            original_kwargs, _variant, payload_info)
                        _retry_url = _retry_kwargs.pop("_retry_url", url)
                        try:
                            budget.record(str(_retry_url))
                        except budget.BudgetExceeded:
                            break
                        try:
                            _r3 = self._client.request(
                                method, _retry_url,
                                headers=req_headers or None,
                                follow_redirects=False, **_retry_kwargs)
                        except Exception as _e:
                            attempts.append({"encoding": f"llm_{_idx}",
                                             "error": str(_e)[:120]})
                            continue
                        attempts.append({"encoding": f"llm_{_idx}",
                                         "status": _r3.status_code})
                        if _r3.status_code != 403:
                            try:
                                _r3.headers["X-SC-WAF-Bypass"] = f"llm_{_idx}"
                                _r3.headers["X-SC-WAF-Vendor"] = (
                                    waf_name or "unknown")
                            except Exception:
                                pass
                            return _r3
            except Exception:
                pass
        try:
            initial_response.headers["X-SC-WAF-Vendor"] = waf_name or "unknown"
            initial_response.headers["X-SC-WAF-Attempts"] = str(len(attempts))
        except Exception:
            pass
        return initial_response

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
    "Client", "ROEBlock", "ensure_configured", "CircuitBreaker",
    "get", "post", "request",
    "ConnectError", "TimeoutException", "NetworkError",
    "RequestError", "HTTPError", "HTTPStatusError", "InvalidURL",
]
