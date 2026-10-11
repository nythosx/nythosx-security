"""Compatibility wrapper over engine.http.Client.

HttpClient preserves the legacy call signature used by executor.py,
route_enum.py, idor.py, combo.py, ssrf.py, baseline.py, and auth_flow.py
while delegating all outbound traffic to the central client so ROE, the
shared rate limiter, and the request budget are enforced uniformly.
"""
import hashlib
import time

from . import http as _http


class HttpClient:
    def __init__(self, default_headers=None, timeout=30.0, verify=True,
                 roe_guard=None, rotate_ua=False, max_retries=3, backoff_base_ms=500,
                 cookies=None, rate_limit_global_rps=10,
                 rate_limit_per_endpoint_rps=5, rate_limit_burst=20,
                 rate_limit_on_429_ms=5000, shared_rate_limit=True):
        self._default_headers = dict(default_headers or {})
        self._cookies = dict(cookies or {})
        self._client = _http.Client(
            timeout=timeout, verify=verify,
            rate_limit_global_rps=rate_limit_global_rps,
            rate_limit_per_endpoint_rps=rate_limit_per_endpoint_rps,
            rate_limit_burst=rate_limit_burst,
            rate_limit_on_429_ms=rate_limit_on_429_ms,
        )
        self._closed = False

    def _merged_headers(self, extra, skip_default, skip_cookies):
        merged = {} if skip_default else dict(self._default_headers)
        if extra:
            merged.update(extra)
        if not skip_cookies and self._cookies:
            has_cookie = any(k.lower() == "cookie" for k in merged)
            if not has_cookie:
                merged["Cookie"] = "; ".join(
                    f"{k}={v}" for k, v in self._cookies.items())
        return merged

    def request(self, method, url, headers=None, json=None, data=None, params=None,
                skip_default_headers=False, skip_rate_limit=False,
                skip_cookies=False, follow_redirects=False):
        merged = self._merged_headers(headers, skip_default_headers, skip_cookies)
        t0 = time.perf_counter()
        try:
            r = self._client.request(
                method.upper(), url,
                headers=merged or None,
                json=json, data=data, params=params,
                skip_rate_limit=skip_rate_limit,
                follow_redirects=follow_redirects,
            )
        except _http.ROEBlock as e:
            return self._error(url, f"ROE_BLOCK: {e}", t0)
        except _http.ConnectError as e:
            return self._error(url, f"connection error: {e}", t0)
        except _http.TimeoutException:
            return self._error(url, "timeout", t0)
        except Exception as e:
            return self._error(url, f"{type(e).__name__}: {e}", t0)
        elapsed = (time.perf_counter() - t0) * 1000.0
        body = r.text or ""
        return {
            "status": r.status_code,
            "headers": dict(r.headers),
            "body": body,
            "body_hash": hashlib.sha256(
                body.encode("utf-8", "ignore")).hexdigest()[:16],
            "time_ms": round(elapsed, 3),
            "url": str(r.url),
            "error": None,
            "attempts": 1,
            "set_cookies": dict(r.cookies),
        }

    @staticmethod
    def _error(url, msg, t0):
        return {
            "status": None, "headers": {}, "body": "", "body_hash": None,
            "time_ms": round((time.perf_counter() - t0) * 1000.0, 3),
            "url": url, "error": msg, "attempts": 1,
        }

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


__all__ = ["HttpClient"]
