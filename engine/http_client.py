import time
import hashlib
import random
import httpx
from pathlib import Path
from .roe_guard import ROEGuard, ROEViolation
from .ratelimit import RateLimiter, get_shared_limiter

ROOT = Path(__file__).parent.parent.absolute()
UA_FILE = ROOT / "wordlists" / "user_agents.txt"


def _load_user_agents():
    if not UA_FILE.exists():
        return ["sec-checker/1.0"]
    return [l.strip() for l in UA_FILE.read_text(encoding="utf-8").splitlines() if l.strip()]


class HttpClient:
    def __init__(self, default_headers=None, timeout=30.0, verify=True,
                 roe_guard=None, rotate_ua=False, max_retries=3, backoff_base_ms=500,
                 cookies=None, rate_limit_global_rps=10,
                 rate_limit_per_endpoint_rps=5, rate_limit_burst=20,
                 rate_limit_on_429_ms=5000, shared_rate_limit=True):
        self.default_headers = default_headers or {}
        self.max_retries = max_retries
        self.backoff_base_ms = backoff_base_ms
        self.roe_guard = roe_guard or ROEGuard()
        self.user_agents = _load_user_agents() if rotate_ua else []
        self.client = httpx.Client(timeout=timeout, verify=verify, follow_redirects=False)
        # A shared limiter (default) enforces global_rps across every pattern
        # and worker thread in the process (Confidence Gap #1). Pass
        # shared_rate_limit=False for an isolated bucket (e.g. in tests).
        if shared_rate_limit:
            self.limiter = get_shared_limiter(
                global_rps=rate_limit_global_rps,
                per_endpoint_rps=rate_limit_per_endpoint_rps,
                burst=rate_limit_burst,
                on_429_backoff_ms=rate_limit_on_429_ms,
            )
        else:
            self.limiter = RateLimiter(
                global_rps=rate_limit_global_rps,
                per_endpoint_rps=rate_limit_per_endpoint_rps,
                burst=rate_limit_burst,
                on_429_backoff_ms=rate_limit_on_429_ms,
            )
        if cookies:
            for k, v in cookies.items():
                self.client.cookies.set(k, v)

    def _build_headers(self, extra):
        headers = {**self.default_headers, **(extra or {})}
        if self.user_agents:
            headers.setdefault("User-Agent", random.choice(self.user_agents))
        return headers

    def request(self, method, url, headers=None, json=None, data=None, params=None,
                skip_default_headers=False, skip_rate_limit=False):
        try:
            self.roe_guard.check_url(url, method)
        except ROEViolation as e:
            return {
                "status": None, "headers": {}, "body": "", "body_hash": None,
                "time_ms": 0.0, "url": url, "error": f"ROE_BLOCK: {e}", "attempts": 0,
            }
        if skip_default_headers:
            merged = dict(headers or {})
            if self.user_agents:
                merged.setdefault("User-Agent", random.choice(self.user_agents))
        else:
            merged = self._build_headers(headers)
        if not skip_rate_limit:
            self.limiter.acquire(url)
        attempt = 0
        last_error = None
        while attempt <= self.max_retries:
            t0 = time.perf_counter()
            try:
                r = self.client.request(
                    method=method.upper(), url=url, headers=merged,
                    json=json, data=data, params=params
                )
                elapsed = (time.perf_counter() - t0) * 1000.0
                body = r.text
                if r.status_code == 429:
                    self.limiter.on_429()
                return {
                    "status": r.status_code,
                    "headers": dict(r.headers),
                    "body": body,
                    "body_hash": hashlib.sha256(body.encode("utf-8", "ignore")).hexdigest()[:16],
                    "time_ms": round(elapsed, 3),
                    "url": str(r.url),
                    "error": None,
                    "attempts": attempt + 1,
                    "set_cookies": dict(r.cookies),
                }
            except (httpx.TimeoutException, httpx.NetworkError, httpx.ConnectError) as e:
                last_error = e
                attempt += 1
                if attempt <= self.max_retries:
                    time.sleep((self.backoff_base_ms * (2 ** (attempt - 1))) / 1000.0)
            except Exception as e:
                elapsed = (time.perf_counter() - t0) * 1000.0
                return {
                    "status": None, "headers": {}, "body": "", "body_hash": None,
                    "time_ms": round(elapsed, 3), "url": url,
                    "error": f"{type(e).__name__}: {e}", "attempts": attempt + 1,
                }
        return {
            "status": None, "headers": {}, "body": "", "body_hash": None,
            "time_ms": 0.0, "url": url,
            "error": f"MAX_RETRIES: {type(last_error).__name__}: {last_error}",
            "attempts": attempt,
        }

    def close(self):
        try:
            self.client.close()
        except Exception:
            pass
