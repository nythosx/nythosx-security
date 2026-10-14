import time
import threading
from urllib.parse import urlparse


class TokenBucket:
    def __init__(self, rate, burst):
        self.rate = float(rate)
        self.burst = float(burst)
        self.tokens = float(burst)
        self.last = time.monotonic()

    def _refill(self, now):
        elapsed = now - self.last
        self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
        self.last = now

    def wait_time(self, now):
        self._refill(now)
        if self.tokens >= 1:
            return 0.0
        return (1 - self.tokens) / self.rate if self.rate > 0 else 1.0

    def consume(self, now):
        self._refill(now)
        self.tokens -= 1


class RateLimiter:
    def __init__(self, global_rps=10, per_endpoint_rps=5, burst=20,
                 on_429_backoff_ms=5000):
        self.global_rps = float(global_rps)
        self.per_endpoint_rps = float(per_endpoint_rps)
        self.burst = float(burst)
        self.on_429_backoff_ms = int(on_429_backoff_ms)
        self.global_bucket = TokenBucket(self.global_rps, self.burst)
        self.endpoints = {}
        self.lock = threading.Lock()

    def _key(self, url):
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}{p.path}"

    def acquire(self, url):
        key = self._key(url)
        with self.lock:
            now = time.monotonic()
            bucket = self.endpoints.get(key)
            if bucket is None:
                bucket = TokenBucket(self.per_endpoint_rps, self.burst)
                self.endpoints[key] = bucket
            wait = max(self.global_bucket.wait_time(now), bucket.wait_time(now))
            if wait > 0:
                time.sleep(wait)
                now = time.monotonic()
            self.global_bucket.consume(now)
            bucket.consume(now)

    def on_429(self):
        time.sleep(self.on_429_backoff_ms / 1000.0)

    def snapshot(self):
        with self.lock:
            return {
                "global_rps": self.global_rps,
                "per_endpoint_rps": self.per_endpoint_rps,
                "burst": self.burst,
                "global_tokens": round(self.global_bucket.tokens, 2),
                "endpoint_count": len(self.endpoints),
            }


# --- Shared limiter registry (Confidence Gap #1) ---------------------------
# A fresh HttpClient (and therefore a fresh RateLimiter) is created for every
# pattern. Under parallel scan-all that meant `global_rps` was enforced
# per-pattern, so N workers produced ~N x the intended throughput. Keying a
# single RateLimiter by its rate-config signature makes the global token
# bucket shared across every pattern/thread in the process, restoring a truly
# global cap. Per-endpoint buckets stay keyed by URL inside the instance.
_registry_lock = threading.Lock()
_shared_limiters = {}


def get_shared_limiter(global_rps=10, per_endpoint_rps=5, burst=20,
                       on_429_backoff_ms=5000):
    key = (float(global_rps), float(per_endpoint_rps), float(burst),
           int(on_429_backoff_ms))
    with _registry_lock:
        lim = _shared_limiters.get(key)
        if lim is None:
            lim = RateLimiter(global_rps, per_endpoint_rps, burst,
                              on_429_backoff_ms)
            _shared_limiters[key] = lim
        return lim


def reset_shared_limiters():
    """Clear the shared registry. Used by tests to isolate state."""
    with _registry_lock:
        _shared_limiters.clear()

def snapshot():
    with _registry_lock:
        return {
            "limiter_count": len(_shared_limiters),
            "limiters": [
                {"key": list(k), **v.snapshot()}
                for k, v in _shared_limiters.items()
            ],
        }
