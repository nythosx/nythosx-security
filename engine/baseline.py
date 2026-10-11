from __future__ import annotations

import json
import statistics
from pathlib import Path
from datetime import datetime, timezone

from .config import load_engine
from .util import safe_name
from .diff import BaselineSnapshot, build_structure

ROOT = Path(__file__).parent.parent.absolute()
BASELINE_DIR = ROOT / "findings"
ENGINE_BASELINE_DIR = ROOT / "findings" / "baselines"

class BaselineEngine:
    def __init__(self, cache_dir=None, samples=10, timeout=10.0, verify=None):
        self.cache_dir = Path(cache_dir) if cache_dir else ENGINE_BASELINE_DIR
        self.samples = int(samples)
        self.timeout = float(timeout)
        if verify is None:
            try:
                cfg = load_engine() or {}
                verify = bool(cfg.get("http", {}).get("verify_tls", True))
            except Exception:
                verify = True
        self.verify = bool(verify)

    def cache_key(self, target, url, method="GET"):
        return safe_name(target) + "__" + safe_name(method + "_" + url)

    def _cache_path(self, target, url, method="GET"):
        return self.cache_dir / (self.cache_key(target, url, method) + ".json")

    def acquire(self, url, method="GET", headers=None, samples=None):
        from . import http as _http
        n = int(samples) if samples else self.samples
        n = max(2, min(50, n))
        statuses = []
        timings = []
        bodies = []
        try:
            with _http.Client(timeout=self.timeout, verify=self.verify,
                              follow_redirects=False) as c:
                for _ in range(n):
                    r = c.request(method.upper(), url,
                                  headers=headers or {},
                                  skip_rate_limit=True)
                    statuses.append(r.status_code)
                    timings.append(r.elapsed.total_seconds() * 1000.0
                                    if getattr(r, "elapsed", None) else 0.0)
                    bodies.append(r.text or "")
        except Exception:
            return None
        if not bodies:
            return None
        status_mode = max(set(statuses), key=statuses.count) if statuses else 0
        body_mode = max(bodies, key=bodies.count)
        structure = build_structure(body_mode, "")
        snap = BaselineSnapshot(
            url=url, method=method.upper(), status=status_mode,
            body=body_mode, body_len=len(body_mode),
            timing_samples=timings,
            structural_hash=str(structure)[:200] if structure else "",
            structure=structure,
        )
        return snap

    def save(self, target, snapshot):
        if snapshot is None:
            return None
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        path = self._cache_path(target, snapshot.url, snapshot.method)
        data = {
            "target": target,
            "url": snapshot.url,
            "method": snapshot.method,
            "status": snapshot.status,
            "body_len": snapshot.body_len,
            "timing_samples": list(snapshot.timing_samples),
            "timing_mean": snapshot.timing_mean,
            "timing_stdev": snapshot.timing_stdev,
            "structure": snapshot.structure,
            "structure_hash": snapshot.structural_hash,
            "header_names": sorted(snapshot.header_names),
            "updated": datetime.now(timezone.utc).isoformat(),
        }
        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        return str(path)

    def load(self, target, url, method="GET"):
        path = self._cache_path(target, url, method)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return None
        snap = BaselineSnapshot(
            url=data.get("url", url),
            method=data.get("method", method),
            status=int(data.get("status") or 0),
            body="",
            body_len=int(data.get("body_len") or 0),
            timing_samples=list(data.get("timing_samples") or []),
            structural_hash=data.get("structure_hash", ""),
            structure=data.get("structure"),
        )
        snap.header_names = set(data.get("header_names") or [])
        return snap

    def acquire_and_save(self, target, url, method="GET", headers=None):
        snap = self.acquire(url, method=method, headers=headers)
        if snap is None:
            return None
        self.save(target, snap)
        return snap

def _safe(s):
    return safe_name(s)

def profile_endpoint(url, method="GET", samples=50, headers=None):
    from .http_client import HttpClient
    client = HttpClient(default_headers=headers or {})
    timings = []
    statuses = []
    hashes = []
    try:
        for _ in range(samples):
            r = client.request(method, url)
            if r.get("status") is not None:
                timings.append(r["time_ms"])
                statuses.append(r["status"])
                if r.get("body_hash"):
                    hashes.append(r["body_hash"])
    finally:
        client.close()
    if not timings:
        return None
    timings_sorted = sorted(timings)

    def pct(p):
        idx = min(int(len(timings_sorted) * p), len(timings_sorted) - 1)
        return timings_sorted[idx]

    return {
        "url": url, "method": method, "sample_count": len(timings),
        "mean_ms": round(statistics.mean(timings), 3),
        "stdev_ms": round(statistics.pstdev(timings), 3),
        "min_ms": round(min(timings), 3),
        "max_ms": round(max(timings), 3),
        "p50_ms": round(pct(0.50), 3),
        "p95_ms": round(pct(0.95), 3),
        "p99_ms": round(pct(0.99), 3),
        "status_distribution": {str(s): statuses.count(s) for s in set(statuses)},
        "distinct_bodies": len(set(hashes)),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

def save_baseline(target, profile):
    BASELINE_DIR.mkdir(parents=True, exist_ok=True)
    path = BASELINE_DIR / ("baseline_" + safe_name(target) + ".json")
    data = {}
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            data = {}
    endpoints = data.get("endpoints", {})
    endpoints[profile["url"]] = profile
    data["target"] = target
    data["endpoints"] = endpoints
    data["updated"] = datetime.now(timezone.utc).isoformat()
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return str(path)

def load_baseline(target, url):
    path = BASELINE_DIR / ("baseline_" + _safe(target) + ".json")
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data.get("endpoints", {}).get(url)
    except Exception:
        return None

__all__ = ["BaselineEngine", "BaselineSnapshot",
           "profile_endpoint", "save_baseline", "load_baseline"]
