import json
import statistics
from pathlib import Path
from datetime import datetime, timezone
from .http_client import HttpClient
from .util import safe_name

ROOT = Path(__file__).parent.parent.absolute()
BASELINE_DIR = ROOT / "findings"


def _safe(s):
    return safe_name(s)


def profile_endpoint(url, method="GET", samples=50, headers=None):
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
        "url": url,
        "method": method,
        "sample_count": len(timings),
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
    path = BASELINE_DIR / f"baseline_{safe_name(target)}.json"
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
    path = BASELINE_DIR / f"baseline_{_safe(target)}.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data.get("endpoints", {}).get(url)
    except Exception:
        return None
