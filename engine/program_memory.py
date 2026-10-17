"""Program Memory & Rejection Learning.
Persists WAF bypass success rates and user-rejected finding patterns.
Over time this compounds into a massive advantage: the scanner learns
what works and what the user marks as N/A.
"""
import json
from pathlib import Path

MEMORY_DIR = Path(__file__).parent.parent / "findings" / "memory"
MEMORY_DIR.mkdir(parents=True, exist_ok=True)
WAF_FILE = MEMORY_DIR / "waf_bypasses.json"
REJECTIONS_FILE = MEMORY_DIR / "rejections.json"
EV_STATS_FILE = MEMORY_DIR / "ev_stats.json"

def _load(path):
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}

def _save(path, data):
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")

def record_waf_bypass(waf_name, encoding_name, success=True):
    data = _load(WAF_FILE)
    waf_data = data.setdefault(waf_name, {})
    enc_data = waf_data.setdefault(encoding_name, {"hits": 0, "misses": 0})
    if success:
        enc_data["hits"] += 1
    else:
        enc_data["misses"] += 1
    _save(WAF_FILE, data)

def get_waf_bypasses(waf_name):
    data = _load(WAF_FILE)
    waf_data = data.get(waf_name, {})
    scored = []
    for enc, stats in waf_data.items():
        total = stats["hits"] + stats["misses"]
        rate = stats["hits"] / total if total > 0 else 0.0
        scored.append((enc, rate, stats["hits"]))
    scored.sort(key=lambda x: (-x[1], -x[2]))
    return [x[0] for x in scored]

def record_rejection(pattern_id, reason="user_marked_na"):
    data = _load(REJECTIONS_FILE)
    data[pattern_id] = data.get(pattern_id, 0) + 1
    _save(REJECTIONS_FILE, data)

def is_rejected(pattern_id, threshold=3):
    data = _load(REJECTIONS_FILE)
    return data.get(pattern_id, 0) >= threshold

def record_ev_stat(chain_id, vuln_class, framework, hit=True):
    data = _load(EV_STATS_FILE)
    key = f"{vuln_class}|{framework}"
    slot = data.setdefault(key, {"attempts": 0, "hits": 0})
    slot["attempts"] += 1
    if hit:
        slot["hits"] += 1
    _save(EV_STATS_FILE, data)

def get_ev_stats(vuln_class, framework):
    data = _load(EV_STATS_FILE)
    key = f"{vuln_class}|{framework}"
    return data.get(key, {"attempts": 0, "hits": 0})

__all__ = [
    "record_waf_bypass", "get_waf_bypasses",
    "record_rejection", "is_rejected",
    "record_ev_stat", "get_ev_stats",
]
