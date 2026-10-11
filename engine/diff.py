from __future__ import annotations

import json
import re
import statistics
from dataclasses import dataclass, field
from typing import Any, Optional

@dataclass
class BaselineSnapshot:
    url: str = ""
    method: str = "GET"
    status: int = 0
    body: str = ""
    body_len: int = 0
    timing_samples: list = field(default_factory=list)
    structural_hash: str = ""
    structure: Any = None
    header_names: set = field(default_factory=set)

    @property
    def timing_mean(self):
        if not self.timing_samples:
            return 0.0
        return statistics.mean(self.timing_samples)

    @property
    def timing_stdev(self):
        if len(self.timing_samples) < 2:
            return 0.0
        return statistics.pstdev(self.timing_samples)

@dataclass
class DiffResult:
    signal_strength: float = 0.0
    status_shift: float = 0.0
    timing_zscore: float = 0.0
    length_delta_pct: float = 0.0
    structural_delta: float = 0.0
    marker_reflected: bool = False
    header_delta: float = 0.0
    notes: list = field(default_factory=list)

def _json_skeleton(obj, depth=0):
    if depth > 12:
        return "..."
    if isinstance(obj, dict):
        return {k: _json_skeleton(v, depth + 1)
                for k, v in sorted(obj.items())[:200]}
    if isinstance(obj, list):
        if not obj:
            return []
        return [_json_skeleton(obj[0], depth + 1)]
    if isinstance(obj, bool):
        return "bool"
    if isinstance(obj, int):
        return "int"
    if isinstance(obj, float):
        return "float"
    if obj is None:
        return "null"
    return "str"

def _try_json(text):
    if not text:
        return None
    t = text.lstrip()
    if not (t.startswith("{") or t.startswith("[")):
        return None
    try:
        return json.loads(text)
    except Exception:
        return None

_HTML_TAG_RE = re.compile(r"<([a-zA-Z][a-zA-Z0-9]*)\b[^>]*>")

def _html_skeleton(text):
    return [m.group(1).lower() for m in _HTML_TAG_RE.finditer(text)]

def _structural_hash(skeleton):
    try:
        return json.dumps(skeleton, sort_keys=True, default=str)[:8000]
    except Exception:
        return str(skeleton)[:8000]

def build_structure(body, content_type=""):
    ct = (content_type or "").lower()
    if "json" in ct or _try_json(body) is not None:
        data = _try_json(body)
        if data is not None:
            return _json_skeleton(data)
    if "html" in ct or "<html" in (body or "").lower()[:400]:
        return _html_skeleton(body or "")
    return None

def _levenshtein(a, b, cap=2000):
    if len(a) > cap or len(b) > cap:
        a, b = a[:cap], b[:cap]
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(cur[-1] + 1, prev[j] + 1,
                           prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]

class SemanticDiff:
    def compare(self, baseline, candidate, marker=None):
        result = DiffResult()
        if baseline is None or candidate is None:
            return result

        b_status = baseline.status
        c_status = candidate.get("status")
        if c_status is not None and b_status:
            if c_status == b_status:
                result.status_shift = 0.0
            elif (c_status // 100) == (b_status // 100):
                result.status_shift = 0.3
            else:
                result.status_shift = 1.0
            result.notes.append("status " + str(b_status) + "->" + str(c_status))

        c_timing = candidate.get("time_ms")
        if c_timing is not None and baseline.timing_stdev > 0:
            result.timing_zscore = abs(c_timing - baseline.timing_mean) / baseline.timing_stdev
            result.notes.append("timing z=" + str(round(result.timing_zscore, 2)))

        c_body = candidate.get("body") or ""
        c_len = len(c_body)
        if baseline.body_len:
            result.length_delta_pct = abs(c_len - baseline.body_len) / baseline.body_len
            result.notes.append("len delta " + str(round(result.length_delta_pct, 2)))

        c_struct = build_structure(c_body, candidate.get("content_type", ""))
        if baseline.structure is not None and c_struct is not None:
            a = _structural_hash(baseline.structure)
            b = _structural_hash(c_struct)
            if a == b:
                result.structural_delta = 0.0
            else:
                dist = _levenshtein(a, b)
                norm = dist / max(len(a), len(b), 1)
                result.structural_delta = min(1.0, norm * 3.0)
                result.notes.append("structure delta " + str(round(result.structural_delta, 2)))

        if marker and marker in c_body:
            result.marker_reflected = True
            result.notes.append("marker reflected")

        c_headers = set((candidate.get("headers") or {}).keys())
        if baseline.header_names and c_headers:
            added = c_headers - baseline.header_names
            removed = baseline.header_names - c_headers
            if added or removed:
                result.header_delta = min(1.0, (len(added) + len(removed)) / 5.0)
                result.notes.append("headers +" + str(len(added)) + " -" + str(len(removed)))

        strength = 0.0
        strength += 0.35 * result.status_shift
        strength += 0.20 * min(1.0, result.timing_zscore / 4.0)
        strength += 0.15 * min(1.0, result.length_delta_pct / 0.5)
        strength += 0.20 * result.structural_delta
        if result.marker_reflected:
            strength = max(strength, 0.85)
        strength += 0.10 * result.header_delta

        result.signal_strength = max(0.0, min(1.0, strength))
        return result

__all__ = ["BaselineSnapshot", "DiffResult", "SemanticDiff", "build_structure"]
