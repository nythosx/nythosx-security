from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional

SOURCE_CONFIDENCE = {
    "js_match": 0.3,
    "regex_html": 0.3,
    "passive_header": 0.5,
    "route_probe": 0.7,
    "active_probe": 0.9,
    "live_confirm": 1.0,
    "recon": 0.6,
    "login": 1.0,
    "cli": 1.0,
    "unknown": 0.5,
}

@dataclass
class Fact:
    key: str
    value: Any
    source: str
    confidence: float
    evidence: list = field(default_factory=list)
    ts: float = field(default_factory=time.time)
    expiry: Optional[float] = None

    def is_fresh(self, now=None):
        if self.expiry is None:
            return True
        now = now if now is not None else time.time()
        return now < self.expiry

class FactStore:
    def __init__(self):
        self._facts = {}

    def add(self, key, value, source="unknown", confidence=None,
            evidence=None, ttl_seconds=None):
        if confidence is None:
            confidence = SOURCE_CONFIDENCE.get(source, 0.5)
        confidence = max(0.0, min(1.0, float(confidence)))
        expiry = None
        if ttl_seconds is not None:
            expiry = time.time() + float(ttl_seconds)
        new_evidence = list(evidence or [])

        existing = self._facts.get(key)
        if existing is not None and existing.is_fresh():
            existing.evidence.extend(new_evidence)
            if existing.confidence >= confidence:
                return
            existing.value = value
            existing.source = source
            existing.confidence = confidence
            existing.expiry = expiry
            return

        self._facts[key] = Fact(
            key=key, value=value, source=source, confidence=confidence,
            evidence=new_evidence, expiry=expiry,
        )

    def get(self, key, default=None):
        f = self._facts.get(key)
        if f is None or not f.is_fresh():
            return default
        return f.value

    def get_fact(self, key):
        f = self._facts.get(key)
        if f is None or not f.is_fresh():
            return None
        return f

    def confidence(self, key):
        f = self.get_fact(key)
        return 0.0 if f is None else f.confidence

    def has(self, key, min_confidence=0.0):
        f = self.get_fact(key)
        return f is not None and f.confidence >= min_confidence

    def __contains__(self, key):
        return self.get_fact(key) is not None

    def __iter__(self):
        return iter(list(self._facts.keys()))

    def keys(self):
        return [k for k, f in self._facts.items() if f.is_fresh()]

    def to_dict(self):
        return {
            k: {
                "value": f.value,
                "source": f.source,
                "confidence": f.confidence,
                "evidence": list(f.evidence),
                "ts": f.ts,
                "expiry": f.expiry,
            }
            for k, f in self._facts.items()
            if f.is_fresh()
        }

    def clear(self):
        self._facts.clear()

__all__ = ["Fact", "FactStore", "SOURCE_CONFIDENCE"]
