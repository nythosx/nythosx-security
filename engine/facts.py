import threading
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
    "identity_broker": 0.95,
    "capgraph": 0.9,
    "tool": 0.8,
}


FRESH = "fresh"
STALE = "stale"
INVALIDATED = "invalidated"


@dataclass
class Fact:
    key: str
    value: Any
    source: str
    confidence: float
    evidence: list = field(default_factory=list)
    ts: float = field(default_factory=time.time)
    expiry: Optional[float] = None
    preconditions: list = field(default_factory=list)
    effects: list = field(default_factory=list)
    provenance: list = field(default_factory=list)
    validity: str = FRESH
    invalidated_at: Optional[float] = None
    invalidated_reason: str = ""

    def is_fresh(self, now=None):
        if self.validity == INVALIDATED:
            return False
        if self.expiry is None:
            return True
        now = now if now is not None else time.time()
        return now < self.expiry


class FactStore:
    def __init__(self):
        self._facts = {}
        self._providers = {}
        self._lock = threading.RLock()
        self._resolving = threading.local()

    def add(self, key, value, source="unknown", confidence=None,
            evidence=None, ttl_seconds=None, preconditions=None,
            effects=None, provenance=None):
        if confidence is None:
            confidence = SOURCE_CONFIDENCE.get(source, 0.5)
        confidence = max(0.0, min(1.0, float(confidence)))
        expiry = None
        if ttl_seconds is not None:
            expiry = time.time() + float(ttl_seconds)
        new_evidence = list(evidence or [])
        new_prov = list(provenance or [])
        with self._lock:
            existing = self._facts.get(key)
            if existing is not None and existing.is_fresh():
                existing.evidence.extend(new_evidence)
                existing.provenance.extend(
                    p for p in new_prov if p not in existing.provenance)
                if preconditions:
                    for p in preconditions:
                        if p not in existing.preconditions:
                            existing.preconditions.append(p)
                if effects:
                    for e in effects:
                        if e not in existing.effects:
                            existing.effects.append(e)
                if existing.confidence > confidence:
                    return
                existing.value = value
                existing.source = source
                existing.confidence = confidence
                existing.expiry = expiry
                existing.validity = FRESH
                existing.invalidated_at = None
                existing.invalidated_reason = ""
                return
            self._facts[key] = Fact(
                key=key, value=value, source=source, confidence=confidence,
                evidence=new_evidence, expiry=expiry,
                preconditions=list(preconditions or []),
                effects=list(effects or []),
                provenance=new_prov,
            )

    def get(self, key, default=None):
        with self._lock:
            f = self._facts.get(key)
            if f is None or not f.is_fresh():
                return default
            return f.value

    def get_fact(self, key):
        with self._lock:
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

    def requires(self, keys, min_confidence=0.0):
        missing = []
        for k in keys or []:
            if not self.has(k, min_confidence=min_confidence):
                missing.append(k)
        return missing

    def invalidate(self, key, reason=""):
        with self._lock:
            f = self._facts.get(key)
            if f is None:
                return False
            f.validity = INVALIDATED
            f.invalidated_at = time.time()
            f.invalidated_reason = reason
            return True

    def is_valid(self, key):
        f = self.get_fact(key)
        return f is not None and f.validity == FRESH

    def register_provider(self, key, provider):
        with self._lock:
            self._providers[key] = provider

    def providers_for(self, key):
        with self._lock:
            return self._providers.get(key)

    def resolve(self, key, context=None, min_confidence=0.0):
        if self.has(key, min_confidence=min_confidence):
            return self.get_fact(key), None
        provider = self.providers_for(key)
        if provider is None:
            return None, None
        stack = getattr(self._resolving, "stack", None)
        if stack is None:
            stack = set()
            self._resolving.stack = stack
        if key in stack:
            return None, provider
        stack.add(key)
        try:
            try:
                provider(self, context)
            except Exception:
                pass
        finally:
            stack.discard(key)
        if self.has(key, min_confidence=min_confidence):
            return self.get_fact(key), provider
        return None, provider

    def resolve_all(self, keys, context=None, min_confidence=0.0):
        unresolved = []
        produced_by = []
        for k in keys or []:
            f, provider = self.resolve(k, context=context,
                                       min_confidence=min_confidence)
            if f is None:
                unresolved.append(k)
            elif provider is not None:
                produced_by.append(
                    (k, getattr(provider, "__name__", str(provider))))
        return unresolved, produced_by

    def provenance(self, key):
        f = self.get_fact(key)
        return list(f.provenance) if f else []

    def __contains__(self, key):
        return self.get_fact(key) is not None

    def __iter__(self):
        with self._lock:
            keys = list(self._facts.keys())
        return iter(keys)

    def keys(self):
        with self._lock:
            return [k for k, f in self._facts.items() if f.is_fresh()]

    def all_keys(self):
        with self._lock:
            return list(self._facts.keys())

    def to_dict(self):
        with self._lock:
            return {
                k: {
                    "value": f.value,
                    "source": f.source,
                    "confidence": f.confidence,
                    "evidence": list(f.evidence),
                    "ts": f.ts,
                    "expiry": f.expiry,
                    "preconditions": list(f.preconditions),
                    "effects": list(f.effects),
                    "provenance": list(f.provenance),
                    "validity": f.validity,
                }
                for k, f in self._facts.items()
                if f.is_fresh()
            }

    def clear(self):
        with self._lock:
            self._facts.clear()
            self._providers.clear()


__all__ = ["Fact", "FactStore", "SOURCE_CONFIDENCE", "FRESH",
           "STALE", "INVALIDATED"]
