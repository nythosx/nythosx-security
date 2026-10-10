from __future__ import annotations

from .library import load_chains
from .models import AttackChain, ChainVerdict


def _extract_findings(findings):
    out = []
    for f in findings or []:
        pid = None
        verdict = None
        confidence = None
        if isinstance(f, dict):
            pid = f.get("pattern_id") or f.get("capability") or f.get("id")
            verdict = f.get("verdict")
            confidence = f.get("confidence")
        else:
            pid = getattr(f, "pattern_id", None) or getattr(f, "capability", None)
            verdict = getattr(f, "verdict", None)
            confidence = getattr(f, "confidence", None)
        if hasattr(verdict, "value"):
            verdict = verdict.value
        if pid:
            out.append({"pattern_id": pid, "verdict": verdict,
                        "confidence": float(confidence) if confidence is not None else None})
    return out


def _geometric_mean(values):
    vals = [v for v in values if v is not None]
    if not vals:
        return 0.0
    prod = 1.0
    for v in vals:
        prod *= max(0.0001, float(v))
    return prod ** (1.0 / len(vals))


def _classify(chain, matched, missing, confidence, threshold):
    if missing:
        return ChainVerdict.INCOMPLETE
    if not matched:
        return ChainVerdict.INCOMPLETE
    verdicts = [m.get("verdict") for m in matched]
    if all(v == "VULNERABLE" for v in verdicts) and confidence >= threshold:
        return ChainVerdict.CONFIRMED
    if any(v == "VULNERABLE" for v in verdicts):
        return ChainVerdict.LIKELY
    if all(v == "SUSPICIOUS" for v in verdicts):
        return ChainVerdict.THEORETICAL
    return ChainVerdict.INCOMPLETE


def resolve_chains(findings, threshold=0.7):
    flat = _extract_findings(findings)
    by_pid = {}
    for f in flat:
        pid = f["pattern_id"]
        prev = by_pid.get(pid)
        if prev is None:
            by_pid[pid] = f
        else:
            rank = {"VULNERABLE": 3, "SUSPICIOUS": 2, "PASS": 1, "UNKNOWN": 0}
            if rank.get(f.get("verdict"), 0) > rank.get(prev.get("verdict"), 0):
                by_pid[pid] = f

    out = []
    for chain in load_chains():
        matched = []
        missing = []
        confs = []
        for req in chain.prerequisites:
            hit = by_pid.get(req)
            if hit is None:
                missing.append(req)
                continue
            matched.append({"pattern_id": req, "verdict": hit.get("verdict"),
                            "confidence": hit.get("confidence")})
            c = hit.get("confidence")
            if c is None:
                c = {"VULNERABLE": 0.9, "SUSPICIOUS": 0.6,
                     "PASS": 0.8, "UNKNOWN": 0.3}.get(hit.get("verdict"), 0.3)
            confs.append(c)
        confidence = _geometric_mean(confs) if matched else 0.0
        verdict = _classify(chain, matched, missing, confidence, threshold)
        chain.matched = matched
        chain.missing = missing
        chain.confidence = round(confidence, 4)
        chain.verdict = verdict.value if hasattr(verdict, "value") else str(verdict)
        out.append(chain)
    out.sort(key=lambda c: (
        -{"CONFIRMED": 3, "LIKELY": 2, "THEORETICAL": 1, "INCOMPLETE": 0}.get(c.verdict, 0),
        -c.confidence,
        c.id,
    ))
    return out


__all__ = ["resolve_chains"]
