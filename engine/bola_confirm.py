import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone


CONFIRMED = "CONFIRMED"
REFUTED = "REFUTED"
INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class BolaDecision:
    status: str
    reason: str
    proof: dict = field(default_factory=dict)

    def to_dict(self):
        return {"status": self.status, "reason": self.reason,
                "proof": self.proof}


def _hash(blob):
    if isinstance(blob, (dict, list)):
        blob = json.dumps(blob, sort_keys=True, default=str)
    return hashlib.sha256(
        str(blob).encode("utf-8", "ignore")).hexdigest()[:32]


def _sign(record, key=None):
    key = (key or os.environ.get("EVIDENCE_KEY")
           or "unsigned").encode("utf-8")
    body = json.dumps(record, sort_keys=True, default=str).encode("utf-8")
    return hmac.new(key, body, hashlib.sha256).hexdigest()


def _canonical_body(body):
    try:
        from .noise_model import strip_noise
        return strip_noise(body or "")
    except Exception:
        return body or ""


def _same_body(a, b):
    ca = _canonical_body(a)
    cb = _canonical_body(b)
    if ca == cb:
        return True
    try:
        from .diff import build_structure, SemanticDiff, BaselineSnapshot
        sa = build_structure(ca, "")
        sb = build_structure(cb, "")
        if sa is None or sb is None:
            return False
        diff = SemanticDiff()
        d = diff.compare(
            BaselineSnapshot(status=200, body=ca, body_len=len(ca),
                             structure=sa),
            {"status": 200, "body": cb, "time_ms": 10,
             "content_type": "", "headers": {}})
        return d.structural_delta < 0.25 and d.length_delta_pct < 0.3
    except Exception:
        return False


def classify(responses_a, responses_b, resource_paths):
    if not responses_a or not responses_b:
        return BolaDecision(
            INCONCLUSIVE,
            "missing responses from one or both identities",
            {"paths_checked": list(resource_paths or [])},
        )

    both_200_distinct = []
    both_200_identical = []
    only_b_200 = []
    only_a_200 = []

    for path in resource_paths or []:
        ra = responses_a.get(path) or {}
        rb = responses_b.get(path) or {}
        sa = ra.get("status")
        sb = rb.get("status")
        ba = ra.get("body") or ""
        bb = rb.get("body") or ""
        if sa == 200 and sb == 200:
            if _same_body(ba, bb):
                both_200_identical.append(path)
            else:
                both_200_distinct.append(path)
        elif sa in (401, 403) and sb == 200:
            only_b_200.append(path)
        elif sa == 200 and sb in (401, 403):
            only_a_200.append(path)

    proof = {
        "paths_checked": list(resource_paths or []),
        "both_200_distinct": both_200_distinct,
        "both_200_identical": both_200_identical,
        "only_b_200": only_b_200,
        "only_a_200": only_a_200,
        "response_hashes": {},
    }
    for path in resource_paths or []:
        ra = responses_a.get(path) or {}
        rb = responses_b.get(path) or {}
        proof["response_hashes"][path] = {
            "a": _hash(ra.get("body") or ""),
            "b": _hash(rb.get("body") or ""),
        }

    if only_b_200:
        proof["basis"] = "user_a token read user_b resource"
        return BolaDecision(
            CONFIRMED,
            f"cross-user access confirmed on {len(only_b_200)} path(s)",
            proof,
        )
    if both_200_distinct:
        proof["basis"] = "both sessions returned distinct 200 bodies"
        return BolaDecision(
            CONFIRMED,
            f"distinct 200 bodies from both sessions on "
            f"{len(both_200_distinct)} path(s)",
            proof,
        )
    if both_200_identical and not (only_b_200 or only_a_200):
        proof["basis"] = "both sessions returned identical bodies"
        return BolaDecision(
            REFUTED,
            "both identities saw identical responses, likely a public "
            "resource, not BOLA",
            proof,
        )
    if only_a_200 and not only_b_200:
        proof["basis"] = "only user_a session received data"
        return BolaDecision(
            REFUTED,
            "only one identity could reach the resource, no cross-user "
            "exposure observed",
            proof,
        )
    return BolaDecision(
        INCONCLUSIVE,
        "neither identity produced a distinguishing response",
        proof,
    )


def build_evidence(decision, target):
    record = {
        "target": target,
        "status": decision.status,
        "reason": decision.reason,
        "proof": decision.proof,
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    record["signature"] = _sign(record)
    return record


__all__ = ["BolaDecision", "classify", "build_evidence",
           "CONFIRMED", "REFUTED", "INCONCLUSIVE"]
