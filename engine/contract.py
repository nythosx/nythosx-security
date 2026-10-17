from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum

try:
    from enum import StrEnum as _StrEnum
except ImportError:
    _StrEnum = None


if _StrEnum is not None:
    class Verdict(_StrEnum):
        VULNERABLE = "VULNERABLE"
        SUSPICIOUS = "SUSPICIOUS"
        PASS = "PASS"
        UNKNOWN = "UNKNOWN"

    class Severity(_StrEnum):
        CRITICAL = "critical"
        HIGH = "high"
        MEDIUM = "medium"
        LOW = "low"
        INFO = "info"
else:
    class Verdict(str, Enum):
        VULNERABLE = "VULNERABLE"
        SUSPICIOUS = "SUSPICIOUS"
        PASS = "PASS"
        UNKNOWN = "UNKNOWN"

        def __str__(self):
            return self.value

    class Severity(str, Enum):
        CRITICAL = "critical"
        HIGH = "high"
        MEDIUM = "medium"
        LOW = "low"
        INFO = "info"

        def __str__(self):
            return self.value


class Outcome(str, Enum):
    NONE = "NONE"
    ACCESS_GRANTED = "ACCESS_GRANTED"
    IDENTITY = "IDENTITY"
    SESSION_MATERIAL = "SESSION_MATERIAL"
    DATA_LEAKED = "DATA_LEAKED"
    CODE_EXECUTED = "CODE_EXECUTED"
    PRIVILEGE_LEVEL = "PRIVILEGE_LEVEL"

    def __str__(self):
        return self.value


VERDICT_RANK = {
    Verdict.VULNERABLE: 3,
    Verdict.SUSPICIOUS: 2,
    Verdict.PASS: 1,
    Verdict.UNKNOWN: 0,
}

SEVERITY_RANK = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}

SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

VERDICT_COLOR = {
    "VULNERABLE": "bold red",
    "SUSPICIOUS": "bold yellow",
    "PASS": "bold green",
    "UNKNOWN": "dim",
}

CONFIDENCE_BY_VERDICT = {
    Verdict.VULNERABLE: 0.9,
    Verdict.SUSPICIOUS: 0.6,
    Verdict.PASS: 0.8,
    Verdict.UNKNOWN: 0.3,
}


def coerce_verdict(v):
    if isinstance(v, Verdict):
        return v
    if v is None:
        return Verdict.UNKNOWN
    try:
        return Verdict(str(v).upper())
    except Exception:
        return Verdict.UNKNOWN


def coerce_severity(v):
    if isinstance(v, Severity):
        return v
    if v is None:
        return Severity.INFO
    try:
        return Severity(str(v).lower())
    except Exception:
        return Severity.INFO


def coerce_outcome(v):
    if isinstance(v, Outcome):
        return v
    if v is None:
        return Outcome.NONE
    try:
        return Outcome(str(v).upper())
    except Exception:
        return Outcome.NONE


def _v(v):
    return v.value if isinstance(v, Verdict) else str(v)


def _s(v):
    return v.value if isinstance(v, Severity) else str(v)


def _o(v):
    return v.value if isinstance(v, Outcome) else str(v)


@dataclass
class Finding:
    id: str = ""
    type: str = ""
    severity: Severity = Severity.INFO
    title: str = ""
    description: str = ""
    evidence: dict = field(default_factory=dict)
    verdict: Verdict = Verdict.UNKNOWN
    reason: str = ""

    def __post_init__(self):
        self.severity = coerce_severity(self.severity)
        self.verdict = coerce_verdict(self.verdict)

    def __getitem__(self, key):
        if key == "verdict":
            return _v(self.verdict)
        if key == "severity":
            return _s(self.severity)
        if key == "reason":
            return self.reason
        if key == "evidence":
            return self.evidence
        return getattr(self, key)

    def get(self, key, default=None):
        try:
            v = self[key]
            return default if v is None else v
        except Exception:
            return default

    def __contains__(self, key):
        if key in ("id", "type", "severity", "title", "description",
                   "evidence", "verdict", "reason"):
            return True
        return False

    def to_dict(self):
        return {
            "id": self.id,
            "type": self.type,
            "severity": _s(self.severity),
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "verdict": _v(self.verdict),
            "reason": self.reason,
        }


@dataclass
class DataRow:
    endpoint: str = ""
    method: str = "GET"
    status: int = 0
    total_rows: int = 0
    extracted: int = 0
    rows: list = field(default_factory=list)
    raw_rows: list = field(default_factory=list)
    auth_used: str = None

    def masked_json(self):
        import json
        from .util import mask_row
        masked = [mask_row(r) for r in self.rows] if self.rows else []
        return json.dumps({
            "endpoint": self.endpoint,
            "method": self.method,
            "status": self.status,
            "total_rows": self.total_rows,
            "extracted": self.extracted,
            "rows": masked,
            "auth_used": self.auth_used,
        }, indent=2, default=str)

    def to_dict(self):
        return {
            "endpoint": self.endpoint,
            "method": self.method,
            "status": self.status,
            "total_rows": self.total_rows,
            "extracted": self.extracted,
            "rows": self.rows,
            "auth_used": self.auth_used,
        }


@dataclass
class ScanBudget:
    max_iterations: int = 5
    max_http_requests: int = 500
    max_duration_seconds: float = 300.0
    max_hypotheses_per_iter: int = 20
    convergence_window: int = 2

    def to_dict(self):
        return {
            "max_iterations": self.max_iterations,
            "max_http_requests": self.max_http_requests,
            "max_duration_seconds": self.max_duration_seconds,
            "max_hypotheses_per_iter": self.max_hypotheses_per_iter,
            "convergence_window": self.convergence_window,
        }


@dataclass
class Capability:
    name: str = ""
    description: str = ""
    params: dict = field(default_factory=dict)
    required: list = field(default_factory=list)
    cost: str = "low"
    destructive: bool = False
    idempotent: bool = True
    prerequisites: list = field(default_factory=list)
    produces_verdicts: list = field(default_factory=lambda: ["VULNERABLE", "SUSPICIOUS", "PASS", "UNKNOWN"])
    category: str = "general"
    default_on: bool = True
    examples: list = field(default_factory=list)
    opt_in: bool = False
    destructive_reason: str = ""

    def to_dict(self):
        return {
            "name": self.name,
            "description": self.description,
            "params": self.params,
            "required": self.required,
            "cost": self.cost,
            "destructive": self.destructive,
            "idempotent": self.idempotent,
            "prerequisites": self.prerequisites,
            "produces_verdicts": self.produces_verdicts,
            "category": self.category,
            "default_on": self.default_on,
            "examples": self.examples,
            "opt_in": self.opt_in,
            "destructive_reason": self.destructive_reason,
        }


@dataclass
class ScanResult:
    capability: str = ""
    target: str = ""
    verdict: Verdict = Verdict.UNKNOWN
    severity: Severity = Severity.INFO
    confidence: float = 0.5
    confidence_reason: str = ""
    reason: str = ""
    evidence: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    next_hints: list = field(default_factory=list)
    duration_ms: float = 0.0
    cost_used: dict = field(default_factory=dict)
    author: str = "system"
    raw: dict = field(default_factory=dict)
    signal_strength: float = 0.0
    confirmation_status: str = "unconfirmed"
    confidence_breakdown: dict = field(default_factory=dict)
    iteration_id: int = 0
    data_rows: list = field(default_factory=list)
    extracted_data: list = field(default_factory=list)
    proof_of_impact: dict = field(default_factory=dict)
    reproduction: str = ""
    cvss: dict = field(default_factory=dict)
    asvs_chapters: list = field(default_factory=list)
    mitre_techniques: list = field(default_factory=list)
    outcome: Outcome = Outcome.NONE
    artifact_ref: str = ""

    def __post_init__(self):
        self.verdict = coerce_verdict(self.verdict)
        self.severity = coerce_severity(self.severity)
        self.outcome = coerce_outcome(self.outcome)
        self.findings = [
            f if isinstance(f, Finding) else Finding(**(f if isinstance(f, dict) else {}))
            for f in (self.findings or [])
        ]

    def __getitem__(self, key):
        if key == "verdict":
            return _v(self.verdict)
        if key == "severity":
            return _s(self.severity)
        if key == "capability":
            return self.capability
        if key == "target":
            return self.target
        if key == "confidence":
            return self.confidence
        if key == "confidence_reason":
            return self.confidence_reason
        if key == "reason":
            return self.reason
        if key == "evidence":
            return self.evidence
        if key == "findings":
            return self.findings
        if key == "next_hints":
            return self.next_hints
        if key == "duration_ms":
            return self.duration_ms
        if key == "cost_used":
            return self.cost_used
        if key == "author":
            return self.author
        if key == "raw":
            return self.raw
        if key == "signal_strength":
            return self.signal_strength
        if key == "confirmation_status":
            return self.confirmation_status
        if key == "confidence_breakdown":
            return self.confidence_breakdown
        if key == "iteration_id":
            return self.iteration_id
        if key == "data_rows":
            return self.data_rows
        if key == "extracted_data":
            return self.extracted_data
        if key == "proof_of_impact":
            return self.proof_of_impact
        if key == "reproduction":
            return self.reproduction
        if key == "cvss":
            return self.cvss
        if key == "asvs_chapters":
            return self.asvs_chapters
        if key == "mitre_techniques":
            return self.mitre_techniques
        if key == "outcome":
            return _o(self.outcome)
        if key == "artifact_ref":
            return self.artifact_ref
        return self.raw.get(key)

    def get(self, key, default=None):
        try:
            v = self[key]
            return default if v is None else v
        except Exception:
            return default

    def __contains__(self, key):
        if key in ("capability", "target", "verdict", "severity", "confidence",
                   "confidence_reason", "reason", "evidence", "findings",
                   "next_hints", "duration_ms", "cost_used", "author", "raw",
                   "signal_strength", "confirmation_status",
                   "confidence_breakdown", "iteration_id",
                   "data_rows", "extracted_data", "proof_of_impact",
                   "reproduction", "cvss", "asvs_chapters",
                   "mitre_techniques", "outcome", "artifact_ref"):
            return True
        return key in self.raw

    def to_dict(self):
        return {
            "capability": self.capability,
            "target": self.target,
            "verdict": _v(self.verdict),
            "severity": _s(self.severity),
            "confidence": self.confidence,
            "confidence_reason": self.confidence_reason,
            "reason": self.reason,
            "evidence": self.evidence,
            "findings": [f.to_dict() if isinstance(f, Finding) else f for f in self.findings],
            "next_hints": self.next_hints,
            "duration_ms": self.duration_ms,
            "cost_used": self.cost_used,
            "author": self.author,
            "signal_strength": self.signal_strength,
            "confirmation_status": self.confirmation_status,
            "confidence_breakdown": self.confidence_breakdown,
            "iteration_id": self.iteration_id,
            "data_rows": self.data_rows,
            "extracted_data": self.extracted_data,
            "proof_of_impact": self.proof_of_impact,
            "reproduction": self.reproduction,
            "cvss": self.cvss,
            "asvs_chapters": self.asvs_chapters,
            "mitre_techniques": self.mitre_techniques,
            "outcome": _o(self.outcome),
            "artifact_ref": self.artifact_ref,
        }


def infer_target(args, kwargs):
    for key in ("target_url", "base_url", "url", "target", "identity_url"):
        v = kwargs.get(key)
        if isinstance(v, str) and v:
            return v
    if args:
        for a in args:
            if isinstance(a, str) and a.startswith(("http://", "https://", "ws://", "wss://")):
                return a
    if args and isinstance(args[0], str):
        return args[0]
    return ""


def infer_verdict(raw):
    if isinstance(raw, ScanResult):
        return raw.verdict
    if isinstance(raw, list):
        best = Verdict.UNKNOWN
        for item in raw:
            if isinstance(item, dict) and item.get("verdict"):
                v = coerce_verdict(item["verdict"])
                if VERDICT_RANK[v] > VERDICT_RANK[best]:
                    best = v
        return best
    if not isinstance(raw, dict):
        return Verdict.UNKNOWN
    for key in ("verdict", "overall"):
        if raw.get(key):
            return coerce_verdict(raw[key])
    sub = raw.get("result")
    if isinstance(sub, dict) and sub.get("verdict"):
        return coerce_verdict(sub["verdict"])
    if isinstance(raw.get("results"), list):
        best = Verdict.UNKNOWN
        for item in raw["results"]:
            if isinstance(item, dict) and item.get("verdict"):
                v = coerce_verdict(item["verdict"])
                if VERDICT_RANK[v] > VERDICT_RANK[best]:
                    best = v
        if best != Verdict.UNKNOWN:
            return best
    if raw.get("vulnerabilities"):
        return Verdict.VULNERABLE
    return Verdict.UNKNOWN


def infer_reason(raw):
    if isinstance(raw, ScanResult):
        return raw.reason
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict) and item.get("reason"):
                return str(item["reason"])
        return ""
    if not isinstance(raw, dict):
        return ""
    if raw.get("reason"):
        return str(raw["reason"])
    sub = raw.get("result")
    if isinstance(sub, dict) and sub.get("reason"):
        return str(sub["reason"])
    return ""


def infer_severity(raw, verdict):
    if isinstance(raw, ScanResult):
        return raw.severity
    if isinstance(raw, dict):
        if raw.get("severity"):
            return coerce_severity(raw["severity"])
        sub = raw.get("result")
        if isinstance(sub, dict) and sub.get("severity"):
            return coerce_severity(sub["severity"])
    return {
        Verdict.VULNERABLE: Severity.HIGH,
        Verdict.SUSPICIOUS: Severity.MEDIUM,
        Verdict.PASS: Severity.INFO,
        Verdict.UNKNOWN: Severity.INFO,
    }[verdict]


def _findings_from_raw(raw, capability):
    out = []
    if isinstance(raw, dict):
        sub = raw.get("result")
        if isinstance(sub, dict) and sub.get("verdict"):
            out.append(Finding(
                id=f"{capability}:root",
                type=capability,
                severity=coerce_severity(sub.get("severity", "info")),
                verdict=coerce_verdict(sub.get("verdict", "UNKNOWN")),
                reason=str(sub.get("reason", "")),
                evidence=sub.get("evidence", {}) or {},
            ))
        for i, item in enumerate(raw.get("results") or []):
            if isinstance(item, dict) and item.get("verdict"):
                out.append(Finding(
                    id=f"{capability}:{i}",
                    type=str(item.get("vector") or item.get("category") or capability),
                    severity=coerce_severity(item.get("severity", "info")),
                    verdict=coerce_verdict(item["verdict"]),
                    reason=str(item.get("reason", "")),
                    evidence=item.get("evidence", {}) or {},
                ))
    elif isinstance(raw, list):
        for i, item in enumerate(raw):
            if not isinstance(item, dict):
                continue
            out.append(Finding(
                id=f"{capability}:{i}",
                type=str(item.get("category") or item.get("vector") or capability),
                severity=coerce_severity(item.get("severity", "info")),
                verdict=coerce_verdict(item.get("verdict", "UNKNOWN")),
                reason=str(item.get("reason", "")),
                evidence=item.get("evidence", {}) or {},
            ))
    return out


def make_result(raw, capability, args=(), kwargs=None):
    if isinstance(raw, ScanResult):
        if not raw.capability:
            raw.capability = capability
        return raw
    kwargs = kwargs or {}
    verdict = infer_verdict(raw)
    severity = infer_severity(raw, verdict)
    reason = infer_reason(raw)
    target = infer_target(args, kwargs)
    findings = _findings_from_raw(raw, capability)
    if isinstance(raw, dict):
        ev = raw.get("evidence")
        evidence = ev if isinstance(ev, dict) else {}
        raw_dict = raw
    elif isinstance(raw, list):
        evidence = {}
        raw_dict = {"items": raw, "results": raw}
    else:
        evidence = {}
        raw_dict = {"items": raw, "results": raw}
    return ScanResult(
        capability=capability,
        target=target,
        verdict=verdict,
        severity=severity,
        confidence=CONFIDENCE_BY_VERDICT.get(verdict, 0.5),
        confidence_reason=f"derived from verdict {_v(verdict)}",
        reason=reason,
        evidence=evidence,
        findings=findings,
        next_hints=[],
        duration_ms=0.0,
        cost_used={},
        author="system",
        raw=raw_dict,
    )


def wrap_evaluate(raw, otype):
    if isinstance(raw, Finding):
        return raw
    if not isinstance(raw, dict):
        raw = {"verdict": "UNKNOWN", "reason": str(raw), "evidence": {}}
    return Finding(
        id=otype or "oracle",
        type=otype or "oracle",
        verdict=raw.get("verdict", "UNKNOWN"),
        severity=raw.get("severity", "info"),
        reason=raw.get("reason", ""),
        evidence=raw.get("evidence", {}) or {},
    )



@dataclass(frozen=True)
class FindingKey:
    tool: str
    reason_prefix: str
    severity: str

    @classmethod
    def from_finding(cls, finding):
        if finding is None:
            return cls("", "", "info")
        tool = (finding.get("tool") or finding.get("pattern_id")
                or finding.get("capability") or finding.get("type")
                or finding.get("kind") or "")
        reason = finding.get("reason") or ""
        prefix = reason[:120].strip().lower()
        severity = (finding.get("severity")
                    or (finding.get("evidence") or {}).get("severity")
                    or "medium")
        return cls(tool=str(tool), reason_prefix=prefix,
                   severity=str(severity).lower())


@dataclass
class DedupPolicy:
    reason_prefix_chars: int = 120
    normalize_case: bool = True
    default_severity: str = "medium"

    def key_for(self, finding):
        return FindingKey.from_finding(self._normalize(finding))

    def _normalize(self, finding):
        if finding is None:
            return {}
        out = dict(finding)
        reason = out.get("reason") or ""
        truncated = reason[:self.reason_prefix_chars]
        if self.normalize_case:
            truncated = truncated.strip().lower()
        out["reason"] = truncated
        return out


def is_duplicate(existing, candidate, policy=None):
    p = policy or DedupPolicy()
    return p.key_for(existing) == p.key_for(candidate)


__all__ = [
    "Verdict", "Severity", "Outcome", "Finding", "ScanResult", "ScanBudget", "Capability",
    "VERDICT_RANK", "SEVERITY_RANK", "CONFIDENCE_BY_VERDICT",
    "coerce_verdict", "coerce_severity", "coerce_outcome",
    "make_result", "wrap_evaluate", "infer_verdict", "infer_reason",
    "infer_severity", "infer_target",
    "FindingKey", "DedupPolicy", "is_duplicate",
]
