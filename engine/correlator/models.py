from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

try:
    from enum import StrEnum as _StrEnum
except ImportError:
    _StrEnum = None


if _StrEnum is not None:
    class ChainVerdict(_StrEnum):
        CONFIRMED = "CONFIRMED"
        LIKELY = "LIKELY"
        THEORETICAL = "THEORETICAL"
        INCOMPLETE = "INCOMPLETE"
else:
    class ChainVerdict(str, Enum):
        CONFIRMED = "CONFIRMED"
        LIKELY = "LIKELY"
        THEORETICAL = "THEORETICAL"
        INCOMPLETE = "INCOMPLETE"

        def __str__(self):
            return self.value


CHAIN_VERDICT_RANK = {
    ChainVerdict.CONFIRMED: 3,
    ChainVerdict.LIKELY: 2,
    ChainVerdict.THEORETICAL: 1,
    ChainVerdict.INCOMPLETE: 0,
}


@dataclass
class ChainRequirement:
    capability: str
    min_confidence: float = 0.0
    required_verdict: str = "VULNERABLE"
    optional: bool = False


@dataclass
class ChainStep:
    order: int
    action: str
    expects: str = ""
    outcome: str = ""


@dataclass
class AttackChain:
    id: str
    name: str
    prerequisites: list = field(default_factory=list)
    narrative: str = ""
    severity: str = "high"
    verdict: str = "INCOMPLETE"
    confidence: float = 0.0
    matched: list = field(default_factory=list)
    missing: list = field(default_factory=list)
    steps: list = field(default_factory=list)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "prerequisites": self.prerequisites,
            "narrative": self.narrative,
            "severity": self.severity,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "matched": self.matched,
            "missing": self.missing,
            "steps": self.steps,
        }


__all__ = [
    "AttackChain", "ChainRequirement", "ChainStep", "ChainVerdict",
    "CHAIN_VERDICT_RANK",
]
