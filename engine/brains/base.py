from typing import List, Optional, Protocol, runtime_checkable

from ..state import Hypothesis, ScanState, TriageDecision


@runtime_checkable
class ScanBrain(Protocol):
    def propose(self, state: ScanState) -> List[Hypothesis]:
        ...

    def triage(self, finding) -> TriageDecision:
        ...

    def should_stop(self, state: ScanState) -> bool:
        ...

    def can_author_payload(self, capability: str) -> bool:
        ...

    def propose_payload(self, state: ScanState,
                        capability: str) -> Optional[str]:
        ...


__all__ = ["ScanBrain"]
