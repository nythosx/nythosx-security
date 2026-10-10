from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from .contract import ScanBudget, ScanResult


@dataclass
class Hypothesis:
    capability: str
    target: str
    reason: str = ""
    priority: int = 0
    params: dict = field(default_factory=dict)
    source: str = "default"


@dataclass
class TriageDecision:
    keep: bool = True
    rerun: bool = False
    escalate: bool = False
    reason: str = ""


@dataclass
class CoverageReport:
    owasp: dict = field(default_factory=dict)
    attack_surfaces: dict = field(default_factory=dict)
    unrun_capabilities: list = field(default_factory=list)
    untested_categories: list = field(default_factory=list)
    executed_count: int = 0
    total_count: int = 0

    def to_dict(self):
        return {
            "owasp": self.owasp,
            "attack_surfaces": self.attack_surfaces,
            "unrun_capabilities": self.unrun_capabilities,
            "untested_categories": self.untested_categories,
            "executed_count": self.executed_count,
            "total_count": self.total_count,
        }


@dataclass
class ScanState:
    target: str = ""
    framework: dict = field(default_factory=dict)
    discovered_endpoints: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    chains: list = field(default_factory=list)
    coverage: CoverageReport = field(default_factory=CoverageReport)
    visited: set = field(default_factory=set)
    pruned: list = field(default_factory=list)
    budget: ScanBudget = field(default_factory=ScanBudget)
    iterations: int = 0
    elapsed_seconds: float = 0.0
    executed_capabilities: set = field(default_factory=set)

    def mark_visited(self, capability, target):
        self.visited.add((capability, target))

    def is_visited(self, capability, target):
        return (capability, target) in self.visited

    def add_finding(self, finding):
        self.findings.append(finding)

    def add_findings(self, findings):
        for f in findings or []:
            self.findings.append(f)

    def to_dict(self):
        return {
            "target": self.target,
            "framework": self.framework,
            "discovered_endpoints": list(self.discovered_endpoints),
            "findings": [f.to_dict() if isinstance(f, ScanResult) else f for f in self.findings],
            "chains": self.chains,
            "coverage": self.coverage.to_dict() if isinstance(self.coverage, CoverageReport) else self.coverage,
            "visited": sorted(list(self.visited)),
            "pruned": self.pruned,
            "budget": self.budget.to_dict() if isinstance(self.budget, ScanBudget) else self.budget,
            "iterations": self.iterations,
            "elapsed_seconds": self.elapsed_seconds,
            "executed_capabilities": sorted(list(self.executed_capabilities)),
        }


__all__ = ["Hypothesis", "TriageDecision", "CoverageReport", "ScanState"]
