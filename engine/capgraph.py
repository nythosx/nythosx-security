"""Phase 5 — Capability Graph.

Models what an attacker can DO after each confirmed finding, and reports
multi-step attack paths that a per-finding view misses.

A capability is a verb an actor gains. Confirmed findings are edges: a
finding `requires` a capability (or starts from `anon`) and `grants` another.
Running BFS from `anon`, any path of length >= 2 that reaches `write_data` or
`escalate_role` is reported as a CHAIN finding, with severity bumped one step
above the worst component (capped at critical).

The finding-class -> edge mapping is declarative in
`configs/capability_map.yaml`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

ROOT = Path(__file__).parent.parent.absolute()
CAPABILITY_MAP = ROOT / "configs" / "capability_map.yaml"

START = "anon"

CANONICAL_VERBS = [
    "read_data", "write_data", "obtain_token", "escalate_role",
    "ssrf_to_internal", "execute_js_in_victim", "pivot_internal",
]

TARGET_VERBS = {"write_data", "escalate_role"}

_SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
_ORDER_SEVERITY = {v: k for k, v in _SEVERITY_ORDER.items()}

# finding class -> {requires: [cap...], grants: cap}. requires defaults to
# [anon]. Keys match pattern_id / class / kind (exact, then prefix/substring).
_DEFAULT_MAP = {
    "jwt_weak_secret": {"requires": [START], "grants": "obtain_token"},
    "jwt-weak-secret": {"requires": [START], "grants": "obtain_token"},
    "jwt-chain": {"requires": [START], "grants": "obtain_token"},
    "auth_bypass": {"requires": [START], "grants": "obtain_token"},
    "auth-bypass-probe": {"requires": [START], "grants": "obtain_token"},
    # IDOR/BOLA of a mutable object is a cross-account write primitive.
    "idor": {"requires": ["obtain_token"], "grants": "write_data"},
    "idor-user": {"requires": ["obtain_token"], "grants": "read_data"},
    "idor_scan": {"requires": ["obtain_token"], "grants": "write_data"},
    "bola": {"requires": ["obtain_token"], "grants": "write_data"},
    "bola-chain": {"requires": ["obtain_token"], "grants": "write_data"},
    "mass_assignment": {"requires": ["obtain_token"],
                        "grants": "escalate_role"},
    "mass-assignment": {"requires": ["obtain_token"],
                        "grants": "escalate_role"},
    "stored-xss": {"requires": [START], "grants": "execute_js_in_victim"},
    "xss": {"requires": [START], "grants": "execute_js_in_victim"},
    "dom-xss-advanced": {"requires": [START],
                         "grants": "execute_js_in_victim"},
    "execute_js_in_victim": {"requires": ["execute_js_in_victim"],
                             "grants": "obtain_token"},
    "ssrf": {"requires": [START], "grants": "ssrf_to_internal"},
    "ssrf-cloud-metadata": {"requires": [START], "grants": "obtain_token"},
    "ssrf_to_internal": {"requires": ["ssrf_to_internal"],
                         "grants": "pivot_internal"},
    "sqli": {"requires": [START], "grants": "read_data"},
    "sqli_scan": {"requires": [START], "grants": "read_data"},
    "missing_access_control": {"requires": [START], "grants": "read_data"},
}


def load_capability_map(path=None):
    data = {k: dict(v) for k, v in _DEFAULT_MAP.items()}
    p = Path(path) if path else CAPABILITY_MAP
    if p.exists():
        try:
            import yaml
            loaded = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            if isinstance(loaded, dict):
                for k, v in loaded.items():
                    if isinstance(v, dict):
                        data[k] = {"requires": v.get("requires", [START]),
                                   "grants": v.get("grants")}
                    elif isinstance(v, str):
                        data[k] = {"requires": [START], "grants": v}
        except Exception:
            pass
    return data


def _lookup(cmap, finding_class):
    if not finding_class:
        return None
    if finding_class in cmap:
        return cmap[finding_class]
    for key, spec in cmap.items():
        if finding_class.startswith(key) or key in finding_class:
            return spec
    return None


def _finding_class(finding):
    return (finding.get("finding_class") or finding.get("class")
            or finding.get("pattern_id") or finding.get("capability")
            or finding.get("kind") or "")


def _finding_id(finding):
    return finding.get("id") or finding.get("finding_id") \
        or _finding_class(finding)


def _severity(finding):
    return (finding.get("severity") or "medium").lower()


@dataclass
class Capability:
    actor: str
    can: str
    derived_from: list = field(default_factory=list)
    facts: list = field(default_factory=list)


@dataclass
class Edge:
    src: str
    dst: str
    finding_id: Any
    finding_class: str
    severity: str


class CapabilityGraph:
    def __init__(self, capability_map=None, actor="anon"):
        self.cmap = capability_map or load_capability_map()
        self.actor = actor
        self.edges = []            # list[Edge]
        self._adj = {}             # cap -> list[Edge]
        self._findings = {}        # finding_id -> finding

    def add_finding(self, finding):
        spec = _lookup(self.cmap, _finding_class(finding))
        if not spec or not spec.get("grants"):
            return []
        grants = spec["grants"]
        requires = spec.get("requires") or [START]
        fid = _finding_id(finding)
        self._findings[fid] = finding
        added = []
        for req in requires:
            edge = Edge(src=req, dst=grants, finding_id=fid,
                        finding_class=_finding_class(finding),
                        severity=_severity(finding))
            self.edges.append(edge)
            self._adj.setdefault(req, []).append(edge)
            added.append(edge)
        return added

    def build(self, findings):
        for f in findings or []:
            if f.get("verdict") not in (None, "VULNERABLE"):
                continue
            self.add_finding(f)
        return self

    def attack_paths(self, start=START, targets=None, min_steps=2):
        """Return simple edge-paths from start reaching a target verb."""
        targets = targets or TARGET_VERBS
        paths = []

        def dfs(node, path, seen_nodes):
            for edge in self._adj.get(node, []):
                if edge in path:
                    continue
                if edge.dst in seen_nodes:
                    # avoid cycles on capability nodes
                    continue
                new_path = path + [edge]
                if edge.dst in targets and len(new_path) >= min_steps:
                    paths.append(new_path)
                    # keep exploring for longer paths too
                dfs(edge.dst, new_path, seen_nodes | {edge.dst})

        dfs(start, [], {start})
        return _dedupe_paths(paths)

    def _bump_severity(self, path):
        worst = max((_SEVERITY_ORDER.get(e.severity, 3) for e in path),
                    default=3)
        bumped = min(5, worst + 1)
        return _ORDER_SEVERITY[bumped]

    def chain_findings(self, start=START, targets=None, min_steps=2):
        out = []
        for path in self.attack_paths(start, targets, min_steps):
            steps = []
            for i, e in enumerate(path, 1):
                steps.append({
                    "step": i,
                    "from": e.src,
                    "to": e.dst,
                    "finding_id": e.finding_id,
                    "finding_class": e.finding_class,
                    "severity": e.severity,
                })
            cap_seq = [start] + [e.dst for e in path]
            out.append({
                "kind": "capability_chain",
                "verdict": "VULNERABLE",
                "severity": self._bump_severity(path),
                "steps": steps,
                "n_steps": len(path),
                "path": cap_seq,
                "reason": f"{len(path)}-step attack path: "
                          + " -> ".join(cap_seq),
                "finding_ids": [e.finding_id for e in path],
            })
        # most steps / highest severity first
        out.sort(key=lambda c: (-c["n_steps"],
                                -_SEVERITY_ORDER.get(c["severity"], 0)))
        return out

    def render_markdown(self, chain):
        lines = [f"### {chain['n_steps']}-step attack path "
                 f"({chain['severity'].upper()})",
                 "", f"`{' -> '.join(chain['path'])}`", ""]
        for s in chain["steps"]:
            lines.append(f"{s['step']}. **{s['from']} → {s['to']}** — "
                         f"finding `{s['finding_id']}` "
                         f"({s['finding_class']}); see its evidence row.")
        return "\n".join(lines)


def _dedupe_paths(paths):
    seen = set()
    out = []
    for p in paths:
        key = tuple((e.finding_id, e.src, e.dst) for e in p)
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out


def analyze(findings, capability_map=None, start=START, min_steps=2):
    """Convenience: build graph from findings and return chain findings."""
    g = CapabilityGraph(capability_map=capability_map, actor=start)
    g.build(findings)
    return g.chain_findings(start=start, min_steps=min_steps)


__all__ = [
    "CapabilityGraph", "Capability", "Edge", "CANONICAL_VERBS",
    "TARGET_VERBS", "load_capability_map", "analyze", "START",
]
