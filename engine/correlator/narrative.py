from __future__ import annotations


def render(chain):
    if chain is None:
        return ""
    if isinstance(chain, dict):
        return _render_dict(chain)
    lines = []
    lines.append(f"{chain.name} ({chain.id})")
    lines.append(f"Verdict: {chain.verdict}   Confidence: {chain.confidence:.2f}   Severity: {chain.severity}")
    lines.append("")
    if chain.narrative:
        lines.append(chain.narrative.strip())
        lines.append("")
    if chain.prerequisites:
        lines.append("Prerequisites:")
        for req in chain.prerequisites:
            hit = next((m for m in chain.matched if m["pattern_id"] == req), None)
            if hit:
                lines.append(f"  [x] {req}  ({hit.get('verdict')})")
            else:
                lines.append(f"  [ ] {req}  (missing)")
        lines.append("")
    if chain.steps:
        lines.append("Steps:")
        for s in chain.steps:
            order = getattr(s, "order", None) or s.get("order")
            action = getattr(s, "action", None) or s.get("action")
            outcome = getattr(s, "outcome", None) or s.get("outcome")
            suffix = f" -> {outcome}" if outcome else ""
            lines.append(f"  {order}. {action}{suffix}")
    return "\n".join(lines)


def _render_dict(chain):
    lines = [f"{chain.get('name')} ({chain.get('id')})",
             f"Verdict: {chain.get('verdict')}",
             "", (chain.get("narrative") or "").strip()]
    return "\n".join(lines)


__all__ = ["render"]
