from __future__ import annotations

from pathlib import Path

import yaml

from .models import AttackChain, ChainStep, ChainVerdict

_LIB_PATH = Path(__file__).parent / "library.yaml"
_CACHE = None


def _coerce_steps(raw):
    out = []
    for i, s in enumerate(raw or []):
        if isinstance(s, dict):
            out.append(ChainStep(
                order=int(s.get("order", i + 1)),
                action=str(s.get("action", "")),
                expects=str(s.get("expects", "")),
                outcome=str(s.get("outcome", "")),
            ))
        elif isinstance(s, str):
            out.append(ChainStep(order=i + 1, action=s))
    return out


def load_chains():
    global _CACHE
    if _CACHE is not None:
        return list(_CACHE)
    if not _LIB_PATH.exists():
        _CACHE = []
        return []
    from ..util import strict_yaml_load
    from .. import schema
    raw = strict_yaml_load(_LIB_PATH.read_text(encoding="utf-8")) or {}
    chains = []
    for entry in raw.get("chains") or []:
        if not isinstance(entry, dict):
            continue
        schema.validate_correlator_chain(
            entry, where=f"correlator:{entry.get('id', '?')}")
        chains.append(AttackChain(
            id=str(entry.get("id", "")),
            name=str(entry.get("name", "")),
            prerequisites=list(entry.get("prerequisites") or []),
            narrative=str(entry.get("narrative") or "").strip(),
            severity=str(entry.get("severity") or "high"),
            steps=_coerce_steps(entry.get("steps")),
        ))
    _CACHE = chains
    return list(chains)


def reload():
    global _CACHE
    _CACHE = None
    return load_chains()


__all__ = ["load_chains", "reload", "ChainVerdict"]
