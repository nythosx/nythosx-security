from __future__ import annotations

import copy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .config import load_roe

ROOT = Path(__file__).parent.parent.absolute()


DEFAULT_MUST_NEVER = (
    "rm -rf",
    "rm -fr",
    "drop table",
    "drop database",
    "truncate table",
    "shutdown",
    "reboot",
    "mkfs",
    "dd if=",
    ":(){:|:&};:",
    "cat /etc/shadow",
    "systemctl stop",
    "kill -9 1",
    "/dev/sda",
)


@dataclass
class PayloadPack:
    id: str
    family: str
    waf_safe: list = field(default_factory=list)
    waf_bypass: list = field(default_factory=list)
    context_variants: dict = field(default_factory=dict)
    decoder_chain: list = field(default_factory=list)
    must_never: list = field(default_factory=list)
    expected_signal: dict = field(default_factory=dict)

    def all_payloads(self):
        out = []
        for p in self.waf_safe:
            out.append(("waf_safe", p))
        for p in self.waf_bypass:
            out.append(("waf_bypass", p))
        for ctx, items in self.context_variants.items():
            for p in items:
                out.append((f"ctx:{ctx}", p))
        return out

    def copy(self):
        return copy.deepcopy(self)


_packs: dict = {}


def register(pack):
    _packs[pack.id] = pack


def get(pack_id):
    return _packs.get(pack_id)


def all_packs():
    return dict(_packs)


def _roe_must_never():
    try:
        roe = load_roe() or {}
    except Exception:
        return ()
    scope = roe.get("scope") or {}
    paths = scope.get("forbidden_paths") or []
    return tuple(str(p) for p in paths if p)


def combined_must_never(pack=None):
    parts = list(DEFAULT_MUST_NEVER)
    if pack is not None:
        parts.extend(pack.must_never)
    parts.extend(_roe_must_never())
    seen = []
    for p in parts:
        if p not in seen:
            seen.append(p)
    return tuple(seen)


def violates_must_never(payload, pack=None):
    if not payload:
        return False
    low = str(payload).lower()
    for blocker in combined_must_never(pack):
        if blocker.lower() in low:
            return True
    return False


def _prior_success(pack_id, waf_fingerprint):
    try:
        from . import program_memory
    except Exception:
        return {}
    waf = waf_fingerprint or "unknown"
    encodings = list(program_memory.get_waf_bypasses(waf) or [])
    scores = {}
    for idx, enc in enumerate(encodings):
        scores[enc] = 1.0 - (idx * 0.05)
    return scores


def _context_score(entry_kind, ctx):
    if not ctx:
        return 0
    if entry_kind == "waf_safe":
        return 1
    if entry_kind == "waf_bypass":
        return 2
    if entry_kind == f"ctx:{ctx}":
        return 5
    return 0


def pick(pack, ctx=None, waf=None, budget=None):
    if pack is None:
        return []
    prior = _prior_success(pack.id, waf)
    scored = []
    for idx, (kind, payload) in enumerate(pack.all_payloads()):
        if violates_must_never(payload, pack):
            continue
        base = _context_score(kind, ctx)
        bonus = 0.0
        for enc in pack.decoder_chain:
            if enc in prior:
                bonus = max(bonus, prior[enc])
        cost = 0.0
        if kind == "waf_bypass":
            cost = 1.0
        elif kind.startswith("ctx:"):
            cost = 0.5
        score = base + bonus - cost
        scored.append((score, idx, payload))
    scored.sort(key=lambda t: (-t[0], t[1]))
    out = [p for _s, _i, p in scored]
    if budget is not None and budget >= 0:
        return out[: int(budget)]
    return out


def pick_signal(pack, payload):
    if not pack or not payload:
        return {}
    return dict(pack.expected_signal.get(payload, {}) or {})
