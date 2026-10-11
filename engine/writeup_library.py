from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

_LIB_PATH = Path(__file__).parent / "writeup_library.yaml"
_TEMPLATE_RE = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")
_DATA = None


@dataclass
class WriteupEntry:
    pattern_id: str
    family: str
    title: str = ""
    attack: str = ""
    gap: str = ""
    impact: str = ""
    fix: str = ""
    refs: dict = field(default_factory=dict)
    vars: dict = field(default_factory=dict)

    def to_dict(self):
        return {
            "pattern_id": self.pattern_id,
            "family": self.family,
            "title": self.title,
            "attack": self.attack,
            "gap": self.gap,
            "impact": self.impact,
            "fix": self.fix,
            "refs": self.refs,
            "vars": self.vars,
        }


def _load():
    global _DATA
    if _DATA is not None:
        return _DATA
    if not _LIB_PATH.exists():
        _DATA = {"families": {}, "patterns": {}}
        return _DATA
    from .util import strict_yaml_load
    from . import schema
    raw = strict_yaml_load(_LIB_PATH.read_text(encoding="utf-8")) or {}
    families = raw.get("families") or {}
    patterns = raw.get("patterns") or {}
    for name, fam in families.items():
        schema.validate_writeup_family(
            fam, where=f"writeup-family:{name}")
    for pid, pat in patterns.items():
        schema.validate_writeup_pattern(
            pat, where=f"writeup-pattern:{pid}")
    _DATA = {
        "families": families,
        "patterns": patterns,
    }
    return _DATA


def reload():
    global _DATA
    _DATA = None
    return _load()


def families():
    return dict(_load()["families"])


def _pick(d, keys, default=""):
    for k in keys:
        v = d.get(k)
        if v:
            return v
    return default


def resolve(pattern_id):
    data = _load()
    pat = data["patterns"].get(pattern_id)
    if not pat:
        return None
    fam_name = pat.get("family") or "generic"
    fam = data["families"].get(fam_name) or {}
    return WriteupEntry(
        pattern_id=pattern_id,
        family=fam_name,
        title=_pick(pat, ["title"]) or _pick(fam, ["title"]) or pattern_id,
        attack=_pick(pat, ["attack"]) or _pick(fam, ["attack"]),
        gap=_pick(pat, ["gap"]) or _pick(fam, ["gap"]),
        impact=_pick(pat, ["impact"]) or _pick(fam, ["impact"]),
        fix=_pick(pat, ["fix"]) or _pick(fam, ["fix"]),
        refs=dict(fam.get("refs") or {}),
        vars=dict(pat.get("vars") or {}),
    )


def _lookup_path(evidence, path):
    cur = evidence
    for part in str(path).split("."):
        if part.startswith("evidence.") or part.startswith("evidence_"):
            continue
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list) and part.isdigit():
            i = int(part)
            cur = cur[i] if i < len(cur) else None
        else:
            return None
        if cur is None:
            return None
    return cur


def _resolve_var(evidence, name, spec):
    if spec is None:
        return ""
    if isinstance(spec, str):
        return spec
    if not isinstance(spec, dict):
        return str(spec)
    path = spec.get("path") or ""
    default = spec.get("default", "")
    if path.startswith("evidence."):
        path = path[len("evidence."):]
    value = _lookup_path(evidence or {}, path)
    if value is None:
        value = default
    if isinstance(value, list):
        sep = spec.get("join", ", ")
        value = sep.join(str(v) for v in value)
    return str(value)


def render(entry, evidence=None):
    if entry is None:
        return {"attack": "", "gap": "", "impact": "", "fix": ""}
    evidence = evidence or {}
    resolved = {}
    for name, spec in (entry.vars or {}).items():
        resolved[name] = _resolve_var(evidence, name, spec)

    def sub(template):
        if not template:
            return ""
        return _TEMPLATE_RE.sub(
            lambda m: resolved.get(m.group(1), "{" + m.group(1) + "}"),
            template,
        )

    return {
        "title": sub(entry.title),
        "attack": sub(entry.attack),
        "gap": sub(entry.gap),
        "impact": sub(entry.impact),
        "fix": sub(entry.fix),
        "refs": entry.refs,
    }


def coverage_missing(pattern_ids):
    data = _load()
    known = set(data["patterns"].keys())
    return sorted(set(pattern_ids) - known)


__all__ = [
    "WriteupEntry", "resolve", "render", "families",
    "coverage_missing", "reload",
]
