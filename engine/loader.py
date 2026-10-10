import yaml
from pathlib import Path

ROOT = Path(__file__).parent.parent.absolute()
PATTERNS_DIR = ROOT / "patterns"
CATEGORIES = ["single", "sequence", "temporal", "content", "combination", "meta", "llm"]
REQUIRED_FIELDS = ["id", "name", "severity", "steps", "oracles"]


def validate_pattern(data):
    errors = []
    for field in REQUIRED_FIELDS:
        if field not in data:
            errors.append(f"missing field: {field}")
    if "severity" in data and data["severity"] not in ("critical", "high", "medium", "low", "info"):
        errors.append(f"invalid severity: {data['severity']}")
    if "steps" in data and not isinstance(data["steps"], list):
        errors.append("steps must be a list")
    if "oracles" in data and not isinstance(data["oracles"], list):
        errors.append("oracles must be a list")
    return errors


def load_pattern(pattern_id):
    for cat in CATEGORIES:
        d = PATTERNS_DIR / cat
        if not d.exists():
            continue
        for f in sorted(d.glob("*.yaml")):
            try:
                data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
            except Exception:
                continue
            if data.get("id") == pattern_id or f.stem == pattern_id:
                data["_source"] = str(f)
                data["_category"] = cat
                return data
    return None


def list_patterns():
    results = []
    for cat in CATEGORIES:
        d = PATTERNS_DIR / cat
        if not d.exists():
            continue
        for f in sorted(d.glob("*.yaml")):
            try:
                data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
            except Exception:
                continue
            results.append({
                "id": data.get("id", f.stem),
                "name": data.get("name", ""),
                "severity": data.get("severity", "info"),
                "category": cat,
                "tags": data.get("tags", []),
                "file": str(f.relative_to(ROOT)),
            })
    return results


def validate_all():
    results = []
    for cat in CATEGORIES:
        d = PATTERNS_DIR / cat
        if not d.exists():
            continue
        for f in sorted(d.glob("*.yaml")):
            try:
                data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
                errors = validate_pattern(data)
                results.append((str(f.relative_to(ROOT)), errors))
            except Exception as e:
                results.append((str(f.relative_to(ROOT)), [f"parse error: {e}"]))
    return results
