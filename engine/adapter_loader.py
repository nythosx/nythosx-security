import yaml
from pathlib import Path

ROOT = Path(__file__).parent.parent.absolute()
ADAPTERS_DIR = ROOT / "adapters"


def _load_one(path):
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return None
    if "id" not in data:
        return None
    data["_source"] = str(path.relative_to(ROOT))
    data.setdefault("priority", 50)
    return data


def load_all():
    if not ADAPTERS_DIR.exists():
        return []
    adapters = []
    for p in sorted(ADAPTERS_DIR.glob("*.yaml")):
        a = _load_one(p)
        if a:
            adapters.append(a)
    adapters.sort(key=lambda x: -x.get("priority", 50))
    return adapters


def get(adapter_id):
    for a in load_all():
        if a.get("id") == adapter_id:
            return a
    return None


def list_ids():
    return [a["id"] for a in load_all()]
