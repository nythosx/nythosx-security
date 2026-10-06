import os
import tempfile
from pathlib import Path


def safe_name(s, maxlen=80):
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in s)[:maxlen]


def atomic_write_text(path, text, encoding="utf-8"):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding=encoding) as f:
            f.write(text)
        os.replace(tmp, path)
    except Exception:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def atomic_write_json(path, obj, indent=2):
    import json
    atomic_write_text(path, json.dumps(obj, indent=indent, default=str))
