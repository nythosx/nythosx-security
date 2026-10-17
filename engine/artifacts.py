from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).parent.parent.absolute()
ARTIFACT_DIR = ROOT / "findings" / "artifacts"

try:
    from cryptography.fernet import Fernet
    HAS_FERNET = True
except ImportError:
    HAS_FERNET = False

_lock = threading.Lock()


def _safe(name):
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in str(name))[:80]


def _key():
    raw = os.environ.get("EVIDENCE_KEY")
    if not raw:
        return None
    try:
        return raw.encode("utf-8")
    except Exception:
        return None


def _path_plain(target):
    return ARTIFACT_DIR / (_safe(target) + ".jsonl")


def _path_enc(target):
    return ARTIFACT_DIR / (_safe(target) + ".jsonl.enc")


def _encrypt_lines(lines):
    if not HAS_FERNET:
        return None
    k = _key()
    if not k:
        return None
    try:
        f = Fernet(k)
        return f.encrypt("\n".join(lines).encode("utf-8"))
    except Exception:
        return None


def _decrypt_lines(blob):
    if not HAS_FERNET:
        return []
    k = _key()
    if not k:
        return []
    try:
        f = Fernet(k)
        raw = f.decrypt(blob).decode("utf-8")
        return [line for line in raw.split("\n") if line.strip()]
    except Exception:
        return []


def _ingest(target, kind, chain_id, outcome, body):
    try:
        from . import evidence_warehouse as _wh
        _wh.ingest(target=target, endpoint="(artifact)",
                   kind=f"artifact:{kind}", status=0,
                   body=body, chain_id=chain_id)
    except Exception:
        pass


def write(target, kind, value, chain_id="", outcome=""):
    if not target:
        return None
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "target": str(target),
        "kind": str(kind or "artifact"),
        "chain_id": str(chain_id or ""),
        "outcome": str(outcome or ""),
        "value": value if isinstance(value, (dict, list, str, int, float, bool, type(None))) else str(value),
    }
    line = json.dumps(entry, default=str, ensure_ascii=False)
    with _lock:
        ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
        if HAS_FERNET and _key():
            enc_path = _path_enc(target)
            lines = _decrypt_lines(enc_path.read_bytes()) if enc_path.exists() else []
            lines.append(line)
            token = _encrypt_lines(lines)
            if token is not None:
                enc_path.write_bytes(token)
                _ingest(target, kind, chain_id, outcome, line)
                return str(enc_path)
        plain = _path_plain(target)
        with plain.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        _ingest(target, kind, chain_id, outcome, line)
        return str(plain)


def load_for(target):
    if not target:
        return []
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    enc_path = _path_enc(target)
    if enc_path.exists():
        lines = _decrypt_lines(enc_path.read_bytes())
    else:
        plain = _path_plain(target)
        if not plain.exists():
            return []
        try:
            lines = [l for l in plain.read_text(encoding="utf-8").split("\n") if l.strip()]
        except Exception:
            return []
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out


def clear(target):
    for p in (_path_plain(target), _path_enc(target)):
        try:
            if p.exists():
                p.unlink()
        except Exception:
            pass


__all__ = ["write", "load_for", "clear", "ARTIFACT_DIR"]
