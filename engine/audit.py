from __future__ import annotations

import atexit
import hashlib
import json
import queue
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).parent.parent.absolute()
AUDIT_DIR = ROOT / "findings"
AUDIT_FILE = AUDIT_DIR / "audit.jsonl"

_enabled = True
_QUEUE_MAX = 10000
_queue = queue.Queue(maxsize=_QUEUE_MAX)
_writer_lock = threading.Lock()
_writer_thread = None
_dropped = 0


def enable():
    global _enabled
    _enabled = True


def disable():
    global _enabled
    _enabled = False


def _drain_batch(first):
    batch = [first]
    while True:
        try:
            batch.append(_queue.get_nowait())
        except queue.Empty:
            break
    return batch


def _writer_loop():
    while True:
        line = _queue.get()
        if line is None:
            _queue.task_done()
            return
        batch = _drain_batch(line)
        try:
            AUDIT_DIR.mkdir(parents=True, exist_ok=True)
            with AUDIT_FILE.open("a", encoding="utf-8") as f:
                for entry in batch:
                    if entry is not None:
                        f.write(entry + "\n")
        except Exception:
            pass
        for _ in batch:
            _queue.task_done()


def _ensure_writer():
    global _writer_thread
    if _writer_thread is not None and _writer_thread.is_alive():
        return
    with _writer_lock:
        if _writer_thread is not None and _writer_thread.is_alive():
            return
        _writer_thread = threading.Thread(
            target=_writer_loop, name="audit-writer", daemon=True)
        _writer_thread.start()


def flush(timeout=5.0):
    if _writer_thread is None:
        return
    deadline = time.monotonic() + timeout
    while not _queue.empty() and time.monotonic() < deadline:
        time.sleep(0.01)


atexit.register(flush)


def _hash(value):
    if value is None:
        return None
    return hashlib.sha256(str(value).encode("utf-8", "ignore")).hexdigest()[:16]


def _redact(value):
    if value is None:
        return None
    try:
        from . import redact as _redact_mod
        return _redact_mod.redact_text(str(value))
    except Exception:
        return str(value)


def record(action, target=None, method=None, url=None, credential_used=None,
           payload=None, verdict=None, status=None, duration_ms=None,
           error=None, extra=None):
    if not _enabled:
        return
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "mono": round(time.monotonic(), 6),
        "action": str(action),
    }
    if target is not None:
        entry["target"] = _redact(target)
    if method is not None:
        entry["method"] = str(method).upper()
    if url is not None:
        entry["url"] = _redact(url)
    if credential_used is not None:
        entry["credential_hash"] = _hash(credential_used)
    if payload is not None:
        entry["payload_hash"] = _hash(payload)
        entry["payload_len"] = len(str(payload))
    if verdict is not None:
        entry["verdict"] = str(verdict)
    if status is not None:
        try:
            entry["status"] = int(status)
        except (TypeError, ValueError):
            pass
    if duration_ms is not None:
        try:
            entry["duration_ms"] = float(duration_ms)
        except (TypeError, ValueError):
            pass
    if error is not None:
        entry["error"] = _redact(error)[:500]
    if extra:
        try:
            entry["extra"] = _redact(json.dumps(extra, default=str))[:1000]
        except Exception:
            pass
    global _dropped
    line = json.dumps(entry, ensure_ascii=False, default=str)
    _ensure_writer()
    try:
        _queue.put_nowait(line)
    except queue.Full:
        _dropped += 1


def tail(n=100):
    flush()
    if not AUDIT_FILE.exists():
        return []
    try:
        with AUDIT_FILE.open("r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception:
        return []
    out = []
    for line in lines[-n:]:
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out


def count():
    flush()
    if not AUDIT_FILE.exists():
        return 0
    try:
        with AUDIT_FILE.open("r", encoding="utf-8") as f:
            return sum(1 for _ in f)
    except Exception:
        return 0


def dropped():
    return _dropped


__all__ = ["record", "tail", "count", "enable", "disable", "flush", "dropped"]
