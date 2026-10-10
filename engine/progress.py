import time
import threading
from collections import defaultdict, deque
from queue import Queue, Empty

_lock = threading.Lock()
_subscribers = defaultdict(list)
_events = defaultdict(lambda: deque(maxlen=2000))
_done = set()

_active = threading.local()


def emit(job_id, event_type, data=None):
    if not job_id:
        return
    event = {"type": event_type, "data": data or {}, "ts": time.time()}
    with _lock:
        _events[job_id].append(event)
        if event_type in ("done", "error"):
            _done.add(job_id)
        for q in list(_subscribers.get(job_id, [])):
            try:
                q.put_nowait(event)
            except Exception:
                pass


def set_active_job(job_id):
    _active.job_id = job_id


def clear_active_job():
    _active.job_id = None


def active_job():
    return getattr(_active, "job_id", None)


def activity(message, stage=None, i=None, n=None, **extra):
    job_id = active_job()
    if not job_id:
        return
    data = {"message": message}
    if stage is not None:
        data["stage"] = stage
    if i is not None:
        data["i"] = i
    if n is not None:
        data["n"] = n
    if extra:
        data.update(extra)
    emit(job_id, "activity", data)


def subscribe(job_id):
    q = Queue()
    with _lock:
        for ev in _events.get(job_id, []):
            q.put_nowait(ev)
        _subscribers[job_id].append(q)
    return q


def unsubscribe(job_id, q):
    with _lock:
        try:
            _subscribers[job_id].remove(q)
        except (KeyError, ValueError):
            pass


def is_done(job_id):
    with _lock:
        return job_id in _done


def clear(job_id):
    with _lock:
        _events.pop(job_id, None)
        _subscribers.pop(job_id, None)
        _done.discard(job_id)