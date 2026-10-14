from __future__ import annotations

import re

from .chain_engine import register_tool
from .config import load_engine
from . import http as _http


_ADD_LISTENER = re.compile(
    r"""addEventListener\s*\(\s*['"]message['"][^)]*""", re.DOTALL)


def _verify_tls():
    try:
        return bool((load_engine() or {}).get("http", {}).get("verify_tls", True))
    except Exception:
        return True


def _tool_postmessage_probe(orch, args):
    url = args.get("url") or orch.target
    verify = _verify_tls()
    try:
        with _http.Client(timeout=10, verify=verify, follow_redirects=True) as c:
            r = c.get(url)
    except Exception as e:
        return {"verdict": "UNKNOWN", "reason": f"{type(e).__name__}: {e}"}

    body = r.text or ""
    listeners = _ADD_LISTENER.findall(body)
    if not listeners:
        return {"verdict": "PASS",
                "reason": "no message event listener found",
                "evidence": {"size": len(body)}}

    unsafe = []
    for m in listeners:
        snippet = m[:300]
        if "event.origin" not in snippet and "e.origin" not in snippet \
                and "evt.origin" not in snippet and "ev.origin" not in snippet:
            unsafe.append(snippet[:200])

    if unsafe:
        return {"verdict": "SUSPICIOUS",
                "reason": (f"{len(unsafe)} message listener(s) do not check "
                            f"event.origin"),
                "evidence": {"unsafe_listeners": unsafe}}
    return {"verdict": "PASS",
            "reason": "all message listeners check event.origin",
            "evidence": {"listeners": len(listeners)}}


register_tool("postmessage_probe", _tool_postmessage_probe)
