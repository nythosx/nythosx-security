from __future__ import annotations

from .chain_engine import register_tool
from .config import load_engine
from . import http as _http


def _verify_tls():
    try:
        return bool((load_engine() or {}).get("http", {}).get("verify_tls", True))
    except Exception:
        return True


def _session_cookie(r):
    cookies = {}
    try:
        for k, v in r.cookies.items():
            if any(h in k.lower() for h in ("session", "sid", "jsession",
                                             "phpsessid", "auth")):
                cookies[k] = v
    except Exception:
        pass
    return cookies


def _tool_session_fixation(orch, args):
    url = args.get("url") or orch.target
    login_path = args.get("login_path") or "/api/login"
    verify = _verify_tls()
    roe_guard = getattr(orch, "roe_guard", None)
    try:
        with _http.Client(timeout=10, verify=verify,
                          follow_redirects=False) as c:
            pre = c.get(url, headers={"Accept": "application/json"})
            pre_cookies = _session_cookie(pre)
            post = c.post(url.rstrip("/") + login_path,
                          json={"email": "probe@example.com",
                                "username": "probe@example.com",
                                "password": "probe"},
                          headers={"Accept": "application/json"})
            post_cookies = _session_cookie(post)
    except _http.ROEBlock as e:
        return {"verdict": "UNKNOWN", "reason": "ROE_BLOCK: " + str(e)}
    except Exception as e:
        return {"verdict": "UNKNOWN",
                "reason": f"{type(e).__name__}: {e}"}

    if not pre_cookies:
        return {"verdict": "UNKNOWN",
                "reason": "no session cookie issued before login",
                "evidence": {"pre_cookies": list(pre_cookies.keys()),
                             "post_cookies": list(post_cookies.keys())}}

    unchanged = [k for k in pre_cookies if post_cookies.get(k) == pre_cookies[k]]
    rotated = [k for k in pre_cookies if k in post_cookies
               and post_cookies[k] != pre_cookies[k]]
    if unchanged and not rotated:
        return {"verdict": "VULNERABLE",
                "reason": ("session cookie not rotated on login: "
                            + ", ".join(unchanged)),
                "evidence": {"unchanged": unchanged,
                             "pre_cookies": list(pre_cookies.keys()),
                             "post_cookies": list(post_cookies.keys())}}
    if rotated:
        return {"verdict": "PASS",
                "reason": "session cookie rotated on login",
                "evidence": {"rotated": rotated}}
    return {"verdict": "UNKNOWN",
            "reason": "session cookie present before login but absent after",
            "evidence": {"pre_cookies": list(pre_cookies.keys())}}


register_tool("session_fixation", _tool_session_fixation)
