"""LLM-driven business logic probing.

DeepSeek/Claude infers the intended state machine and proposes concrete
tampered step sequences. The deterministic probes in bizlogic.py remain
the fallback. This module only infers and executes; it never invents
endpoints, only proposes paths within the discovered surface.
"""
from __future__ import annotations

import json as _json
import re as _re

_MAX_PROMPT_CHARS = 12000
_MAX_FLAWS = 10


def infer_app_model(client, crawl_data):
    if client is None:
        return {"states": [], "transitions": [], "flaws": []}
    payload = _json.dumps(crawl_data or {}, default=str)[:_MAX_PROMPT_CHARS]
    prompt = (
        "You are a business logic auditor. Given the app's observed routes, "
        "forms, and response shapes, infer the intended state machine "
        "(states + allowed transitions) and list up to 5 plausible logic "
        "flaws (step skip, role confusion, negative quantity, currency "
        "mismatch, coupon stacking, verification bypass).\n"
        'Return JSON only: {"states": [str], "transitions": [str], '
        '"flaws": [{"name": str, "steps": [{"method": str, "path": str, '
        '"body": {}}]}]}\n\n'
        + payload
    )
    try:
        raw = client(prompt)
    except Exception:
        return {"states": [], "transitions": [], "flaws": []}
    txt = (raw or "").strip()
    m = _re.search(r"\{.*\}", txt, _re.S)
    if m:
        txt = m.group(0)
    try:
        data = _json.loads(txt)
    except Exception:
        return {"states": [], "transitions": [], "flaws": []}
    if not isinstance(data, dict):
        return {"states": [], "transitions": [], "flaws": []}
    flaws = []
    for f in (data.get("flaws") or [])[:_MAX_FLAWS]:
        if not isinstance(f, dict):
            continue
        steps = []
        for s in f.get("steps") or []:
            if not isinstance(s, dict):
                continue
            path = s.get("path") or ""
            method = str(s.get("method") or "POST").upper()
            if not path or not path.startswith("/"):
                continue
            steps.append({
                "method": method,
                "path": path,
                "body": s.get("body"),
            })
        if steps:
            flaws.append({
                "name": str(f.get("name") or "unnamed")[:80],
                "steps": steps,
            })
    return {
        "states": [str(s)[:120] for s in (data.get("states") or [])[:20]],
        "transitions": [str(s)[:200]
                        for s in (data.get("transitions") or [])[:50]],
        "flaws": flaws,
    }


def execute_flaws(roe_guard, base_url, model):
    from . import http as _http
    findings = []
    attempts = []
    for flaw in (model or {}).get("flaws") or []:
        name = flaw.get("name") or "unknown"
        for step in flaw.get("steps") or []:
            method = (step.get("method") or "POST").upper()
            path = step.get("path") or "/"
            url = base_url.rstrip("/") + "/" + path.lstrip("/")
            if roe_guard is not None:
                try:
                    roe_guard.check_url(url, method)
                except Exception as e:
                    attempts.append({"flaw": name, "url": url,
                                     "status": None,
                                     "error": f"ROE_BLOCK: {e}"})
                    continue
            try:
                with _http.Client(timeout=10, follow_redirects=False) as c:
                    kwargs = {}
                    if step.get("body") is not None:
                        kwargs["json"] = step["body"]
                    r = c.request(method, url, **kwargs)
            except _http.ROEBlock as e:
                attempts.append({"flaw": name, "url": url,
                                 "status": None,
                                 "error": f"ROE_BLOCK: {e}"})
                continue
            except Exception as e:
                attempts.append({"flaw": name, "url": url,
                                 "status": None,
                                 "error": f"{type(e).__name__}: {e}"})
                continue
            status = r.status_code
            ct = (r.headers.get("Content-Type") or "").lower()
            attempts.append({"flaw": name, "url": url,
                             "status": status, "method": method})
            if status in (200, 201, 202) and "json" in ct:
                findings.append({
                    "type": "business_logic",
                    "flaw": name,
                    "url": url,
                    "method": method,
                    "status": status,
                    "preview": (r.text or "")[:400],
                })
    return findings
