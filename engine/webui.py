import io
import json
import time
import threading
import uuid
from urllib.parse import urlparse as _urlparse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from queue import Empty
from rich.console import Console

from . import auto as auto_mod
from . import ledger
from . import progress
from .config import load_engine
from .roe_guard import ROEGuard, ROEViolation
from . import redact


_jobs = {}
_jobs_lock = threading.Lock()
_run_lock = threading.Lock()


def _set(job_id, **kw):
    with _jobs_lock:
        _jobs.setdefault(job_id, {}).update(kw)


def _get(job_id):
    with _jobs_lock:
        j = _jobs.get(job_id)
        return dict(j) if j else None


def _collect_data_rows(outcome):
    chain_report = (outcome or {}).get("chain_report") or {}
    rows = []
    for chain in (chain_report.get("chain_results") or []):
        for step in (chain.get("steps") or []):
            for dr in (step.get("data_rows") or []):
                if isinstance(dr, dict) and dr.get("rows"):
                    rows.append(dr)
    return rows


def _findings_for(target):
    rows = ledger.findings_for_target(target)
    keys = ["id", "timestamp", "pattern_id", "category", "verdict", "severity",
            "reason", "wstg_id", "cwe_id", "evidence_path", "duration_ms"]
    seen = set()
    out = []
    for r in rows:
        f = dict(zip(keys, r))
        key = (f["pattern_id"], f["verdict"], (f.get("reason") or "")[:120])
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def _extracted_dedup_key(endpoint, rows):
    import hashlib, json as _json
    first = None
    if isinstance(rows, list) and rows:
        first = rows[0]
    try:
        blob = _json.dumps(first, sort_keys=True, default=str)
    except Exception:
        blob = str(first)
    h = hashlib.sha256(blob.encode("utf-8", "replace")).hexdigest()[:16]
    return (str(endpoint or ""), h)


def _build_result(url, outcome, log_text):
    targets = (outcome or {}).get("targets") or {}
    scan_target = targets.get("api_base") or url
    framework = (outcome or {}).get("framework") or {}
    adapter = framework.get("adapter") or {}
    login = (outcome or {}).get("login")
    findings = _findings_for(scan_target)
    chains, coverage = [], None
    extracted_rows = []
    try:
        from . import report as _report
        _report.enrich_findings(findings)
        chains = _report.build_chains(findings)
        coverage = _report.build_coverage(scan_target, findings)
        _report._enrich_extracted_from_evidence_json(findings)
        extracted_rows = _report._collect_extracted_for_report(findings)
    except Exception:
        pass
    seen_extracted = set()
    for e in extracted_rows:
        seen_extracted.add(_extracted_dedup_key(e.get("endpoint"), e.get("rows")))
    try:
        from . import ledger as _ledger
        for entry in _ledger.extracted_for_target(scan_target):
            rows = entry.get("rows") or []
            if not rows:
                continue
            masked = []
            for r in rows:
                if isinstance(r, dict):
                    try:
                        from .util import mask_row
                        masked.append(mask_row(r))
                    except Exception:
                        masked.append(r)
                else:
                    masked.append(r)
            endpoint = entry.get("endpoint") or scan_target
            key = _extracted_dedup_key(endpoint, masked)
            if key in seen_extracted:
                continue
            seen_extracted.add(key)
            extracted_rows.append({
                "endpoint": endpoint,
                "auth_used": entry.get("auth_used") or "unknown",
                "total_rows": int(entry.get("total_rows") or len(rows)),
                "extracted": int(entry.get("extracted") or len(masked)),
                "pattern": entry.get("source_pattern") or "cli",
                "rows": masked,
            })
    except Exception:
        pass
    confirmed_count = sum(
        1 for f in findings
        if (f.get("confirmation_status") or "") == "confirmed")
    signal_findings = [f for f in findings if f.get("signal_strength")]
    avg_signal = (round(sum(f["signal_strength"] for f in signal_findings)
                        / len(signal_findings), 3)
                  if signal_findings else None)
    return redact.redact_dict({
        "target": scan_target,
        "entered_url": url,
        "framework": {"name": adapter.get("name", framework.get("name", "Generic")),
                      "id": adapter.get("id", framework.get("framework", "generic")),
                      "score": framework.get("score", 0)},
        "api_base": scan_target,
        "api_paths_count": len((outcome or {}).get("api_paths") or []),
        "logged_in": bool(login and (login.get("token") if isinstance(login, dict) else False)),
        "counts": (outcome or {}).get("counts") or {},
        "findings": findings,
        "chains": chains,
        "coverage": coverage,
        "confirmed_count": confirmed_count,
        "avg_signal_strength": avg_signal,
        "report_target": scan_target,
        "endpoint_probes": (outcome or {}).get("endpoint_probes") or [],
        "data_rows": _collect_data_rows(outcome),
        "extracted_rows": extracted_rows,
        "total_extracted": sum(e.get("extracted", 0)
                                for e in extracted_rows),
        "log": log_text,
    })


def _run_job(job_id, url, min_severity, credentials=None, ai_key=None, use_brain=True):
    buf = io.StringIO()
    # sec-checker runs one scan at a time (auto_mod.console is a shared
    # global swapped per job). If another scan is already running, say so
    # instead of sitting silently on the lock — the client would otherwise
    # see no events at all and look hung.
    if not _run_lock.acquire(blocking=False):
        _set(job_id, status="queued", phase="queued")
        progress.emit(job_id, "activity", {
            "message": "Queued: another scan is already running "
                       "(sec-checker runs one scan at a time). Waiting for "
                       "it to finish..."})
        _run_lock.acquire()
    try:
        old_console = auto_mod.console
        auto_mod.console = Console(file=buf, force_terminal=False, width=100)
        try:
            _set(job_id, status="running", phase="starting")
            outcome = auto_mod.run_auto(url, min_severity=min_severity,
                                          job_id=job_id,
                                          credentials=credentials,
                                          ai_key=ai_key,
                                          use_brain=use_brain)
            result = _build_result(url, outcome, buf.getvalue())
            _set(job_id, status="done", phase="done", result=result)
            if not progress.is_done(job_id):
                progress.emit(job_id, "done", {"counts": result.get("counts") or {},
                                                 "report_target": result.get("report_target")})
        except Exception as e:
            _set(job_id, status="error", phase="error",
                 error=f"{type(e).__name__}: {e}", log=buf.getvalue())
            progress.emit(job_id, "error", {"message": f"{type(e).__name__}: {e}"})
        finally:
            auto_mod.console = old_console
    finally:
        _run_lock.release()


def _resolve_session_headers(session_name, auth_str):
    headers = {}
    if auth_str:
        if auth_str.startswith("bearer:"):
            headers["Authorization"] = f"Bearer {auth_str[7:]}"
        elif auth_str.startswith("apikey:"):
            headers["X-API-Key"] = auth_str[7:]
    if session_name:
        try:
            from .config import load_session
            from . import auth_flow
            sess = load_session(session_name)
            if sess:
                headers.update(auth_flow.build_headers_from_session(sess))
        except Exception:
            pass
    return headers, {}, True


def _roe_ok(url):
    try:
        ROEGuard(engine_cfg=load_engine()).check_url(url, "GET")
        return True, None
    except ROEViolation as e:
        return False, str(e)


class _Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def do_GET(self):
        if not _check_origin(self):
            return self._send(403, {"error": "cross-origin request rejected"})
        if not _check_token(self):
            return self._send(401, {"error": "missing or invalid token"})
        if self.path == "/" or self.path.startswith("/?"):
            import os as _os
            classic = (
                "ui=classic" in self.path
                or _os.environ.get("SEC_CHECKER_UI", "").lower() == "classic"
            )
            page = PAGE_CLASSIC if classic else PAGE
            return self._send(200, page, "text/html; charset=utf-8")
        if self.path.startswith("/api/scan/") and self.path.endswith("/stream"):
            parts = self.path.split("/")
            job_id = parts[3] if len(parts) >= 4 else ""
            if not job_id:
                return self._send(400, {"error": "missing job_id"})
            return self._stream(job_id)
        if self.path.startswith("/api/job/"):
            job_id = self.path.rsplit("/", 1)[1]
            job = _get(job_id)
            if not job:
                return self._send(404, {"error": "unknown job"})
            if job.get("status") == "done" and job.get("result"):
                from . import narrator
                try:
                    job = dict(job)
                    job["narrator_summary"] = narrator.summarize(job["result"])
                except Exception:
                    pass
            return self._send(200, {k: v for k, v in job.items()})
        if self.path.startswith("/api/export"):
            return self._export()
        if self.path == "/api/ai_status":
            return self._ai_status()
        if self.path == "/api/defaults":
            return self._defaults()
        return self._send(404, {"error": "not found"})

    def _defaults(self):
        from pathlib import Path as _P
        out = {"target": "https://nythosx.com"}
        try:
            p = _P(__file__).parent.parent / "configs" / "credentials.yaml"
            if p.exists():
                import yaml as _yaml
                data = _yaml.safe_load(p.read_text(encoding="utf-8")) or {}
                wd = data.get("webui_defaults") or {}
                if wd.get("target"):
                    out["target"] = wd["target"]
                for k in ("username", "password", "login_url", "token"):
                    if wd.get(k):
                        out[k] = wd[k]
        except Exception:
            pass
        return self._send(200, out)

    def _ai_status(self):
        try:
            from engine.config import load_engine
            import os
            cfg = (load_engine() or {}).get("brain") or {}
            llm = cfg.get("llm") or {}
            provider = llm.get("provider") or cfg.get("provider") or ""
            model = llm.get("model") or cfg.get("model") or ""
            env_name = llm.get("api_key_env") or "SECCHECKER_LLM_API_KEY"
            key_envs = [env_name, "SECCHECKER_LLM_API_KEY", "LLM_API_KEY",
                        "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
                        "GEMINI_API_KEY", "GOOGLE_API_KEY"]
            configured = any(os.environ.get(e) for e in key_envs)
            return self._send(200, {
                "configured": configured,
                "provider": provider,
                "model": model,
                "env_names": key_envs,
            })
        except Exception as e:
            return self._send(200, {"configured": False,
                                     "error": f"{type(e).__name__}: {e}"})

    def _extract(self):
        length = int(self.headers.get("Content-Length", 0))
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return self._send(400, {"error": "invalid JSON"})
        url = (payload.get("url") or "").strip()
        if not url:
            return self._send(400, {"error": "url is required"})
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        ok, reason = _roe_ok(url)
        if not ok:
            return self._send(403, {
                "error": "URL not in ROE scope",
                "detail": reason,
                "hint": ("Add the host to configs/roe.yaml -> scope.in_scope, "
                         "then retry. sec-checker is fail-closed by design."),
            })
        session = payload.get("session")
        auth_str = payload.get("auth")
        rows = int(payload.get("rows") or 5)
        headers, _cookies, ok = _resolve_session_headers(session, auth_str)
        token = None
        for k, v in headers.items():
            if k.lower() == "authorization":
                token = v.split(" ", 1)[1] if " " in v else v
                break
        from engine.data_extractor import extract_endpoint
        row, err, kind = extract_endpoint(url, token=token, max_rows=rows)
        if row is None:
            return self._send(200, {"verdict": "PASS", "reason": err,
                                     "kind": kind, "rows": []})
        return self._send(200, {
            "verdict": "VULNERABLE",
            "endpoint": row.endpoint,
            "auth_used": row.auth_used,
            "total_rows": row.total_rows,
            "extracted": row.extracted,
            "rows": row.masked_json_rows() if hasattr(row, "masked_json_rows")
                    else row.rows,
        })

    def _recon(self):
        length = int(self.headers.get("Content-Length", 0))
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return self._send(400, {"error": "invalid JSON"})
        url = (payload.get("url") or "").strip()
        if not url:
            return self._send(400, {"error": "url is required"})
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        ok, reason = _roe_ok(url)
        if not ok:
            return self._send(403, {
                "error": "URL not in ROE scope",
                "detail": reason,
                "hint": ("Add the host to configs/roe.yaml -> scope.in_scope, "
                         "then retry. sec-checker is fail-closed by design.")})
        session = payload.get("session")
        auth_str = payload.get("auth")
        rows = int(payload.get("rows") or 3)
        headers, _cookies, _ok = _resolve_session_headers(session, auth_str)
        token = None
        for k, v in headers.items():
            if k.lower() == "authorization":
                token = v.split(" ", 1)[1] if " " in v else v
                break
        try:
            from . import recon_sweep
            result = recon_sweep.deep_recon(
                url, token=token,
                do_extract=payload.get("extract", True) is not False,
                do_idor=payload.get("idor", True) is not False,
                rows=rows)
        except Exception as e:
            return self._send(500, {"error": f"{type(e).__name__}: {e}"})
        return self._send(200, redact.redact_dict(result))

    def _export(self):
        from urllib.parse import parse_qs
        parsed = _urlparse(self.path)
        qs = parse_qs(parsed.query)
        target = (qs.get("target") or [""])[0].strip()
        fmt = (qs.get("fmt") or ["pdf"])[0].strip().lower()
        if fmt not in ("pdf", "html", "md", "sarif"):
            return self._send(400, {"error": "fmt must be pdf, html, md, or sarif"})
        if not target or target not in ledger.all_targets():
            return self._send(404, {"error": "unknown scan target"})
        from . import report as _report
        try:
            path = _report.generate(target, fmt=fmt)
        except Exception as e:
            return self._send(500, {"error": f"{type(e).__name__}: {e}"})
        import os as _os
        ctypes = {"pdf": "application/pdf", "html": "text/html; charset=utf-8",
                  "md": "text/markdown; charset=utf-8",
                  "sarif": "application/json"}
        try:
            with open(path, "rb") as f:
                data = f.read()
        except Exception as e:
            return self._send(500, {"error": f"{type(e).__name__}: {e}"})
        self.send_response(200)
        self.send_header("Content-Type", ctypes.get(fmt, "application/octet-stream"))
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Disposition",
                          f'attachment; filename="{_os.path.basename(path)}"')
        self.end_headers()
        try:
            self.wfile.write(data)
        except Exception:
            pass

    def _stream(self, job_id):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache, no-transform")
        self.send_header("Connection", "close")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        q = progress.subscribe(job_id)
        try:
            while True:
                try:
                    event = q.get(timeout=20)
                except Empty:
                    try:
                        self.wfile.write(b": hb\n\n")
                        self.wfile.flush()
                    except Exception:
                        break
                    continue
                payload = json.dumps(event, default=str)
                try:
                    self.wfile.write(("data: " + payload + "\n\n").encode("utf-8"))
                except Exception:
                    break
                from . import narrator
                try:
                    narration = narrator.narrate(
                        event.get("type"), event.get("data") or {})
                except Exception:
                    narration = None
                if narration:
                    n_event = {"type": "narrator", "data": narration}
                    np = json.dumps(n_event, default=str)
                    try:
                        self.wfile.write(("data: " + np + "\n\n").encode("utf-8"))
                    except Exception:
                        break
                try:
                    self.wfile.flush()
                except Exception:
                    break
                if event.get("type") in ("done", "error"):
                    break
        finally:
            progress.unsubscribe(job_id, q)

    def do_POST(self):
        if not _check_origin(self):
            return self._send(403, {"error": "cross-origin request rejected"})
        if not _check_token(self):
            return self._send(401, {"error": "missing or invalid token"})
        if self.path == "/api/extract":
            return self._extract()
        if self.path == "/api/recon":
            return self._recon()
        if self.path != "/api/scan":
            return self._send(404, {"error": "not found"})
        length = int(self.headers.get("Content-Length", 0))
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return self._send(400, {"error": "invalid JSON"})
        url = (payload.get("url") or "").strip()
        min_severity = payload.get("min_severity", "medium")
        credentials = payload.get("credentials")
        if not isinstance(credentials, dict):
            credentials = None
        ai_key = payload.get("ai_key")
        if not isinstance(ai_key, str) or not ai_key.strip():
            ai_key = None
        use_brain = payload.get("use_brain", True) is not False
        if not url:
            return self._send(400, {"error": "url is required"})
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        ok, reason = _roe_ok(url)
        if not ok:
            return self._send(403, {
                "error": "URL not in ROE scope",
                "detail": reason,
                "hint": "Add the host to configs/roe.yaml -> scope.in_scope, "
                        "then retry. sec-checker is fail-closed by design."})
        job_id = uuid.uuid4().hex[:12]
        progress.clear(job_id)
        _set(job_id, status="queued", phase="queued", url=url)
        threading.Thread(target=_run_job,
                         args=(job_id, url, min_severity, credentials, ai_key, use_brain),
                         daemon=True).start()
        return self._send(200, {"job_id": job_id})

    def log_message(self, *a):
        pass


WEBUI_TOKEN = None

_LOOPBACK = {"127.0.0.1", "::1", "localhost"}


def _check_origin(handler):
    origin = handler.headers.get("Origin")
    if not origin:
        return True
    host = handler.headers.get("Host", "")
    try:
        o = _urlparse(origin)
    except Exception:
        return False
    return not o.netloc or o.netloc == host


def _check_token(handler):
    if not WEBUI_TOKEN:
        return True
    auth = handler.headers.get("Authorization", "")
    return auth == f"Bearer {WEBUI_TOKEN}"


def serve(host="127.0.0.1", port=8900, require_token=None):
    global WEBUI_TOKEN
    WEBUI_TOKEN = None
    import os as _os
    import secrets as _secrets
    if require_token is None:
        env_token = _os.environ.get("SEC_CHECKER_WEBUI_TOKEN")
        require_token = bool(env_token) or host not in _LOOPBACK
    if require_token:
        WEBUI_TOKEN = (_os.environ.get("SEC_CHECKER_WEBUI_TOKEN")
                       or _secrets.token_urlsafe(32))
        print(f"[sec-checker webui] bearer token: {WEBUI_TOKEN}")
    httpd = ThreadingHTTPServer((host, port), _Handler)
    return httpd


PAGE_CLASSIC = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>sec-checker</title>
<style>
:root{--bg:#0b0d12;--panel:#12161e;--panel2:#161b26;--border:#242b39;
--fg:#e6edf3;--muted:#7d8998;--accent:#58a6ff;--accent2:#79c0ff;
--crit:#f85149;--high:#ff7b72;--med:#d29922;--low:#58a6ff;--info:#7d8998;
--ok:#3fb950;--run:#58a6ff;--text:#e6edf3;}
*{box-sizing:border-box}
html,body{margin:0;padding:0;height:100%}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
background:var(--bg);color:var(--fg);display:flex;flex-direction:column;min-height:100vh}
header{padding:14px 24px;border-bottom:1px solid var(--border);display:flex;
align-items:center;gap:14px;background:var(--panel)}
header .logo{font-weight:700;color:var(--accent);letter-spacing:.5px;font-size:16px}
header .tag{color:var(--muted);font-size:12px}
header .spacer{flex:1}
header .howbtn{background:var(--panel2);border:1px solid var(--border);color:var(--accent2);
border-radius:8px;padding:6px 12px;font-size:12px;font-weight:600;cursor:pointer;font-family:inherit}
header .howbtn:hover{border-color:var(--accent)}
header .pill{padding:3px 10px;border-radius:12px;font-size:11px;font-weight:600;
text-transform:uppercase;letter-spacing:.5px}
.pill.idle{background:#1e242f;color:var(--muted)}
.pill.running{background:rgba(88,166,255,.15);color:var(--accent);animation:pulse 1.6s infinite}
.pill.done{background:rgba(63,185,80,.15);color:var(--ok)}
.pill.error{background:rgba(248,81,73,.15);color:var(--crit)}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.55}}
main{flex:1;padding:20px 24px 60px;max-width:1400px;margin:0 auto;width:100%}
.hero{max-width:820px;margin:7vh auto 0;text-align:center}
.hero h1{font-size:30px;margin:0 0 8px;letter-spacing:-.5px}
.hero p{color:var(--muted);margin:0 0 30px;font-size:15px}
.box{display:flex;gap:10px;background:var(--panel);border:1px solid var(--border);
border-radius:14px;padding:10px;box-shadow:0 10px 50px rgba(0,0,0,.5)}
.box input{flex:1;background:transparent;border:none;outline:none;color:var(--fg);
font-size:17px;padding:12px 14px;font-family:inherit}
.box button{background:var(--accent);color:#0b0d12;border:none;border-radius:10px;
padding:0 24px;font-size:15px;font-weight:600;cursor:pointer;font-family:inherit}
.box button:disabled{opacity:.5;cursor:default}
.opts{margin-top:14px;color:var(--muted);font-size:13px}
.opts select{background:var(--panel);color:var(--fg);border:1px solid var(--border);
border-radius:8px;padding:5px 10px;font-family:inherit}

/* ---- How-to-use (3 modes) ---- */
.modes{max-width:900px;margin:26px auto 0;background:var(--panel);border:1px solid var(--border);
border-radius:14px;overflow:hidden;text-align:left}
.modes.floating{position:fixed;top:64px;right:24px;left:24px;max-width:900px;margin:0 auto;
z-index:40;box-shadow:0 20px 70px rgba(0,0,0,.6);max-height:82vh;overflow:auto}
.modes-head{display:flex;align-items:center;gap:10px;padding:12px 16px;border-bottom:1px solid var(--border);
background:var(--panel2)}
.modes-head .mt{font-weight:600;font-size:13px}
.modes-head .ms{color:var(--muted);font-size:12px}
.modes-head .x{margin-left:auto;cursor:pointer;color:var(--muted);border:none;background:none;
font-size:18px;line-height:1}
.mode-tabs{display:flex;gap:6px;padding:12px 16px 0;flex-wrap:wrap}
.mode-tab{background:var(--panel2);border:1px solid var(--border);color:var(--muted);
border-radius:9px 9px 0 0;padding:8px 14px;font-size:13px;font-weight:600;cursor:pointer;
font-family:inherit;display:flex;align-items:center;gap:7px}
.mode-tab .glyph{width:18px;height:18px;border-radius:50%;display:inline-flex;align-items:center;
justify-content:center;font-size:11px;background:#1e242f;color:var(--muted)}
.mode-tab.on{color:var(--fg);border-bottom-color:var(--panel)}
.mode-tab.on .glyph{background:var(--accent);color:#0b0d12}
.mode-body{padding:16px 18px;border-top:1px solid var(--border);margin-top:-1px}
.mode-pane{display:none}
.mode-pane.on{display:block}
.mode-pane h4{margin:0 0 4px;font-size:15px}
.mode-pane .lead{color:var(--muted);font-size:13px;margin:0 0 14px;line-height:1.5}
.step{display:flex;gap:12px;margin:10px 0}
.step .n{width:22px;height:22px;border-radius:50%;background:var(--panel2);border:1px solid var(--border);
color:var(--accent2);font-size:12px;font-weight:700;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.step .sc{flex:1}
.step .sc .st{font-size:13px;margin-bottom:5px}
.code{background:#080a0e;border:1px solid var(--border);border-radius:8px;padding:9px 12px;
font-family:ui-monospace,Consolas,monospace;font-size:12.5px;color:#b6c2cf;display:flex;
align-items:center;gap:10px;white-space:pre-wrap;word-break:break-all;line-height:1.5}
.code code{flex:1}
.code .cp{background:var(--panel2);border:1px solid var(--border);color:var(--accent2);
border-radius:6px;padding:3px 8px;font-size:11px;cursor:pointer;font-family:inherit;flex-shrink:0}
.code .cp:hover{border-color:var(--accent)}
.mode-note{color:var(--muted);font-size:12px;margin-top:12px;line-height:1.55;
border-left:2px solid var(--border);padding-left:12px}
.mode-note b{color:var(--text)}

.dash{display:none}
.dash.on{display:block}
.section{margin-bottom:24px}
.section-title{font-size:12px;text-transform:uppercase;letter-spacing:1px;
color:var(--muted);margin-bottom:10px;font-weight:600;display:flex;align-items:center;gap:8px}
.section-title .hint{text-transform:none;letter-spacing:0;font-weight:400;font-size:11px;color:var(--muted);opacity:.8}

/* ---- Flow chart (balloon pipeline) ---- */
.flow{background:var(--panel);border:1px solid var(--border);border-radius:14px;
padding:22px 20px;overflow-x:auto}
.flow-row{display:flex;align-items:stretch;gap:0;min-width:min-content}
.node{display:flex;flex-direction:column;align-items:center;gap:8px;flex-shrink:0;width:150px}
.balloon{position:relative;width:100%;background:var(--panel2);border:1.5px solid var(--border);
border-radius:14px;padding:12px 10px 11px;text-align:center;transition:all .3s;min-height:84px;
display:flex;flex-direction:column;align-items:center;justify-content:center;gap:4px}
.balloon .ico{font-size:19px;line-height:1}
.balloon .nm{font-size:12px;font-weight:700;letter-spacing:.3px}
.balloon .stt{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;min-height:12px}
.balloon .el{font-size:10px;font-family:ui-monospace,monospace;color:var(--muted)}
.balloon .sdot{position:absolute;top:8px;right:9px;width:9px;height:9px;border-radius:50%;background:#2a3140}
.node.running .balloon{border-color:var(--accent);background:rgba(88,166,255,.10);
box-shadow:0 0 0 3px rgba(88,166,255,.10)}
.node.running .balloon .sdot{background:var(--accent);animation:pulse 1.1s infinite}
.node.running .balloon .stt{color:var(--accent)}
.node.done .balloon{border-color:rgba(63,185,80,.5)}
.node.done .balloon .sdot{background:var(--ok)}
.node.done .balloon .stt{color:var(--ok)}
.node.failed .balloon{border-color:var(--crit)}
.node.failed .balloon .sdot{background:var(--crit)}
.node.failed .balloon .stt{color:var(--crit)}
.node.skipped .balloon{opacity:.55}
.node.skipped .balloon .stt{color:var(--muted)}
/* connector w/ data label */
.conn{display:flex;flex-direction:column;align-items:center;justify-content:center;
flex-shrink:0;width:92px;padding-top:28px}
.conn .arrow{width:100%;height:2px;background:var(--border);position:relative}
.conn .arrow:after{content:"";position:absolute;right:0;top:-4px;border-left:7px solid var(--border);
border-top:5px solid transparent;border-bottom:5px solid transparent}
.conn.active .arrow{background:var(--accent)}
.conn.active .arrow:after{border-left-color:var(--accent)}
.conn .data{font-size:10px;font-family:ui-monospace,monospace;color:var(--muted);
margin-top:7px;text-align:center;line-height:1.3;max-width:88px;word-break:break-word;min-height:13px}
.conn.active .data{color:var(--accent2)}

/* ---- Capability / tool cloud ---- */
.cloud{display:flex;flex-wrap:wrap;gap:8px;background:var(--panel);border:1px solid var(--border);
border-radius:12px;padding:14px;min-height:56px}
.cloud .empty{color:var(--muted);font-size:13px}
.cap{display:flex;align-items:center;gap:8px;background:var(--panel2);border:1px solid var(--border);
border-radius:20px;padding:6px 12px 6px 9px;font-size:12px;font-family:ui-monospace,monospace;
transition:all .25s}
.cap .cd{width:8px;height:8px;border-radius:50%;background:var(--muted);flex-shrink:0}
.cap .ct{font-size:10px;color:var(--muted)}
.cap.running{border-color:var(--accent);background:rgba(88,166,255,.10)}
.cap.running .cd{background:var(--accent);animation:pulse 1s infinite}
.cap.VULNERABLE{border-color:var(--crit)}.cap.VULNERABLE .cd{background:var(--crit)}
.cap.SUSPICIOUS{border-color:var(--med)}.cap.SUSPICIOUS .cd{background:var(--med)}
.cap.PASS{border-color:rgba(63,185,80,.4)}.cap.PASS .cd{background:var(--ok)}
.cap.UNKNOWN{opacity:.65}.cap.UNKNOWN .cd{background:#2a3140}

/* ---- Data exchange feed ---- */
.feed{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:6px 0;
max-height:260px;overflow-y:auto}
.feed .fr{display:flex;align-items:baseline;gap:10px;padding:7px 16px;border-bottom:1px solid var(--border);font-size:12.5px}
.feed .fr:last-child{border-bottom:none}
.feed .ff{color:var(--accent2);font-weight:600;font-family:ui-monospace,monospace;flex-shrink:0;min-width:86px}
.feed .fa{color:var(--muted);flex-shrink:0}
.feed .fp{color:var(--fg);word-break:break-word}
.feed .fp .mono{font-family:ui-monospace,monospace;color:var(--accent2)}
.feed .empty{color:var(--muted);font-size:13px;padding:12px 16px}

.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:10px;
padding:14px 16px;transition:border-color .2s}
.card .k{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.5px;
font-weight:600;margin-bottom:6px}
.card .v{font-size:15px;font-weight:600;word-break:break-all;line-height:1.4}
.card .sub{color:var(--muted);font-size:12px;margin-top:4px;font-weight:400}
.card.accent{border-color:rgba(88,166,255,.35)}
.card.ok{border-color:rgba(63,185,80,.35)}
.card.warn{border-color:rgba(210,153,34,.35)}
.card.bad{border-color:rgba(248,81,73,.35)}
.bar{height:8px;background:#1e242f;border-radius:6px;overflow:hidden;margin-top:8px}
.bar .fill{height:100%;background:linear-gradient(90deg,var(--accent),var(--accent2));
width:0%;transition:width .35s ease;border-radius:6px}
.bar .fill.done{background:linear-gradient(90deg,var(--ok),#56d364)}
.progress-meta{display:flex;justify-content:space-between;font-size:13px;
color:var(--muted);margin-top:8px;font-family:ui-monospace,monospace}
.findings{background:var(--panel);border:1px solid var(--border);border-radius:10px;
overflow:hidden}
.findings table{width:100%;border-collapse:collapse}
.findings th{text-align:left;padding:10px 14px;font-size:11px;text-transform:uppercase;
letter-spacing:.5px;color:var(--muted);font-weight:600;background:var(--panel2);
border-bottom:1px solid var(--border)}
.findings td{padding:9px 14px;font-size:13px;border-bottom:1px solid var(--border);
vertical-align:top}
.findings tr:last-child td{border-bottom:none}
.findings tr.new{animation:slidein .35s ease}
.chain-card{background:var(--panel);border:1px solid var(--border);border-left:4px solid var(--muted);border-radius:8px;padding:12px 14px;margin:8px 0}
.chain-card.CONFIRMED{border-left-color:#f85149}
.chain-card.LIKELY{border-left-color:#ff7b72}
.chain-card.THEORETICAL{border-left-color:#d29922}
.chain-card .cn{font-weight:600;color:var(--text)}
.chain-card .cm{color:var(--muted);font-size:12px;margin-top:4px}
.cov-row{display:flex;align-items:center;gap:10px;margin:5px 0;font-size:13px}
.cov-row .code2{width:44px;color:var(--muted);font-family:ui-monospace,monospace}
.cov-track{flex:1;background:var(--border);border-radius:5px;height:9px;overflow:hidden}
.cov-track>span{display:block;height:100%;background:#238636}
.why-card{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:12px 14px;margin:8px 0;font-size:13px}
.why-card .wt{font-weight:600;color:var(--accent);margin-bottom:6px}
.why-card .wp{margin:3px 0}.why-card .wp b{color:var(--text)}
@keyframes slidein{from{background:rgba(88,166,255,.12)}to{background:transparent}}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:10px;
font-weight:700;letter-spacing:.5px;text-transform:uppercase}
.badge.VULNERABLE{background:var(--crit);color:#fff}
.badge.SUSPICIOUS{background:var(--med);color:#000}
.badge.PASS{background:var(--ok);color:#001b0c}
.badge.UNKNOWN{background:#2a3140;color:var(--muted)}
.sev-critical{color:var(--crit);font-weight:600}
.sev-high{color:var(--high);font-weight:600}
.sev-medium{color:var(--med);font-weight:600}
.sev-low{color:var(--low);font-weight:600}
.sev-info{color:var(--muted)}
.console{background:#080a0e;border:1px solid var(--border);border-radius:10px;
padding:12px 16px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
font-size:12px;line-height:1.65;height:260px;overflow-y:auto;color:#b6c2cf}
.console .ln{white-space:pre-wrap;word-break:break-word}
.console .t{color:#5a6675;margin-right:8px}
.console .info{color:#b6c2cf}
.console .ok{color:#56d364}
.console .warn{color:#e3b341}
.console .err{color:#ff7b72}
.console .accent{color:#79c0ff}
.console .dim{color:#7d8998}
.summary-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));
gap:10px}
.summary-card{background:var(--panel);border:1px solid var(--border);
border-radius:10px;padding:14px;text-align:center}
.summary-card .n{font-size:26px;font-weight:700;line-height:1}
.summary-card .l{color:var(--muted);font-size:11px;text-transform:uppercase;
letter-spacing:.5px;margin-top:6px;font-weight:600}
.summary-card.crit .n{color:var(--crit)}
.summary-card.high .n{color:var(--high)}
.summary-card.med .n{color:var(--med)}
.summary-card.low .n{color:var(--low)}
.summary-card.info .n{color:var(--info)}
.summary-card.pass .n{color:var(--ok)}
.report-link{display:inline-block;margin-top:12px;padding:10px 18px;
background:var(--panel2);border:1px solid var(--border);border-radius:8px;
color:var(--accent);text-decoration:none;font-size:13px;font-weight:600}
.report-link:hover{border-color:var(--accent)}
.err-box{background:#2a1114;border:1px solid var(--crit);color:#ffb4ae;
padding:16px 18px;border-radius:10px;font-size:14px}
.err-box b{display:block;margin-bottom:6px;font-size:15px}
.err-box .hint{color:var(--muted);font-size:13px;margin-top:8px;line-height:1.5}
.backdrop{display:none;position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:30}
.backdrop.on{display:block}
</style>
</head>
<body>
<header>
  <span class="logo">sec-checker</span>
  <span class="tag">black-box security scanner &middot; local &middot; ROE fail-closed</span>
  <span class="spacer"></span>
  <button class="howbtn" id="howbtn" type="button">How to use &middot; 3 modes</button>
  <span class="pill idle" id="status">idle</span>
</header>

<div class="backdrop" id="backdrop"></div>

<main>
  <div class="hero" id="hero">
    <h1>Scan a target</h1>
    <p>Enter a URL. It studies what the target is, then runs the scan live as a flow of tools.</p>
    <form class="box" id="form">
      <input id="url" type="text" placeholder="http://localhost:3000" value="https://nythosx.com" autocomplete="off" autofocus>
      <button id="go" type="submit">Analyze &amp; Scan</button>
    </form>
    <div class="opts">
      Min severity:
      <select id="sev">
        <option value="info">info</option>
        <option value="low">low</option>
        <option value="medium" selected>medium</option>
        <option value="high">high</option>
        <option value="critical">critical</option>
      </select>
    </div>

    <!-- 3 modes, inline on the hero -->
    <div class="modes" id="modes">
      <div class="modes-head">
        <span class="mt">How to use sec-checker</span>
        <span class="ms">&mdash; 3 ways: by hand, with any AI API, or via Claude Code (MCP)</span>
        <button class="x" id="modes-x" type="button" style="display:none">&times;</button>
      </div>
      <div class="mode-tabs" id="mode-tabs">
        <button class="mode-tab on" data-mode="manual" type="button"><span class="glyph">1</span>Manual &middot; walang AI</button>
        <button class="mode-tab" data-mode="api" type="button"><span class="glyph">2</span>AI API</button>
        <button class="mode-tab" data-mode="mcp" type="button"><span class="glyph">3</span>Claude Code (MCP)</button>
      </div>
      <div class="mode-body">
        <!-- MANUAL -->
        <div class="mode-pane on" data-mode="manual">
          <h4>Manual &mdash; tao ang nagpapatakbo, walang AI</h4>
          <p class="lead">Ito ang ginagamit mo ngayon. Deterministic ang mga rule &mdash; walang AI na kailangan. Pinakaligtas at pinakamabilis para sa paulit-ulit na scan.</p>
          <div class="step"><div class="n">A</div><div class="sc"><div class="st">Dito sa web UI: i-type ang URL sa taas, pindutin ang <b>Analyze &amp; Scan</b>. Live mong makikita ang flow sa ibaba.</div></div></div>
          <div class="step"><div class="n">B</div><div class="sc"><div class="st">O sa terminal (CLI):</div>
            <div class="code"><code>python run.py auto https://TARGET --profile standard</code><button class="cp" type="button">copy</button></div></div></div>
          <div class="mode-note"><b>Profiles:</b> <code>quick</code> (mabilis) &middot; <code>standard</code> (default) &middot; <code>deep</code> (buo). Ang mga report ay napupunta sa <code>reports/</code>. Zero-false-positive discipline: kapag hindi masiguro, <b>UNKNOWN</b> hindi VULNERABLE.</div>
        </div>
        <!-- API -->
        <div class="mode-pane" data-mode="api">
          <h4>AI API &mdash; kahit anong AI ang nagde-decide ng susunod</h4>
          <p class="lead">Ang &ldquo;brain&rdquo; (LLM) ang pumipili kung anong capability ang susunod itakbo. Provider-agnostic: OpenAI-compatible, Anthropic, o Gemini. Ang API key ay galing sa <b>environment variable lang</b> &mdash; hindi binabasa ang <code>.env</code> file sa product.</p>
          <div class="step"><div class="n">1</div><div class="sc"><div class="st">Ilagay ang key sa env var (Windows PowerShell):</div>
            <div class="code"><code>$env:SECCHECKER_LLM_API_KEY = "sk-...your-key..."</code><button class="cp" type="button">copy</button></div></div></div>
          <div class="step"><div class="n">2</div><div class="sc"><div class="st">Piliin ang provider/model sa <code>configs/engine.yaml</code> &rarr; <code>brain.llm</code> (hal. <code>provider: gemini</code>, <code>model: gemini-flash-lite-latest</code>).</div></div></div>
          <div class="step"><div class="n">3</div><div class="sc"><div class="st">Patakbuhin gamit ang AI brain:</div>
            <div class="code"><code>python run.py auto https://TARGET --brain llm --profile deep</code><button class="cp" type="button">copy</button></div></div></div>
          <div class="mode-note"><b>Fail-safe:</b> kapag nag-error o na-rate-limit ang AI, awtomatikong babalik sa rule-based brain &mdash; tatapusin pa rin ang scan. Ang arms (mga tool) pa rin ang gumagawa ng HTTP + ROE + verdict, kaya walang bagong false positive mula sa AI.</div>
        </div>
        <!-- MCP -->
        <div class="mode-pane" data-mode="mcp">
          <h4>Claude Code (MCP) &mdash; si Claude ang gumagamit ng tools</h4>
          <p class="lead">Ina-expose ang mga scanner bilang MCP tools. Makokausap mo si Claude Code (&ldquo;scan this target&rdquo;) at siya na ang tatawag sa tamang tools, babasahin ang resulta, at mag-rereason.</p>
          <div class="step"><div class="n">1</div><div class="sc"><div class="st">I-register ang MCP server sa Claude Code:</div>
            <div class="code"><code>claude mcp add sec-checker -- python C:\xampp8.4\htdocs\sec-checker\sec_checker_mcp.py</code><button class="cp" type="button">copy</button></div></div></div>
          <div class="step"><div class="n">2</div><div class="sc"><div class="st">O patakbuhin nang direkta (stdio server):</div>
            <div class="code"><code>python sec_checker_mcp.py</code><button class="cp" type="button">copy</button></div></div></div>
          <div class="step"><div class="n">3</div><div class="sc"><div class="st">Sa Claude Code, sabihin lang: <i>&ldquo;Gamitin ang sec-checker para i-scan ang https://TARGET&rdquo;</i> &mdash; tatawagin ni Claude ang mga tool mismo.</div></div></div>
          <div class="mode-note"><b>Parehong engine</b> ang ginagamit ng tatlong mode &mdash; magkaiba lang kung <i>sino</i> ang nagde-desisyon: ikaw (manual), isang AI API (api), o Claude Code (mcp). ROE fail-closed sa lahat.</div>
        </div>
      </div>
    </div>
  </div>

  <div class="dash" id="dash">
    <div class="section">
      <div class="section-title">Pipeline flow <span class="hint">&mdash; bawat balloon ay isang stage; kumikinang ang kasalukuyang gumagana, at nasa arrow ang data na ipinapasa</span></div>
      <div class="flow" id="flow">
        <div class="flow-row" id="flow-row">
          <div class="node" data-phase="preflight"><div class="balloon"><span class="sdot"></span><span class="ico">&#128225;</span><span class="nm">Preflight</span><span class="stt"></span><span class="el"></span></div></div>
          <div class="conn" data-edge="preflight"><div class="arrow"></div><div class="data"></div></div>
          <div class="node" data-phase="framework"><div class="balloon"><span class="sdot"></span><span class="ico">&#129513;</span><span class="nm">Framework</span><span class="stt"></span><span class="el"></span></div></div>
          <div class="conn" data-edge="framework"><div class="arrow"></div><div class="data"></div></div>
          <div class="node" data-phase="discovery"><div class="balloon"><span class="sdot"></span><span class="ico">&#128269;</span><span class="nm">Discovery</span><span class="stt"></span><span class="el"></span></div></div>
          <div class="conn" data-edge="discovery"><div class="arrow"></div><div class="data"></div></div>
          <div class="node" data-phase="login"><div class="balloon"><span class="sdot"></span><span class="ico">&#128273;</span><span class="nm">Login</span><span class="stt"></span><span class="el"></span></div></div>
          <div class="conn" data-edge="login"><div class="arrow"></div><div class="data"></div></div>
          <div class="node" data-phase="scanning"><div class="balloon"><span class="sdot"></span><span class="ico">&#128737;</span><span class="nm">Scan</span><span class="stt"></span><span class="el"></span></div></div>
          <div class="conn" data-edge="scanning"><div class="arrow"></div><div class="data"></div></div>
          <div class="node" data-phase="report"><div class="balloon"><span class="sdot"></span><span class="ico">&#128196;</span><span class="nm">Report</span><span class="stt"></span><span class="el"></span></div></div>
        </div>
      </div>
    </div>

    <div class="section">
      <div class="section-title">Tools running <span class="hint">&mdash; kung sino ang gumagana ngayon, at ang verdict ng bawat isa</span></div>
      <div class="cloud" id="cloud"><span class="empty">Naghihintay ng scan&hellip;</span></div>
    </div>

    <div class="section">
      <div class="section-title">Data exchange <span class="hint">&mdash; ang palitan ng data sa pagitan ng mga stage</span></div>
      <div class="feed" id="feed"><div class="empty">Wala pang data na naipapasa&hellip;</div></div>
    </div>

    <div class="section">
      <div class="section-title">Discovery</div>
      <div class="grid">
        <div class="card" id="card-framework"><div class="k">Framework</div><div class="v" id="v-framework">&mdash;</div><div class="sub" id="s-framework"></div></div>
        <div class="card" id="card-api"><div class="k">API base</div><div class="v" id="v-api">&mdash;</div><div class="sub" id="s-api"></div></div>
        <div class="card" id="card-js"><div class="k">JS bundles</div><div class="v" id="v-js">&mdash;</div><div class="sub" id="s-js"></div></div>
        <div class="card" id="card-login"><div class="k">Login</div><div class="v" id="v-login">&mdash;</div><div class="sub" id="s-login"></div></div>
      </div>
    </div>

    <div class="section">
      <div class="section-title">Scan progress</div>
      <div class="card accent">
        <div class="progress-meta"><span id="p-label">waiting</span><span id="p-count">0 / 0</span></div>
        <div class="bar"><div class="fill" id="p-fill"></div></div>
      </div>
    </div>

    <div class="section">
      <div class="section-title">Live findings</div>
      <div class="findings">
        <table>
          <thead><tr><th style="width:30%">Pattern</th><th style="width:9%">Severity</th><th style="width:15%">Triage</th><th style="width:11%">Verdict</th><th>Reason</th></tr></thead>
          <tbody id="findings-body"><tr><td colspan="5" style="color:var(--muted);padding:16px 14px">Waiting for results&hellip;</td></tr></tbody>
        </table>
      </div>
    </div>

    <div class="section" id="data-rows-section" style="display:none">
      <div class="section-title">Extracted rows <span class="hint">&mdash; masked, first character visible</span></div>
      <div id="data-rows-body"></div>
    </div>

    <div class="section" id="extracted-section" style="display:none">
      <div class="section-title">Extracted Data &mdash; Proof of Impact <span class="hint">&mdash; live, masked</span></div>
      <div id="extracted-body"></div>
    </div>

    <div class="section" id="chains-section" style="display:none">
      <div class="section-title">Attack Chains</div>
      <div id="chains-body"></div>
    </div>

    <div class="section" id="coverage-section" style="display:none">
      <div class="section-title">Coverage</div>
      <div id="coverage-body"></div>
    </div>

    <div class="section" id="why-section" style="display:none">
      <div class="section-title">Why This Matters</div>
      <div id="why-body"></div>
    </div>

    <div class="section">
      <div class="section-title">Console</div>
      <div class="console" id="console"></div>
    </div>

    <div class="section" id="summary-section" style="display:none">
      <div class="section-title">Summary</div>
      <div class="summary-cards" id="summary-cards"></div>
      <div id="summary-extra"></div>
    </div>
  </div>
</main>

<script>
var $ = function(id){return document.getElementById(id);};
var form = $("form");
var hero = $("hero");
var dash = $("dash");
var go = $("go");
var statusPill = $("status");
var consoleEl = $("console");
var findingsBody = $("findings-body");
var pFill = $("p-fill");
var pCount = $("p-count");
var pLabel = $("p-label");

var currentJob = null;
var es = null;
var phaseStart = {};
var findingsSeen = new Set();

var caps = {};          // id -> {el}
var feedEl = $("feed");
var feedHasRows = false;
var cloudEl = $("cloud");
var cloudHasCaps = false;

var ticker = null;
var runningPhase = null;
var SLOW_MS = 8000;

/* ---------- How-to-use modes ---------- */
function selectMode(mode){
  document.querySelectorAll(".mode-tab").forEach(function(t){
    t.classList.toggle("on", t.getAttribute("data-mode") === mode);
  });
  document.querySelectorAll(".mode-pane").forEach(function(p){
    p.classList.toggle("on", p.getAttribute("data-mode") === mode);
  });
}
document.querySelectorAll(".mode-tab").forEach(function(t){
  t.addEventListener("click", function(){ selectMode(t.getAttribute("data-mode")); });
});
document.addEventListener("click", function(e){
  if(e.target && e.target.classList && e.target.classList.contains("cp")){
    var code = e.target.parentNode.querySelector("code");
    if(code && navigator.clipboard){
      navigator.clipboard.writeText(code.textContent).then(function(){
        var o = e.target.textContent; e.target.textContent = "copied";
        setTimeout(function(){ e.target.textContent = o; }, 1200);
      }).catch(function(){});
    }
  }
});
var modesEl = $("modes");
var backdrop = $("backdrop");
var modesX = $("modes-x");
function floatModes(on){
  if(on){
    modesEl.classList.add("floating");
    backdrop.classList.add("on");
    modesX.style.display = "block";
  } else {
    modesEl.classList.remove("floating");
    backdrop.classList.remove("on");
    modesX.style.display = "none";
    if(!dash.classList.contains("on")) hero.appendChild(modesEl);
  }
}
$("howbtn").addEventListener("click", function(){
  // when dashboard is active, float the panel; on hero it's already inline
  floatModes(!modesEl.classList.contains("floating"));
});
modesX.addEventListener("click", function(){ floatModes(false); });
backdrop.addEventListener("click", function(){ floatModes(false); });

/* ---------- helpers ---------- */
function esc(s){
  if(s === null || s === undefined) return "";
  return String(s).replace(/[&<>"']/g, function(c){
    return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c];
  });
}
function now(){ var d = new Date(); return d.toTimeString().slice(0,8); }
function fmtMs(ms){
  if(ms === null || ms === undefined) return "";
  if(ms < 1000) return ms.toFixed(0) + "ms";
  return (ms/1000).toFixed(2) + "s";
}
function log(text, cls){
  var ln = document.createElement("div");
  ln.className = "ln";
  ln.innerHTML = '<span class="t">' + now() + '</span><span class="' + (cls||"info") + '">' + esc(text) + '</span>';
  consoleEl.appendChild(ln);
  while(consoleEl.childNodes.length > 500) consoleEl.removeChild(consoleEl.firstChild);
  consoleEl.scrollTop = consoleEl.scrollHeight;
}
function setStatus(s, cls){
  statusPill.textContent = s;
  statusPill.className = "pill " + (cls || "idle");
}

/* ---------- flow chart ---------- */
var PHASE_ORDER = ["preflight","framework","discovery","login","scanning","report"];
function nodeFor(name){ return document.querySelector('.node[data-phase="' + name + '"]'); }
function edgeFor(name){ return document.querySelector('.conn[data-edge="' + name + '"]'); }

function setPhase(name, status){
  var el = nodeFor(name);
  if(!el) return;
  el.classList.remove("running","done","failed","skipped");
  if(status) el.classList.add(status);
  var stt = el.querySelector(".stt");
  var elapsed = el.querySelector(".el");
  if(stt) stt.textContent = status || "";
  if(status === "running"){
    phaseStart[name] = performance.now();
    runningPhase = name;
    if(elapsed) elapsed.textContent = "";
    var e = edgeFor(name); if(e) e.classList.add("active");
    startTicker();
  } else if(status === "done"){
    if(runningPhase === name) runningPhase = null;
    if(elapsed && phaseStart[name] !== undefined) elapsed.textContent = fmtMs(performance.now() - phaseStart[name]);
    var e2 = edgeFor(name); if(e2) e2.classList.add("active");
  } else if(status === "skipped"){
    if(stt) stt.textContent = "skipped";
  } else if(status === "failed"){
    if(stt) stt.textContent = "failed";
  }
}
function setEdgeData(name, text){
  var e = edgeFor(name);
  if(!e) return;
  var d = e.querySelector(".data");
  if(d) d.textContent = text || "";
}

function startTicker(){ if(!ticker) ticker = setInterval(tick, 150); }
function stopTicker(){ if(ticker){ clearInterval(ticker); ticker = null; } }
function tick(){
  if(runningPhase && phaseStart[runningPhase] !== undefined){
    var el = document.querySelector('.node[data-phase="' + runningPhase + '"] .el');
    if(el) el.textContent = fmtMs(performance.now() - phaseStart[runningPhase]);
  }
}

/* ---------- tool cloud ---------- */
function capStart(id){
  if(caps[id]) return;
  if(!cloudHasCaps){ cloudEl.innerHTML = ""; cloudHasCaps = true; }
  var chip = document.createElement("span");
  chip.className = "cap running";
  chip.innerHTML = '<span class="cd"></span>' + esc(id) + ' <span class="ct">running</span>';
  cloudEl.appendChild(chip);
  caps[id] = {el: chip};
}
function capDone(id, verdict, ms){
  var c = caps[id];
  if(!c){ capStart(id); c = caps[id]; }
  c.el.className = "cap " + esc(verdict || "UNKNOWN");
  c.el.querySelector(".ct").textContent = (verdict || "") + (ms !== undefined ? " · " + fmtMs(ms) : "");
}

/* ---------- data exchange feed ---------- */
function feed(from, payloadHtml){
  if(!feedHasRows){ feedEl.innerHTML = ""; feedHasRows = true; }
  var row = document.createElement("div");
  row.className = "fr";
  row.innerHTML = '<span class="ff">' + esc(from) + '</span><span class="fa">&rarr;</span><span class="fp">' + payloadHtml + '</span>';
  feedEl.appendChild(row);
  while(feedEl.childNodes.length > 200) feedEl.removeChild(feedEl.firstChild);
  feedEl.scrollTop = feedEl.scrollHeight;
}

/* ---------- discovery cards ---------- */
function setFramework(id, name, score){
  $("v-framework").textContent = name;
  $("s-framework").textContent = "id=" + id + "  score=" + score;
  $("card-framework").classList.add("ok");
}
function setApi(url, source, ports){
  $("v-api").textContent = url;
  var sub = source || "";
  if(ports && ports.length){ sub += "  ·  " + ports.length + " port(s) live"; }
  $("s-api").textContent = sub;
  $("card-api").classList.add("accent");
}
function setJs(count, sizeKb, paths){
  $("v-js").textContent = count + " bundles";
  $("s-js").textContent = sizeKb + " KB  ·  " + paths + " paths found";
  $("card-js").classList.add("accent");
}
function setLogin(ok, url, tokenPreview){
  $("v-login").textContent = ok ? "OK" : "not authenticated";
  var sub = url || "";
  if(tokenPreview) sub += "  ·  " + tokenPreview;
  $("s-login").textContent = sub;
  $("card-login").classList.add(ok ? "ok" : "warn");
}

function triageCell(f){
  if(!f || !f.triage_category) return "—";
  var cat = esc(f.triage_category);
  var conf = f.triage_confidence ? ' <span style="opacity:.55;font-size:11px">' + esc(f.triage_confidence) + '</span>' : "";
  if(f.triage_by_design) cat += ' <span style="opacity:.6;font-size:11px">(by-design)</span>';
  return cat + conf;
}

function addFinding(d){
  var key = d.id + "|" + d.verdict + "|" + (d.reason||"").slice(0,60);
  if(findingsSeen.has(key)) return;
  findingsSeen.add(key);
  var td = findingsBody.querySelector('td[colspan]');
  if(td) findingsBody.innerHTML = "";
  var tr = document.createElement("tr");
  tr.className = "new";
  tr.innerHTML =
    "<td>" + esc(d.id) + "</td>" +
    '<td class="sev-' + esc(d.severity) + '">' + esc(d.severity) + "</td>" +
    "<td>" + triageCell(d) + "</td>" +
    '<td><span class="badge ' + esc(d.verdict) + '">' + esc(d.verdict) + "</span></td>" +
    "<td>" + esc((d.reason||"").slice(0,220)) + "</td>";
  findingsBody.insertBefore(tr, findingsBody.firstChild);
}

function setProgress(done, total){
  var pct = total > 0 ? (done / total) * 100 : 0;
  pFill.style.width = pct.toFixed(1) + "%";
  pCount.textContent = done + " / " + total;
  pLabel.textContent = done < total ? "scanning…" : "complete";
  if(done >= total) pFill.classList.add("done");
}

function showSummary(counts, reportTarget){
  var c = counts || {};
  var cards = [
    ["Vulnerable", c.VULNERABLE || 0, "crit"],
    ["Suspicious", c.SUSPICIOUS || 0, "med"],
    ["Pass", c.PASS || 0, "pass"],
    ["Unknown", c.UNKNOWN || 0, "info"]
  ];
  $("summary-cards").innerHTML = cards.map(function(row){
    return '<div class="summary-card ' + row[2] + '"><div class="n">' + row[1] + '</div><div class="l">' + esc(row[0]) + '</div></div>';
  }).join("");
  var extra = "";
  if(reportTarget){
    var base = "/api/export?target=" + encodeURIComponent(reportTarget) + "&fmt=";
    extra += "No report is generated automatically — export one if you want it:";
    extra += ' <a class="report-link" href="' + base + 'pdf" target="_blank">Export PDF</a>';
    extra += ' <a class="report-link" href="' + base + 'html" target="_blank">Export HTML</a>';
  }
  $("summary-extra").innerHTML = extra;
  $("summary-section").style.display = "block";
}

function renderResult(result){
  var chains = result.chains || [];
  if(chains.length){
    $("chains-body").innerHTML = chains.map(function(c){
      var conf = Math.round((c.confidence || 0) * 100);
      var met = (c.matched || []).length + "/" + (c.prerequisites || []).length;
      return '<div class="chain-card ' + esc(c.verdict) + '">' +
        '<div class="cn">' + esc(c.name) + ' — ' + esc(c.verdict) + '</div>' +
        '<div class="cm">Severity: ' + esc(c.severity) + ' · Confidence: ' + conf +
        '% · Prerequisites met: ' + met + '</div></div>';
    }).join("");
    $("chains-section").style.display = "block";
  }
  var cov = result.coverage;
  if(cov && cov.owasp){
    var rows = Object.keys(cov.owasp).map(function(code){
      var c = cov.owasp[code];
      return '<div class="cov-row"><span class="code2">' + esc(code) + '</span>' +
        '<span class="cov-track"><span style="width:' + c.coverage_pct + '%"></span></span>' +
        '<span>' + c.covered + '/' + c.total + '</span></div>';
    }).join("");
    var untested = (cov.untested_categories || []).length ?
      '<div class="cm" style="margin-top:8px;color:var(--muted)">Untested: ' +
      esc(cov.untested_categories.join(", ")) + '</div>' : "";
    $("coverage-body").innerHTML =
      '<div class="cm" style="margin-bottom:8px">' + cov.executed_count + '/' +
      cov.total_count + ' capabilities executed</div>' + rows + untested;
    $("coverage-section").style.display = "block";
  }
  var dRows = result.data_rows || [];
  if(dRows.length){
    var dHtml = dRows.map(function(dr){
      var rows = dr.rows || [];
      var rowBlocks = rows.map(function(r){
        var cells = Object.keys(r).map(function(k){
          return '<tr><td class="k" style="padding:5px 10px;color:var(--muted);font-family:var(--mono);width:32%">' +
            esc(k) + '</td><td style="padding:5px 10px;font-family:var(--mono);word-break:break-all">' +
            esc(r[k]) + '</td></tr>';
        }).join("");
        return '<table style="width:100%;border-collapse:collapse;background:var(--panel2);border-radius:6px;margin:6px 0">' + cells + '</table>';
      }).join("");
      var authCls = String(dr.auth_used || "").indexOf("unauth") === 0 ? "unauth" : "auth";
      var authBg = authCls === "unauth" ? "var(--crit)" : "var(--accent)";
      return '<div style="background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:12px 14px;margin:10px 0">' +
        '<div style="color:var(--accent2);font-family:var(--mono);font-size:12px;margin-bottom:8px">' +
        esc(dr.endpoint) +
        ' <span style="display:inline-block;padding:1px 8px;border-radius:10px;background:' + authBg + ';color:#fff;font-size:10px;margin-left:8px;text-transform:uppercase">' +
        esc(dr.auth_used || "unknown") + '</span>' +
        ' <span style="color:var(--muted)">&middot; ' + (dr.extracted || 0) + ' of ' + (dr.total_rows || 0) + ' row(s)</span></div>' +
        rowBlocks + '</div>';
    }).join("");
    $("data-rows-body").innerHTML = dHtml;
    $("data-rows-section").style.display = "block";
  }
  var ff = (result.findings || []).filter(function(f){
    return f.verdict === "VULNERABLE" || f.verdict === "SUSPICIOUS";
  });
  if(ff.length){
    findingsBody.innerHTML = ff.map(function(f){
      return '<tr>' +
        '<td>' + esc(f.pattern_id || f.id) + '</td>' +
        '<td class="sev-' + esc(f.severity) + '">' + esc(f.severity) + '</td>' +
        '<td>' + triageCell(f) + '</td>' +
        '<td><span class="badge ' + esc(f.verdict) + '">' + esc(f.verdict) + '</span></td>' +
        '<td>' + esc((f.reason||"").slice(0,220)) + '</td>' +
      '</tr>';
    }).join("");
  }
  var whys = (result.findings || []).filter(function(f){
    return f.why && (f.verdict === "VULNERABLE" || f.verdict === "SUSPICIOUS");
  });
  if(whys.length){
    $("why-body").innerHTML = whys.map(function(f){
      var w = f.why, parts = "";
      if(w.attack) parts += '<div class="wp"><b>Attack:</b> ' + esc(w.attack) + '</div>';
      if(w.gap) parts += '<div class="wp"><b>Gap:</b> ' + esc(w.gap) + '</div>';
      if(w.impact) parts += '<div class="wp"><b>Impact:</b> ' + esc(w.impact) + '</div>';
      if(w.fix) parts += '<div class="wp"><b>Fix:</b> ' + esc(w.fix) + '</div>';
      return '<div class="why-card"><div class="wt">' + esc(f.pattern_id) + '</div>' + parts + '</div>';
    }).join("");
    $("why-section").style.display = "block";
  }
}

/* ---------- event handling ---------- */
function handleEvent(ev){
  var d = ev.data || {};
  switch(ev.type){
    case "start":
      log("Starting scan for " + d.url, "accent");
      feed("input", 'target <span class="mono">' + esc(d.url) + '</span>');
      break;
    case "phase":
      setPhase(d.name, d.status);
      log("Phase: " + d.name + " → " + d.status, d.status === "failed" ? "err" : "dim");
      break;
    case "activity":
      log(d.message + (d.n ? "  (" + d.i + "/" + d.n + ")" : ""), "dim");
      break;
    case "pattern_start":
      capStart(d.id);
      break;
    case "preflight":
      if(d.ok){ log("Preflight OK (HTTP " + d.status + ")", "ok"); setEdgeData("preflight", "HTTP " + d.status + " live"); feed("preflight", 'reachable <span class="mono">HTTP ' + esc(d.status) + '</span>'); }
      else { log("Preflight FAILED: " + d.error, "err"); setEdgeData("preflight", "unreachable"); }
      break;
    case "framework":
      setFramework(d.id, d.name, d.score);
      setEdgeData("framework", d.id + " (" + d.score + ")");
      feed("framework", 'detected <span class="mono">' + esc(d.name) + '</span> (id=' + esc(d.id) + ', score=' + esc(d.score) + ')');
      log("Framework: " + d.name + " (score=" + d.score + ")", "ok");
      break;
    case "api_base":
      setApi(d.url, d.source, d.ports);
      setEdgeData("discovery", d.url);
      feed("discovery", 'API base <span class="mono">' + esc(d.url) + '</span> [' + esc(d.source) + ']');
      log("API base: " + d.url + "  [" + d.source + "]", "ok");
      break;
    case "js_start":
      log("Extracting " + d.count + " script sources…", "info");
      break;
    case "js_done":
      setJs(d.count, d.size_kb, d.paths);
      feed("discovery", 'analyzed <span class="mono">' + esc(d.count) + '</span> JS bundles &rarr; <span class="mono">' + esc(d.paths) + '</span> paths');
      log("Analyzed " + d.count + " bundles (" + d.size_kb + " KB), found " + d.paths + " paths", "ok");
      break;
    case "login":
      setLogin(d.ok, d.url, d.token);
      setEdgeData("login", d.ok ? "token acquired" : "no auth");
      feed("login", d.ok ? 'authenticated &rarr; <span class="mono">token</span> passed to scan' : 'no login (anonymous scan)');
      log("Login: " + (d.ok ? "OK" : "skipped"), d.ok ? "ok" : "warn");
      break;
    case "baseline":
      log("Baseline: mean=" + d.mean_ms + "ms stdev=" + d.stdev_ms + "ms", "info");
      break;
    case "scan_start":
      log("Running " + d.total_patterns + " patterns with " + d.workers + " workers", "accent");
      setEdgeData("scanning", d.total_patterns + " tools");
      feed("scan", 'dispatching <span class="mono">' + esc(d.total_patterns) + '</span> tools, ' + esc(d.workers) + ' workers');
      setProgress(0, d.total_work);
      break;
    case "pattern_done":
      capDone(d.id, d.verdict, d.duration_ms);
      log("→ " + d.id + " → " + d.verdict + "  (" + fmtMs(d.duration_ms) + ")", d.verdict === "PASS" ? "dim" : "warn");
      if(d.verdict !== "PASS" && d.verdict !== "UNKNOWN") addFinding(d);
      break;
    case "progress":
      setProgress(d.done, d.total);
      break;
    case "worker_error":
      log("Worker error: " + d.id + " — " + d.message, "err");
      break;
    case "summary":
      feed("scan", 'result <span class="mono">' + esc(JSON.stringify(d.counts)) + '</span>');
      log("Summary: " + JSON.stringify(d.counts), "accent");
      break;
    case "done":
      setStatus("done", "done");
      runningPhase = null;
      stopTicker();
      log("Scan complete.", "ok");
      if(findingsBody.querySelector('td[colspan]')){
        findingsBody.innerHTML = '<tr><td colspan="5" style="color:var(--muted);padding:16px 14px">Scan complete — no vulnerable or suspicious findings.</td></tr>';
      }
      showSummary(d.counts, d.report_target);
      if(currentJob){
        fetch("/api/job/" + currentJob).then(function(r){return r.json();}).then(function(job){
          if(job && job.result){
            renderResult(job.result);
            renderExtractedFromResult(job.result);
          }
        }).catch(function(){});
      }
      break;
    case "error":
      setStatus("error", "error");
      runningPhase = null;
      stopTicker();
      log("ERROR: " + d.message, "err");
      break;
  }
}

var extractedSeen = [];
var extractedValues = [];
function escAttr(v){
  if(v === null || v === undefined) return '';
  return String(v).replace(/[&<>"']/g, function(c){
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
  });
}
function handleExtractionEvent(d){
  var ev = d.evidence || {};
  var recs = ev.extracted_records || ev.extracted_data || d.extracted_data;
  if(Array.isArray(recs) && recs.length){
    for(var i=0;i<recs.length;i++){ extractedSeen.push(recs[i]); }
    renderExtractedPanel();
  }
  if(typeof ev.extracted_value === 'string' && ev.extracted_value){
    extractedValues.push(ev.extracted_value);
    renderExtractedValues();
  }
  var files = ev.files_read;
  if(Array.isArray(files) && files.length){
    for(var j=0;j<files.length;j++){ extractedValues.push(files[j]); }
    renderExtractedValues();
  }
}
function renderExtractedPanel(){
  var sec = $("extracted-section");
  var body = $("extracted-body");
  if(!sec || !body) return;
  if(!extractedSeen.length){ sec.style.display = 'none'; return; }
  var groups = {};
  for(var i=0;i<extractedSeen.length;i++){
    var item = extractedSeen[i];
    var key = (item && (item.endpoint || item.url)) || 'records';
    var rows = (item && item.rows) || [];
    if(!rows.length && item && typeof item === 'object'){
      rows = [item];
    }
    if(!groups[key]) groups[key] = [];
    groups[key] = groups[key].concat(rows);
  }
  var html = '';
  html += '<div style="background:#2a1114;border:1px solid #f85149;color:#ffb4ae;padding:12px 16px;border-radius:8px;margin-bottom:12px;font-size:13px">';
  html += '<b style="color:#fff">PROOF OF IMPACT:</b> ' + extractedSeen.length + ' record(s) extracted across ' + Object.keys(groups).length + ' endpoint(s)';
  html += '</div>';
  for(var k in groups){
    html += '<div class="datarow-card">';
    html += '<div class="hd">' + escAttr(k) + ' <span class="datarow-empty">&middot; ' + groups[k].length + ' row(s)</span></div>';
    var shown = groups[k].slice(0,5);
    for(var r=0;r<shown.length;r++){
      var row = shown[r];
      if(typeof row !== 'object'){ continue; }
      html += '<table class="datarow-table">';
      var keys = Object.keys(row).slice(0,10);
      for(var ki=0;ki<keys.length;ki++){
        var kk = keys[ki];
        html += '<tr><td class="k">' + escAttr(kk) + '</td><td class="v">' + escAttr(String(row[kk]).slice(0,80)) + '</td></tr>';
      }
      html += '</table>';
    }
    html += '</div>';
  }
  body.innerHTML = html;
  sec.style.display = 'block';
}
function renderExtractedValues(){
  var sec = $("extracted-section");
  var body = $("extracted-body");
  if(!sec || !body) return;
  if(!extractedValues.length) return;
  var html = body.innerHTML || '';
  html += '<div class="datarow-card"><div class="hd">Recovered value(s)</div>';
  for(var i=0;i<extractedValues.length;i++){
    html += '<table class="datarow-table"><tr><td class="k">value</td><td class="v">' + escAttr(String(extractedValues[i]).slice(0,200)) + '</td></tr></table>';
  }
  html += '</div>';
  body.innerHTML = html;
  sec.style.display = 'block';
}
function renderExtractedFromResult(result){
  var rows = (result && result.extracted_rows) || [];
  if(!rows.length) return;
  extractedSeen = [];
  for(var i=0;i<rows.length;i++){ extractedSeen.push(rows[i]); }
  renderExtractedPanel();
}

form.addEventListener("submit", async function(e){
  e.preventDefault();
  var url = $("url").value.trim();
  var sev = $("sev").value;
  if(!url) return;
  go.disabled = true;
  floatModes(false);
  hero.style.display = "none";
  dash.classList.add("on");

  // reset state
  findingsSeen.clear();
  extractedSeen = [];
  extractedValues = [];
  var _esec = $("extracted-section"); if(_esec) _esec.style.display = 'none';
  var _eb = $("extracted-body"); if(_eb) _eb.innerHTML = '';
  caps = {}; cloudHasCaps = false; cloudEl.innerHTML = '<span class="empty">Naghihintay ng tools…</span>';
  feedHasRows = false; feedEl.innerHTML = '<div class="empty">Wala pang data na naipapasa…</div>';
  consoleEl.innerHTML = "";
  ["chains-section","coverage-section","why-section","summary-section","data-rows-section"].forEach(function(id){
    var el = $(id); if(el) el.style.display = "none";
  });
  findingsBody.innerHTML = '<tr><td colspan="5" style="color:var(--muted);padding:16px 14px">Waiting for results…</td></tr>';
  pFill.style.width = "0%"; pFill.classList.remove("done");
  pCount.textContent = "0 / 0"; pLabel.textContent = "waiting";
  ["framework","api","js","login"].forEach(function(k){
    $("card-" + k).classList.remove("ok","warn","bad","accent");
  });
  document.querySelectorAll(".node").forEach(function(p){
    p.classList.remove("running","done","failed","skipped");
    var s = p.querySelector(".stt"); if(s) s.textContent = "";
    var el = p.querySelector(".el"); if(el) el.textContent = "";
  });
  document.querySelectorAll(".conn").forEach(function(c){
    c.classList.remove("active");
    var d2 = c.querySelector(".data"); if(d2) d2.textContent = "";
  });
  runningPhase = null; phaseStart = {}; stopTicker();
  setStatus("starting", "running");

  var res;
  try{
    res = await fetch("/api/scan", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({url: url, min_severity: sev})
    });
  } catch(err){
    dash.classList.remove("on");
    hero.style.display = "block";
    hero.insertAdjacentHTML("beforeend", '<div class="err-box" style="margin-top:24px"><b>Network error</b>' + esc(String(err)) + '</div>');
    go.disabled = false;
    return;
  }
  var data = await res.json();
  if(!res.ok){
    dash.classList.remove("on");
    hero.style.display = "block";
    hero.insertAdjacentHTML("beforeend",
      '<div class="err-box" style="margin-top:24px"><b>' + esc(data.error || "Error") + '</b>' + esc(data.detail || "") + '<div class="hint">' + esc(data.hint || "") + '</div></div>');
    go.disabled = false;
    return;
  }

  currentJob = data.job_id;
  setStatus("running", "running");
  log("Job started: " + currentJob, "accent");

  es = new EventSource("/api/scan/" + currentJob + "/stream");
  es.onmessage = function(e){
    try{
      var ev = JSON.parse(e.data);
      handleEvent(ev);
      if(ev.type === "done" || ev.type === "error"){
        es.close(); es = null; go.disabled = false;
      }
    } catch(err){
      log("parse error: " + err, "err");
    }
  };
  es.onerror = function(){
    if(es && es.readyState === EventSource.CLOSED){ log("stream closed", "dim"); }
  };
});
</script>
</body>
</html>
"""

PAGE = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>sec-checker · live scan</title>
<style>
:root {
  color-scheme: light;
  --bg:#efefec; --bg-s:#ffffff; --bg-s2:#f6f6f3;
  --ph:#141414; --ph-hi:#000000; --ph-dim:#8b8b86; --ph-dimmer:#d9d9d4;
  --ph-line:#e6e6e1;
  --amber:#d98a00; --red:#e5484d; --green:#2f9e5f;
  --mono: ui-monospace, "JetBrains Mono", "SF Mono", Menlo, Consolas, monospace;
  --sans: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", sans-serif;
}
* { box-sizing: border-box; }
html, body { margin: 0; height: 100%; overflow: hidden; }
body {
  background: var(--bg); color: var(--ph); font-family: var(--sans);
  font-size: 13px; display: grid;
  grid-template-rows: 52px 1fr 90px; height: 100vh;
}
header {
  display: flex; align-items: center; padding: 0 22px;
  background: var(--bg-s); border-bottom: 1px solid var(--ph-line);
  font-family: var(--mono); font-size: 11.5px; gap: 14px;
}
.brand { color: var(--ph-hi); letter-spacing: 0.09em; font-weight: 700; display: flex; align-items: center; gap: 8px; }
.brand::before { content: ""; width: 6px; height: 6px; background: var(--ph-hi); }
.sep { color: var(--ph-dimmer); }
.target { color: var(--ph); max-width: 240px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-weight: 500; }
.spacer { flex: 1; }
.stat { color: var(--ph-dim); font-variant-numeric: tabular-nums; }
.stat b { color: var(--ph); font-weight: 600; }
.stat.v b { color: var(--red); }
.stat.s b { color: var(--amber); }
.stat.p b { color: var(--green); }
.status { display: flex; align-items: center; gap: 7px; color: var(--ph-dim); text-transform: uppercase; letter-spacing: 0.14em; font-size: 10.5px; font-weight: 600; }
.status::before { content: ""; width: 5px; height: 5px; background: var(--ph-dimmer); border-radius: 50%; }
.status.running::before { background: var(--ph); animation: blink 1.3s ease-in-out infinite; }
.status.done::before { background: var(--green); }
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:.25} }
.btn { background: var(--bg-s); border: 1px solid var(--ph-line); color: #4a4a46; padding: 5px 12px; border-radius: 999px; font-family: var(--mono); font-size: 10px; letter-spacing: 0.12em; text-transform: uppercase; cursor: pointer; font-weight: 600; }
.btn:hover { border-color: var(--ph); color: var(--ph-hi); }
.main { display: grid; grid-template-columns: 1fr 460px; min-height: 0; }
.canvas-wrap { position: relative; overflow: hidden; }
.canvas-wrap::before { content: ""; position: absolute; inset: 0; background-image: radial-gradient(circle, var(--ph-dimmer) 0.8px, transparent 0.8px); background-size: 22px 22px; opacity: 0.35; pointer-events: none; }
svg.exec { position: relative; display: block; width: 100%; height: 100%; }
.node rect { fill: var(--bg-s); stroke: var(--ph-line); stroke-width: 1; transition: all 240ms; }
.node text { font-family: var(--mono); font-size: 11px; fill: var(--ph); dominant-baseline: middle; user-select: none; transition: fill 240ms; }
.node .label { font-size: 11px; font-weight: 600; }
.node .meta { font-size: 9px; fill: var(--ph-dim); font-weight: 500; }
.node.terminal .label { font-size: 10px; letter-spacing: 0.14em; font-weight: 700; }
.node.pending rect { stroke-dasharray: 3 4; opacity: 0.85; }
.node.pending .label { fill: var(--ph-dim); }
.node.active rect { stroke: var(--ph-hi); stroke-width: 1.6; animation: pulseActive 1.15s ease-in-out infinite; }
.node.active .label { fill: var(--ph-hi); }
@keyframes pulseActive { 0%,100% { stroke-opacity: 1 } 50% { stroke-opacity: 0.55 } }
.node.done-pass rect { stroke: var(--green); fill: #f3faf4; }
.node.done-pass .label { fill: #1e6b3e; }
.node.done-pass .meta { fill: #3c8c5c; }
.node.done-susp rect { stroke: var(--amber); fill: #fdf8ef; }
.node.done-susp .label { fill: #8a5a05; }
.node.done-susp .meta { fill: #b07514; }
.node.done-vuln rect { stroke: var(--red); fill: #fdf0f0; }
.node.done-vuln .label { fill: #a82226; }
.node.done-vuln .meta { fill: var(--red); }
.node.skipped rect { stroke-dasharray: 3 4; stroke: var(--ph-dimmer); fill: var(--bg-s2); opacity: 0.75; }
.node.skipped .label { fill: var(--ph-dim); }
.edge { fill: none; stroke: var(--ph-dimmer); stroke-width: 1; transition: stroke 260ms; }
.edge.pending { stroke-dasharray: 3 5; }
.edge.active { stroke: var(--ph); stroke-width: 1.4; stroke-dasharray: 6 4; animation: dash 0.55s linear infinite; }
.edge.done { stroke: var(--ph-dim); stroke-dasharray: none; }
.edge.done-vuln { stroke: var(--red); stroke-width: 1.6; stroke-dasharray: none; }
.edge.done-susp { stroke: var(--amber); stroke-width: 1.4; stroke-dasharray: none; }
.edge.done-pass { stroke: var(--green); stroke-dasharray: none; }
@keyframes dash { to { stroke-dashoffset: -10; } }
.edge-label { font-family: var(--mono); font-size: 9px; fill: var(--ph-dim); font-weight: 500; user-select: none; }
.edge-label.active { fill: var(--ph); font-weight: 600; }
.edge-label.vuln { fill: var(--red); font-weight: 600; }
.edge-label.susp { fill: var(--amber); font-weight: 600; }
.packet { fill: var(--ph); pointer-events: none; }
.packet.vuln { fill: var(--red); }
.packet.susp { fill: var(--amber); }
.packet.pass { fill: var(--green); }
.panel { background: var(--bg-s); border-left: 1px solid var(--ph-line); display: grid; grid-template-rows: 1fr 220px; min-height: 0; overflow: hidden; }
.narrator { display: flex; flex-direction: column; min-height: 0; border-bottom: 1px solid var(--ph-line); }
.narrator-hd { display: flex; align-items: center; gap: 10px; padding: 12px 20px; background: var(--bg-s2); border-bottom: 1px solid var(--ph-line); }
.avatar { width: 26px; height: 26px; border-radius: 50%; background: var(--ph-hi); color: #fff; display: flex; align-items: center; justify-content: center; font-family: var(--mono); font-size: 12px; font-weight: 700; }
.avatar.running { animation: pulseAvatar 1.6s ease-in-out infinite; }
@keyframes pulseAvatar { 0%,100% { box-shadow: 0 0 0 0 rgba(20,20,20,.15) } 50% { box-shadow: 0 0 0 8px rgba(20,20,20,0) } }
.narrator-hd .who { font-family: var(--mono); font-size: 11px; font-weight: 700; color: var(--ph-hi); letter-spacing: 0.04em; }
.narrator-hd .state { font-family: var(--mono); font-size: 10px; color: var(--ph-dim); margin-left: auto; font-weight: 500; }
.narrator-hd .state::before { content: "\00b7 "; color: var(--ph-dimmer); }
.transcript { flex: 1; min-height: 0; overflow-y: auto; padding: 4px 16px 20px; scroll-behavior: smooth; }
.transcript::-webkit-scrollbar { width: 6px; }
.transcript::-webkit-scrollbar-thumb { background: var(--ph-dimmer); border-radius: 999px; }
.n-msg { display: grid; grid-template-columns: 22px 1fr; gap: 10px; padding: 12px 0; opacity: 0; animation: nIn 320ms cubic-bezier(.2,.9,.3,1) forwards; }
@keyframes nIn { from { opacity: 0; transform: translateY(4px) } to { opacity: 1; transform: translateY(0) } }
.n-msg + .n-msg { border-top: 1px solid var(--ph-line); }
.n-prefix { width: 22px; height: 22px; border-radius: 50%; background: var(--bg-s2); border: 1px solid var(--ph-line); color: var(--ph-dim); display: flex; align-items: center; justify-content: center; font-family: var(--mono); font-size: 11px; font-weight: 700; }
.n-body { min-width: 0; padding-top: 1px; }
.n-text { font-size: 13px; line-height: 1.65; color: var(--ph); word-wrap: break-word; }
.n-text b { font-weight: 600; color: var(--ph-hi); }
.n-text code { font-family: var(--mono); font-size: 11.5px; background: var(--bg-s2); padding: 1px 5px; border-radius: 4px; color: #0e0e0e; }
.n-detail { margin-top: 10px; background: var(--bg-s2); border-radius: 10px; padding: 10px 12px; font-family: var(--mono); font-size: 10.5px; line-height: 1.6; color: #4a4a46; white-space: pre-wrap; word-break: break-all; max-height: 180px; overflow-y: auto; border: 1px solid var(--ph-line); }
.n-msg.pass .n-prefix { background: var(--green); border-color: var(--green); color: #fff; }
.n-msg.pass .n-text { color: #1e6b3e; }
.n-msg.susp .n-prefix { background: var(--amber); border-color: var(--amber); color: #fff; }
.n-msg.susp .n-text { color: #8a5a05; }
.n-msg.vuln .n-prefix { background: var(--red); border-color: var(--red); color: #fff; }
.n-msg.vuln .n-text { color: #7a181b; font-weight: 500; }
.n-msg.vuln .n-detail { background: #fdf0f0; border-color: #fbd4d5; color: #7a181b; }
.n-msg.summary { grid-template-columns: 1fr; background: var(--ph-hi); color: #fff; border-radius: 16px; padding: 20px; margin: 14px 0 6px; border-top: none; }
.n-msg.summary .n-prefix { display: none; }
.n-msg.summary .n-text { color: #fff; font-size: 13.5px; line-height: 1.75; }
.n-msg.summary .n-text b { color: #fff; }
.n-msg.summary .n-text code { background: rgba(255,255,255,0.14); color: #fff; }
.n-msg.summary .n-title { font-family: var(--mono); font-size: 10px; letter-spacing: 0.16em; text-transform: uppercase; color: rgba(255,255,255,0.6); font-weight: 700; margin-bottom: 10px; display: flex; align-items: center; gap: 8px; }
.n-msg.summary .n-title::before { content: ""; width: 6px; height: 6px; background: #fff; border-radius: 50%; }
.n-msg.summary .n-list { list-style: none; padding: 0; margin: 14px 0 0; display: grid; gap: 10px; }
.n-msg.summary .n-list li { padding: 10px 12px; background: rgba(255,255,255,0.06); border-left: 3px solid rgba(255,255,255,0.35); border-radius: 10px; font-size: 12.5px; line-height: 1.6; color: rgba(255,255,255,0.88); }
.n-msg.summary .n-list li b { color: #fff; }
.n-msg.summary .n-list li.danger { background: rgba(229,72,77,0.18); border-left-color: var(--red); }
.findings-pane { display: flex; flex-direction: column; min-height: 0; }
.findings-hd { display: flex; align-items: center; gap: 8px; padding: 10px 20px; background: var(--bg-s2); border-bottom: 1px solid var(--ph-line); font-family: var(--mono); font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.16em; color: var(--ph-dim); }
.findings-hd .dot { width: 6px; height: 6px; border-radius: 50%; background: var(--red); }
.findings-hd .count { margin-left: auto; background: var(--bg-s); border: 1px solid var(--ph-line); border-radius: 999px; padding: 1px 8px; font-size: 9.5px; color: var(--ph); }
.findings-hd .count.has { background: var(--red); color: #fff; border-color: var(--red); }
.findings-body { flex: 1; min-height: 0; overflow-y: auto; padding: 10px 14px; display: flex; flex-direction: column; gap: 8px; }
.findings-body::-webkit-scrollbar { width: 5px; }
.findings-body::-webkit-scrollbar-thumb { background: var(--ph-dimmer); border-radius: 999px; }
.findings-empty { color: var(--ph-dim); font-size: 11px; font-family: var(--mono); padding: 20px 6px; line-height: 1.7; text-align: center; }
.fcard { border: 1px solid var(--ph-line); border-left: 3px solid var(--ph-dim); border-radius: 10px; padding: 9px 12px; background: var(--bg-s); font-family: var(--mono); font-size: 10.5px; animation: cardIn 340ms cubic-bezier(.2,.9,.3,1); line-height: 1.5; }
.fcard.vuln { border-left-color: var(--red); background: #fffafa; }
.fcard.susp { border-left-color: var(--amber); background: #fffdf7; }
@keyframes cardIn { from { opacity: 0; transform: translateY(-6px) } to { opacity: 1; transform: translateY(0) } }
.fcard .fh { display: flex; align-items: center; gap: 6px; margin-bottom: 5px; color: var(--ph-dim); font-size: 9px; font-weight: 600; letter-spacing: 0.05em; text-transform: uppercase; }
.fcard .fh .tag { padding: 1px 6px; border-radius: 999px; font-size: 8.5px; font-weight: 700; }
.fcard.vuln .fh .tag { background: var(--red); color: #fff; }
.fcard.susp .fh .tag { background: var(--amber); color: #fff; }
.fcard .fn { font-family: var(--sans); font-size: 12.5px; font-weight: 600; color: var(--ph-hi); margin-bottom: 4px; }
.fcard .fp { color: #4a4a46; font-size: 10px; word-break: break-all; }
.ep-badge { display: inline-block; margin-left: 6px; padding: 1px 7px; border-radius: 999px; font-size: 9px; font-weight: 700; font-family: var(--mono); background: var(--ph-dim); color: #fff; vertical-align: middle; }
.ep-badge.ep-ok { background: var(--green); }
.ep-badge.ep-warn { background: var(--amber); }
.ep-badge.ep-dim { background: var(--ph-dim); opacity: .75; }
.ep-badge.ep-bad { background: var(--red); }
.log-ribbon { background: var(--bg-s); border-top: 1px solid var(--ph-line); font-family: var(--mono); font-size: 11px; padding: 10px 22px; display: flex; flex-direction: column; gap: 2px; overflow: hidden; line-height: 1.55; }
.log-line { display: flex; gap: 12px; color: var(--ph-dim); white-space: nowrap; opacity: 0; animation: logIn 240ms ease forwards; }
.log-line .t { color: var(--ph-dim); }
.log-line .src { color: var(--ph-dim); min-width: 100px; font-weight: 600; }
.log-line .msg { color: var(--ph); overflow: hidden; text-overflow: ellipsis; }
.log-line.pass .msg { color: var(--green); }
.log-line.vuln .msg { color: var(--red); font-weight: 600; }
.log-line.susp .msg { color: var(--amber); }
.log-line.hi .msg { color: var(--ph-hi); font-weight: 600; }
@keyframes logIn { from { opacity: 0; transform: translateY(3px) } to { opacity: 1; transform: translateY(0) } }
.overlay { position: absolute; inset: 0; display: flex; align-items: center; justify-content: center; background: rgba(239,239,236,0.94); backdrop-filter: blur(8px); z-index: 10; transition: opacity 400ms; }
.overlay.hidden { opacity: 0; pointer-events: none; }
.overlay-inner { width: min(520px, 88%); background: var(--bg-s); border: 1px solid var(--ph-line); border-radius: 30px; padding: 36px 34px 30px; box-shadow: 0 34px 70px rgba(17,17,17,.13); }
.overlay-inner h1 { margin: 0 0 10px; font-family: var(--mono); font-size: 13px; font-weight: 600; color: var(--ph-hi); letter-spacing: 0.14em; text-transform: uppercase; }
.overlay-inner h1::before { content: "> "; color: var(--ph-dimmer); }
.overlay-inner p { margin: 0 0 24px; color: var(--ph-dim); font-size: 12.5px; line-height: 1.75; }
.input-row { display: flex; background: var(--bg-s2); border: 1px solid var(--ph-line); border-radius: 999px; padding: 5px 5px 5px 20px; }
.input-row:focus-within { border-color: var(--ph); box-shadow: 0 0 0 4px rgba(20,20,20,.05); }
.input-row input { flex: 1; background: transparent; border: none; outline: none; padding: 9px 0; color: var(--ph); font-family: var(--mono); font-size: 13px; }
.input-row input::placeholder { color: var(--ph-dimmer); }
.input-row button { background: var(--ph-hi); border: none; padding: 0 22px; border-radius: 999px; color: #fff; font-family: var(--mono); font-size: 11px; letter-spacing: 0.14em; text-transform: uppercase; cursor: pointer; font-weight: 700; }
.input-row button:hover { background: #2b2b2b; }
@media (max-width: 1000px) {
  header { padding: 0 14px; gap: 10px; font-size: 10.5px; }
  .stat.maybe-hide { display: none; }
  .main { grid-template-columns: 1fr; }
  .panel { display: none; }
}
</style>
</head>
<body>
<header>
  <div class="brand">sec-checker</div>
  <div class="sep">/</div>
  <div class="target" id="hTarget">—</div>
  <div class="spacer"></div>
  <div class="stat maybe-hide" id="hCounts">V <b>0</b> · S <b>0</b> · P <b>0</b> · U <b>0</b></div>
  <div class="stat" id="hElapsed">00:00.0</div>
  <div class="status" id="hStatus">idle</div>
  <button class="btn" id="resetBtn">reset</button>
</header>
<div class="main">
  <div class="canvas-wrap">
    <svg class="exec" id="exec" viewBox="0 0 900 640" preserveAspectRatio="xMidYMid meet">
      <g id="edges"></g>
      <g id="packets"></g>
      <g id="nodes"></g>
    </svg>
    <div class="overlay" id="overlay">
      <div class="overlay-inner">
        <h1>scan a target</h1>
        <p>Enter a URL. I will walk you through every step — what I found, what I tried, and why — in plain language.</p>
        <div class="input-row">
          <input id="url" type="text" placeholder="https://target" value="https://nythosx.com" spellcheck="false" autocomplete="off">
          <button id="startBtn">Analyze →</button>
        </div>
      </div>
    </div>
  </div>
  <aside class="panel">
    <div class="narrator">
      <div class="narrator-hd">
        <div class="avatar" id="avatar">S</div>
        <div class="who">sec-checker</div>
        <div class="state" id="narratorState">idle</div>
      </div>
      <div class="transcript" id="transcript">
        <div class="n-msg obs">
          <div class="n-prefix">·</div>
          <div class="n-body"><div class="n-text">Waiting for you to start a scan. I will explain everything as it happens.</div></div>
        </div>
      </div>
    </div>
    <div class="findings-pane">
      <div class="findings-hd">
        <span class="dot"></span>
        <span>findings</span>
        <span class="count" id="findingsCount">0</span>
      </div>
      <div class="findings-body" id="findingsBody">
        <div class="findings-empty">nothing found yet</div>
      </div>
    </div>
    <div class="findings-pane" id="reconPane" style="display:none">
      <div class="findings-hd">
        <span class="dot" style="background:var(--accent,#39f)"></span>
        <span>recon &amp; data</span>
        <span class="count" id="reconCount">0</span>
      </div>
      <div class="findings-body" id="reconBody"></div>
    </div>
  </aside>
</div>
<div class="log-ribbon" id="logRibbon"></div>
<script>
(function () {
  'use strict';
  var NS = 'http://www.w3.org/2000/svg';
  function el(tag, attrs) {
    var e = document.createElementNS(NS, tag);
    for (var k in attrs) e.setAttribute(k, attrs[k]);
    return e;
  }
  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c];
    });
  }
  var edgesG = document.getElementById('edges');
  var packetsG = document.getElementById('packets');
  var nodesG = document.getElementById('nodes');
  var nodeEls = {};
  var nodeMetaEls = {};
  var edgeEls = {};
  var edgeLabelEls = {};
  var MAIN = [
    { id: 'start', label: 'START', x: 30, y: 30, w: 62, h: 42, kind: 'terminal' },
    { id: 'preflight', label: 'PREFLIGHT', x: 112, y: 20, w: 100, h: 62, kind: 'phase' },
    { id: 'fp', label: 'FINGERPRINT', x: 232, y: 20, w: 110, h: 62, kind: 'phase' },
    { id: 'disc', label: 'DISCOVERY', x: 362, y: 20, w: 100, h: 62, kind: 'phase' },
    { id: 'login', label: 'LOGIN', x: 482, y: 20, w: 90, h: 62, kind: 'phase' },
    { id: 'propose', label: 'PROPOSE', x: 592, y: 20, w: 100, h: 62, kind: 'phase' },
    { id: 'report', label: 'REPORT', x: 782, y: 20, w: 100, h: 62, kind: 'terminal' }
  ];
  var CHAIN = [
    { id: 'jwt', label: 'jwt-chain', y: 160, edge: 'has_jwt' },
    { id: 'gql', label: 'graphql-chain', y: 232, edge: 'has_graphql' },
    { id: 'ssrf', label: 'ssrf-chain', y: 304, edge: 'has_ssrf_hint' },
    { id: 'biz', label: 'bizlogic-chain', y: 376, edge: 'has_ecommerce' },
    { id: 'race', label: 'race-chain', y: 448, edge: 'has_cart' }
  ];
  for (var i = 0; i < CHAIN.length; i++) {
    CHAIN[i].x = 300;
    CHAIN[i].w = 180;
    CHAIN[i].h = 46;
  }
  var SPINE = [];
  for (var s = 0; s < MAIN.length - 1; s++) {
    SPINE.push({ id: 'e-spine-' + s, from: MAIN[s].id, to: MAIN[s + 1].id });
  }
  var FAN = CHAIN.map(function (c) {
    return { id: 'e-fan-' + c.id, from: 'propose', to: 'chain-' + c.id, label: c.edge };
  });
  var RETURN = CHAIN.map(function (c) {
    return { id: 'e-ret-' + c.id, from: 'chain-' + c.id, to: 'report' };
  });
  function getBox(id) {
    var n = null;
    for (var k = 0; k < MAIN.length; k++) if (MAIN[k].id === id) n = MAIN[k];
    for (var c = 0; c < CHAIN.length; c++) {
      if (CHAIN[c].id === 'chain-' + CHAIN[c].id) continue;
      if (('chain-' + CHAIN[c].id) === id) {
        n = { x: CHAIN[c].x, y: CHAIN[c].y, w: CHAIN[c].w, h: CHAIN[c].h };
      }
    }
    return n;
  }
  function spinePath(e) {
    var f = getBox(e.from), t = getBox(e.to);
    var p1 = { x: f.x + f.w, y: f.y + f.h / 2 };
    var p2 = { x: t.x, y: t.y + t.h / 2 };
    var c = Math.max(30, (p2.x - p1.x) * 0.45);
    return 'M ' + p1.x + ' ' + p1.y + ' C ' + (p1.x + c) + ' ' + p1.y + ', ' + (p2.x - c) + ' ' + p2.y + ', ' + p2.x + ' ' + p2.y;
  }
  function fanPath(e) {
    var f = getBox(e.from), t = getBox(e.to);
    var p1 = { x: f.x + f.w / 2, y: f.y + f.h };
    var p2 = { x: t.x + t.w / 2, y: t.y };
    var my = (p1.y + p2.y) / 2;
    return 'M ' + p1.x + ' ' + p1.y + ' C ' + p1.x + ' ' + my + ', ' + p2.x + ' ' + my + ', ' + p2.x + ' ' + p2.y;
  }
  function retPath(e) {
    var f = getBox(e.from), t = getBox(e.to);
    var p1 = { x: f.x + f.w, y: f.y + f.h / 2 };
    var p2 = { x: t.x, y: t.y + t.h - 4 };
    var c = (p2.x - p1.x) * 0.5;
    return 'M ' + p1.x + ' ' + p1.y + ' C ' + (p1.x + c) + ' ' + p1.y + ', ' + (p2.x - c) + ' ' + p2.y + ', ' + p2.x + ' ' + p2.y;
  }
  function mid(e, kind) {
    var f = getBox(e.from), t = getBox(e.to);
    if (kind === 'fan') {
      return { x: (f.x + f.w / 2 + t.x + t.w / 2) / 2 + 30, y: (f.y + f.h + t.y) / 2 };
    }
    return { x: (f.x + f.w + t.x) / 2, y: (f.y + f.h / 2 + t.y + t.h / 2) / 2 - 8 };
  }
  function drawNode(box, kind, extra) {
    var g = el('g', { class: 'node pending ' + kind });
    g.appendChild(el('rect', { x: box.x, y: box.y, width: box.w, height: box.h, rx: 8 }));
    var ly = box.y + box.h / 2 - (extra !== undefined ? 6 : 0);
    var l = el('text', { x: box.x + box.w / 2, y: ly, class: 'label', 'text-anchor': 'middle' });
    l.textContent = box.label;
    g.appendChild(l);
    if (extra !== undefined) {
      var m = el('text', { x: box.x + box.w / 2, y: box.y + box.h / 2 + 8, class: 'meta', 'text-anchor': 'middle' });
      m.textContent = extra;
      g.appendChild(m);
      nodeMetaEls[box.id] = m;
    }
    nodesG.appendChild(g);
    nodeEls[box.id] = g;
  }
  MAIN.forEach(function (n) { n.id = n.id; drawNode(n, n.kind, undefined); });
  CHAIN.forEach(function (c) {
    var box = { id: 'chain-' + c.id, label: c.label, x: c.x, y: c.y, w: c.w, h: c.h };
    drawNode(box, 'phase', '· idle');
  });
  SPINE.forEach(function (e) {
    var p = el('path', { class: 'edge pending', d: spinePath(e) });
    edgesG.appendChild(p);
    edgeEls[e.id] = p;
  });
  FAN.forEach(function (e) {
    var p = el('path', { class: 'edge pending', d: fanPath(e) });
    edgesG.appendChild(p);
    edgeEls[e.id] = p;
    var m = mid(e, 'fan');
    var lbl = el('text', { x: m.x, y: m.y, class: 'edge-label', 'text-anchor': 'start' });
    lbl.textContent = e.label;
    edgesG.appendChild(lbl);
    edgeLabelEls[e.id] = lbl;
  });
  RETURN.forEach(function (e) {
    var p = el('path', { class: 'edge pending', d: retPath(e) });
    edgesG.appendChild(p);
    edgeEls[e.id] = p;
  });
  function setNode(id, state, meta) {
    var g = nodeEls[id];
    if (!g) return;
    g.classList.remove('pending','active','done','done-pass','done-susp','done-vuln','skipped');
    g.classList.add(state);
    if (meta !== undefined && nodeMetaEls[id]) nodeMetaEls[id].textContent = meta || '';
  }
  function setEdge(id, state) {
    var p = edgeEls[id];
    if (!p) return;
    p.classList.remove('pending','active','done','done-vuln','done-susp','done-pass');
    p.classList.add(state);
    var lbl = edgeLabelEls[id];
    if (lbl) {
      lbl.classList.remove('active','vuln','susp');
      if (state === 'active') lbl.classList.add('active');
      if (state === 'done-vuln') lbl.classList.add('vuln');
      if (state === 'done-susp') lbl.classList.add('susp');
    }
  }
  function firePacket(edgeId, cls, dur) {
    var p = edgeEls[edgeId];
    if (!p) return;
    var len = p.getTotalLength();
    if (!len) return;
    var d = el('circle', { r: 3, class: 'packet' + (cls ? ' ' + cls : '') });
    packetsG.appendChild(d);
    var t0 = performance.now();
    var duration = dur || 560;
    (function step(now) {
      var t = Math.min(1, (now - t0) / duration);
      var e = t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2;
      var pt = p.getPointAtLength(e * len);
      d.setAttribute('cx', pt.x);
      d.setAttribute('cy', pt.y);
      d.setAttribute('opacity', t < 0.85 ? 1 : (1 - t) * 6.6);
      if (t < 1) requestAnimationFrame(step);
      else d.remove();
    })(performance.now());
  }
  var ribbon = document.getElementById('logRibbon');
  var logLines = [];
  function log(src, msg, cls) {
    var t = new Date().toTimeString().slice(0, 8);
    logLines.push({ t: t, src: src, msg: msg, cls: cls || '' });
    while (logLines.length > 4) logLines.shift();
    ribbon.innerHTML = logLines.map(function (l) {
      return '<div class="log-line ' + l.cls + '"><span class="t">' + l.t + '</span><span class="src">' + esc(l.src) + '</span><span class="msg">' + esc(l.msg) + '</span></div>';
    }).join('');
  }
  var transcript = document.getElementById('transcript');
  var narratorState = document.getElementById('narratorState');
  var avatar = document.getElementById('avatar');
  var ICONS = { obs: '·', action: '▸', pass: '✓', susp: '?', vuln: '✗' };
  function narrate(text, opts) {
    opts = opts || {};
    var type = opts.type || 'obs';
    var node = document.createElement('div');
    node.className = 'n-msg ' + type;
    var icon = ICONS[type] || '·';
    var html = '<div class="n-prefix">' + icon + '</div>' +
               '<div class="n-body"><div class="n-text">' + text + '</div>';
    if (opts.detail) {
      html += '<div class="n-detail">' + esc(opts.detail) + '</div>';
    }
    html += '</div>';
    node.innerHTML = html;
    transcript.appendChild(node);
    transcript.scrollTop = transcript.scrollHeight;
    while (transcript.childNodes.length > 200) transcript.removeChild(transcript.firstChild);
  }
  function narrateSummary(s) {
    var bullets = (s.bullets || []).map(function (b) {
      return '<li class="' + esc(b.class || '') + '">' + b.html + '</li>';
    }).join('');
    var node = document.createElement('div');
    node.className = 'n-msg summary';
    var exportHtml = '';
    if (s.target) {
      var base = '/api/export?target=' + encodeURIComponent(s.target) + '&fmt=';
      exportHtml = '<div class="n-text" style="margin-top:12px;font-size:12.5px">' +
        'No report is saved automatically — export one if you want it: ' +
        '<a href="' + base + 'pdf" target="_blank" style="color:#79c0ff">Export PDF</a>' +
        ' &middot; <a href="' + base + 'html" target="_blank" style="color:#79c0ff">Export HTML</a></div>';
    }
    node.innerHTML = '<div class="n-title">summary · ' + esc(s.target || 'target') + '</div>' +
      '<div class="n-text">Here is what I found.</div>' +
      (bullets ? '<ul class="n-list">' + bullets + '</ul>' : '') +
      (s.closing ? '<div class="n-text" style="margin-top:14px;padding-top:12px;border-top:1px solid rgba(255,255,255,0.15);color:rgba(255,255,255,0.85);font-size:12.5px">' + s.closing + '</div>' : '') +
      exportHtml;
    transcript.appendChild(node);
    transcript.scrollTop = transcript.scrollHeight;
  }
  function clearTranscript() {
    transcript.innerHTML = '';
    var n = document.createElement('div');
    n.className = 'n-msg obs';
    n.innerHTML = '<div class="n-prefix">·</div><div class="n-body"><div class="n-text">Starting a scan…</div></div>';
    transcript.appendChild(n);
  }
  var findingsBody = document.getElementById('findingsBody');
  var findingsCount = document.getElementById('findingsCount');
  var findings = [];
  var reconTarget = '';
var extractedSeen = [];
function renderExtractedSummary(result) {
  var rows = (result && result.extracted_rows) || [];
  var total = 0;
  var byEndpoint = {};
  for (var i = 0; i < rows.length; i++) {
    var n = rows[i].extracted || (rows[i].rows || []).length || 0;
    total += n;
    var ep = rows[i].endpoint || 'records';
    if (!byEndpoint[ep]) byEndpoint[ep] = {count: 0, auth: rows[i].auth_used || '?'};
    byEndpoint[ep].count += n;
  }
  if (!total) return;
  var body = document.getElementById('findingsBody');
  if (!body) return;
  if (findingsBody && findingsBody.querySelector) {
    var empty = findingsBody.querySelector('.findings-empty');
    if (empty) empty.remove();
  }
  var html = '<div class="fcard vuln" style="border-left-color:#f85149;'
    + 'background:#2a1114;color:#ffb4ae">';
  html += '<div class="fh" style="color:#ffb4ae"><span>EXTRACTED</span>'
    + '<span class="tag" style="background:#f85149;color:#fff">PROOF</span></div>';
  html += '<div class="fn" style="color:#fff"><b>PROOF OF IMPACT</b> — '
    + total + ' record(s) across ' + Object.keys(byEndpoint).length + ' endpoint(s)</div>';
  for (var ep in byEndpoint) {
    var info = byEndpoint[ep];
    html += '<div class="fp" style="color:#ffb4ae;margin-top:4px">'
      + '<b>' + esc(ep) + '</b>: ' + info.count + ' row(s) [' + esc(info.auth) + ']</div>';
  }
  html += '</div>';
  body.insertAdjacentHTML('afterbegin', html);
}
function handleLiveExtraction(d) {
  var ev = d.evidence || {};
  var recs = ev.extracted_records || ev.extracted_data;
  if (Array.isArray(recs) && recs.length) {
    for (var i = 0; i < recs.length; i++) extractedSeen.push(recs[i]);
  }
  if (typeof ev.extracted_value === 'string' && ev.extracted_value) {
    extractedSeen.push({endpoint: 'blind-extract', extracted: 1,
                        rows: [{value: ev.extracted_value}]});
  }
  if (Array.isArray(ev.files_read) && ev.files_read.length) {
    for (var j = 0; j < ev.files_read.length; j++) {
      extractedSeen.push({endpoint: 'files-read', extracted: 1,
                          rows: [{file: ev.files_read[j]}]});
    }
  }
}
  function addFinding(f) {
    if (findings.find(function (x) { return x.id === f.id; })) return;
    findings.push(f);
    findingsCount.textContent = String(findings.length);
    findingsCount.classList.toggle('has', findings.length > 0);
    if (findings.length === 1) findingsBody.innerHTML = '';
    var card = document.createElement('div');
    card.className = 'fcard ' + (f.verdict === 'vuln' ? 'vuln' : 'susp');
    card.innerHTML = '<div class="fh"><span>' + esc(f.chain) + ' · ' + esc(f.step) + '</span>' +
      '<span class="tag">' + (f.verdict === 'vuln' ? 'VULN' : 'SUSP') + '</span></div>' +
      '<div class="fn">' + esc(f.title) + '</div>' +
      '<div class="fp">' + esc(f.payload || '') + '</div>';
    findingsBody.appendChild(card);
    findingsBody.scrollTop = findingsBody.scrollHeight;
  }
  function triageLine(f) {
    if (!f.triage_category) return '';
    var t = 'triage: ' + esc(f.triage_category);
    if (f.triage_by_design) t += ' (by-design)';
    if (f.triage_confidence) t += ' · conf ' + esc(f.triage_confidence);
    return '<div class="fp" style="opacity:.8;margin-top:3px">' + t + '</div>';
  }
  function renderFinalFindings(result) {
    var ff = (result.findings || []).filter(function (f) {
      return f.verdict === 'VULNERABLE' || f.verdict === 'SUSPICIOUS';
    });
    if (!ff.length) return;
    findingsBody.innerHTML = '';
    findingsCount.textContent = String(ff.length);
    findingsCount.classList.toggle('has', ff.length > 0);
    ff.forEach(function (f) {
      var card = document.createElement('div');
      card.className = 'fcard ' + (f.verdict === 'VULNERABLE' ? 'vuln' : 'susp');
      card.innerHTML = '<div class="fh"><span>' + esc(f.pattern_id || f.id) +
        ' · ' + esc(f.severity) + '</span>' +
        '<span class="tag">' + (f.verdict === 'VULNERABLE' ? 'VULN' : 'SUSP') + '</span></div>' +
        '<div class="fn">' + esc((f.reason || '').slice(0, 160)) + '</div>' +
        triageLine(f);
      findingsBody.appendChild(card);
    });
  }
  var catColor = { sensitive: 'var(--red)', content: 'var(--accent,#39f)',
    telemetry: 'var(--ph-dim)', form: '#a06bd6', unknown: 'var(--amber,#e0a030)' };
  function dataTable(d) {
    if (!d || !d.rows || !d.rows.length) return '';
    var first = d.rows[0];
    if (typeof first !== 'object' || first === null) return '';
    var keys = Object.keys(first).slice(0, 8);
    var head = keys.map(function (k) { return '<th style="text-align:left;padding:2px 6px;opacity:.6">' + esc(k) + '</th>'; }).join('');
    var body = d.rows.slice(0, 5).map(function (r) {
      return '<tr>' + keys.map(function (k) {
        var v = r[k]; if (v && typeof v === 'object') v = JSON.stringify(v);
        return '<td style="padding:2px 6px;word-break:break-all">' + esc(String(v).slice(0, 60)) + '</td>';
      }).join('') + '</tr>';
    }).join('');
    return '<table style="width:100%;border-collapse:collapse;font-size:9.5px;margin-top:5px">' +
      '<thead><tr>' + head + '</tr></thead><tbody>' + body + '</tbody></table>' +
      '<div style="opacity:.55;font-size:9px;margin-top:3px">' + (d.extracted || 0) + ' of ' + (d.total_rows || 0) + ' rows · ' + esc(d.auth_used || 'unauth') + ' · masked</div>';
  }
  function renderRecon(data) {
    if (!data || data.error) return;
    var body = document.getElementById('reconBody');
    var pane = document.getElementById('reconPane');
    var cnt = document.getElementById('reconCount');
    if (!body || !pane) return;
    var inv = (data.inventory || []).filter(function (i) { return i.real; });
    var s = data.summary || {};
    var idorCands = (data.idor && data.idor.idor_candidates) || [];
    cnt.textContent = String(inv.length);
    cnt.classList.toggle('has', inv.length > 0);
    var sum = '<div class="fcard" style="border-left-color:var(--accent,#39f)">' +
      '<div class="fn">' + (s.live || 0) + ' live endpoints · ' + (s.with_data || 0) +
      ' returning data · ' + (s.idor_candidates || 0) + ' IDOR candidate(s)</div>';
    if (data.soft_404) sum += '<div class="fp" style="opacity:.7">soft-404 baseline: status ' +
      esc(data.soft_404.status) + ' len ' + esc(data.soft_404.len) + '</div>';
    sum += '</div>';
    var cards = inv.map(function (i) {
      var col = catColor[i.category] || 'var(--ph-dim)';
      var badge = '<span class="tag" style="background:' + col + ';color:#fff">' + esc(i.category) +
        (i.by_design ? ' · pub' : '') + '</span>';
      return '<div class="fcard" style="border-left-color:' + col + '">' +
        '<div class="fh"><span>' + esc(i.path) + '</span>' + badge + '</div>' +
        '<div class="fp">HTTP ' + esc(i.status) + ' · conf ' + esc(i.confidence || '?') +
        (i.data ? '' : ' · no data') + '</div>' +
        dataTable(i.data) + '</div>';
    }).join('');
    var idorBlock = '';
    if (idorCands.length) {
      idorBlock = '<div class="fcard vuln"><div class="fh"><span>IDOR candidates</span>' +
        '<span class="tag" style="background:var(--red);color:#fff">CHECK</span></div>' +
        '<div class="fp">' + idorCands.map(esc).join('<br>') + '</div></div>';
    }
    body.innerHTML = sum + idorBlock + cards;
    pane.style.display = 'flex';
  }
  function fetchRecon(url) {
    if (!url) return;
    fetch('/api/recon', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url })
    }).then(function (r) { return r.json(); })
      .then(function (d) { renderRecon(d); })
      .catch(function () {});
  }
  function endpointBadgeClass(status, verdict) {
    if (verdict === 'blocked' || verdict === 'unreachable') return 'ep-dim';
    if (status === 401 || status === 403 || status === 405) return 'ep-warn';
    if (status >= 200 && status < 300) return 'ep-ok';
    if (status === 404) return 'ep-dim';
    if (status >= 500) return 'ep-bad';
    return 'ep-dim';
  }
  function narrateEndpoint(e) {
    var label = e.status != null ? String(e.status) : (e.verdict || '?').toUpperCase();
    var cls = endpointBadgeClass(e.status, e.verdict);
    var line = esc(e.path) + '<span class="ep-badge ' + cls + '">' + esc(label) + '</span>';
    narrate(line, { type: 'obs' });
  }
  var hTarget = document.getElementById('hTarget');
  var hCounts = document.getElementById('hCounts');
  var hElapsed = document.getElementById('hElapsed');
  var hStatus = document.getElementById('hStatus');
  var counts = { v: 0, s: 0, p: 0, u: 0 };
  function renderCounts() {
    hCounts.innerHTML = 'V <b>' + counts.v + '</b> · S <b>' + counts.s + '</b> · P <b>' + counts.p + '</b> · U <b>' + counts.u + '</b>';
  }
  var startT = 0, timerId = null;
  function startTimer() {
    startT = performance.now();
    clearInterval(timerId);
    timerId = setInterval(function () {
      var dt = (performance.now() - startT) / 1000;
      var m = String(Math.floor(dt / 60)).padStart(2, '0');
      var s = String(Math.floor(dt % 60)).padStart(2, '0');
      var d = String(Math.floor((dt * 10) % 10));
      hElapsed.textContent = m + ':' + s + '.' + d;
    }, 100);
  }
  function stopTimer() { clearInterval(timerId); timerId = null; }
  function setStatus(s, cls) { hStatus.textContent = s; hStatus.className = 'status' + (cls ? ' ' + cls : ''); }
  function setNarratorState(s) { narratorState.textContent = s; }
  function setAvatarRunning(on) {
    avatar.classList.toggle('running', !!on);
    if (on) setNarratorState('speaking…'); else setNarratorState('idle');
  }
  var overlay = document.getElementById('overlay');
  var inputEl = document.getElementById('url');
  var startBtn = document.getElementById('startBtn');
  var resetBtn = document.getElementById('resetBtn');
  var currentJob = null;
  var es = null;
  function handleEvent(ev) {
    var d = ev.data || {};
    switch (ev.type) {
      case 'start':
        log('core', 'starting scan for ' + d.url, 'hi');
        break;
      case 'phase':
        if (d.status === 'running') setAvatarRunning(true);
        break;
      case 'preflight':
        if (d.ok) log('preflight', 'HTTP ' + d.status, 'pass');
        else log('preflight', 'unreachable', 'vuln');
        break;
      case 'framework':
        setNode('fp', 'done-pass', d.id);
        setEdge('e-spine-1', 'done');
        log('framework', d.name + ' (' + d.score + ')', 'pass');
        break;
      case 'api_base':
        setNode('disc', 'done-pass');
        setEdge('e-spine-2', 'done');
        log('discovery', d.url + ' [' + d.source + ']', 'pass');
        break;
      case 'js_done':
        log('discovery', d.count + ' bundles · ' + d.paths + ' paths', '');
        break;
      case 'endpoint_probe':
        narrateEndpoint(d);
        log('discovery', d.path + ' ' + (d.status != null ? d.status : d.verdict), d.verdict === 'live_api' ? 'pass' : '');
        break;
      case 'login':
        if (d.ok) { setNode('login', 'done-pass'); setEdge('e-spine-3', 'done'); }
        else setNode('login', 'skipped', 'unauthenticated');
        log('login', d.ok ? 'token acquired' : 'unauthenticated', d.ok ? 'pass' : '');
        break;
      case 'propose':
        setNode('propose', 'done-pass');
        log('propose', 'chains ranked', 'pass');
        break;
      case 'pattern_start':
        log('scan', d.id, '');
        break;
      case 'pattern_done':
        if (d.verdict === 'VULNERABLE') {
          log('scan', d.id + ' VULNERABLE', 'vuln');
          addFinding({
            id: d.id, chain: 'pattern', step: d.id, verdict: 'vuln',
            title: d.id, payload: d.payload || d.reason,
          });
        } else if (d.verdict === 'SUSPICIOUS') {
          log('scan', d.id + ' SUSPICIOUS', 'susp');
          addFinding({
            id: d.id, chain: 'pattern', step: d.id, verdict: 'susp',
            title: d.id, payload: d.payload || d.reason,
          });
        } else {
          log('scan', d.id + ' ' + d.verdict, '');
        }
        break;
      case 'narrator':
        narrate(d.text, { type: d.type, detail: d.detail });
        if(d.extracted && d.extracted.length){
          handleLiveExtraction(d);
        }
        break;
      case 'step_done':
        handleLiveExtraction(d);
        break;
      case 'activity':
        if (d.message) {
          log('core', d.message, '');
          if (d.message.indexOf('Probing endpoint ') !== 0) {
            narrate(esc(d.message), { type: 'obs' });
          }
        }
        break;
      case 'done':
        setStatus('done', 'done');
        setAvatarRunning(false);
        stopTimer();
        if (d.counts) {
          counts.v = d.counts.VULNERABLE || 0;
          counts.s = d.counts.SUSPICIOUS || 0;
          counts.p = d.counts.PASS || 0;
          counts.u = d.counts.UNKNOWN || 0;
          renderCounts();
        }
        if (currentJob) {
          fetch('/api/job/' + currentJob)
            .then(function (r) { return r.json(); })
            .then(function (job) {
              if (job && job.narrator_summary) narrateSummary(job.narrator_summary);
              if (job && job.result) renderFinalFindings(job.result);
              fetchRecon(reconTarget);
            })
            .catch(function () {});
        }
        if (es) { es.close(); es = null; }
        break;
      case 'error':
        setStatus('error', 'error');
        setAvatarRunning(false);
        stopTimer();
        log('core', 'ERROR: ' + d.message, 'vuln');
        break;
      case 'report':
        log('report', 'saved', 'pass');
        break;
      case 'summary':
        log('core', JSON.stringify(d.counts), 'hi');
        break;
    }
  }
  function resetAll() {
    stopTimer();
    counts.v = counts.s = counts.p = counts.u = 0;
    renderCounts();
    hElapsed.textContent = '00:00.0';
    hTarget.textContent = '—';
    setStatus('idle', '');
    setNarratorState('idle');
    setAvatarRunning(false);
    ribbon.innerHTML = '';
    logLines.length = 0;
    clearTranscript();
    findings.length = 0;
    findingsCount.textContent = '0';
    findingsCount.classList.remove('has');
    findingsBody.innerHTML = '<div class="findings-empty">nothing found yet</div>';
    var rp = document.getElementById('reconPane');
    if (rp) { rp.style.display = 'none'; document.getElementById('reconBody').innerHTML = ''; }
    for (var id in nodeEls) {
      var kind = 'phase';
      for (var k = 0; k < MAIN.length; k++) if (MAIN[k].id === id) kind = MAIN[k].kind;
      nodeEls[id].setAttribute('class', 'node pending ' + kind);
      if (nodeMetaEls[id] && id.indexOf('chain-') === 0) nodeMetaEls[id].textContent = '· idle';
    }
    for (var eid in edgeEls) edgeEls[eid].setAttribute('class', 'edge pending');
    for (var lid in edgeLabelEls) edgeLabelEls[lid].setAttribute('class', 'edge-label');
    packetsG.innerHTML = '';
    if (es) { es.close(); es = null; }
    overlay.classList.remove('hidden');
  }
  function run() {
    var url = (inputEl.value || '').trim();
    if (!url) { inputEl.focus(); return; }
    reconTarget = url;
    resetAll();
    overlay.classList.add('hidden');
    hTarget.textContent = url;
    setStatus('running', 'running');
    startTimer();
    fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url, min_severity: 'medium' }),
    })
    .then(function (r) {
      return r.json().then(function (data) { return { ok: r.ok, data: data }; });
    })
    .then(function (res) {
      if (!res.ok) {
        overlay.classList.remove('hidden');
        setStatus('idle', '');
        stopTimer();
        log('core', 'REJECTED: ' + (res.data.error || 'unknown'), 'vuln');
        narrate('<b>Scan rejected.</b> ' + esc(res.data.error || '') + (res.data.hint ? '<br><i>' + esc(res.data.hint) + '</i>' : ''), { type: 'vuln' });
        return;
      }
      currentJob = res.data.job_id;
      es = new EventSource('/api/scan/' + currentJob + '/stream');
      es.onmessage = function (msg) {
        try {
          var ev = JSON.parse(msg.data);
          handleEvent(ev);
        } catch (err) { /* ignore */ }
      };
      es.onerror = function () {
        if (es && es.readyState === EventSource.CLOSED) es = null;
      };
    })
    .catch(function (err) {
      overlay.classList.remove('hidden');
      setStatus('idle', '');
      stopTimer();
      log('core', 'network error: ' + err, 'vuln');
    });
  }
  startBtn.addEventListener('click', run, true);
  inputEl.addEventListener('keydown', function (e) { if (e.key === 'Enter') run(); });
  resetBtn.addEventListener('click', resetAll);
  renderCounts();
})();
</script>
</body>
</html>
'''

def _inject_credential_ui(html):
    if "credToggleRuntime" in html:
        return html
    marker = "</body>"
    idx = html.rfind(marker)
    if idx == -1:
        return html
    injection = """
<script>
(function(){
  if (window.__credToggleRuntime) return;
  window.__credToggleRuntime = true;

  function init(){
    var url = document.getElementById("url");
    if (!url) return;
    if (document.getElementById("credToggle")) return;
    var row = url.parentNode;
    if (!row) return;

    var btn = document.createElement("button");
    btn.type = "button";
    btn.id = "credToggle";
    btn.textContent = "+";
    btn.title = "Add credentials (optional)";
    btn.style.cssText = "background:transparent;border:1px solid rgba(128,128,128,0.45);border-radius:999px;color:inherit;font-size:13px;line-height:1;width:22px;height:22px;margin:8px;padding:0;display:inline-flex;align-items:center;justify-content:center;cursor:pointer;flex-shrink:0;font-family:inherit";
    row.insertBefore(btn, url);

    var form = document.createElement("div");
    form.id = "credForm";
    form.style.cssText = "display:none;grid-template-columns:1fr 1fr;gap:8px;margin-top:12px;padding-top:12px;border-top:1px dashed rgba(128,128,128,0.35)";
    form.innerHTML =
      '<input id="credUser" type="text" placeholder="username / email (optional)" autocomplete="off" spellcheck="false" style="background:transparent;border:1px solid rgba(128,128,128,0.45);border-radius:6px;color:inherit;font-family:inherit;font-size:12px;padding:8px 10px;outline:none;min-width:0">' +
      '<input id="credPass" type="password" placeholder="password (optional)" autocomplete="off" style="background:transparent;border:1px solid rgba(128,128,128,0.45);border-radius:6px;color:inherit;font-family:inherit;font-size:12px;padding:8px 10px;outline:none;min-width:0">' +
      '<input id="credLoginUrl" type="text" placeholder="login URL (optional \u2014 defaults to auto-discovered)" autocomplete="off" spellcheck="false" style="grid-column:1/-1;background:transparent;border:1px solid rgba(128,128,128,0.45);border-radius:6px;color:inherit;font-family:inherit;font-size:12px;padding:8px 10px;outline:none;min-width:0">' +
      '<input id="credToken" type="password" placeholder="bearer token (optional \u2014 paste if you already have one)" autocomplete="off" spellcheck="false" style="grid-column:1/-1;background:transparent;border:1px solid rgba(128,128,128,0.45);border-radius:6px;color:inherit;font-family:inherit;font-size:12px;padding:8px 10px;outline:none;min-width:0">';
    row.parentNode.insertBefore(form, row.nextSibling);

    function openForm(){
      form.style.display = "grid";
      btn.textContent = "x";
      btn.style.color = "currentColor";
      btn.style.borderColor = "currentColor";
    }

    btn.addEventListener("click", function(){
      var open = form.style.display !== "grid";
      form.style.display = open ? "grid" : "none";
      btn.textContent = open ? "x" : "+";
      btn.style.color = open ? "currentColor" : "inherit";
      btn.style.borderColor = open ? "currentColor" : "rgba(128,128,128,0.45)";
    });

    fetch("/api/defaults").then(function(r){return r.json();}).then(function(d){
      if (!d) return;
      if (d.target && (!url.value || url.value.trim() === "")) url.value = d.target;
      else if (d.target) url.value = d.target;
      var map = {credUser: d.username, credPass: d.password,
                 credLoginUrl: d.login_url, credToken: d.token};
      var any = false;
      Object.keys(map).forEach(function(id){
        var el = document.getElementById(id);
        if (el && map[id]) { el.value = map[id]; any = true; }
      });
      if (any) openForm();
    }).catch(function(){});

    var origFetch = window.fetch;
    window.fetch = function(input, init){
      try {
        if (init && init.body && typeof input === "string" &&
            input.indexOf("/api/scan") !== -1) {
          var b = JSON.parse(init.body);
          var uEl = document.getElementById("credUser");
          var pEl = document.getElementById("credPass");
          var luEl = document.getElementById("credLoginUrl");
          var tEl = document.getElementById("credToken");
          var u = uEl ? (uEl.value || "").trim() : "";
          var p = pEl ? (pEl.value || "") : "";
          var lu = luEl ? (luEl.value || "").trim() : "";
          var tk = tEl ? (tEl.value || "").trim() : "";
          if (u || p || lu || tk) {
            b.credentials = {};
            if (u) b.credentials.username = u;
            if (p) b.credentials.password = p;
            if (lu) b.credentials.login_url = lu;
            if (tk) b.credentials.token = tk;
            init.body = JSON.stringify(b);
          }
          var aiEl = document.getElementById("aiKey");
          var aiV = aiEl ? (aiEl.value || "").trim() : "";
          if (aiV) b.ai_key = aiV;
          var aiToggleEl = document.getElementById("aiToggle");
          if (aiToggleEl && !aiToggleEl.checked) b.use_brain = false;
        }
      } catch (e) {}
      return origFetch.apply(this, arguments);
    };
  }

  function buildAI(){
    if (document.getElementById("aiBox")) return;
    var form = document.getElementById("credForm");
    if (!form) return;
    var box = document.createElement("div");
    box.id = "aiBox";
    box.style.cssText = "grid-column:1/-1;margin-top:10px;padding-top:10px;border-top:1px dashed rgba(128,128,128,0.35);font-family:inherit;font-size:12px";
    box.innerHTML =
      '<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">' +
        '<span id="aiDot" style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#5c6166"></span>' +
        '<span id="aiLabel" style="color:inherit;opacity:0.8">AI: checking…</span>' +
      '</div>' +
      '<label id="aiToggleLabel" style="display:none;align-items:center;gap:6px;margin-bottom:6px;cursor:pointer;opacity:0.9">' +
        '<input id="aiToggle" type="checkbox" checked style="margin:0">' +
        '<span>Gamitin ang AI brain para sa scan na ito</span>' +
      '</label>' +
      '<input id="aiKey" type="password" placeholder="LLM API key (optional \u2014 used for triage only)" autocomplete="off" spellcheck="false" style="width:100%;background:transparent;border:1px solid rgba(128,128,128,0.45);border-radius:6px;color:inherit;font-family:inherit;font-size:12px;padding:8px 10px;outline:none;display:none">';
    form.appendChild(box);
    fetch("/api/ai_status").then(function(r){return r.json();}).then(function(s){
      var dot = document.getElementById("aiDot");
      var lbl = document.getElementById("aiLabel");
      var inp = document.getElementById("aiKey");
      var toggleLabel = document.getElementById("aiToggleLabel");
      if (s && s.configured) {
        dot.style.background = "#2f9e5f";
        lbl.textContent = "AI: online (" + (s.provider || "?") + "/" + (s.model || "?") + ")";
        if (toggleLabel) toggleLabel.style.display = "flex";
      } else {
        dot.style.background = "#5c6166";
        lbl.textContent = "AI: offline \u2014 paste a key to enable triage";
        if (inp) inp.style.display = "block";
      }
    }).catch(function(){
      var lbl = document.getElementById("aiLabel");
      if (lbl) lbl.textContent = "AI: status unknown";
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function(){ init(); buildAI(); });
  } else {
    init(); buildAI();
  }
})();
</script>
"""
    return html[:idx] + injection + html[idx:]


PAGE = _inject_credential_ui(PAGE)
PAGE_CLASSIC = _inject_credential_ui(PAGE_CLASSIC)
