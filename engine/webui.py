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


def _build_result(url, outcome, log_text):
    targets = (outcome or {}).get("targets") or {}
    scan_target = targets.get("api_base") or url
    framework = (outcome or {}).get("framework") or {}
    adapter = framework.get("adapter") or {}
    login = (outcome or {}).get("login")
    findings = _findings_for(scan_target)
    chains, coverage = [], None
    try:
        from . import report as _report
        _report.enrich_findings(findings)
        chains = _report.build_chains(findings)
        coverage = _report.build_coverage(scan_target, findings)
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
        "report": (outcome or {}).get("report"),
        "log": log_text,
    })


def _run_job(job_id, url, min_severity):
    buf = io.StringIO()
    with _run_lock:
        old_console = auto_mod.console
        auto_mod.console = Console(file=buf, force_terminal=False, width=100)
        try:
            _set(job_id, status="running", phase="starting")
            outcome = auto_mod.run_auto(url, min_severity=min_severity, job_id=job_id)
            result = _build_result(url, outcome, buf.getvalue())
            _set(job_id, status="done", phase="done", result=result)
            if not progress.is_done(job_id):
                progress.emit(job_id, "done", {"counts": result.get("counts") or {},
                                                 "report": result.get("report")})
        except Exception as e:
            _set(job_id, status="error", phase="error",
                 error=f"{type(e).__name__}: {e}", log=buf.getvalue())
            progress.emit(job_id, "error", {"message": f"{type(e).__name__}: {e}"})
        finally:
            auto_mod.console = old_console


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
            return self._send(200, PAGE, "text/html; charset=utf-8")
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
            return self._send(200, {k: v for k, v in job.items()})
        return self._send(404, {"error": "not found"})

    def _stream(self, job_id):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache, no-transform")
        self.send_header("Connection", "keep-alive")
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
        if self.path != "/api/scan":
            return self._send(404, {"error": "not found"})
        length = int(self.headers.get("Content-Length", 0))
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return self._send(400, {"error": "invalid JSON"})
        url = (payload.get("url") or "").strip()
        min_severity = payload.get("min_severity", "medium")
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
        threading.Thread(target=_run_job, args=(job_id, url, min_severity),
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


PAGE = r"""<!doctype html>
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
      <input id="url" type="text" placeholder="http://localhost:3000" autocomplete="off" autofocus>
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
          <thead><tr><th style="width:36%">Pattern</th><th style="width:10%">Severity</th><th style="width:12%">Verdict</th><th>Reason</th></tr></thead>
          <tbody id="findings-body"><tr><td colspan="4" style="color:var(--muted);padding:16px 14px">Waiting for results&hellip;</td></tr></tbody>
        </table>
      </div>
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
  c.el.querySelector(".ct").textContent = (verdict || "") + (ms !== undefined ? " \u00b7 " + fmtMs(ms) : "");
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
  if(ports && ports.length){ sub += "  \u00b7  " + ports.length + " port(s) live"; }
  $("s-api").textContent = sub;
  $("card-api").classList.add("accent");
}
function setJs(count, sizeKb, paths){
  $("v-js").textContent = count + " bundles";
  $("s-js").textContent = sizeKb + " KB  \u00b7  " + paths + " paths found";
  $("card-js").classList.add("accent");
}
function setLogin(ok, url, tokenPreview){
  $("v-login").textContent = ok ? "OK" : "not authenticated";
  var sub = url || "";
  if(tokenPreview) sub += "  \u00b7  " + tokenPreview;
  $("s-login").textContent = sub;
  $("card-login").classList.add(ok ? "ok" : "warn");
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
    '<td><span class="badge ' + esc(d.verdict) + '">' + esc(d.verdict) + "</span></td>" +
    "<td>" + esc((d.reason||"").slice(0,220)) + "</td>";
  findingsBody.insertBefore(tr, findingsBody.firstChild);
}

function setProgress(done, total){
  var pct = total > 0 ? (done / total) * 100 : 0;
  pFill.style.width = pct.toFixed(1) + "%";
  pCount.textContent = done + " / " + total;
  pLabel.textContent = done < total ? "scanning\u2026" : "complete";
  if(done >= total) pFill.classList.add("done");
}

function showSummary(counts, reportPath){
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
  if(reportPath){
    var fileUrl = "file:///" + String(reportPath).replace(/\\/g, "/");
    extra += '<a class="report-link" href="' + esc(fileUrl) + '" target="_blank">Open HTML report \u2192</a>';
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
      log("Phase: " + d.name + " \u2192 " + d.status, d.status === "failed" ? "err" : "dim");
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
      log("Extracting " + d.count + " script sources\u2026", "info");
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
      log("\u2192 " + d.id + " \u2192 " + d.verdict + "  (" + fmtMs(d.duration_ms) + ")", d.verdict === "PASS" ? "dim" : "warn");
      if(d.verdict !== "PASS" && d.verdict !== "UNKNOWN") addFinding(d);
      break;
    case "progress":
      setProgress(d.done, d.total);
      break;
    case "worker_error":
      log("Worker error: " + d.id + " \u2014 " + d.message, "err");
      break;
    case "summary":
      feed("scan", 'result <span class="mono">' + esc(JSON.stringify(d.counts)) + '</span>');
      log("Summary: " + JSON.stringify(d.counts), "accent");
      break;
    case "report":
      setEdgeData("report", "saved");
      feed("report", 'report saved <span class="mono">' + esc(d.path) + '</span>');
      log("Report: " + d.path, "ok");
      break;
    case "done":
      setStatus("done", "done");
      runningPhase = null;
      stopTicker();
      log("Scan complete.", "ok");
      showSummary(d.counts, d.report);
      if(currentJob){
        fetch("/api/job/" + currentJob).then(function(r){return r.json();}).then(function(job){
          if(job && job.result) renderResult(job.result);
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
  caps = {}; cloudHasCaps = false; cloudEl.innerHTML = '<span class="empty">Naghihintay ng tools\u2026</span>';
  feedHasRows = false; feedEl.innerHTML = '<div class="empty">Wala pang data na naipapasa\u2026</div>';
  consoleEl.innerHTML = "";
  ["chains-section","coverage-section","why-section","summary-section"].forEach(function(id){
    var el = $(id); if(el) el.style.display = "none";
  });
  findingsBody.innerHTML = '<tr><td colspan="4" style="color:var(--muted);padding:16px 14px">Waiting for results\u2026</td></tr>';
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
