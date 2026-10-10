import io
import json
import time
import threading
import uuid
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from queue import Empty
from rich.console import Console

from . import auto as auto_mod
from . import ledger
from . import progress
from .config import load_engine
from .roe_guard import ROEGuard, ROEViolation

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
    return {
        "target": scan_target,
        "entered_url": url,
        "framework": {"name": adapter.get("name", framework.get("name", "Generic")),
                      "id": adapter.get("id", framework.get("framework", "generic")),
                      "score": framework.get("score", 0)},
        "api_base": scan_target,
        "api_paths_count": len((outcome or {}).get("api_paths") or []),
        "logged_in": bool(login and (login.get("token") if isinstance(login, dict) else False)),
        "counts": (outcome or {}).get("counts") or {},
        "findings": _findings_for(scan_target),
        "report": (outcome or {}).get("report"),
        "log": log_text,
    }


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


def serve(host="127.0.0.1", port=8900):
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
--ok:#3fb950;--run:#58a6ff;}
*{box-sizing:border-box}
html,body{margin:0;padding:0;height:100%}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
background:var(--bg);color:var(--fg);display:flex;flex-direction:column;min-height:100vh}
header{padding:14px 24px;border-bottom:1px solid var(--border);display:flex;
align-items:center;gap:14px;background:var(--panel)}
header .logo{font-weight:700;color:var(--accent);letter-spacing:.5px;font-size:16px}
header .tag{color:var(--muted);font-size:12px}
header .spacer{flex:1}
header .pill{padding:3px 10px;border-radius:12px;font-size:11px;font-weight:600;
text-transform:uppercase;letter-spacing:.5px}
.pill.idle{background:#1e242f;color:var(--muted)}
.pill.running{background:rgba(88,166,255,.15);color:var(--accent);animation:pulse 1.6s infinite}
.pill.done{background:rgba(63,185,80,.15);color:var(--ok)}
.pill.error{background:rgba(248,81,73,.15);color:var(--crit)}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.55}}
main{flex:1;padding:20px 24px 60px;max-width:1400px;margin:0 auto;width:100%}
.hero{max-width:760px;margin:10vh auto 0;text-align:center}
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
.dash{display:none}
.dash.on{display:block}
.section{margin-bottom:24px}
.section-title{font-size:12px;text-transform:uppercase;letter-spacing:1px;
color:var(--muted);margin-bottom:10px;font-weight:600}
.phases{display:flex;gap:0;background:var(--panel);border:1px solid var(--border);
border-radius:12px;padding:16px 20px;overflow-x:auto}
.phase{display:flex;align-items:center;gap:10px;padding-right:22px;
position:relative;flex-shrink:0}
.phase:not(:last-child):after{content:"";position:absolute;right:6px;top:50%;
width:14px;height:1px;background:var(--border)}
.phase .dot{width:22px;height:22px;border-radius:50%;display:flex;align-items:center;
justify-content:center;font-size:11px;font-weight:700;background:#1e242f;
color:var(--muted);border:1px solid var(--border);flex-shrink:0;transition:all .3s}
.phase .lbl{font-size:12px;color:var(--muted);text-transform:uppercase;
letter-spacing:.5px;font-weight:600;white-space:nowrap}
.phase .elapsed{font-size:11px;color:var(--muted);font-family:ui-monospace,monospace;
margin-left:4px}
.phase.running .dot{background:rgba(88,166,255,.2);color:var(--accent);
border-color:var(--accent);animation:pulse 1.4s infinite}
.phase.running .lbl{color:var(--accent)}
.phase.done .dot{background:rgba(63,185,80,.15);color:var(--ok);border-color:var(--ok)}
.phase.done .dot:before{content:"\2713"}
.phase.done .dot span{display:none}
.phase.done .lbl{color:var(--ok)}
.phase.failed .dot{background:rgba(248,81,73,.15);color:var(--crit);border-color:var(--crit)}
.phase.failed .dot:before{content:"\00d7"}
.phase.failed .dot span{display:none}
.phase.failed .lbl{color:var(--crit)}
.phase.skipped .dot{background:#1e242f;color:var(--muted)}
.activity-panel{background:var(--panel);border:1px solid var(--border);
border-radius:12px;padding:14px 18px}
.activity-head{display:flex;align-items:center;gap:12px}
.spinner{width:14px;height:14px;border-radius:50%;border:2px solid var(--border);
border-top-color:var(--accent);animation:spin .8s linear infinite;flex-shrink:0}
.activity-panel.done .spinner,.activity-panel.error .spinner{animation:none;
border-top-color:var(--border)}
@keyframes spin{to{transform:rotate(360deg)}}
.act-stage{font-size:11px;text-transform:uppercase;letter-spacing:.5px;font-weight:700;
color:var(--accent);background:rgba(88,166,255,.12);padding:3px 9px;border-radius:10px;
flex-shrink:0}
.act-msg{font-size:14px;color:var(--fg);font-family:ui-monospace,SFMono-Regular,Consolas,monospace;
overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.act-timer{font-size:13px;color:var(--muted);font-family:ui-monospace,monospace;flex-shrink:0}
.activity-panel.done .act-stage{color:var(--ok);background:rgba(63,185,80,.12)}
.activity-panel.error .act-stage{color:var(--crit);background:rgba(248,81,73,.12)}
.act-subbar{height:5px;background:#1e242f;border-radius:4px;overflow:hidden;margin-top:12px}
.act-subfill{height:100%;background:linear-gradient(90deg,var(--accent),var(--accent2));
width:0%;transition:width .25s ease;border-radius:4px}
.act-inflight{display:flex;flex-wrap:wrap;gap:6px;margin-top:12px}
.act-chip{font-size:11px;font-family:ui-monospace,monospace;background:var(--panel2);
border:1px solid var(--border);border-radius:8px;padding:3px 9px;color:var(--muted);
display:flex;align-items:center;gap:6px}
.act-chip .c-dot{width:6px;height:6px;border-radius:50%;background:var(--accent);
animation:pulse 1.2s infinite}
.act-chip .c-t{color:var(--muted);font-size:10px}
.act-chip.slow{border-color:var(--med);color:var(--med)}
.act-chip.slow .c-dot{background:var(--med)}
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
</style>
</head>
<body>
<header>
  <span class="logo">sec-checker</span>
  <span class="tag">black-box security scanner &middot; local &middot; ROE fail-closed</span>
  <span class="spacer"></span>
  <span class="pill idle" id="status">idle</span>
</header>

<main>
  <div class="hero" id="hero">
    <h1>Scan a target</h1>
    <p>Enter a URL. It studies what the target is, then runs the scan live.</p>
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
  </div>

  <div class="dash" id="dash">
    <div class="section">
      <div class="section-title">Progress</div>
      <div class="phases" id="phases">
        <div class="phase" data-phase="preflight"><div class="dot"><span>1</span></div><div class="lbl">Preflight</div><div class="elapsed"></div></div>
        <div class="phase" data-phase="framework"><div class="dot"><span>2</span></div><div class="lbl">Framework</div><div class="elapsed"></div></div>
        <div class="phase" data-phase="discovery"><div class="dot"><span>3</span></div><div class="lbl">Discovery</div><div class="elapsed"></div></div>
        <div class="phase" data-phase="login"><div class="dot"><span>4</span></div><div class="lbl">Login</div><div class="elapsed"></div></div>
        <div class="phase" data-phase="scanning"><div class="dot"><span>5</span></div><div class="lbl">Scan</div><div class="elapsed"></div></div>
        <div class="phase" data-phase="report"><div class="dot"><span>6</span></div><div class="lbl">Report</div><div class="elapsed"></div></div>
      </div>
    </div>

    <div class="section">
      <div class="section-title">Now doing</div>
      <div class="activity-panel" id="activity-panel">
        <div class="activity-head">
          <span class="spinner" id="act-spin"></span>
          <span class="act-stage" id="act-stage">starting</span>
          <span class="act-msg" id="act-msg">Initializing&hellip;</span>
          <span class="spacer"></span>
          <span class="act-timer" id="act-timer">0.0s</span>
        </div>
        <div class="act-subbar" id="act-subbar" style="display:none">
          <div class="act-subfill" id="act-subfill"></div>
        </div>
        <div class="act-inflight" id="act-inflight"></div>
      </div>
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
      <div class="section-title">Patterns</div>
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

var actStage = $("act-stage");
var actMsg = $("act-msg");
var actTimer = $("act-timer");
var actPanel = $("activity-panel");
var actSubbar = $("act-subbar");
var actSubfill = $("act-subfill");
var actInflight = $("act-inflight");

var actStart = 0;
var runningPhase = null;
var inflight = {};
var ticker = null;
var SLOW_MS = 8000;

function startTicker(){
  if(ticker) return;
  ticker = setInterval(tick, 100);
}
function stopTicker(){
  if(ticker){ clearInterval(ticker); ticker = null; }
}
function tick(){
  var p = performance.now();
  if(actStart) actTimer.textContent = ((p - actStart) / 1000).toFixed(1) + "s";
  if(runningPhase && phaseStart[runningPhase] !== undefined){
    var el = document.querySelector('.phase[data-phase="' + runningPhase + '"] .elapsed');
    if(el) el.textContent = fmtMs(p - phaseStart[runningPhase]);
  }
  for(var id in inflight){
    var chip = inflight[id].el;
    if(!chip) continue;
    var ms = p - inflight[id].t;
    var tEl = chip.querySelector(".c-t");
    if(tEl) tEl.textContent = fmtMs(ms);
    if(ms > SLOW_MS) chip.classList.add("slow");
  }
}

function setActivity(stage, message, i, n){
  if(stage) actStage.textContent = stage;
  if(message !== undefined && message !== null) actMsg.textContent = message;
  actStart = performance.now();
  if(n){
    actSubbar.style.display = "block";
    actSubfill.style.width = ((i / n) * 100).toFixed(1) + "%";
  } else {
    actSubbar.style.display = "none";
  }
  startTicker();
}

function addInflight(id){
  if(inflight[id]) return;
  var chip = document.createElement("span");
  chip.className = "act-chip";
  chip.innerHTML = '<span class="c-dot"></span>' + esc(id) + ' <span class="c-t">0ms</span>';
  actInflight.appendChild(chip);
  inflight[id] = {el: chip, t: performance.now()};
}
function removeInflight(id){
  var e = inflight[id];
  if(e && e.el && e.el.parentNode) e.el.parentNode.removeChild(e.el);
  delete inflight[id];
}
function clearInflight(){
  actInflight.innerHTML = "";
  inflight = {};
}

function esc(s){
  if(s === null || s === undefined) return "";
  return String(s).replace(/[&<>"']/g, function(c){
    return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c];
  });
}
function now(){
  var d = new Date();
  return d.toTimeString().slice(0,8);
}
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
  consoleEl.scrollTop = consoleEl.scrollHeight;
}

function setStatus(s, cls){
  statusPill.textContent = s;
  statusPill.className = "pill " + (cls || "idle");
}

function setPhase(name, status){
  var el = document.querySelector('.phase[data-phase="' + name + '"]');
  if(!el) return;
  el.classList.remove("running","done","failed","skipped");
  if(status) el.classList.add(status);
  var el2 = el.querySelector(".elapsed");
  if(status === "running"){
    phaseStart[name] = performance.now();
    runningPhase = name;
    el2.textContent = "";
  } else if(status === "done" && phaseStart[name] !== undefined){
    if(runningPhase === name) runningPhase = null;
    el2.textContent = fmtMs(performance.now() - phaseStart[name]);
  } else if(status === "skipped"){
    el2.textContent = "skipped";
  } else if(status === "failed"){
    el2.textContent = "failed";
  }
}

function setFramework(id, name, score){
  $("v-framework").textContent = name;
  $("s-framework").textContent = "id=" + id + "  score=" + score;
  $("card-framework").classList.add("ok");
}

function setApi(url, source, ports){
  $("v-api").textContent = url;
  var sub = source || "";
  if(ports && ports.length){
    sub += "  \u00b7  " + ports.length + " port(s) live";
  }
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

function handleEvent(ev){
  var d = ev.data || {};
  switch(ev.type){
    case "start":
      log("Starting scan for " + d.url, "accent");
      break;
    case "phase":
      setPhase(d.name, d.status);
      if(d.status === "running"){
        setActivity(d.name, d.name.charAt(0).toUpperCase() + d.name.slice(1) + "\u2026", 0, 0);
        if(d.name !== "scanning") clearInflight();
      }
      log("Phase: " + d.name + " \u2192 " + d.status, d.status === "failed" ? "err" : "dim");
      break;
    case "activity":
      setActivity(d.stage, d.message, d.i, d.n);
      log(d.message + (d.n ? "  (" + d.i + "/" + d.n + ")" : ""), "dim");
      break;
    case "pattern_start":
      addInflight(d.id);
      break;
    case "preflight":
      if(d.ok) log("Preflight OK (HTTP " + d.status + ")", "ok");
      else log("Preflight FAILED: " + d.error, "err");
      break;
    case "framework":
      setFramework(d.id, d.name, d.score);
      log("Framework: " + d.name + " (score=" + d.score + ")", "ok");
      break;
    case "api_base":
      setApi(d.url, d.source, d.ports);
      log("API base: " + d.url + "  [" + d.source + "]", "ok");
      break;
    case "js_start":
      log("Extracting " + d.count + " script sources\u2026", "info");
      break;
    case "js_done":
      setJs(d.count, d.size_kb, d.paths);
      log("Analyzed " + d.count + " bundles (" + d.size_kb + " KB), found " + d.paths + " paths", "ok");
      break;
    case "login":
      setLogin(d.ok, d.url, d.token);
      log("Login: " + (d.ok ? "OK" : "skipped"), d.ok ? "ok" : "warn");
      break;
    case "baseline":
      log("Baseline: mean=" + d.mean_ms + "ms stdev=" + d.stdev_ms + "ms", "info");
      break;
    case "scan_start":
      log("Running " + d.total_patterns + " patterns with " + d.workers + " workers", "accent");
      setActivity("scan", "Running " + d.total_patterns + " patterns, " + d.workers + " workers", 0, 0);
      clearInflight();
      setProgress(0, d.total_work);
      break;
    case "pattern_done":
      removeInflight(d.id);
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
      log("Summary: " + JSON.stringify(d.counts), "accent");
      break;
    case "report":
      log("Report: " + d.path, "ok");
      break;
    case "done":
      setStatus("done", "done");
      runningPhase = null;
      clearInflight();
      stopTicker();
      actPanel.classList.add("done");
      actStage.textContent = "done";
      actMsg.textContent = "Scan complete";
      actSubbar.style.display = "none";
      log("Scan complete.", "ok");
      showSummary(d.counts, d.report);
      break;
    case "error":
      setStatus("error", "error");
      runningPhase = null;
      clearInflight();
      stopTicker();
      actPanel.classList.add("error");
      actStage.textContent = "error";
      actMsg.textContent = d.message || "Scan failed";
      actSubbar.style.display = "none";
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
  hero.style.display = "none";
  dash.classList.add("on");
  findingsSeen.clear();
  consoleEl.innerHTML = "";
  findingsBody.innerHTML = '<tr><td colspan="4" style="color:var(--muted);padding:16px 14px">Waiting for results\u2026</td></tr>';
  pFill.style.width = "0%";
  pFill.classList.remove("done");
  pCount.textContent = "0 / 0";
  pLabel.textContent = "waiting";
  ["framework","api","js","login"].forEach(function(k){
    var c = $("card-" + k);
    c.classList.remove("ok","warn","bad","accent");
  });
  document.querySelectorAll(".phase").forEach(function(p){
    p.classList.remove("running","done","failed","skipped");
  });
  document.querySelectorAll(".phase .elapsed").forEach(function(e){
    e.textContent = "";
  });
  runningPhase = null;
  clearInflight();
  stopTicker();
  actPanel.classList.remove("done","error");
  actStage.textContent = "starting";
  actMsg.textContent = "Initializing…";
  actTimer.textContent = "0.0s";
  actSubbar.style.display = "none";
  actStart = performance.now();
  startTicker();
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
        es.close();
        es = null;
        go.disabled = false;
      }
    } catch(err){
      log("parse error: " + err, "err");
    }
  };
  es.onerror = function(){
    if(es && es.readyState === EventSource.CLOSED){
      log("stream closed", "dim");
    }
  };
});
</script>
</body>
</html>
"""