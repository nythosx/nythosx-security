import io
import json
import time
import threading
import uuid
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from rich.console import Console

from . import auto as auto_mod
from . import ledger
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
            _set(job_id, status="running", phase="studying target + scanning")
            outcome = auto_mod.run_auto(url, min_severity=min_severity)
            result = _build_result(url, outcome, buf.getvalue())
            _set(job_id, status="done", phase="done", result=result)
        except Exception as e:
            _set(job_id, status="error", phase="error",
                 error=f"{type(e).__name__}: {e}", log=buf.getvalue())
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
        if self.path.startswith("/api/job/"):
            job_id = self.path.rsplit("/", 1)[1]
            job = _get(job_id)
            if not job:
                return self._send(404, {"error": "unknown job"})
            return self._send(200, {k: v for k, v in job.items()})
        return self._send(404, {"error": "not found"})

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
:root{--bg:#0d1117;--panel:#161b22;--border:#30363d;--fg:#c9d1d9;--muted:#8b949e;
--accent:#58a6ff;--crit:#f85149;--high:#ff7b72;--med:#d29922;--low:#58a6ff;--ok:#3fb950;}
*{box-sizing:border-box}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
background:var(--bg);color:var(--fg);min-height:100vh;display:flex;flex-direction:column;}
header{padding:16px 24px;border-bottom:1px solid var(--border);display:flex;
align-items:center;gap:10px;}
header .logo{font-weight:700;color:var(--accent);letter-spacing:.5px}
header .tag{color:var(--muted);font-size:13px}
main{flex:1;display:flex;flex-direction:column;align-items:center;padding:24px 16px;}
.hero{width:100%;max-width:720px;margin:8vh auto 0;text-align:center;}
.hero h1{font-size:28px;margin:0 0 6px}
.hero p{color:var(--muted);margin:0 0 28px}
.box{display:flex;gap:10px;background:var(--panel);border:1px solid var(--border);
border-radius:14px;padding:10px;box-shadow:0 8px 40px rgba(0,0,0,.35);}
.box input{flex:1;background:transparent;border:none;outline:none;color:var(--fg);
font-size:17px;padding:12px 14px;}
.box button{background:var(--accent);color:#0d1117;border:none;border-radius:10px;
padding:0 22px;font-size:15px;font-weight:600;cursor:pointer;}
.box button:disabled{opacity:.5;cursor:default}
.opts{margin-top:12px;color:var(--muted);font-size:13px}
.opts select{background:var(--panel);color:var(--fg);border:1px solid var(--border);
border-radius:8px;padding:4px 8px;}
.results{width:100%;max-width:980px;margin:28px auto 60px;display:none}
.phase{display:flex;align-items:center;gap:10px;color:var(--muted);margin-bottom:16px}
.spinner{width:16px;height:16px;border:2px solid var(--border);border-top-color:var(--accent);
border-radius:50%;animation:spin 1s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:20px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:14px}
.card .k{color:var(--muted);font-size:12px;text-transform:uppercase}
.card .v{font-size:20px;font-weight:700;margin-top:4px}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--border);
border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--border);font-size:13px}
th{background:#1c2230;color:var(--accent)}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700}
.VULNERABLE{background:var(--crit);color:#fff}.SUSPICIOUS{background:var(--med);color:#000}
.PASS{background:var(--ok);color:#001b0c}.UNKNOWN{background:#30363d;color:var(--muted)}
.sev-critical{color:var(--crit)}.sev-high{color:var(--high)}.sev-medium{color:var(--med)}
.sev-low{color:var(--low)}.sev-info{color:var(--muted)}
details{margin-top:20px;background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:12px}
summary{cursor:pointer;color:var(--accent)}
pre{white-space:pre-wrap;word-break:break-word;font-size:12px;color:var(--muted);max-height:360px;overflow:auto}
.err{background:#2d1114;border:1px solid var(--crit);color:#ffb4ae;padding:14px;border-radius:10px}
.err .hint{color:var(--muted);font-size:13px;margin-top:6px}
</style>
</head>
<body>
<header>
  <span class="logo">sec-checker</span>
  <span class="tag">black-box security scanner · local · ROE fail-closed</span>
</header>
<main>
  <div class="hero">
    <h1>Scan a target</h1>
    <p>Enter a URL. It studies what the target is (framework, API, auth), then runs the scan.</p>
    <form class="box" id="form">
      <input id="url" type="text" placeholder="https://localhost:3000" autocomplete="off" autofocus>
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

  <div class="results" id="results"></div>
</main>

<script>
const form=document.getElementById('form');
const results=document.getElementById('results');
const go=document.getElementById('go');

function esc(s){return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}

form.addEventListener('submit',async e=>{
  e.preventDefault();
  const url=document.getElementById('url').value.trim();
  const sev=document.getElementById('sev').value;
  if(!url)return;
  go.disabled=true;
  results.style.display='block';
  results.innerHTML='<div class="phase"><div class="spinner"></div><span>submitting…</span></div>';
  let res;
  try{
    res=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({url,min_severity:sev})});
  }catch(err){results.innerHTML=errBox('Network error',String(err));go.disabled=false;return;}
  const data=await res.json();
  if(!res.ok){results.innerHTML=errBox(data.error||'Error',(data.detail||'')+'<br>'+(data.hint||''));go.disabled=false;return;}
  poll(data.job_id);
});

function errBox(t,d){return '<div class="err"><b>'+esc(t)+'</b><div class="hint">'+d+'</div></div>';}

async function poll(id){
  try{
    const r=await fetch('/api/job/'+id);
    const j=await r.json();
    if(j.status==='running'||j.status==='queued'){
      results.innerHTML='<div class="phase"><div class="spinner"></div><span>'+esc(j.phase||j.status)+'…</span></div>';
      setTimeout(()=>poll(id),1200);return;
    }
    if(j.status==='error'){results.innerHTML=errBox('Scan error',esc(j.error||''));go.disabled=false;return;}
    render(j.result);go.disabled=false;
  }catch(err){results.innerHTML=errBox('Poll error',String(err));go.disabled=false;}
}

function render(r){
  const c=r.counts||{};
  let h='';
  h+='<div class="cards">';
  h+=card('Framework',esc(r.framework.name)+' <span style="color:var(--muted);font-size:12px">('+esc(r.framework.id)+')</span>');
  h+=card('API base',esc(r.api_base));
  h+=card('API paths found',r.api_paths_count);
  h+=card('Authenticated',r.logged_in?'yes':'no');
  h+='</div>';
  h+='<div class="cards">';
  h+=card('Vulnerable',(c.VULNERABLE||0),'sev-critical');
  h+=card('Suspicious',(c.SUSPICIOUS||0),'sev-medium');
  h+=card('Pass',(c.PASS||0),'sev-low');
  h+=card('Unknown',(c.UNKNOWN||0));
  h+='</div>';
  const f=(r.findings||[]).slice().sort((a,b)=>rank(b.verdict)-rank(a.verdict));
  h+='<table><thead><tr><th>Pattern</th><th>Severity</th><th>Verdict</th><th>Reason</th></tr></thead><tbody>';
  if(!f.length)h+='<tr><td colspan="4" style="color:var(--muted)">No findings recorded.</td></tr>';
  for(const x of f){
    h+='<tr><td>'+esc(x.pattern_id)+'</td><td class="sev-'+esc(x.severity)+'">'+esc(x.severity)+
       '</td><td><span class="badge '+esc(x.verdict)+'">'+esc(x.verdict)+'</span></td><td>'+esc((x.reason||'').slice(0,160))+'</td></tr>';
  }
  h+='</tbody></table>';
  if(r.report)h+='<p style="color:var(--muted);font-size:13px">HTML report: '+esc(r.report)+'</p>';
  if(r.log)h+='<details><summary>Engine log (what it studied &amp; executed)</summary><pre>'+esc(r.log)+'</pre></details>';
  results.innerHTML=h;
}
function rank(v){return {VULNERABLE:3,SUSPICIOUS:2,PASS:1,UNKNOWN:0}[v]||0;}
function card(k,v,cls){return '<div class="card"><div class="k">'+esc(k)+'</div><div class="v '+(cls||'')+'">'+v+'</div></div>';}
</script>
</body>
</html>
"""
