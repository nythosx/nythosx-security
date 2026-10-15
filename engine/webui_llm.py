
_CSS = r"""
body.sc-ai-ready #brain .brain-ring {
  transform-box: fill-box; transform-origin: center;
}
body.sc-ai-ready #brain.sc-online .brain-ring {
  stroke: var(--ph-dimmer); opacity: 0.9;
  animation: scBrainRotate 22s linear infinite;
}
body.sc-ai-ready #brain.sc-online .brain-ring.inner {
  animation-duration: 34s; animation-direction: reverse; opacity: 0.6;
}
body.sc-ai-ready #brain.sc-queried .brain-ring {
  stroke: var(--ph); opacity: 1;
  animation: scBrainRotate 1.2s linear infinite;
}
body.sc-ai-ready #brain.sc-queried .brain-ring.inner {
  animation-duration: 0.85s; animation-direction: reverse;
}
body.sc-ai-ready #brain.sc-queried .brain-halo {
  fill: rgba(88,166,255,0.06);
}
body.sc-ai-ready #brain.sc-offline .brain-ring { opacity: 0.25; }
@keyframes scBrainRotate { to { transform: rotate(360deg); } }

#transcript .n-msg {
  display: flex; align-items: flex-start; gap: 10px;
  padding: 3px 0; border-top: none;
  opacity: 0;
  animation: scTrIn 320ms cubic-bezier(.2,.9,.3,1) forwards;
}
@keyframes scTrIn {
  from { opacity: 0; transform: translateX(-6px); }
  to   { opacity: 1; transform: translateX(0); }
}
#transcript .n-msg .n-prefix {
  flex-shrink: 0; width: 14px; text-align: center;
  font-weight: 700; line-height: 1.65;
  background: transparent; border: none;
  color: var(--ph); font-size: 12px;
}
#transcript .n-msg .n-body { flex: 1; min-width: 0; padding-top: 1px; }
#transcript .n-msg .n-text {
  font-size: 11.5px; line-height: 1.6;
  color: var(--ph); font-weight: 600;
}
#transcript .n-msg .n-text code {
  font-family: var(--mono); font-size: 11px;
  background: var(--bg-s2); padding: 1px 5px; border-radius: 4px;
}
#transcript .n-msg .n-detail {
  margin-top: 6px;
  background: var(--bg-s2);
  border: 1px solid var(--ph-line);
  border-radius: 6px;
  padding: 8px 10px;
  font-family: var(--mono); font-size: 10.5px;
  line-height: 1.55; color: var(--ph-dim);
  white-space: pre-wrap; word-break: break-all;
  max-height: 180px; overflow-y: auto;
}
#transcript .n-msg.pass .n-prefix { color: var(--green); }
#transcript .n-msg.pass .n-text { color: var(--ph); }
#transcript .n-msg.susp .n-prefix { color: var(--amber); }
#transcript .n-msg.susp .n-text { color: var(--ph); }
#transcript .n-msg.vuln .n-prefix { color: var(--red); }
#transcript .n-msg.vuln .n-text { color: var(--red); font-weight: 600; }
#transcript .n-msg.vuln .n-detail {
  background: rgba(248,81,73,0.08);
  border-color: rgba(248,81,73,0.28);
  color: var(--red);
}
#transcript .n-msg.obs .n-prefix { color: var(--ph-dim); }
#transcript .n-msg.obs .n-text { color: var(--ph); font-weight: 400; }
#transcript .n-msg.action .n-prefix { color: var(--ph-hi); }
#transcript .n-msg.action .n-text { color: var(--ph-hi); }
#transcript .n-msg.summary {
  display: block; background: var(--bg-s2);
  border-radius: 10px; padding: 14px 16px; margin: 10px 0 4px;
  border: 1px solid var(--ph-line);
}
#transcript .n-msg.summary .n-prefix { display: none; }
#transcript .n-msg.summary .n-text { font-weight: 600; color: var(--ph-hi); }

#transcript .tr {
  display: flex; align-items: flex-start; gap: 10px;
  padding: 3px 0;
  opacity: 0;
  animation: scTrIn 320ms cubic-bezier(.2,.9,.3,1) forwards;
}
#transcript .tr .mark {
  flex-shrink: 0; width: 14px; text-align: center;
  font-weight: 700; line-height: 1.65;
  font-family: var(--mono); font-size: 12px;
}
#transcript .tr.step .mark { color: var(--ph); }
#transcript .tr.step.done .mark { color: var(--green); }
#transcript .tr.step.vuln .mark { color: var(--red); }
#transcript .tr.step.susp .mark { color: var(--amber); }
#transcript .tr.step.skip .mark { color: var(--ph-dimmer); }
#transcript .tr.sub .mark { color: var(--ph-dimmer); }
#transcript .tr.summary .mark { color: var(--ph-hi); }
#transcript .tr .body { flex: 1; min-width: 0; line-height: 1.6; }
#transcript .tr.step .body { color: var(--ph); font-weight: 600; font-size: 11.5px; }
#transcript .tr.step .body .tool {
  color: var(--ph-dim); font-weight: 400; font-size: 11px;
}
#transcript .tr.sub .body {
  color: var(--ph-dim); font-size: 11px; padding-left: 2px;
}
#transcript .tr.sub .body .t {
  color: var(--ph-dimmer); font-family: var(--mono);
  font-variant-numeric: tabular-nums;
}
#transcript .tr.summary .body {
  color: var(--ph); font-weight: 600; font-size: 11.5px;
  padding: 6px 0 4px;
  border-top: 1px dashed var(--ph-line);
  margin-top: 4px;
}
#transcript .tr.summary .body b.vuln { color: var(--red); }
#transcript .tr.summary .body b.susp { color: var(--amber); }
#transcript .tr.summary .body b.pass { color: var(--green); }
#transcript .tr.summary .body b.unknown { color: var(--ph-dimmer); }

.sc-ai-tag {
  display: inline-block; margin-left: 6px;
  font-family: var(--mono); font-size: 9px;
  padding: 1px 6px; border-radius: 8px;
  background: rgba(88,166,255,0.14); color: var(--ph-hi);
  border: 1px solid rgba(88,166,255,0.32);
  font-weight: 700; letter-spacing: 0.5px; vertical-align: middle;
}
.sc-ai-finding {
  display: block; margin-top: 3px; padding-left: 10px;
  border-left: 2px solid rgba(88,166,255,0.5);
  color: var(--ph-dim); font-size: 11px; font-family: var(--mono);
}

.sc-ai-panel {
  padding: 12px 14px;
  border-bottom: 1px solid var(--ph-line);
  flex-shrink: 0;
}
.sc-panel-title {
  font-size: 10px; text-transform: uppercase;
  letter-spacing: 1px; color: var(--ph-dim);
  font-weight: 700; margin-bottom: 9px;
}
.sc-ai-status {
  display: flex; align-items: center; gap: 10px;
  padding: 9px 12px; background: var(--bg-s2);
  border-radius: 8px; border: 1px solid var(--ph-line);
  transition: border-color 400ms;
}
.sc-ai-status.sc-online { border-color: rgba(63,185,80,0.4); }
.sc-ai-status.sc-thinking { border-color: rgba(88,166,255,0.6); }
.sc-ai-dot {
  width: 10px; height: 10px; border-radius: 50%;
  background: var(--ph-dimmer); flex-shrink: 0;
  transition: background 300ms, box-shadow 300ms;
}
.sc-ai-status.sc-online .sc-ai-dot {
  background: var(--green); box-shadow: 0 0 10px var(--green);
  animation: scPulse 2s infinite;
}
.sc-ai-status.sc-thinking .sc-ai-dot {
  background: var(--ph-hi); box-shadow: 0 0 14px var(--ph-hi);
  animation: scPulse 0.6s infinite;
}
@keyframes scPulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
.sc-ai-info { flex: 1; min-width: 0; }
.sc-ai-label { font-size: 12px; font-weight: 600; letter-spacing: 0.3px; color: var(--ph); }
.sc-ai-sub {
  font-family: var(--mono); font-size: 10px;
  color: var(--ph-dim); margin-top: 2px;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.sc-cap-chips {
  display: flex; flex-wrap: wrap; gap: 5px; margin-top: 8px;
}
.sc-cap-chip {
  display: inline-flex; align-items: center; gap: 5px;
  padding: 3px 8px; border-radius: 10px;
  font-family: var(--mono); font-size: 9.5px;
  background: var(--bg-s2); border: 1px solid var(--ph-line);
  color: var(--ph-dim); transition: all 300ms;
}
.sc-cap-chip .sc-cd {
  width: 5px; height: 5px; border-radius: 50%;
  background: var(--ph-dimmer);
}
.sc-cap-chip.sc-active { border-color: var(--ph-hi); color: var(--ph-hi); }
.sc-cap-chip.sc-active .sc-cd { background: var(--ph-hi); animation: scPulse 1s infinite; }
.sc-cap-chip.sc-used { border-color: rgba(63,185,80,0.4); color: var(--green); }
.sc-cap-chip.sc-used .sc-cd { background: var(--green); }
.sc-cap-chip .sc-cn { font-variant-numeric: tabular-nums; opacity: 0.7; }

.sc-trace-log {
  margin-top: 8px; max-height: 220px; overflow-y: auto;
  font-family: var(--mono); font-size: 10.5px; line-height: 1.55;
  padding: 4px 0;
}
.sc-trace-log::-webkit-scrollbar { width: 5px; }
.sc-trace-log::-webkit-scrollbar-thumb {
  background: var(--ph-line); border-radius: 3px;
}
.sc-trace {
  margin-bottom: 10px; opacity: 0;
  animation: scTrIn 340ms ease-out forwards;
}
.sc-trace .sc-ts {
  font-size: 9px; color: var(--ph-dimmer);
  margin-bottom: 4px; letter-spacing: 0.4px;
}
.sc-trace .sc-role {
  display: inline-block; font-size: 9px; font-weight: 700;
  padding: 2px 7px; border-radius: 3px;
  margin-right: 6px; letter-spacing: 0.6px;
}
.sc-trace .sc-prompt {
  background: rgba(121,192,255,0.14); color: var(--ph-hi);
  border: 1px solid rgba(121,192,255,0.3);
}
.sc-trace .sc-response {
  background: rgba(63,185,80,0.14); color: var(--green);
  border: 1px solid rgba(63,185,80,0.3);
}
.sc-trace .sc-task {
  background: rgba(88,166,255,0.1); color: var(--ph);
  border: 1px solid rgba(88,166,255,0.25);
  font-size: 8.5px; text-transform: uppercase;
}
.sc-trace .sc-tbody {
  background: var(--bg); border: 1px solid var(--ph-line);
  border-radius: 6px; padding: 8px 10px; margin-top: 4px;
  color: var(--ph); word-break: break-word; white-space: pre-wrap;
  font-size: 10.5px; max-height: 180px; overflow-y: auto; line-height: 1.5;
}
.sc-trace .sc-tbody.sc-prompt-body { border-color: rgba(121,192,255,0.28); }
.sc-trace .sc-tbody.sc-response-body { border-color: rgba(63,185,80,0.28); }
.sc-trace-empty {
  color: var(--ph-dimmer); font-size: 11px; font-style: italic;
  text-align: center; padding: 16px 0;
}

.sc-flash-vuln rect { animation: scFlashRed 800ms ease-out; }
.sc-flash-susp rect { animation: scFlashAmber 800ms ease-out; }
.sc-flash-pass rect { animation: scFlashGreen 700ms ease-out; }
@keyframes scFlashRed {
  0%   { stroke-width: 6; filter: drop-shadow(0 0 30px rgba(248,81,73,0.9)); }
  100% { stroke-width: 2.4; filter: drop-shadow(0 0 18px rgba(248,81,73,0.6)); }
}
@keyframes scFlashAmber {
  0%   { stroke-width: 6; filter: drop-shadow(0 0 28px rgba(210,153,34,0.8)); }
  100% { stroke-width: 2; filter: drop-shadow(0 0 14px rgba(210,153,34,0.4)); }
}
@keyframes scFlashGreen {
  0%   { stroke-width: 5; filter: drop-shadow(0 0 24px rgba(63,185,80,0.7)); }
  100% { stroke-width: 1.5; filter: drop-shadow(0 0 0 rgba(63,185,80,0)); }
}

.sc-data-label {
  font-family: var(--mono); font-size: 9.5px;
  text-anchor: middle; pointer-events: none;
  opacity: 0; transition: opacity 350ms;
}
.sc-data-label.sc-show { opacity: 1; }
.sc-data-label.sc-vuln { fill: var(--red); font-weight: 700; }
.sc-data-label.sc-susp { fill: var(--amber); font-weight: 700; }
.sc-data-label.sc-pass { fill: var(--green); font-weight: 700; }
.sc-data-label.sc-data { fill: var(--ph-dim); }
"""

_JS = r"""
(function(){
  'use strict';

  function esc(s){
    return String(s).replace(/[&<>"']/g, function(c){
      return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
    });
  }

  var transcript = document.getElementById('transcript');
  var traceLog   = document.getElementById('scTraceLog');
  var aiStatusEl = document.getElementById('scAiStatus');
  var aiLabelEl  = document.getElementById('scAiLabel');
  var aiSubEl    = document.getElementById('scAiSub');

  function trStep(text, tool, state){
    if (!transcript) return;
    var mark = state === 'running' ? '\u25b8' :
               state === 'vuln'    ? '\u2717' :
               state === 'susp'    ? '?' :
               state === 'skip'    ? '\u2014' : '\u2713';
    var cls = 'tr step' + (state ? ' ' + state : '');
    var toolHtml = tool
      ? ' <span class="tool">(' + esc(tool) + ')</span>' : '';
    var d = document.createElement('div');
    d.className = cls;
    d.innerHTML = '<span class="mark">' + mark + '</span>' +
      '<span class="body">' + esc(text) + toolHtml + '</span>';
    transcript.appendChild(d);
    transcript.scrollTop = transcript.scrollHeight;
  }

  function trSub(text, opts){
    if (!transcript) return;
    opts = opts || {};
    var aiTag = opts.ai
      ? '<span class="sc-ai-tag">AI \u00b7 ' + esc(opts.ai) + '</span>' : '';
    var bodyHtml = esc(text);
    if (opts.t) {
      bodyHtml += ' <span class="t">(' + esc(opts.t) + ')</span>';
    }
    var findings = '';
    if (opts.ai_findings && opts.ai_findings.length) {
      findings = opts.ai_findings.map(function(f){
        return '<span class="sc-ai-finding">\u2192 ' + esc(f) + '</span>';
      }).join('');
    }
    var d = document.createElement('div');
    d.className = 'tr sub';
    d.innerHTML = '<span class="mark">\u00b7</span>' +
      '<span class="body">' + bodyHtml + aiTag + findings + '</span>';
    transcript.appendChild(d);
    transcript.scrollTop = transcript.scrollHeight;
  }

  function trSummary(html){
    if (!transcript) return;
    var d = document.createElement('div');
    d.className = 'tr summary';
    d.innerHTML = '<span class="mark">\u25c6</span>' +
      '<span class="body">' + html + '</span>';
    transcript.appendChild(d);
    transcript.scrollTop = transcript.scrollHeight;
  }

  function appendTrace(role, text, kind, extra, task){
    if (!traceLog) return;
    var empty = traceLog.querySelector('.sc-trace-empty');
    if (empty) empty.remove();
    var t = new Date().toTimeString().slice(0, 8);
    var roleHtml = '';
    if (role === 'PROMPT') {
      roleHtml = '<span class="sc-role sc-prompt">PROMPT</span>';
    } else if (role === 'RESPONSE') {
      roleHtml = '<span class="sc-role sc-response ' + (kind || '') + '">RESPONSE</span>';
    } else if (role === 'TASK') {
      roleHtml = '<span class="sc-role sc-task">' + esc(task || 'task') + '</span>';
    }
    var bodyCls = 'sc-tbody ' + (role === 'PROMPT'
      ? 'sc-prompt-body' : 'sc-response-body ' + (kind || ''));
    var d = document.createElement('div');
    d.className = 'sc-trace';
    d.innerHTML =
      '<div class="sc-ts">' + t +
        (extra ? ' \u00b7 ' + esc(extra) : '') + '</div>' +
      roleHtml +
      '<div class="' + bodyCls + '">' + esc(text) + '</div>';
    traceLog.appendChild(d);
    while (traceLog.children.length > 200) {
      traceLog.removeChild(traceLog.firstChild);
    }
    traceLog.scrollTop = traceLog.scrollHeight;
  }

  function setAIPanel(state, label, sub){
    if (!aiStatusEl) return;
    aiStatusEl.className = 'sc-ai-status sc-' + state;
    if (aiLabelEl) aiLabelEl.textContent = label;
    if (aiSubEl) aiSubEl.textContent = sub || '';
  }

  var capCounts = {};
  function bumpCap(cap, isActive){
    if (!cap) return;
    capCounts[cap] = capCounts[cap] || 0;
    if (!isActive) capCounts[cap]++;
    var chips = document.querySelectorAll('[data-cap="' + cap + '"]');
    for (var i = 0; i < chips.length; i++) {
      var chip = chips[i];
      chip.classList.toggle('sc-active', !!isActive);
      if (!isActive && capCounts[cap] > 0) chip.classList.add('sc-used');
      var cn = chip.querySelector('.sc-cn');
      if (cn) cn.textContent = capCounts[cap];
    }
  }

  var brainNode = document.getElementById('brain');
  function setAIState(state, sub){
    if (!brainNode) return;
    document.body.classList.add('sc-ai-ready');
    brainNode.classList.remove('sc-online','sc-offline','sc-queried');
    if (state === 'queried') {
      brainNode.classList.add('sc-queried','sc-online');
    } else if (state === 'online') {
      brainNode.classList.add('sc-online');
    } else if (state === 'offline') {
      brainNode.classList.add('sc-offline');
    }
    if (sub !== undefined) {
      var subEl = document.querySelector('#brainContent .bc-data');
      if (subEl) subEl.textContent = sub;
    }
  }

  function flash(nodeEl, cls){
    if (!nodeEl) return;
    nodeEl.classList.remove('sc-flash-vuln','sc-flash-susp','sc-flash-pass');
    void nodeEl.offsetWidth;
    nodeEl.classList.add(cls);
    setTimeout(function(){ nodeEl.classList.remove(cls); }, 900);
  }

  function showLabel(edgeId, text, kind){
    var edgeEl = document.getElementById(edgeId);
    if (!edgeEl || typeof edgeEl.getTotalLength !== 'function') return;
    var len = edgeEl.getTotalLength();
    if (!len) return;
    var pt = edgeEl.getPointAtLength(len * 0.5);
    var svg = edgeEl.ownerSVGElement;
    if (!svg) return;
    var labelsG = svg.querySelector('#labels') || svg;
    var t = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    t.setAttribute('x', pt.x);
    t.setAttribute('y', pt.y - 8);
    t.setAttribute('class', 'sc-data-label sc-' + (kind || 'data'));
    t.textContent = text;
    labelsG.appendChild(t);
    requestAnimationFrame(function(){ t.classList.add('sc-show'); });
    setTimeout(function(){
      t.classList.remove('sc-show');
      setTimeout(function(){ if (t.parentNode) t.parentNode.removeChild(t); }, 400);
    }, 2500);
  }

  function verdictKind(v){
    var u = String(v || '').toUpperCase();
    if (u === 'VULNERABLE') return 'vuln';
    if (u === 'SUSPICIOUS') return 'susp';
    if (u === 'PASS') return 'pass';
    return 'unknown';
  }

  function fmtMs(ms){
    if (!ms && ms !== 0) return '';
    return ms < 1000 ? Math.round(ms) + 'ms' : (ms / 1000).toFixed(2) + 's';
  }

  function onEvent(ev){
    if (!ev || !ev.type) return;
    var d = ev.data || {};

    if (ev.type === 'llm_trace') {
      if (d.task) bumpCap(d.task, !!d.active);
      if (d.role) appendTrace(d.role, d.text || '', d.kind, d.extra, d.task);
      if (d.task && !d.active) {
        trSub('LLM \u00b7 ' + (d.task_label || d.task) + ' completed',
              { ai: d.task, ai_findings: d.findings || [] });
      }
      if (d.task && d.active) {
        setAIPanel('thinking', 'AI THINKING', d.task + ' \u00b7 running');
        setAIState('queried', d.task);
      } else if (d.task && !d.active) {
        setAIPanel('online', 'AI ONLINE', 'last: ' + d.task);
        setAIState('online', 'online');
      }
      return;
    }

    if (ev.type === 'chain_start') {
      trStep('chain \u00b7 ' + (d.name || d.id || '?'), d.id, 'running');
      return;
    }

    if (ev.type === 'chain_done') {
      var kind = verdictKind(d.verdict);
      var v = String(d.verdict || 'UNKNOWN').toUpperCase();
      trSummary('Chain <b>' + esc(d.id || '?') + '</b> \u2192 ' +
                '<b class="' + kind + '">' + esc(v) + '</b>');
      if (d.id) {
        showLabel('e-' + d.id, v, kind);
        var nodeEl = document.getElementById('node-' + d.id);
        if (nodeEl) flash(nodeEl, 'sc-flash-' + kind);
      }
      return;
    }

    if (ev.type === 'step_done') {
      var sKind = verdictKind(d.verdict);
      if (d.verdict && d.verdict !== 'PASS' && d.verdict !== 'UNKNOWN') {
        var toolName = d.tool || d.step || '?';
        trSub(toolName + ' \u2014 ' + String(d.verdict).toUpperCase(),
              { t: fmtMs(d.duration_ms) });
        var tNode = document.getElementById('node-' + toolName);
        if (tNode) flash(tNode, 'sc-flash-' + sKind);
      }
      return;
    }
  }

  window.scLLM = {
    onEvent: onEvent,
    trStep: trStep,
    trSub: trSub,
    trSummary: trSummary,
    appendTrace: appendTrace,
    setAIPanel: setAIPanel,
    bumpCap: bumpCap,
    setAIState: setAIState,
    flash: flash,
    showLabel: showLabel
  };

  function checkAIStatus(){
    fetch('/api/ai_status').then(function(r){ return r.json(); })
      .then(function(s){
        if (s && s.configured) {
          var prov = s.provider || 'llm';
          var mdl  = s.model || 'default';
          setAIPanel('online', 'AI ONLINE', prov + ' \u00b7 ' + mdl);
          setAIState('online', 'online \u00b7 ' + mdl);
        } else {
          setAIPanel('offline', 'AI OFFLINE', 'no LLM key configured');
          setAIState('offline', 'offline');
        }
      })
      .catch(function(){
        setAIPanel('offline', 'AI OFFLINE', 'status unavailable');
        setAIState('offline', 'offline');
      });
  }
  checkAIStatus();
  setInterval(checkAIStatus, 30000);
})();
"""


def _inject_css(html):
    if 'id="sc-llm-v1"' in html:
        return html
    block = '<style id="sc-llm-v1">' + _CSS + '</style>'
    idx = html.rfind("</head>")
    if idx == -1:
        return html
    return html[:idx] + block + html[idx:]


_AI_PANEL_HTML = (
    '<div class="sc-ai-panel">'
    '<div class="sc-panel-title">AI Brain</div>'
    '<div class="sc-ai-status sc-offline" id="scAiStatus">'
    '<span class="sc-ai-dot"></span>'
    '<div class="sc-ai-info">'
    '<div class="sc-ai-label" id="scAiLabel">Checking\u2026</div>'
    '<div class="sc-ai-sub" id="scAiSub">initializing</div>'
    '</div></div>'
    '<div class="sc-cap-chips">'
    '<span class="sc-cap-chip" data-cap="payload_author"><span class="sc-cd"></span>payload author <span class="sc-cn">0</span></span>'
    '<span class="sc-cap-chip" data-cap="bundle_analyst"><span class="sc-cd"></span>bundle analyst <span class="sc-cn">0</span></span>'
    '<span class="sc-cap-chip" data-cap="response_triage"><span class="sc-cd"></span>response triage <span class="sc-cn">0</span></span>'
    '<span class="sc-cap-chip" data-cap="chain_synth"><span class="sc-cd"></span>chain synth <span class="sc-cn">0</span></span>'
    '<span class="sc-cap-chip" data-cap="exploit_plan"><span class="sc-cd"></span>exploit plan <span class="sc-cn">0</span></span>'
    '<span class="sc-cap-chip" data-cap="narrative"><span class="sc-cd"></span>narrative <span class="sc-cn">0</span></span>'
    '</div>'
    '<div class="sc-panel-title" style="margin-top:12px">Prompt / Response Trace</div>'
    '<div class="sc-trace-log" id="scTraceLog">'
    '<div class="sc-trace-empty">No LLM activity yet\u2026</div>'
    '</div>'
    '</div>'
)


def _inject_ai_panel(html):
    if 'id="scAiStatus"' in html:
        return html
    anchors = [
        '<div class="findings-list" id="findingsList">',
        '<div class="findings-list" id="findings-body">',
        '<div class="findings-body" id="findingsBody">',
    ]
    for a in anchors:
        if a in html:
            return html.replace(a, _AI_PANEL_HTML + a, 1)
    return html


def _inject_sse_hook(html):
    if 'scLLM.onEvent' in html:
        return html
    old = "handleEvent(ev);"
    if old not in html:
        return html
    new = ("handleEvent(ev); "
           "try{ if (window.scLLM) window.scLLM.onEvent(ev); }catch(_scE){}")
    return html.replace(old, new, 1)


def _inject_js(html):
    if 'id="sc-llm-js"' in html:
        return html
    block = '<script id="sc-llm-js">' + _JS + '</script>'
    idx = html.rfind("</body>")
    if idx == -1:
        return html
    return html[:idx] + block + html[idx:]


def apply(page_html):
    if not isinstance(page_html, str):
        return page_html
    out = _inject_css(page_html)
    out = _inject_ai_panel(out)
    out = _inject_sse_hook(out)
    out = _inject_js(out)
    return out


__all__ = ["apply"]
