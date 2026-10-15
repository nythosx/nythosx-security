
_CSS = r"""
.brain-canvas .conn-line {
  transition: stroke 400ms, stroke-width 400ms, opacity 400ms, filter 400ms;
}
.brain-canvas.running .conn-line.active {
  stroke-dasharray: 9 7;
  animation: scDashFlow 0.55s linear infinite;
  stroke-width: 2.2;
  filter: drop-shadow(0 0 6px rgba(88,166,255,0.55));
}
@keyframes scDashFlow { to { stroke-dashoffset: -16; } }
.brain-canvas .conn-line.done-vuln {
  stroke: var(--red); stroke-width: 2.2;
  filter: drop-shadow(0 0 8px rgba(248,81,73,0.45));
}
.brain-canvas .conn-line.done-susp {
  stroke: var(--amber); stroke-width: 2;
  filter: drop-shadow(0 0 7px rgba(210,153,34,0.4));
}
.brain-canvas .conn-line.done-pass {
  stroke: var(--green); stroke-width: 1.6;
  filter: drop-shadow(0 0 5px rgba(63,185,80,0.35));
}

.brain-canvas.running .tool-node.active .tool-card {
  animation: scNodePulse 1.1s ease-in-out infinite;
  filter: drop-shadow(0 0 20px rgba(88,166,255,0.7));
}
@keyframes scNodePulse {
  0%,100% { stroke-width: 2.2; stroke-opacity: 1; }
  50%     { stroke-width: 2.8; stroke-opacity: 0.55; }
}
.brain-canvas.running .tool-node.active .tool-status {
  animation: scStatusPulse 0.85s ease-in-out infinite;
}
@keyframes scStatusPulse { 0%,100%{opacity:1} 50%{opacity:0.25} }

.brain-canvas.running .brain-ring {
  animation-duration: 11s;
  opacity: 1;
}
.brain-canvas.running .brain-ring.inner {
  animation-duration: 17s;
  opacity: 0.8;
}
.brain-canvas.sc-ai-queried .brain-ring {
  stroke: var(--ph); opacity: 1;
  animation-duration: 1.4s;
}
.brain-canvas.sc-ai-queried .brain-ring.inner {
  animation-duration: 0.95s;
  opacity: 0.9;
}
.brain-canvas.sc-ai-queried .brain-halo {
  fill: rgba(88,166,255,0.07);
}
.brain-canvas.running .brain-core {
  animation: scCorePulse 2.6s ease-out infinite;
}
.brain-canvas.sc-ai-queried .brain-core {
  animation: scCorePulse 0.9s ease-out infinite;
}
@keyframes scCorePulse {
  0%   { filter: drop-shadow(0 0 0 rgba(88,166,255,0)); }
  50%  { filter: drop-shadow(0 0 26px rgba(88,166,255,0.85)); }
  100% { filter: drop-shadow(0 0 0 rgba(88,166,255,0)); }
}

.brain-canvas .brain-pulse {
  fill: none; stroke: var(--ph-dim); stroke-width: 1;
  opacity: 0; transform-origin: 400px 460px;
}
.brain-canvas.running .brain-pulse {
  animation: scBrainPulse 3s ease-out infinite;
}
.brain-canvas.running .brain-pulse.d1 { animation-delay: 1s; }
.brain-canvas.running .brain-pulse.d2 { animation-delay: 2s; }
.brain-canvas.sc-ai-queried .brain-pulse {
  animation-duration: 1.1s;
}
@keyframes scBrainPulse {
  0%   { r: 80;  opacity: 0.55; stroke-width: 1.4; }
  100% { r: 260; opacity: 0;    stroke-width: 0.3; }
}

.brain-canvas .packet {
  filter: drop-shadow(0 0 6px currentColor);
}

.canvas-wrap,
.chart-wrap {
  background:
    radial-gradient(ellipse at 50% 50%, rgba(88,166,255,0.05), transparent 60%),
    repeating-linear-gradient(0deg, transparent 0, transparent 39px,
      rgba(35,42,55,0.32) 39px, rgba(35,42,55,0.32) 40px),
    repeating-linear-gradient(90deg, transparent 0, transparent 39px,
      rgba(35,42,55,0.32) 39px, rgba(35,42,55,0.32) 40px),
    var(--bg) !important;
  background-size: auto, 40px 40px, 40px 40px, auto !important;
}
body.theme-light .canvas-wrap,
body.theme-light .chart-wrap {
  background:
    radial-gradient(ellipse at 50% 50%, rgba(217,138,0,0.05), transparent 60%),
    repeating-linear-gradient(0deg, transparent 0, transparent 39px,
      rgba(214,214,209,0.55) 39px, rgba(214,214,209,0.55) 40px),
    repeating-linear-gradient(90deg, transparent 0, transparent 39px,
      rgba(214,214,209,0.55) 39px, rgba(214,214,209,0.55) 40px),
    var(--bg) !important;
  background-size: auto, 40px 40px, 40px 40px, auto !important;
}
.canvas-wrap::before,
.chart-wrap::before {
  display: none !important;
}

.brain-canvas.sc-ai-queried #brain-to-site .link-line,
.brain-canvas.sc-ai-queried #brain-to-site .link-core {
  stroke: var(--ph-hi);
  animation: scLinkDash 0.35s linear infinite;
}
@keyframes scLinkDash { to { stroke-dashoffset: -12; } }
"""


_JS = r"""
(function(){
  'use strict';

  function injectPulseRings(){
    var brain = document.getElementById('brain');
    if (!brain) return;
    if (brain.querySelector('.brain-pulse')) return;
    var cx = 400, cy = 460;
    var d = ['', 'd1', 'd2'];
    for (var i = 0; i < d.length; i++) {
      var c = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      c.setAttribute('cx', cx);
      c.setAttribute('cy', cy);
      c.setAttribute('r', 80);
      c.setAttribute('class', 'brain-pulse ' + d[i]);
      brain.insertBefore(c, brain.firstChild);
    }
  }

  function queryBurst(ms){
    var canvas = document.querySelector('.brain-canvas');
    if (!canvas) return;
    canvas.classList.add('sc-ai-queried');
    if (queryBurst._t) clearTimeout(queryBurst._t);
    queryBurst._t = setTimeout(function(){
      canvas.classList.remove('sc-ai-queried');
    }, ms || 2200);
  }

  function wrapPacket(){
    if (window.__scPacketWrapped) return;
    window.__scPacketWrapped = true;
    var orig = window.firePacket;
    if (typeof orig !== 'function') return;
    window.firePacket = function(edgeId, cls, dur){
      orig.apply(this, arguments);
      var canvas = document.querySelector('.brain-canvas');
      if (!canvas) return;
      var path = document.getElementById(edgeId);
      if (!path || typeof path.getTotalLength !== 'function') return;
      var len = path.getTotalLength();
      if (!len) return;
      var trail = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      trail.setAttribute('r', 2.5);
      trail.setAttribute('class', 'packet trail ' + (cls || ''));
      trail.setAttribute('opacity', '0.35');
      var m = document.createElementNS('http://www.w3.org/2000/svg', 'animateMotion');
      m.setAttribute('dur', ((dur || 700) * 1.2) + 'ms');
      m.setAttribute('fill', 'freeze');
      m.setAttribute('path', path.getAttribute('d') || '');
      trail.appendChild(m);
      var packetsG = canvas.querySelector('#packets');
      (packetsG || canvas).appendChild(trail);
      setTimeout(function(){ if (trail.parentNode) trail.parentNode.removeChild(trail); },
                 ((dur || 700) * 1.2) + 200);
    };
  }

  function hookLLM(){
    if (!window.scLLM) return;
    var orig = window.scLLM.onEvent;
    if (orig && !orig.__scWrapped) {
      var wrapped = function(ev){
        var r = orig.apply(this, arguments);
        try {
          if (ev && ev.type === 'llm_trace' && ev.data && ev.data.active) {
            queryBurst(2000);
          }
        } catch(e){}
        return r;
      };
      wrapped.__scWrapped = true;
      window.scLLM.onEvent = wrapped;
    }
    var origSetAI = window.scLLM.setAIState;
    if (origSetAI && !origSetAI.__scWrapped) {
      var wrappedAI = function(state){
        var r = origSetAI.apply(this, arguments);
        try {
          if (state === 'queried') queryBurst(1800);
        } catch(e){}
        return r;
      };
      wrappedAI.__scWrapped = true;
      window.scLLM.setAIState = wrappedAI;
    }
  }

  function hookBase(){
    if (window.__scBaseHooked) return;
    window.__scBaseHooked = true;
    if (typeof window.setAIState === 'function' && !window.setAIState.__scWrapped) {
      var orig = window.setAIState;
      window.setAIState = function(state){
        var r = orig.apply(this, arguments);
        try {
          if (state === 'queried') queryBurst(1800);
        } catch(e){}
        return r;
      };
      window.setAIState.__scWrapped = true;
    }
  }

  function ready(){
    injectPulseRings();
    wrapPacket();
    hookLLM();
    hookBase();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', ready);
  } else {
    ready();
  }

  var iv = setInterval(function(){
    injectPulseRings();
    wrapPacket();
    hookLLM();
    hookBase();
  }, 400);
  setTimeout(function(){ clearInterval(iv); }, 4000);

  window.scChart = { queryBurst: queryBurst, injectPulseRings: injectPulseRings };
})();
"""


def _inject_css(html):
    if 'id="sc-chart-v1"' in html:
        return html
    block = '<style id="sc-chart-v1">' + _CSS + '</style>'
    idx = html.rfind("</head>")
    if idx == -1:
        return html
    return html[:idx] + block + html[idx:]


def _inject_js(html):
    if 'id="sc-chart-js"' in html:
        return html
    block = '<script id="sc-chart-js">' + _JS + '</script>'
    idx = html.rfind("</body>")
    if idx == -1:
        return html
    return html[:idx] + block + html[idx:]


def apply(page_html):
    if not isinstance(page_html, str):
        return page_html
    out = _inject_css(page_html)
    out = _inject_js(out)
    return out


__all__ = ["apply"]
