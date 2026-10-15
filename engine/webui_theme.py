
_THEME_CSS = r"""
body.theme-dark {
  color-scheme: dark;
  --bg: #0a0c10;
  --bg-s: #10141b;
  --bg-s2: #161b24;
  --ph: #e6edf3;
  --ph-hi: #ffffff;
  --ph-dim: #7d8998;
  --ph-dimmer: #4a5361;
  --ph-line: #232a37;
  --amber: #d29922;
  --red: #f85149;
  --green: #3fb950;
}
body.theme-light {
  color-scheme: light;
  --bg: #efefec;
  --bg-s: #ffffff;
  --bg-s2: #f6f6f3;
  --ph: #141414;
  --ph-hi: #000000;
  --ph-dim: #8b8b86;
  --ph-dimmer: #d9d9d4;
  --ph-line: #e6e6e1;
  --amber: #d98a00;
  --red: #e5484d;
  --green: #2f9e5f;
}
body.theme-dark,
body.theme-light {
  grid-template-rows: 52px 1fr auto;
  transition: background 400ms, color 400ms, grid-template-rows 320ms cubic-bezier(.2,.8,.2,1);
}
body.theme-dark .canvas-wrap {
  background:
    radial-gradient(ellipse at 45% 45%, rgba(88,166,255,0.045), transparent 60%),
    linear-gradient(0deg, transparent 0, transparent 39px, rgba(35,42,55,0.32) 39px, rgba(35,42,55,0.32) 40px),
    linear-gradient(90deg, transparent 0, transparent 39px, rgba(35,42,55,0.32) 39px, rgba(35,42,55,0.32) 40px),
    var(--bg);
  background-size: auto, 40px 40px, 40px 40px, auto;
}
body.theme-dark .canvas-wrap::before { display: none; }

.sc-icon-btn {
  appearance: none; background: transparent;
  border: 1px solid var(--ph-line);
  color: var(--ph-dim); width: 28px; height: 26px;
  border-radius: 6px; cursor: pointer; font-size: 12px;
  display: inline-flex; align-items: center; justify-content: center;
  font-family: inherit; transition: all 200ms;
}
.sc-icon-btn:hover { color: var(--ph); border-color: var(--ph-dimmer); }
.sc-icon-btn.off { opacity: 0.38; }
.sc-theme-btn {
  appearance: none; background: transparent;
  border: 1px solid var(--ph-line);
  color: var(--ph-dim); padding: 5px 10px; border-radius: 6px;
  cursor: pointer; font-family: inherit; font-size: 10px;
  letter-spacing: 0.4px; transition: all 200ms;
}
.sc-theme-btn:hover { color: var(--ph); border-color: var(--ph-dimmer); }

.sc-dock {
  display: flex; flex-direction: column; min-height: 0;
  background: var(--bg-s);
  border-top: 1px solid var(--ph-line);
  max-height: 42vh;
}
.sc-dock-head {
  display: flex; align-items: center; gap: 6px;
  padding: 0 12px; height: 34px; flex-shrink: 0;
  background: var(--bg-s2);
  border-bottom: 1px solid var(--ph-line);
}
.sc-dock.sc-collapsed .sc-dock-head { border-bottom-color: transparent; }
.sc-dock.sc-collapsed .sc-dock-panes { height: 0; }
.sc-dock-panes {
  position: relative; min-height: 0;
  height: clamp(120px, 24vh, 260px);
  transition: height 320ms cubic-bezier(.2,.8,.2,1);
  overflow: hidden;
}
.sc-pane { position: absolute; inset: 0; display: none; }
.sc-pane.on { display: block; }
.sc-tab {
  appearance: none; background: transparent; border: 1px solid transparent;
  color: var(--ph-dim); padding: 4px 12px; border-radius: 6px;
  font-family: var(--mono); font-size: 10px; font-weight: 700;
  letter-spacing: 1px; cursor: pointer; transition: all 200ms;
}
.sc-tab:hover { color: var(--ph); }
.sc-tab.on {
  color: var(--ph-hi); background: var(--bg);
  border-color: var(--ph-line);
}
.sc-dock-spacer { flex: 1; }
.sc-find-badge {
  font-family: var(--mono); font-size: 10px;
  padding: 3px 10px; border-radius: 10px;
  background: var(--bg); border: 1px solid var(--ph-line);
  color: var(--ph-dim);
}
.sc-find-badge.has {
  background: var(--red); color: #fff; border-color: var(--red);
}
.sc-chev {
  appearance: none; background: transparent;
  border: 1px solid var(--ph-line);
  color: var(--ph-dim); width: 26px; height: 24px;
  border-radius: 6px; cursor: pointer; font-size: 10px;
  transition: transform 260ms;
}
.sc-chev:hover { color: var(--ph); border-color: var(--ph-dimmer); }
.sc-dock.sc-collapsed .sc-chev { transform: rotate(180deg); }

body.theme-dark .log-ribbon,
body.theme-light .log-ribbon {
  border-top: none;
  background: transparent;
  padding: 6px 14px;
  height: 100%;
  max-height: none;
  overflow-y: auto;
}

.sc-transcript-mirror {
  height: 100%; overflow-y: auto;
  padding: 8px 16px 10px;
  font-family: var(--mono); font-size: 11.5px; line-height: 1.6;
  color: var(--ph);
}
.sc-transcript-mirror::-webkit-scrollbar,
.sc-dock .log-ribbon::-webkit-scrollbar { width: 7px; }
.sc-transcript-mirror::-webkit-scrollbar-thumb,
.sc-dock .log-ribbon::-webkit-scrollbar-thumb {
  background: var(--ph-line); border-radius: 4px;
}
.sc-transcript-mirror .findings-empty,
.sc-transcript-mirror .findings-body { color: var(--ph-dim); }
.sc-transcript-mirror table { width: 100%; border-collapse: collapse; }
.sc-transcript-mirror th,
.sc-transcript-mirror td {
  padding: 6px 8px; font-size: 11px;
  border-bottom: 1px solid var(--ph-line);
  text-align: left; vertical-align: top;
}
.sc-transcript-mirror th { color: var(--ph-dim); font-weight: 600; }
.sc-transcript-mirror .fcard,
.sc-transcript-mirror .finding {
  padding: 8px 10px; margin: 6px 0;
  border-left: 3px solid var(--ph-line);
  background: var(--bg-s2); border-radius: 6px;
}
.sc-transcript-mirror .fcard.vuln,
.sc-transcript-mirror .finding.vuln { border-left-color: var(--red); }
.sc-transcript-mirror .fcard.susp,
.sc-transcript-mirror .finding.susp { border-left-color: var(--amber); }
.sc-transcript-mirror .badge {
  display: inline-block; padding: 2px 8px; border-radius: 10px;
  font-size: 10px; font-weight: 700; letter-spacing: 0.5px;
  text-transform: uppercase;
}
.sc-transcript-mirror .badge.VULNERABLE { background: var(--red); color: #fff; }
.sc-transcript-mirror .badge.SUSPICIOUS { background: var(--amber); color: #fff; }
.sc-transcript-mirror .badge.PASS { background: var(--green); color: #001b0c; }
.sc-transcript-mirror .badge.UNKNOWN {
  background: var(--ph-line); color: var(--ph-dim);
}
.sc-transcript-mirror .sev-critical,
.sc-transcript-mirror .sev-high { color: var(--red); font-weight: 600; }
.sc-transcript-mirror .sev-medium { color: var(--amber); font-weight: 600; }
.sc-transcript-mirror .sev-low,
.sc-transcript-mirror .sev-info { color: var(--ph-dim); }
"""

_THEME_JS = r"""
(function(){
  'use strict';

  var tb = document.getElementById('scThemeBtn');
  function setTheme(t){
    document.body.classList.remove('theme-dark','theme-light');
    document.body.classList.add('theme-' + t);
    if (tb) tb.textContent = t === 'dark' ? '\u25d0 LIGHT' : '\u25d1 DARK';
    try { localStorage.setItem('sc-theme', t); } catch(e){}
  }
  if (tb) {
    try {
      var saved = localStorage.getItem('sc-theme');
      if (saved === 'light' || saved === 'dark') setTheme(saved);
    } catch(e){}
    tb.addEventListener('click', function(){
      setTheme(document.body.classList.contains('theme-dark') ? 'light' : 'dark');
    });
  }

  var dock = document.getElementById('scDock');
  var dchev = document.getElementById('scDockChev');
  var dtoggle = document.getElementById('scDockBtn');
  function toggleDock(){
    if (!dock) return;
    dock.classList.toggle('sc-collapsed');
    if (dtoggle) dtoggle.classList.toggle('off', dock.classList.contains('sc-collapsed'));
  }
  if (dchev) dchev.addEventListener('click', toggleDock);
  if (dtoggle) dtoggle.addEventListener('click', toggleDock);

  var sb = document.getElementById('scSideBtn');
  if (sb) {
    sb.addEventListener('click', function(){
      var p = document.querySelector('.panel') || document.querySelector('.side');
      if (!p) return;
      var hidden = p.style.display === 'none';
      p.style.display = hidden ? '' : 'none';
      sb.classList.toggle('off', !hidden);
    });
  }

  document.addEventListener('keydown', function(e){
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    if (e.target && /input|textarea|select/i.test(e.target.tagName)) return;
    var k = e.key.toLowerCase();
    if (k === 'd') toggleDock();
    else if (k === 's' && sb) sb.click();
  });

  document.querySelectorAll('.sc-tab').forEach(function(tab){
    tab.addEventListener('click', function(){
      var name = tab.getAttribute('data-tab');
      document.querySelectorAll('.sc-tab').forEach(function(t){
        t.classList.toggle('on', t === tab);
      });
      document.querySelectorAll('.sc-pane').forEach(function(p){
        p.classList.toggle('on', p.getAttribute('data-pane') === name);
      });
      if (dock && dock.classList.contains('sc-collapsed')) toggleDock();
    });
  });

  var srcFind = document.getElementById('findingsBody')
             || document.getElementById('findings-body')
             || document.getElementById('findingsList');
  var dstFind = document.getElementById('scFindingsMirror');
  var badge = document.getElementById('scFindBadge');
  function countFindings(){
    if (!srcFind) return 0;
    var trs = srcFind.querySelectorAll('tr');
    var cards = srcFind.querySelectorAll('.fcard, .finding');
    var n = Math.max(trs.length, cards.length);
    if (n === 1 && srcFind.querySelector('td[colspan], .findings-empty')) n = 0;
    return n;
  }
  function mirrorFindings(){
    if (srcFind && dstFind) dstFind.innerHTML = srcFind.innerHTML;
    if (badge) {
      var n = countFindings();
      badge.textContent = 'findings ' + n;
      badge.classList.toggle('has', n > 0);
    }
  }
  if (srcFind) {
    try {
      new MutationObserver(mirrorFindings).observe(
        srcFind, {childList:true, subtree:true, characterData:true});
    } catch(e){}
    mirrorFindings();
  }

  var srcTrans = document.getElementById('transcript');
  var dstTrans = document.getElementById('scNarratorMirror');
  function mirrorTranscript(){
    if (srcTrans && dstTrans) dstTrans.innerHTML = srcTrans.innerHTML;
  }
  if (srcTrans) {
    try {
      new MutationObserver(mirrorTranscript).observe(
        srcTrans, {childList:true, subtree:true, characterData:true});
    } catch(e){}
    mirrorTranscript();
  }
})();
"""

_HEADER_BUTTONS = (
    '<button class="sc-icon-btn" id="scDockBtn" title="Toggle bottom panel (D)">\u25a4</button>'
    '<button class="sc-icon-btn" id="scSideBtn" title="Toggle sidebar (S)">\u25e7</button>'
    '<button class="sc-theme-btn" id="scThemeBtn">\u25d0 LIGHT</button>'
)

_DOCK_HTML = (
    '<section class="sc-dock" id="scDock">'
    '<div class="sc-dock-head">'
    '<button class="sc-tab" data-tab="narrator" type="button">NARRATOR</button>'
    '<button class="sc-tab on" data-tab="console" type="button">CONSOLE</button>'
    '<button class="sc-tab" data-tab="findings" type="button">FINDINGS</button>'
    '<span class="sc-dock-spacer"></span>'
    '<span class="sc-find-badge" id="scFindBadge">findings 0</span>'
    '<button class="sc-chev" id="scDockChev" type="button">\u25be</button>'
    '</div>'
    '<div class="sc-dock-panes">'
    '<div class="sc-pane" data-pane="narrator">'
    '<div class="sc-transcript-mirror" id="scNarratorMirror"></div>'
    '</div>'
    '<div class="sc-pane on" data-pane="console">'
    '<div class="log-ribbon" id="logRibbon"></div>'
    '</div>'
    '<div class="sc-pane" data-pane="findings">'
    '<div class="sc-transcript-mirror" id="scFindingsMirror"></div>'
    '</div>'
    '</div>'
    '</section>'
)


def _inject_body_class(html):
    if '<body class="theme-dark">' in html:
        return html
    if "<body>" in html:
        return html.replace("<body>", '<body class="theme-dark">', 1)
    return html


def _inject_css(html):
    if 'id="sc-theme-v1"' in html:
        return html
    block = '<style id="sc-theme-v1">' + _THEME_CSS + '</style>'
    idx = html.rfind("</head>")
    if idx == -1:
        return html
    return html[:idx] + block + html[idx:]


def _inject_header_buttons(html):
    if 'id="scThemeBtn"' in html:
        return html
    anchor = '<button class="btn" id="resetBtn">'
    if anchor not in html:
        return html
    return html.replace(anchor, _HEADER_BUTTONS + anchor, 1)


def _inject_dock(html):
    if 'id="scDock"' in html:
        return html
    old = '<div class="log-ribbon" id="logRibbon"></div>'
    if old not in html:
        return html
    return html.replace(old, _DOCK_HTML, 1)


def _inject_js(html):
    if 'id="sc-theme-js"' in html:
        return html
    block = '<script id="sc-theme-js">' + _THEME_JS + '</script>'
    idx = html.rfind("</body>")
    if idx == -1:
        return html
    return html[:idx] + block + html[idx:]


def apply(page_html):
    if not isinstance(page_html, str):
        return page_html
    out = _inject_body_class(page_html)
    out = _inject_css(out)
    out = _inject_header_buttons(out)
    out = _inject_dock(out)
    out = _inject_js(out)
    return out


__all__ = ["apply"]
