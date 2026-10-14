import json
from pathlib import Path
from datetime import datetime, timezone
from jinja2 import Environment, select_autoescape
from . import ledger
from .util import safe_name

try:
    from . import writeup_library
except Exception:
    writeup_library = None
try:
    from . import coverage as coverage_mod
except Exception:
    coverage_mod = None
try:
    from .correlator import resolver as chain_resolver
    from .correlator import narrative as chain_narrative
except Exception:
    chain_resolver = None
    chain_narrative = None

ROOT = Path(__file__).parent.parent.absolute()
REPORTS_DIR = ROOT / "reports"
_HTML_ENV = Environment(autoescape=select_autoescape(["html", "xml"]),
                        auto_reload=False)
_MD_ENV = Environment(autoescape=False, auto_reload=False)

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Report - {{ target }}</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; background: #0d1117; color: #c9d1d9; }
.container { max-width: 1200px; margin: 0 auto; padding: 40px 20px; }
h1 { color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 12px; }
h2 { color: #79c0ff; margin-top: 40px; }
.meta { color: #8b949e; font-size: 14px; margin-bottom: 24px; }
.summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; margin: 24px 0; }
.card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; text-align: center; }
.card .count { font-size: 32px; font-weight: bold; }
.card .label { color: #8b949e; font-size: 12px; text-transform: uppercase; margin-top: 4px; }
.critical .count { color: #f85149; }
.high .count { color: #ff7b72; }
.medium .count { color: #d29922; }
.low .count { color: #58a6ff; }
.info .count { color: #8b949e; }
table { width: 100%; border-collapse: collapse; margin-top: 16px; }
th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid #30363d; font-size: 14px; }
th { background: #161b22; color: #79c0ff; }
tr:hover { background: #161b22; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; text-transform: uppercase; }
.badge.VULNERABLE { background: #f85149; color: #fff; }
.badge.SUSPICIOUS { background: #d29922; color: #fff; }
.badge.PASS { background: #238636; color: #fff; }
.badge.UNKNOWN { background: #30363d; color: #8b949e; }
.sev-critical { color: #f85149; font-weight: 600; }
.sev-high { color: #ff7b72; font-weight: 600; }
.sev-medium { color: #d29922; font-weight: 600; }
.sev-low { color: #58a6ff; font-weight: 600; }
.sev-info { color: #8b949e; }
.footer { margin-top: 60px; padding-top: 20px; border-top: 1px solid #30363d; color: #8b949e; font-size: 12px; text-align: center; }
.chain { background: #161b22; border: 1px solid #30363d; border-left: 4px solid #d29922; border-radius: 8px; padding: 16px; margin: 12px 0; }
.chain.CONFIRMED { border-left-color: #f85149; }
.chain.LIKELY { border-left-color: #ff7b72; }
.chain.THEORETICAL { border-left-color: #d29922; }
.chain h3 { margin: 0 0 6px; color: #f0f6fc; font-size: 16px; }
.chain .cverdict { font-size: 11px; font-weight: 700; text-transform: uppercase; padding: 2px 8px; border-radius: 12px; background: #30363d; color: #c9d1d9; }
.chain pre { white-space: pre-wrap; color: #8b949e; font-size: 13px; margin: 8px 0 0; }
.chain-graph { margin: 16px 0 24px; overflow-x: auto; }
.why { background: #0d1117; border: 1px dashed #30363d; border-radius: 6px; padding: 10px 14px; margin: 6px 0; font-size: 13px; }
.why b { color: #79c0ff; }
.why .part { margin: 4px 0; }
details.why-wrap summary { cursor: pointer; color: #58a6ff; font-size: 12px; }
.cov-bar { background: #30363d; border-radius: 6px; height: 10px; overflow: hidden; min-width: 80px; }
.cov-bar > span { display: block; height: 100%; background: #238636; }
.datarow-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; margin: 10px 0; padding: 12px 14px; }
.datarow-card .hd { color: #79c0ff; font-family: ui-monospace, monospace; font-size: 12px; margin-bottom: 8px; }
.datarow-card .hd .badge2 { display: inline-block; padding: 1px 8px; border-radius: 10px; font-size: 10px; margin-left: 8px; font-weight: 600; text-transform: uppercase; }
.datarow-card .hd .badge2.auth { background: #1f6feb; color: #fff; }
.datarow-card .hd .badge2.unauth { background: #f85149; color: #fff; }
.datarow-table { width: 100%; border-collapse: collapse; margin-top: 6px; }
.datarow-table td { padding: 5px 10px; font-family: ui-monospace, monospace; font-size: 12px; border-bottom: 1px solid #21262d; vertical-align: top; }
.datarow-table td.k { color: #8b949e; width: 32%; }
.datarow-table td.v { color: #c9d1d9; word-break: break-all; }
.datarow-empty { color: #8b949e; font-size: 12px; }
</style>
</head>
<body>
<div class="container">
<h1>Security Assessment Report</h1>
<div class="meta">
<strong>Target:</strong> {{ target }}<br>
<strong>Generated:</strong> {{ timestamp }}<br>
<strong>Total Findings:</strong> {{ findings|length }}
</div>
<h2>Executive Summary</h2>
<div class="summary">
<div class="card critical"><div class="count">{{ counts.critical }}</div><div class="label">Critical</div></div>
<div class="card high"><div class="count">{{ counts.high }}</div><div class="label">High</div></div>
<div class="card medium"><div class="count">{{ counts.medium }}</div><div class="label">Medium</div></div>
<div class="card low"><div class="count">{{ counts.low }}</div><div class="label">Low</div></div>
<div class="card info"><div class="count">{{ counts.info }}</div><div class="label">Info</div></div>
</div>
{% if iteration_history %}
<h2>Iteration History</h2>
<table>
<thead><tr><th>Sweep</th><th>Category</th><th>Hypotheses</th><th>Executed</th></tr></thead>
<tbody>
{% for it in iteration_history %}
<tr><td>{{ it.sweep }}</td><td>{{ it.category or '-' }}</td><td>{{ it.hypotheses or 0 }}</td><td>{{ it.executed or 0 }}</td></tr>
{% endfor %}
</tbody>
</table>
{% endif %}
{% if cves %}
<h2>Known Vulnerabilities</h2>
<p class="meta">CVEs affecting the detected component versions.</p>
<table>
<thead>
<tr><th>ID</th><th>Severity</th><th>Component</th><th>Summary</th></tr>
</thead>
<tbody>
{% for c in cves %}
<tr>
<td><a href="https://nvd.nist.gov/vuln/detail/{{ c.id }}" target="_blank">{{ c.id }}</a></td>
<td class="sev-{{ c.severity }}">{{ c.severity }}</td>
<td>{{ c.product }} {{ c.version }}</td>
<td>{{ c.summary }}</td>
</tr>
{% endfor %}
</tbody>
</table>
{% endif %}
{% if chains %}
<h2>Attack Chains</h2>
<p class="meta">Correlated multi-step attacks built from individual findings.</p>
{% if graph_svg %}<div class="chain-graph">{{ graph_svg|safe }}</div>{% endif %}
{% for c in chains %}
<div class="chain {{ c.verdict }}">
<h3>{{ c.name }} <span class="cverdict">{{ c.verdict }}</span></h3>
<div class="meta">Severity: {{ c.severity }} &middot; Confidence: {{ '%.0f'|format((c.confidence or 0) * 100) }}% &middot; Prerequisites met: {{ c.matched|length }}/{{ c.prerequisites|length }}</div>
{% if c.narrative_text %}<pre>{{ c.narrative_text }}</pre>{% endif %}
</div>
{% endfor %}
{% endif %}
<h2>Findings</h2>
<table>
<thead>
<tr><th>ID</th><th>Pattern</th><th>Severity</th><th>Triage</th><th>Verdict</th><th>Confirm</th><th>Reason</th><th>WSTG</th><th>CWE</th></tr>
</thead>
<tbody>
{% for f in findings %}
<tr>
<td>{{ f.id }}</td>
<td>{{ f.pattern_id }}</td>
<td class="sev-{{ f.severity }}">{{ f.severity }}</td>
<td>{% if f.triage_category %}{{ f.triage_category }}{% if f.triage_by_design %} <span title="{{ f.triage_note }}">(by-design)</span>{% endif %}{% else %}-{% endif %}</td>
<td><span class="badge {{ f.verdict }}">{{ f.verdict }}</span></td>
<td>{{ f.confirmation_status or '-' }}</td>
<td>{{ f.reason }}
{% if f.why and f.verdict in ['VULNERABLE', 'SUSPICIOUS'] %}
<details class="why-wrap"><summary>Why this matters</summary>
<div class="why">
{% if f.why.attack %}<div class="part"><b>Attack:</b> {{ f.why.attack }}</div>{% endif %}
{% if f.why.gap %}<div class="part"><b>Gap:</b> {{ f.why.gap }}</div>{% endif %}
{% if f.why.impact %}<div class="part"><b>Impact:</b> {{ f.why.impact }}</div>{% endif %}
{% if f.why.fix %}<div class="part"><b>Fix:</b> {{ f.why.fix }}</div>{% endif %}
</div></details>
{% endif %}
</td>
<td>{{ f.wstg_id or '-' }}</td>
<td>{{ f.cwe_id or '-' }}</td>
</tr>
{% endfor %}
</tbody>
</table>
{% if data_rows %}
<h2>Extracted Data Rows</h2>
<p class="meta">Masked data rows recovered from the target. First character of each sensitive value is preserved; the remainder is rotated.</p>
{% if data_svg %}<div class="chain-graph">{{ data_svg|safe }}</div>{% endif %}
{% for dr in data_rows %}
<div class="datarow-card">
<div class="hd">{{ dr.endpoint }}
<span class="badge2 {{ 'unauth' if 'unauth' in (dr.auth_used or '')|lower else 'auth' }}">{{ dr.auth_used or 'unknown' }}</span>
<span class="datarow-empty"> &middot; {{ dr.extracted }} of {{ dr.total_rows }} row(s)</span>
</div>
{% for row in dr.rows %}
<table class="datarow-table">
{% for k, v in row.items() %}
<tr><td class="k">{{ k }}</td><td class="v">{{ v }}</td></tr>
{% endfor %}
</table>
{% endfor %}
</div>
{% endfor %}
{% endif %}
{% if coverage %}
<h2>Coverage</h2>
<p class="meta">What was tested, and what was not. {{ coverage.executed_count }} of {{ coverage.total_count }} capabilities executed.</p>
<table>
<thead><tr><th>OWASP 2025</th><th>Coverage</th><th>Executed / Total</th></tr></thead>
<tbody>
{% for code, c in coverage.owasp.items() %}
<tr>
<td>{{ code }}</td>
<td><div class="cov-bar"><span style="width: {{ c.coverage_pct }}%"></span></div></td>
<td>{{ c.covered }} / {{ c.total }}</td>
</tr>
{% endfor %}
</tbody>
</table>
{% if coverage.untested_categories %}
<p class="meta"><strong>Untested OWASP categories:</strong> {{ coverage.untested_categories|join(', ') }}</p>
{% endif %}
{% endif %}
<div class="footer">Generated by sec-checker MVP</div>
</div>
</body>
</html>
"""

MD_TEMPLATE = """# Security Assessment Report

**Target:** {{ target }}
**Generated:** {{ timestamp }}
**Total Findings:** {{ findings|length }}

## Executive Summary

| Severity | Count |
|----------|-------|
| Critical | {{ counts.critical }} |
| High     | {{ counts.high }} |
| Medium   | {{ counts.medium }} |
| Low      | {{ counts.low }} |
| Info     | {{ counts.info }} |
{% if cves %}
## Known Vulnerabilities

| CVE | Severity | Component | Summary |
|-----|----------|-----------|---------|
{% for c in cves -%}
| {{ c.id }} | {{ c.severity }} | {{ c.product }} {{ c.version }} | {{ c.summary }} |
{% endfor %}

{% endif %}
{% if chains %}
## Attack Chains

{% for c in chains -%}
### {{ c.name }} — {{ c.verdict }}

Severity: {{ c.severity }} · Confidence: {{ '%.0f'|format((c.confidence or 0) * 100) }}% · Prerequisites met: {{ c.matched|length }}/{{ c.prerequisites|length }}

{% if c.narrative_text %}```
{{ c.narrative_text }}
{% endif %}
{% endfor %}
{% endif %}
{% if iteration_history %}
## Iteration History

| Sweep | Category | Hypotheses | Executed |
|-------|----------|-----------|----------|
{% for it in iteration_history -%}
| {{ it.sweep }} | {{ it.category or '-' }} | {{ it.hypotheses or 0 }} | {{ it.executed or 0 }} |
{% endfor %}

{% endif %}
## Findings

| ID | Pattern | Severity | Verdict | Confirm | Reason | WSTG | CWE |
|----|---------|----------|---------|---------|--------|------|-----|
{% for f in findings -%}
| {{ f.id }} | {{ f.pattern_id }} | {{ f.severity }} | {{ f.verdict }} | {{ f.confirmation_status or '-' }} | {{ f.reason }} | {{ f.wstg_id or '-' }} | {{ f.cwe_id or '-' }} |
{% endfor %}
{% set whys = findings | selectattr('why', 'defined') | selectattr('verdict', 'in', ['VULNERABLE', 'SUSPICIOUS']) | list %}
{% if whys %}
## Why This Matters

{% for f in whys -%}
### {{ f.pattern_id }}
{% if f.why.attack %}- **Attack:** {{ f.why.attack }}{% endif %}
{% if f.why.gap %}- **Gap:** {{ f.why.gap }}{% endif %}
{% if f.why.impact %}- **Impact:** {{ f.why.impact }}{% endif %}
{% if f.why.fix %}- **Fix:** {{ f.why.fix }}{% endif %}

{% endfor %}
{% endif %}
{% if data_rows %}
## Extracted Data Rows

Masked data rows recovered from the target. First character of each sensitive value is preserved; the remainder is rotated.

{% for dr in data_rows -%}
### `{{ dr.endpoint }}` — {{ dr.auth_used or 'unknown' }} ({{ dr.extracted }}/{{ dr.total_rows }})

{% for row in dr.rows -%}
| field | value |
|-------|-------|
{% for k, v in row.items() -%}
| `{{ k }}` | `{{ v }}` |
{% endfor %}

{% endfor %}
{% endfor %}
{% endif %}
{% if coverage %}
## Coverage

{{ coverage.executed_count }} of {{ coverage.total_count }} capabilities executed.

| OWASP 2025 | Coverage | Executed / Total |
|------------|----------|------------------|
{% for code, c in coverage.owasp.items() -%}
| {{ code }} | {{ c.coverage_pct }}% | {{ c.covered }} / {{ c.total }} |
{% endfor %}
{% if coverage.untested_categories %}
**Untested OWASP categories:** {{ coverage.untested_categories|join(', ') }}
{% endif %}
{% endif %}
"""


def _counts(findings):
    c = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        if f.get("verdict") != "VULNERABLE":
            continue
        sev = f.get("severity", "info")
        if sev in c:
            c[sev] += 1
    return c


def _findings_to_dicts(rows):
    keys = ["id", "timestamp", "pattern_id", "category", "verdict", "severity",
            "reason", "wstg_id", "cwe_id", "evidence_path", "duration_ms",
            "evidence_json"]
    return [dict(zip(keys, r)) for r in rows]


def _parse_evidence_json(raw):
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            import json as _json
            return _json.loads(raw) or {}
        except Exception:
            return {}
    return {}


def _extract_cves(findings):
    out = []
    seen = set()
    for f in findings:
        pid = (f.get("pattern_id") or "").lower()
        if "cve" not in pid and "chain-cve" not in pid:
            continue
        ev = _parse_evidence_json(f.get("evidence_json"))
        for c in (ev.get("cves") or []):
            if not isinstance(c, dict):
                continue
            cid = c.get("id")
            if not cid or cid in seen:
                continue
            seen.add(cid)
            out.append({
                "id": cid,
                "severity": (c.get("severity") or "medium").lower(),
                "summary": (c.get("summary") or "")[:280],
                "product": c.get("product") or ev.get("product") or "",
                "version": c.get("version") or ev.get("version") or "",
            })
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    out.sort(key=lambda c: -order.get(c["severity"], 0))
    return out


def _dedupe(findings):
    seen = set()
    out = []
    for f in findings:
        key = (f.get("pattern_id"), f.get("verdict"),
               (f.get("reason") or "")[:120])
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def _load_evidence(evidence_path):
    if not evidence_path:
        return {}
    try:
        p = Path(evidence_path)
        if p.is_file():
            data = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data.get("evidence") or data
    except Exception:
        pass
    return {}


def _strip_unresolved(text):
    import re
    return re.sub(r"\{[a-zA-Z0-9_]+\}", "", text or "").strip()


def _enrich_evidence_fields(f):
    try:
        ev = _load_evidence(f.get("evidence_path"))
    except Exception:
        return
    if not isinstance(ev, dict):
        return
    if "signal_strength" in ev and "signal_strength" not in f:
        f["signal_strength"] = ev["signal_strength"]
    if "confirmation_status" in ev:
        f.setdefault("confirmation_status", ev["confirmation_status"])
    elif "confirmed" in ev:
        f["confirmation_status"] = ("confirmed" if ev["confirmed"]
                                    else "unconfirmed")
    tri = ev.get("triage")
    if isinstance(tri, dict):
        f.setdefault("triage_category", tri.get("category"))
        f.setdefault("triage_by_design", bool(tri.get("by_design")))
        if tri.get("note"):
            f.setdefault("triage_note", tri.get("note"))


def enrich_findings(findings):
    for f in findings or []:
        if writeup_library is not None:
            pid = f.get("pattern_id")
            if pid:
                try:
                    entry = writeup_library.resolve(pid)
                    if entry is not None:
                        rendered = writeup_library.render(
                            entry, _load_evidence(f.get("evidence_path")))
                        f["why"] = {
                            k: (_strip_unresolved(v)
                                if isinstance(v, str) else v)
                            for k, v in rendered.items()}
                except Exception:
                    pass
        _enrich_evidence_fields(f)
    return findings


def build_chains(findings):
    if chain_resolver is None:
        return []
    try:
        chains = chain_resolver.resolve_chains(findings)
    except Exception:
        return []
    def _plain(v):
        if isinstance(v, dict):
            return {k: _plain(x) for k, x in v.items()}
        if isinstance(v, (list, tuple)):
            return [_plain(x) for x in v]
        if hasattr(v, "__dict__"):
            return {k: _plain(x) for k, x in vars(v).items()}
        if hasattr(v, "value"):
            return v.value
        return v

    out = []
    for c in chains:
        d = c.to_dict() if hasattr(c, "to_dict") else dict(c)
        if d.get("verdict") == "INCOMPLETE" and not d.get("matched"):
            continue
        try:
            d["narrative_text"] = chain_narrative.render(c) if chain_narrative else ""
        except Exception:
            d["narrative_text"] = ""
        out.append(_plain(d))
    rank = {"CONFIRMED": 3, "LIKELY": 2, "THEORETICAL": 1, "INCOMPLETE": 0}
    out.sort(key=lambda d: -rank.get(d.get("verdict"), 0))
    return out


def build_coverage(target, findings):
    if coverage_mod is None:
        return None
    try:
        return coverage_mod.build_coverage_report(target=target, findings=findings)
    except Exception:
        return None


from .version import __version__ as SEC_CHECKER_VERSION
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
from .contract import SEVERITY_ORDER as _SEVERITY_RANK  # noqa: E402


def _apply_severity_threshold(findings, threshold):
    thr = _SEVERITY_RANK.get(str(threshold).lower(), 1)
    if thr <= 1:
        return findings
    return [f for f in findings
            if _SEVERITY_RANK.get(f.get("severity"), 0) >= thr]
_SARIF_LEVEL = {"critical": "error", "high": "error",
                "medium": "warning", "low": "note", "info": "note"}


def generate_sarif(target):
    rows = ledger.findings_for_target(target)
    findings = _dedupe(_findings_to_dicts(rows))
    from . import redact as _redact
    findings = _redact.redact_dict(findings)
    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "sec-checker",
                    "version": SEC_CHECKER_VERSION,
                    "informationUri": "https://github.com/local/sec-checker",
                    "rules": [],
                }
            },
            "results": [],
        }],
    }
    rules_seen = set()
    for f in findings:
        if f.get("verdict") not in ("VULNERABLE", "SUSPICIOUS"):
            continue
        _enrich_evidence_fields(f)
        rid = f.get("pattern_id") or "unknown"
        if rid not in rules_seen:
            rules_seen.add(rid)
            sarif["runs"][0]["tool"]["driver"]["rules"].append({
                "id": rid,
                "name": rid,
                "shortDescription": {"text": rid},
                "properties": {
                    "category": f.get("category") or "",
                    "wstg_id": f.get("wstg_id") or "",
                    "cwe_id": f.get("cwe_id") or "",
                    "severity": f.get("severity") or "info",
                },
            })
        sarif["runs"][0]["results"].append({
            "ruleId": rid,
            "level": _SARIF_LEVEL.get(f.get("severity", "info"), "note"),
            "message": {"text": f.get("reason") or ""},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": target},
                },
            }],
            "properties": {
                "verdict": f.get("verdict"),
                "severity": f.get("severity"),
                "triageCategory": f.get("triage_category") or "",
                "triageByDesign": bool(f.get("triage_by_design")),
                "triageNote": f.get("triage_note") or "",
            },
        })
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    safe = safe_name(target)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    path = REPORTS_DIR / f"{stamp}_{safe}.sarif"
    path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    return str(path)


def _extract_data_rows(findings):
    import json as _json
    out = []
    for f in findings or []:
        pid = (f.get("pattern_id") or "").lower()
        if not any(k in pid for k in ("bola", "unauth", "extract")):
            continue
        ev = f.get("evidence_json")
        if isinstance(ev, str):
            try:
                ev = _json.loads(ev)
            except Exception:
                continue
        if not isinstance(ev, dict):
            continue
        if ev.get("rows"):
            out.append({
                "endpoint": ev.get("url") or pid,
                "auth_used": ev.get("auth_used") or "unknown",
                "total_rows": int(ev.get("total_rows") or len(ev["rows"])),
                "extracted": int(ev.get("extracted") or len(ev["rows"])),
                "rows": [r for r in ev["rows"] if isinstance(r, dict)],
            })
            continue
        for entry in ev.get("findings") or []:
            if not isinstance(entry, dict) or not entry.get("rows"):
                continue
            auth = "unauthenticated" if "unauth" in pid else "user-b"
            out.append({
                "endpoint": entry.get("url") or entry.get("path") or pid,
                "auth_used": auth,
                "total_rows": int(entry.get("total_rows")
                                   or entry.get("b_rows")
                                   or len(entry["rows"])),
                "extracted": int(entry.get("extracted")
                                  or entry.get("b_extracted")
                                  or len(entry["rows"])),
                "rows": [r for r in entry["rows"] if isinstance(r, dict)],
            })
    return out


def _build_context(target, engine_cfg=None):
    if engine_cfg is None:
        from .config import load_engine
        engine_cfg = load_engine()
    threshold = engine_cfg.get("report", {}).get("severity_threshold", "info")
    rows = ledger.findings_for_target(target)
    findings = _dedupe(_findings_to_dicts(rows))
    try:
        from . import context as _ctx
        for f in findings:
            f["pattern_severity"] = f.get("severity", "info")
            f["severity"] = _ctx.context_severity(
                target, f["pattern_severity"])
    except Exception:
        pass
    findings = _apply_severity_threshold(findings, threshold)
    from . import redact as _redact
    findings = _redact.redact_dict(findings)
    enrich_findings(findings)
    chains = build_chains(findings)
    coverage = build_coverage(target, findings)
    cves = _extract_cves(findings)
    try:
        from . import report_graph
        graph_svg = report_graph.render_chain_svg(chains) if chains else ""
    except Exception:
        graph_svg = ""
    data_rows = _extract_data_rows(findings)
    try:
        from . import report_graph
        data_svg = report_graph.render_data_flow_svg(data_rows) if data_rows else ""
    except Exception:
        data_svg = ""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return {
        "target": target,
        "timestamp": ts,
        "findings": findings,
        "counts": _counts(findings),
        "chains": chains,
        "coverage": coverage,
        "cves": cves,
        "graph_svg": graph_svg,
        "data_rows": data_rows,
        "data_svg": data_svg,
    }


def _html_to_pdf(html_str, out_path):
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            page = browser.new_page()
            page.set_content(html_str, wait_until="load")
            page.pdf(path=str(out_path), format="A4", print_background=True,
                      margin={"top": "14mm", "bottom": "14mm",
                              "left": "10mm", "right": "10mm"})
        finally:
            browser.close()


def generate(target, fmt="html", engine_cfg=None):
    if fmt == "sarif":
        return generate_sarif(target)
    context = _build_context(target, engine_cfg)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in target)[:80]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    if fmt == "md":
        path = REPORTS_DIR / f"{stamp}_{safe}.md"
        path.write_text(_MD_ENV.from_string(MD_TEMPLATE).render(**context),
                        encoding="utf-8")
    elif fmt == "pdf":
        html_str = _HTML_ENV.from_string(HTML_TEMPLATE).render(**context)
        path = REPORTS_DIR / f"{stamp}_{safe}.pdf"
        _html_to_pdf(html_str, path)
    else:
        path = REPORTS_DIR / f"{stamp}_{safe}.html"
        path.write_text(_HTML_ENV.from_string(HTML_TEMPLATE).render(**context),
                        encoding="utf-8")
    return str(path)
