import html
from typing import Optional


def _esc(s):
    if s is None:
        return ""
    return html.escape(str(s))


PHASE_RUNNING = {
    "preflight": "Checking that the target responds at all.",
    "framework": "Fingerprinting the target \u2014 what tech is it running?",
    "discovery": "Looking for the API base and endpoints.",
    "login": "Attempting to authenticate.",
    "baseline": "Profiling baseline timing for comparison.",
    "scanning": "Fanning out attack patterns across the target.",
    "report": "Composing the report.",
}

PHASE_DONE = {
    "preflight": "Target is alive.",
    "framework": "Fingerprint complete.",
    "discovery": "API discovery complete.",
    "login": "Login complete.",
    "scanning": "All patterns finished.",
    "report": "Report ready.",
}


def _narrate_phase(d):
    name = d.get("name", "")
    status = d.get("status", "")
    if status == "running":
        text = PHASE_RUNNING.get(name)
        if not text:
            return None
        return {"type": "action", "text": text, "stage": name}
    if status == "done":
        text = PHASE_DONE.get(name)
        if text:
            return {"type": "pass", "text": text, "stage": name}
    return None


def _narrate_framework(d):
    fw_id = d.get("id", "generic") or "generic"
    name = d.get("name", fw_id) or fw_id
    score = d.get("score", 0) or 0
    if fw_id == "generic":
        return {
            "type": "obs",
            "text": (
                "Couldn\u2019t identify the framework with confidence. "
                "Treating as generic."
            ),
        }
    evidence = d.get("evidence") or []
    detail = None
    if evidence:
        detail = "\n".join("\u00b7 " + _esc(e) for e in evidence[:5])
    text = "<b>" + _esc(name) + "</b> detected"
    if score:
        text += " (score " + _esc(score) + ")"
    text += " \u2014 I know this framework, I have specific attacks ready."
    return {
        "type": "pass",
        "text": text,
        "detail": detail,
        "framework_id": fw_id,
    }


def _narrate_api_base(d):
    url = d.get("url", "")
    source = (d.get("source") or "").lower()
    ports = d.get("ports") or []
    text = "API base located: <code>" + _esc(url) + "</code>."
    if "js" in source:
        text += (
            " I found it by reading the frontend JavaScript \u2014 "
            "the app itself told me where its API lives."
        )
    elif "portscan" in source:
        text += " Found via port scan. " + str(len(ports)) + " port(s) were reachable."
    return {"type": "pass", "text": text}


def _narrate_js_done(d):
    count = d.get("count", 0) or 0
    size_kb = d.get("size_kb", 0) or 0
    paths = d.get("paths", 0) or 0
    return {
        "type": "obs",
        "text": (
            "Read <b>" + str(count) + " JavaScript bundles</b> (" +
            str(size_kb) + " KB). Extracted <b>" + str(paths) +
            " API paths</b> from the code."
        ),
    }


def _narrate_login(d):
    if d.get("ok"):
        tok = d.get("token") or ""
        preview = ""
        if tok:
            preview = " (starts with <code>" + _esc(str(tok)[:16]) + "\u2026</code>)"
        return {
            "type": "pass",
            "text": "Logged in successfully. Got a session token" + preview + ".",
        }
    return {
        "type": "obs",
        "text": (
            "No login endpoint responded \u2014 scanning unauthenticated. "
            "Some findings may be hidden behind a login."
        ),
    }


def _narrate_pattern_start(d):
    pid = d.get("id", "")
    return {
        "type": "action",
        "text": "Running pattern <code>" + _esc(pid) + "</code>.",
        "pattern": pid,
    }


def _narrate_pattern_done(d):
    pid = d.get("id", "?")
    verdict = (d.get("verdict") or "UNKNOWN").upper()
    reason = d.get("reason") or ""
    evidence = d.get("evidence") or {}
    payload = d.get("payload") or evidence.get("payload") or evidence.get("sent")
    request = d.get("request") or evidence.get("request") or evidence.get("request_preview")
    response = d.get("response") or evidence.get("response") or evidence.get("body_preview")

    detail_lines = []
    if payload:
        detail_lines.append("payload:  " + _esc(payload))
    if request:
        detail_lines.append("request:  " + _esc(request))
    if response:
        detail_lines.append("response: " + _esc(response))
    detail = "\n".join(detail_lines) if detail_lines else None

    if verdict == "VULNERABLE":
        return {
            "type": "vuln",
            "text": "<b>" + _esc(pid) + "</b> \u2014 confirmed vulnerability. " + _esc(reason),
            "detail": detail,
            "pattern": pid,
            "verdict": "vuln",
        }
    if verdict == "SUSPICIOUS":
        return {
            "type": "susp",
            "text": "<b>" + _esc(pid) + "</b> \u2014 suspicious signal, needs manual verification. " + _esc(reason),
            "detail": detail,
            "pattern": pid,
            "verdict": "susp",
        }
    if verdict == "PASS":
        return {
            "type": "pass",
            "text": "<b>" + _esc(pid) + "</b> \u2014 the server held up. " + _esc(reason),
            "pattern": pid,
            "verdict": "pass",
        }
    return {
        "type": "obs",
        "text": "<b>" + _esc(pid) + "</b> \u2014 could not reach a conclusion. " + _esc(reason),
        "pattern": pid,
        "verdict": "unknown",
    }


def _narrate_summary(d):
    c = d.get("counts") or {}
    v = c.get("VULNERABLE", 0)
    s = c.get("SUSPICIOUS", 0)
    p = c.get("PASS", 0)
    u = c.get("UNKNOWN", 0)
    return {
        "type": "obs",
        "text": (
            "Scan finished. <b>" + str(v) + "</b> vulnerable \u00b7 <b>" +
            str(s) + "</b> suspicious \u00b7 <b>" + str(p) + "</b> passed \u00b7 <b>" +
            str(u) + "</b> unknown."
        ),
        "counts": c,
    }


def _narrate_error(d):
    msg = d.get("message", "unknown error")
    return {"type": "vuln", "text": "Scan aborted: " + _esc(msg)}


def _narrate_plan(d):
    chains = d.get("chains") or []
    if not chains:
        return None
    names = ", ".join(_esc(c) for c in chains[:8])
    more = "" if len(chains) <= 8 else f" (+{len(chains) - 8} more)"
    return {"type": "action",
            "text": f"Plan ready: <b>{len(chains)} chain(s)</b> selected "
                    f"&mdash; {names}{more}."}


def _narrate_fact(d):
    key = d.get("key") or "?"
    val = d.get("value")
    if isinstance(val, (list, dict)):
        val = f"<{type(val).__name__} len={len(val)}>"
    src = d.get("source") or ""
    text = f"Fact: <code>{_esc(key)}</code> = <code>{_esc(val)}</code>"
    if src:
        text += f" <span style='color:var(--ph-dim)'>({_esc(src)})</span>"
    return {"type": "obs", "text": text}


def _narrate_chain_start(d):
    cid = d.get("id", "?")
    name = d.get("name", cid)
    return {"type": "action",
            "text": f"Running chain <b>{_esc(name)}</b>."}


def _narrate_chain_done(d):
    cid = d.get("id", "?")
    verdict = (d.get("verdict") or "UNKNOWN").upper()
    reason = d.get("reason") or ""
    ms = d.get("duration_ms")
    dur = f" ({ms:.0f}ms)" if isinstance(ms, (int, float)) else ""
    if verdict == "VULNERABLE":
        return {"type": "vuln",
                "text": f"<b>{_esc(cid)}</b> &mdash; chain confirmed{dur}. "
                        + _esc(reason)}
    if verdict == "SUSPICIOUS":
        return {"type": "susp",
                "text": f"<b>{_esc(cid)}</b> &mdash; suspicious{dur}. "
                        + _esc(reason)}
    if verdict == "PASS":
        return {"type": "pass",
                "text": f"<b>{_esc(cid)}</b> &mdash; the server held up{dur}."}
    return {"type": "obs",
            "text": f"<b>{_esc(cid)}</b> &mdash; inconclusive{dur}. "
                    + _esc(reason)}


def _narrate_step_start(d):
    chain = d.get("chain", "?")
    step = d.get("step", "?")
    tool = d.get("tool", "?")
    return {"type": "obs",
            "text": f"  &middot; step <code>{_esc(step)}</code> "
                    f"({_esc(tool)})"}


def _narrate_step_done(d):
    chain = d.get("chain", "?")
    step = d.get("step", "?")
    tool = d.get("tool") or ""
    verdict = (d.get("verdict") or "UNKNOWN").upper()
    reason = d.get("reason") or ""
    ms = d.get("duration_ms")
    dur = f" ({ms:.0f}ms)" if isinstance(ms, (int, float)) else ""

    labels = {
        "cve_correlation": "CVE correlation",
        "access_bypass": "access bypass",
        "cache_deception": "cache deception",
        "bola_harvest": "BOLA harvest",
        "bola_scan": "BOLA probe",
        "blind_extract": "blind SQLi extract",
        "unauth_pagination": "pagination dump",
        "graphql_dump": "GraphQL dump",
        "llm_prompt_dump": "LLM prompt dump",
        "llm_cred_extract": "LLM credential extract",
        "llm_tool_list": "LLM tool dump",
        "xxe_harvest": "XXE file read",
        "ssrf_harvest": "SSRF harvest",
        "ssti_harvest": "SSTI RCE",
        "mcp_security": "MCP scan",
        "session_fixation": "session fixation",
        "postmessage_probe": "postMessage probe",
        "ci_cd_probe": "CI/CD probe",
        "npmrc_probe": "package-manager probe",
        "firebase_probe": "Firebase probe",
    }
    label = labels.get(tool, step)
    evidence = d.get("evidence") or {}
    extracted = (evidence.get("extracted_records")
                  or evidence.get("extracted_data")
                  or d.get("extracted_data"))
    if isinstance(extracted, list) and extracted:
        count = len(extracted)
        rows_preview = []
        for item in extracted[:20]:
            if isinstance(item, dict):
                rows_preview.append(item)
        return {
            "type": "vuln",
            "text": f"  &middot; <b>{_esc(label)}</b> &mdash; "
                    f"<b>{count} record(s) extracted</b>{dur}. "
                    + _esc(reason),
            "detail": "\n".join(str(r)[:200] for r in rows_preview[:5]),
            "extracted": rows_preview[:20],
            "extracted_count": count,
        }
    extracted_value = evidence.get("extracted_value")
    if isinstance(extracted_value, str) and extracted_value:
        return {
            "type": "vuln",
            "text": f"  &middot; <b>{_esc(label)}</b> &mdash; "
                    f"<b>recovered value: {_esc(extracted_value[:80])}</b>{dur}. "
                    + _esc(reason),
            "extracted_value": extracted_value[:200],
        }
    files_read = evidence.get("files_read")
    if isinstance(files_read, list) and files_read:
        return {
            "type": "vuln",
            "text": f"  &middot; <b>{_esc(label)}</b> &mdash; "
                    f"<b>{len(files_read)} file(s) read</b>{dur}. "
                    + _esc(reason),
            "files_read": files_read[:10],
        }

    if verdict == "VULNERABLE":
        return {"type": "vuln",
                "text": f"  &middot; <b>{_esc(label)}</b> &mdash; VULNERABLE{dur}. "
                        + _esc(reason)}
    if verdict == "SUSPICIOUS":
        return {"type": "susp",
                "text": f"  &middot; <b>{_esc(label)}</b> &mdash; suspicious{dur}. "
                        + _esc(reason)}
    if verdict == "PASS":
        return {"type": "pass",
                "text": f"  &middot; {_esc(label)} &mdash; passed{dur}."}
    return None


def _narrate_warning(d):
    code = d.get("code") or "warning"
    detail = d.get("detail") or ""
    return {"type": "susp",
            "text": "<b>" + _esc(code) + "</b> &mdash; " + _esc(detail)}


def _narrate_diagnostic(d):
    category = d.get("category") or "diagnostic"
    severity = d.get("severity") or "info"
    detail = d.get("detail") or ""
    type_map = {"warning": "susp", "error": "vuln", "info": "obs"}
    return {"type": type_map.get(severity, "obs"),
            "text": "<b>" + _esc(category) + "</b> &mdash; " + _esc(detail)}


_TEMPLATES = {
    "phase": _narrate_phase,
    "framework": _narrate_framework,
    "api_base": _narrate_api_base,
    "js_done": _narrate_js_done,
    "login": _narrate_login,
    "pattern_start": _narrate_pattern_start,
    "pattern_done": _narrate_pattern_done,
    "summary": _narrate_summary,
    "error": _narrate_error,
    "plan": _narrate_plan,
    "fact": _narrate_fact,
    "chain_start": _narrate_chain_start,
    "chain_done": _narrate_chain_done,
    "step_start": _narrate_step_start,
    "step_done": _narrate_step_done,
    "warning": _narrate_warning,
    "diagnostic": _narrate_diagnostic,
}


def narrate(event_type, data):
    fn = _TEMPLATES.get(event_type)
    if not fn:
        return None
    try:
        return fn(data or {})
    except Exception:
        return None


def summarize(result):
    target = result.get("target") or result.get("entered_url") or "the target"
    counts = result.get("counts") or {}
    findings = result.get("findings") or []

    bullets = []
    by_chain = {}
    for f in findings:
        if f.get("verdict") not in ("VULNERABLE", "SUSPICIOUS"):
            continue
        cid = f.get("chain") or f.get("pattern_id") or "unknown"
        by_chain.setdefault(cid, []).append(f)

    for cid, group in by_chain.items():
        has_vuln = any(g.get("verdict") == "VULNERABLE" for g in group)
        cls = "danger" if has_vuln else ""
        label = "CRITICAL" if has_vuln else "SUSPICIOUS"
        first = group[0]
        why = first.get("why") or {}
        text = "<b>" + label + " \u2014 " + _esc(cid) + ".</b> " + _esc(first.get("reason", ""))
        if why.get("impact"):
            text += " <i>Impact:</i> " + _esc(why["impact"])
        bullets.append({"class": cls, "html": text})

    passed = [f for f in findings if f.get("verdict") == "PASS"]
    if passed:
        names = ", ".join(sorted(set(
            (f.get("pattern_id") or "?") for f in passed
        ))[:8])
        bullets.append({
            "class": "",
            "html": "<b>" + str(len(passed)) + " check(s) passed:</b> " + _esc(names) + ".",
        })

    skipped = [f for f in findings if f.get("verdict") == "SKIPPED"]
    if skipped:
        bullets.append({
            "class": "",
            "html": (
                "<b>" + str(len(skipped)) +
                " destructive technique(s) skipped</b> (not authorized in this run)."
            ),
        })

    v = counts.get("VULNERABLE", 0)
    if v > 0:
        closing = (
            "<b>What this means:</b> there are real, exploitable weaknesses. "
            "Fix the critical ones first."
        )
    elif counts.get("SUSPICIOUS"):
        closing = (
            "<b>What this means:</b> no confirmed vulnerabilities, "
            "but some signals need a human to verify."
        )
    else:
        closing = (
            "<b>What this means:</b> the target held up against "
            "everything I threw at it."
        )

    return {
        "target": target,
        "counts": counts,
        "bullets": bullets,
        "closing": closing,
    }
