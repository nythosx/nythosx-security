"""One-command hunter.

Wraps ChainOrchestrator with a clean recon banner, a top-N finding summary
sorted by severity, optional standalone probes (cloud storage), and a JSON
export mode. This is the entry point a user reaches for when they want
"scan this domain, tell me what matters".
"""
from __future__ import annotations

import time
from datetime import datetime, timezone

from rich.console import Console

from .chain_engine import ChainOrchestrator
from .config import load_engine
from .roe_guard import ROEGuard, ROEViolation


SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

_VERDICT_DEFAULT_SEV = {
    "VULNERABLE": "high",
    "SUSPICIOUS": "medium",
    "PASS": "info",
    "UNKNOWN": "info",
}

_SEV_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "dim",
    "info": "dim",
}

_VERDICT_COLORS = {
    "VULNERABLE": "red",
    "SUSPICIOUS": "yellow",
    "PASS": "green",
    "UNKNOWN": "dim",
}


def _severity_for(evidence, verdict):
    sev = (evidence or {}).get("severity")
    if isinstance(sev, str) and sev.lower() in SEVERITY_ORDER:
        return sev.lower()
    return _VERDICT_DEFAULT_SEV.get(verdict, "info")


def _collect_from_report(report):
    out = []
    for f in (report.get("findings") or []):
        out.append({
            "source": "chain",
            "chain": f.get("chain") or "?",
            "step": f.get("step") or "?",
            "tool": f.get("tool") or "?",
            "verdict": f.get("verdict") or "UNKNOWN",
            "severity": _severity_for(f.get("evidence"), f.get("verdict")),
            "reason": f.get("reason") or "",
            "evidence": f.get("evidence") or {},
            "confidence": f.get("confidence"),
        })
    return out


def _collect_extracted(report):
    out = []
    for f in (report.get("findings") or []):
        ed = f.get("extracted_data") or []
        for row in ed:
            if isinstance(row, dict):
                out.append(row)
        ev = f.get("evidence") or {}
        for row in (ev.get("extracted_data") or []):
            if isinstance(row, dict):
                out.append(row)
        for rec in (f.get("extracted_records") or []):
            if isinstance(rec, dict):
                out.append(rec)
        target = f.get("target") or report.get("target") or ""
        pattern = f.get("tool") or f.get("step") or ""
        if ev.get("extracted_records"):
            try:
                from . import ledger as _l
                rows = ev["extracted_records"]
                first_row = []
                for r in rows[:10]:
                    if isinstance(r, dict) and isinstance(r.get("rows"), list):
                        first_row.extend(r["rows"][:1])
                _l.record_extracted(
                    target=target,
                    endpoint=ev.get("endpoint") or target,
                    method="GET",
                    auth_used="user-b",
                    status=200,
                    total_rows=ev.get("total_rows") or len(rows),
                    extracted=len(rows),
                    rows=first_row or rows[:5],
                    source_pattern=pattern,
                )
            except Exception:
                pass
    return out


def _dedupe_and_sort(findings):
    seen = set()
    unique = []
    for f in findings:
        key = (f.get("chain"), f.get("step"), (f.get("reason") or "")[:80])
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    unique.sort(key=lambda f: (
        SEVERITY_ORDER.index(f.get("severity", "info")),
        -(f.get("confidence") or 0.0),
    ))
    return unique


def _run_cloud_storage(target, findings_pool):
    try:
        from . import cloud_storage
    except ImportError:
        return
    try:
        r = cloud_storage.scan(target)
    except Exception:
        return
    if r["verdict"] not in ("VULNERABLE", "SUSPICIOUS"):
        return
    findings_pool.append({
        "source": "standalone",
        "chain": "cloud-storage-chain",
        "step": "cloud_storage",
        "tool": "cloud_storage",
        "verdict": r["verdict"],
        "severity": "high" if r["verdict"] == "VULNERABLE" else "medium",
        "reason": r.get("reason") or "",
        "evidence": r.get("evidence") or {},
        "confidence": 0.7,
    })


def _print_progress_event(console, etype, data):
    if etype == "chain_start":
        name = data.get("name") or data.get("id") or "?"
        console.print(f"  [cyan]\u25b6[/cyan] [bold]{name}[/bold]")
    elif etype == "chain_done":
        v = data.get("verdict") or "UNKNOWN"
        color = _VERDICT_COLORS.get(v, "white")
        cid = data.get("id") or "?"
        console.print(f"    [{color}]\u25c0 {cid} \u2192 {v}[/{color}]")
    elif etype == "step_done":
        v = data.get("verdict") or "UNKNOWN"
        if v in ("VULNERABLE", "SUSPICIOUS"):
            color = _VERDICT_COLORS.get(v, "white")
            step = data.get("step") or "?"
            reason = (data.get("reason") or "")[:100]
            console.print(f"      [{color}]{v}[/{color}] {step} \u2014 {reason}")


def _patch_progress(orch, console):
    orig_activity = orch._activity

    def _activity(msg, stage=None):
        orig_activity(msg, stage)
        if msg:
            prefix = f"[dim]{stage}:[/dim] " if stage else ""
            console.print(f"  {prefix}{msg}")

    orig_emit = orch._emit

    def _emit(etype, data=None):
        orig_emit(etype, data)
        _print_progress_event(console, etype, data or {})

    orch._activity = _activity
    orch._emit = _emit


def _render_recon(console, recon, facts):
    fw = recon.get("framework") or {}
    api_base = recon.get("api_base") or "(not found)"
    js_count = len(recon.get("js_urls") or [])
    path_count = len(recon.get("api_paths") or [])
    console.print("[bold]Recon[/bold]")
    console.print(f"  Framework:  {fw.get('name', 'unknown')} "
                  f"(score={fw.get('score', 0)})")
    console.print(f"  API base:   {api_base}")
    console.print(f"  JS bundles: {js_count}")
    console.print(f"  API paths:  {path_count}")
    for key, label in (("ct_subdomain_count", "CT subdomains"),
                       ("live_subdomains", "Live subdomains"),
                       ("historic_path_count", "Historic paths"),
                       ("server_version", "Server version"),
                       ("powered_version", "Powered by")):
        f = facts.get(key) or {}
        val = f.get("value") if isinstance(f, dict) else f
        if val:
            if isinstance(val, list):
                console.print(f"  {label}: {len(val)}")
            else:
                console.print(f"  {label}: {val}")


def _render_findings(console, findings):
    if not findings:
        console.print()
        console.print("[bold green]No vulnerable or suspicious findings.[/bold green]")
        return
    console.print()
    console.print(f"[bold]Findings ({len(findings)})[/bold]")
    for f in findings:
        sev = f.get("severity", "info")
        color = _SEV_COLORS.get(sev, "white")
        console.print()
        console.print(f"  [{color}]{sev.upper():8}[/{color}] "
                      f"{f['tool']} / {f['step']}")
        reason = (f.get("reason") or "").strip()
        if reason:
            console.print(f"           {reason[:220]}")
        ev = f.get("evidence") or {}
        small = {k: v for k, v in ev.items()
                 if k != "severity" and not isinstance(v, (dict, list))}
        if small:
            pairs = ", ".join(f"{k}={v}" for k, v in list(small.items())[:4])
            console.print(f"           [dim]evidence: {pairs}[/dim]")


def _has_live_subdomains(facts):
    entry = (facts or {}).get("live_subdomains")
    if not entry:
        return False
    value = entry.get("value") if isinstance(entry, dict) else entry
    return bool(value)


def _run_ct_and_takeover(target, facts, findings_pool):
    if _has_live_subdomains(facts):
        return
    try:
        from .recon import ct_logs
    except ImportError:
        return
    try:
        ct = ct_logs.harvest(target, resolve=True)
    except Exception:
        return
    if not ct or not ct.get("live"):
        return
    try:
        from . import subdomain_takeover
    except ImportError:
        return
    urls = [f"https://{x['name']}" for x in ct["live"]
            if isinstance(x, dict) and x.get("name")]
    if not urls:
        return
    try:
        r = subdomain_takeover.scan(urls)
    except Exception:
        return
    verdict = r.get("verdict") if hasattr(r, "get") else getattr(r, "verdict", None)
    if verdict in ("VULNERABLE", "SUSPICIOUS"):
        findings_pool.append({
            "source": "standalone",
            "chain": "subdomain-takeover-chain",
            "step": "subdomain_takeover",
            "tool": "subdomain_takeover",
            "verdict": verdict,
            "severity": "high" if verdict == "VULNERABLE" else "medium",
            "reason": (r.get("reason") if hasattr(r, "get")
                       else getattr(r, "reason", "")) or "",
            "evidence": (r.get("evidence") if hasattr(r, "get")
                         else getattr(r, "evidence", {})) or {},
            "confidence": 0.7,
        })


def hunt(target, budget_sec=600, max_findings=25, allow_destructive=False,
         include_standalone=True, console=None, verbose=True, banking=False):
    console = console or Console()
    started = time.monotonic()

    cfg = load_engine()
    guard = ROEGuard(engine_cfg=cfg)

    if verbose:
        console.print()
        console.rule(f"[bold cyan]HUNT[/bold cyan] {target}")

    triage_brain = None
    try:
        from .brains.llm import make_brain_from_config
        from .brains.rule_based import RuleBasedBrain
        brain = make_brain_from_config(cfg.get("brain"))
        if not isinstance(brain, RuleBasedBrain):
            triage_brain = brain
    except Exception:
        triage_brain = None

    orch = ChainOrchestrator(
        target,
        roe_guard=guard,
        engine_cfg=cfg,
        max_budget_sec=budget_sec,
        allow_destructive=allow_destructive,
        verbose=verbose,
        triage_brain=triage_brain,
    )
    if banking:
        orch.add_fact("banking_requested", True, source="cli")

    if verbose:
        _patch_progress(orch, console)

    report = orch.run()

    pool = _collect_from_report(report)
    if include_standalone:
        if verbose:
            console.print("  [dim]standalone: cloud storage enumeration[/dim]")
        _run_cloud_storage(target, pool)
        if verbose:
            console.print("  [dim]standalone: CT logs + takeover[/dim]")
        _run_ct_and_takeover(target, report.get("facts") or {}, pool)

    unique = _dedupe_and_sort(pool)
    top = unique[:max_findings]
    duration = round(time.monotonic() - started, 2)

    if verbose:
        console.print()
        _render_recon(console, report.get("recon") or {},
                      report.get("facts") or {})
        _render_findings(console, top)
        console.print()
        console.print(f"[dim]Duration: {duration}s  \u00b7  "
                      f"total findings: {len(unique)}[/dim]")

    extracted = _collect_extracted(report)
    return {
        "target": target,
        "duration_sec": duration,
        "verdict": report.get("verdict") or "UNKNOWN",
        "facts": report.get("facts") or {},
        "recon": report.get("recon") or {},
        "findings": top,
        "total_findings": len(unique),
        "extracted_data": extracted,
        "extracted_count": len(extracted),
        "chain_report": report,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


__all__ = ["hunt", "SEVERITY_ORDER"]
