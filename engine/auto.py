from rich.console import Console

console = Console()


def run_auto(url, min_severity="medium", credentials=None, skip_discovery=False,
             api_override=None, adapter_override=None, auto_baseline=False,
             job_id=None, allow_destructive=False, banking=False, ai_key=None,
             use_brain=True):
    """Route the auto scan through ChainOrchestrator.

    This replaces the legacy parallel-pattern fan-out with the adaptive
    chain engine, so recon facts (framework, api_base, has_jwt_token,
    has_ecommerce, has_admin_paths, server_version, ...) actually drive
    which attacks run.

    min_severity, credentials, api_override, adapter_override, auto_baseline,
    and skip_discovery are accepted for backward compatibility with the
    previous auto path but are not used by the chain engine. The web UI
    passes min_severity; the CLI passes several.
    """
    from . import budget as _budget
    try:
        _budget.auto_configure_from_configs()
    except Exception:
        pass

    from .chain_engine import ChainOrchestrator
    from .roe_guard import ROEGuard
    from .config import load_engine

    try:
        from . import progress as _progress
        if job_id:
            _progress.set_active_job(job_id)
    except Exception:
        pass

    engine_cfg = load_engine()
    guard = ROEGuard(engine_cfg=engine_cfg)
    try:
        triage = None
        if use_brain:
            bcfg = engine_cfg.get("brain") or {}
            lcfg = bcfg.get("llm") or {}
            provider = lcfg.get("provider") or bcfg.get("provider") or "openai"
            model = lcfg.get("model") or bcfg.get("model") or "gpt-4o-mini"
            try:
                if ai_key:
                    from .brains.llm import make_llm_client, LLMBrain
                    client = make_llm_client(provider=provider, model=model,
                                              base_url=lcfg.get("base_url"),
                                              api_key=ai_key)
                    triage = LLMBrain(client=client, model=model)
                else:
                    from .brains.llm import make_brain_from_config
                    from .brains.rule_based import RuleBasedBrain
                    brain = make_brain_from_config(bcfg)
                    if not isinstance(brain, RuleBasedBrain):
                        triage = brain
            except Exception:
                triage = None
        orch = ChainOrchestrator(
            url, roe_guard=guard, engine_cfg=engine_cfg, job_id=job_id,
            verbose=False, allow_destructive=allow_destructive,
            credentials=credentials, triage_brain=triage,
        )
    except RuntimeError as e:
        console.print(f"[red]{e}[/red]")
        return None

    if banking:
        orch.add_fact("banking_requested", True, source="cli")

    console.rule("[bold cyan]AUTO-DISCOVERY[/bold cyan]")
    console.print(f"[cyan]Target:[/cyan] {url}")
    console.print()

    try:
        report = orch.run()
    except Exception as e:
        console.print(f"[red]chain run failed: {type(e).__name__}: {e}[/red]")
        return None

    try:
        from .cli import _print_chain_report
        _print_chain_report(report)
    except Exception:
        console.print(f"[cyan]Chain verdict:[/cyan] {report.get('verdict')}")
        console.print(f"[dim]Findings: {len(report.get('findings') or [])}[/dim]")

    outcome = _chain_report_to_outcome(report, url)

    try:
        from . import progress
        if job_id:
            progress.emit(job_id, "summary", {"counts": outcome["counts"]})
            progress.emit(job_id, "done", {
                "counts": outcome["counts"],
                "report_target": outcome["report_target"],
            })
    except Exception:
        pass

    return outcome


def _chain_report_to_outcome(report, url):
    counts = {"VULNERABLE": 0, "SUSPICIOUS": 0, "PASS": 0, "UNKNOWN": 0}
    results = []
    for chain in (report.get("chain_results") or []):
        for step in (chain.get("steps") or []):
            v = step.get("verdict", "UNKNOWN")
            if v in counts:
                counts[v] += 1
            results.append({
                "severity": "high" if v == "VULNERABLE" else "info",
                "verdict": v,
                "capability": step.get("id"),
                "chain": chain.get("id"),
            })
    facts = report.get("facts") or {}
    recon = report.get("recon") or {}
    fw = recon.get("framework") or {}
    api_base = recon.get("api_base") or url

    api_source = "recon"
    src_fact = facts.get("api_source")
    if isinstance(src_fact, dict) and src_fact.get("value"):
        api_source = src_fact["value"]

    catch_all = False
    ca_fact = facts.get("catch_all")
    if isinstance(ca_fact, dict):
        catch_all = bool(ca_fact.get("value"))

    targets = {
        "frontend": url,
        "api_base": api_base,
        "source": api_source,
        "port_scan": [],
        "catch_all": catch_all,
        "soft_404": None,
    }
    api_paths = recon.get("api_paths") or []
    context = report.get("context") or {}
    login_info = context.get("login_info")
    endpoint_probes = recon.get("endpoint_probes") or []
    framework = {
        "adapter": {"id": fw.get("id", "generic"),
                    "name": fw.get("name", "Generic")},
        "score": fw.get("score", 0),
        "framework": fw.get("id", "generic"),
        "name": fw.get("name", "Generic"),
    }
    return {
        "framework": framework,
        "targets": targets,
        "api_paths": api_paths,
        "login": login_info,
        "counts": counts,
        "results": results,
        "report_target": api_base,
        "endpoint_probes": endpoint_probes,
        "chain_report": report,
    }
