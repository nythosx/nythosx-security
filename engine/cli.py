import base64
import json
import sys
import time
from rich.console import Console
from rich.markup import escape
from rich.table import Table
from . import (loader, executor, oracle, evidence, ledger, report,
               baseline, auth_flow, route_enum, adapter_loader)
from .config import (load_engine, load_targets, get_target, save_session,
                     load_session, list_sessions)

import sys as _sys_alias  # noqa: E402
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

console = Console()
from .contract import SEVERITY_ORDER as SEVERITY_RANK, VERDICT_COLOR  # noqa: E402
EXIT_FINDINGS = 3
_ACTIONABLE = ("VULNERABLE", "SUSPICIOUS")


def _compute_fail_exit(results, fail_on):
    if not fail_on:
        return 0
    thr = SEVERITY_RANK.get(str(fail_on).lower())
    if not thr:
        console.print(f"[yellow]--fail-on: unknown severity '{fail_on}', ignored[/yellow]")
        return 0
    offenders = [r for r in results
                 if r.get("verdict") in _ACTIONABLE
                 and SEVERITY_RANK.get(r.get("severity"), 0) >= thr]
    if offenders:
        console.print(f"[bold red]FAIL:[/bold red] {len(offenders)} finding(s) "
                      f">= {fail_on} (exit {EXIT_FINDINGS})")
        return EXIT_FINDINGS
    return 0


def _parse_auth(auth_str):
    if not auth_str:
        return None
    if auth_str.startswith("bearer:"):
        return {"Authorization": f"Bearer {auth_str[7:]}"}
    if auth_str.startswith("cookie:"):
        return {"Cookie": auth_str[7:]}
    if auth_str.startswith("apikey:"):
        return {"X-API-Key": auth_str[7:]}
    if ":" in auth_str:
        token = base64.b64encode(auth_str.encode()).decode()
        return {"Authorization": f"Basic {token}"}
    return None


def _resolve_session(session_name, auth_str):
    headers = _parse_auth(auth_str) or {}
    cookies = {}
    if session_name:
        sess = load_session(session_name)
        if not sess:
            console.print(f"[red]Session not found: {session_name}[/red]")
            return headers, cookies, False
        headers.update(auth_flow.build_headers_from_session(sess))
        cookies.update(auth_flow.build_cookies_from_session(sess))
        console.print(f"[dim]Session loaded: {session_name} "
                       f"({len(headers)} headers, {len(cookies)} cookies)[/dim]")
    return headers, cookies, True


def _build_inputs(pattern, target, overrides):
    inputs = {}
    for key, spec in (pattern.get("inputs") or {}).items():
        if spec is None:
            spec = {}
        if key in overrides and overrides[key] is not None:
            inputs[key] = overrides[key]
        elif key in ("target_url", "url") or key.endswith("_url"):
            inputs[key] = target
        elif spec.get("default") is not None:
            inputs[key] = spec["default"]
        elif spec.get("required"):
            inputs[key] = target
        else:
            inputs[key] = ""
    if "target_url" not in inputs:
        inputs["target_url"] = target
    return inputs


def _pick_verdict(pattern, context):
    oracles = pattern.get("oracles", [])
    rank = {"VULNERABLE": 3, "SUSPICIOUS": 2, "PASS": 1, "UNKNOWN": 0}
    best = None
    for o in oracles:
        r = oracle.evaluate(o, context)
        if best is None or rank.get(r["verdict"], 0) > rank.get(best["verdict"], 0):
            best = r
    if best is None:
        return {"verdict": "UNKNOWN", "reason": "no oracles evaluated",
                "evidence": {}}
    return best


def _run_single(pattern_id, target, auth_str=None, overrides=None, default_headers=None,
                cookies=None):
    overrides = overrides or {}
    pattern = loader.load_pattern(pattern_id)
    if not pattern:
        return None
    suffix = pattern.get("endpoint_suffix", "")
    if suffix:
        target = target.rstrip("/") + suffix
    if pattern.get("ignore_default_auth"):
        default_headers = {}
        cookies = {}
    headers = default_headers or _parse_auth(auth_str)
    inputs = _build_inputs(pattern, target, overrides)
    engine_cfg = load_engine()
    t0 = time.perf_counter()
    context = executor.execute_pattern(pattern, inputs, target,
                                        default_headers=headers,
                                        engine_config=engine_cfg,
                                        cookies=cookies)
    elapsed = (time.perf_counter() - t0) * 1000.0
    result = _pick_verdict(pattern, context)
    return {
        "pattern": pattern,
        "context": context,
        "result": result,
        "duration_ms": round(elapsed, 3),
    }


def _record_and_save(pattern_id, target, out, category=""):
    pattern = out["pattern"]
    result = out["result"]
    tags = pattern.get("tags", [])
    wstg = next((t for t in tags if t.startswith("wstg-")), "")
    cwe = next((t for t in tags if t.startswith("cwe-")), "")
    path = evidence.save_evidence(pattern_id, target, out["context"],
                                   result["verdict"], result)
    ledger.record_finding(
        pattern_id=pattern_id,
        target=target,
        verdict=result["verdict"],
        severity=pattern.get("severity", "info"),
        reason=result.get("reason", ""),
        evidence_path=path,
        evidence_json=result.get("evidence", {}),
        category=category or pattern.get("_category", ""),
        wstg_id=wstg.upper() if wstg else "",
        cwe_id=cwe.upper() if cwe else "",
        duration_ms=out["duration_ms"],
    )
    return path


def cmd_list(args):
    patterns = loader.list_patterns()
    if not patterns:
        console.print("[yellow]No patterns found.[/yellow]")
        return
    t = Table(title="Available Patterns")
    t.add_column("ID", style="cyan")
    t.add_column("Name", style="white")
    t.add_column("Severity", style="yellow")
    t.add_column("Category", style="magenta")
    for p in patterns:
        t.add_row(p["id"], p["name"], p["severity"], p["category"])
    console.print(t)
    console.print(f"\n[dim]Total: {len(patterns)} patterns[/dim]")


def cmd_show(args):
    if not args:
        console.print("[red]Usage: show <pattern_id>[/red]")
        return
    pattern = loader.load_pattern(args[0])
    if not pattern:
        console.print(f"[red]Not found: {args[0]}[/red]")
        return
    console.print(f"[cyan]ID       :[/cyan] {pattern.get('id')}")
    console.print(f"[cyan]Name     :[/cyan] {pattern.get('name')}")
    console.print(f"[cyan]Severity :[/cyan] {pattern.get('severity')}")
    console.print(f"[cyan]Category :[/cyan] {pattern.get('_category')}")
    console.print(f"[cyan]Tags     :[/cyan] {', '.join(pattern.get('tags', []))}")
    console.print(f"[cyan]Source   :[/cyan] {pattern.get('_source')}")
    if pattern.get("endpoint_suffix"):
        console.print(f"[cyan]Endpoint :[/cyan] {pattern.get('endpoint_suffix')}")
    console.print()
    console.print("[bold]Inputs:[/bold]")
    for k, v in (pattern.get("inputs") or {}).items():
        console.print(f"  {k}: {v}")
    console.print()
    console.print("[bold]Steps:[/bold]")
    for s in pattern.get("steps", []):
        console.print(f"  - {s.get('name', 'step')}")
    console.print()
    console.print("[bold]Oracles:[/bold]")
    for o in pattern.get("oracles", []):
        console.print(f"  - {o.get('type')}")


def cmd_validate(args):
    results = loader.validate_all()
    if not results:
        console.print("[yellow]No patterns to validate.[/yellow]")
        return
    ok = 0
    fail = 0
    for path, errors in results:
        if errors:
            console.print(f"[red]FAIL[/red]  {path}")
            for e in errors:
                console.print(f"        {e}")
            fail += 1
        else:
            console.print(f"[green]OK  [/green]  {path}")
            ok += 1
    console.print(f"\n[bold]Total: {ok} OK, {fail} FAIL[/bold]")


def cmd_adapters(args):
    adapters = adapter_loader.load_all()
    if not adapters:
        console.print("[yellow]No adapters found.[/yellow]")
        return
    t = Table(title=f"Framework Adapters ({len(adapters)})")
    t.add_column("ID", style="cyan")
    t.add_column("Name", style="white")
    t.add_column("Priority", style="dim")
    t.add_column("Ports", style="yellow")
    t.add_column("Source", style="dim")
    for a in adapters:
        ports = ",".join(str(p) for p in (a.get("ports") or [])[:4])
        t.add_row(a["id"], a.get("name", ""), str(a.get("priority", 50)),
                   ports, a.get("_source", "")[:40])
    console.print(t)
    console.print()
    console.print("[dim]Force adapter: python run.py auto <url> --adapter <id>[/dim]")


def cmd_scan(args):
    if not args or len(args) < 2:
        console.print("[red]Usage: scan <pattern_id> <target>[/red]")
        return
    pattern_id = args[0]
    target = args[1]
    auth_str = None
    session = None
    fail_on = None
    overrides = {}
    i = 2
    while i < len(args):
        if args[i] == "--auth" and i + 1 < len(args):
            auth_str = args[i + 1]
            i += 2
        elif args[i] == "--session" and i + 1 < len(args):
            session = args[i + 1]
            i += 2
        elif args[i] in ("--iter", "--iterations") and i + 1 < len(args):
            overrides["iterations"] = int(args[i + 1])
            i += 2
        elif args[i] == "--concurrency" and i + 1 < len(args):
            overrides["concurrency"] = int(args[i + 1])
            i += 2
        elif args[i] == "--fail-on" and i + 1 < len(args):
            fail_on = args[i + 1]
            i += 2
        else:
            i += 1
    pattern = loader.load_pattern(pattern_id)
    if not pattern:
        console.print(f"[red]Pattern not found: {pattern_id}[/red]")
        return
    headers, cookies, ok = _resolve_session(session, auth_str)
    if not ok:
        return
    console.print(f"[cyan]Pattern :[/cyan] {pattern.get('name')}")
    console.print(f"[cyan]Target  :[/cyan] {target}")
    console.print(f"[cyan]Category:[/cyan] {pattern.get('_category')}")
    console.print("[dim]Running...[/dim]")
    out = _run_single(pattern_id, target, auth_str, overrides,
                       default_headers=headers, cookies=cookies)
    if not out:
        console.print("[red]Execution failed[/red]")
        return
    result = out["result"]
    color = VERDICT_COLOR.get(result["verdict"], "white")
    console.print()
    console.print(f"  [{color}]{result['verdict']}[/{color}]  {result.get('reason')}")
    ev = result.get("evidence") or {}
    if ev:
        console.print(f"  [dim]evidence: {json.dumps(ev, default=str)[:300]}[/dim]")
    path = _record_and_save(pattern_id, target, out)
    console.print(f"  [dim]saved: {path}[/dim]")
    return _compute_fail_exit(
        [{"severity": pattern.get("severity", "info"), "verdict": result["verdict"]}],
        fail_on)


def cmd_scan_all(args):
    if not args:
        console.print("[red]Usage: scan-all <target> [--auth X] [--session NAME][/red]")
        return
    target = args[0]
    auth_str = None
    session = None
    min_sev = "info"
    cat_filter = None
    fail_on = None
    i = 1
    while i < len(args):
        if args[i] == "--auth" and i + 1 < len(args):
            auth_str = args[i + 1]
            i += 2
        elif args[i] == "--session" and i + 1 < len(args):
            session = args[i + 1]
            i += 2
        elif args[i] == "--min-severity" and i + 1 < len(args):
            min_sev = args[i + 1].lower()
            i += 2
        elif args[i] == "--category" and i + 1 < len(args):
            cat_filter = args[i + 1].lower()
            i += 2
        elif args[i] == "--fail-on" and i + 1 < len(args):
            fail_on = args[i + 1]
            i += 2
        else:
            i += 1
    headers, cookies, ok = _resolve_session(session, auth_str)
    if not ok:
        return
    patterns = loader.list_patterns()
    if cat_filter:
        patterns = [p for p in patterns if p["category"] == cat_filter]
    threshold = SEVERITY_RANK.get(min_sev, 1)
    patterns = [p for p in patterns if SEVERITY_RANK.get(p["severity"], 0) >= threshold]
    allow_destructive = bool(RUNTIME.get("allow_destructive"))
    if not allow_destructive:
        skipped = []
        keep = []
        for p in patterns:
            full = loader.load_pattern(p["id"]) or {}
            if full.get("destructive") or full.get("opt_in"):
                skipped.append(p["id"])
                continue
            keep.append(p)
        patterns = keep
        if skipped:
            console.print(f"[yellow]Skipping {len(skipped)} destructive/opt-in "
                          f"pattern(s): {', '.join(skipped[:5])}"
                          f"{'...' if len(skipped) > 5 else ''}[/yellow]")
            console.print("[dim]  pass --allow-destructive to authorize them[/dim]")
    if not patterns:
        console.print("[yellow]No patterns match filter.[/yellow]")
        return
    console.print(f"[cyan]Target   :[/cyan] {target}")
    console.print(f"[cyan]Patterns :[/cyan] {len(patterns)}")
    console.print(f"[cyan]Min sev  :[/cyan] {min_sev}")
    console.print()
    t = Table(title="Scan Results")
    t.add_column("Pattern", style="cyan")
    t.add_column("Severity", style="yellow")
    t.add_column("Verdict", style="bold")
    t.add_column("Reason", style="white")
    from concurrent.futures import ThreadPoolExecutor
    engine_cfg = load_engine()
    max_workers = int(engine_cfg.get("concurrency", {}).get("max_workers", 8))
    max_workers = max(1, min(max_workers, len(patterns)))
    console.print(f"[dim]Workers: {max_workers}[/dim]")

    def _one(p):
        return p, _run_single(p["id"], target, auth_str,
                              default_headers=headers, cookies=cookies)

    t0 = time.perf_counter()
    results_map = {}
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(_one, p) for p in patterns]
        for f in futures:
            try:
                p, out = f.result()
                results_map[p["id"]] = out
            except Exception as e:
                console.print(f"[red]worker error: {e}[/red]")

    counts = {"VULNERABLE": 0, "SUSPICIOUS": 0, "PASS": 0, "UNKNOWN": 0}
    scan_results = []
    for p in patterns:
        pid = p["id"]
        out = results_map.get(pid)
        if not out:
            continue
        result = out["result"]
        verdict = result["verdict"]
        counts[verdict] = counts.get(verdict, 0) + 1
        scan_results.append({"severity": p["severity"], "verdict": verdict})
        color = VERDICT_COLOR.get(verdict, "white")
        t.add_row(pid, p["severity"], f"[{color}]{verdict}[/{color}]",
                   (result.get("reason") or "")[:60])
        _record_and_save(pid, target, out, category=p["category"])
    elapsed = (time.perf_counter() - t0) * 1000.0
    console.print(t)
    console.print()
    console.print(f"  [bold red]VULNERABLE[/bold red]: {counts['VULNERABLE']}")
    console.print(f"  [bold yellow]SUSPICIOUS[/bold yellow]: {counts['SUSPICIOUS']}")
    console.print(f"  [bold green]PASS[/bold green]      : {counts['PASS']}")
    console.print(f"  [dim]UNKNOWN[/dim]   : {counts['UNKNOWN']}")
    ledger.record_run(target, len(patterns), counts["VULNERABLE"], elapsed)
    return _compute_fail_exit(scan_results, fail_on)


def _make_brain(name):
    if name in ("llm", "ai"):
        try:
            from .brains.llm import make_llm_client, LLMBrain
            bcfg = (load_engine() or {}).get("brain") or {}
            lcfg = bcfg.get("llm") or {}
            model = lcfg.get("model") or bcfg.get("model") or "gpt-4o-mini"
            client = make_llm_client(
                provider=lcfg.get("provider") or bcfg.get("provider") or "openai",
                model=model, base_url=lcfg.get("base_url"),
                env_name=lcfg.get("api_key_env"))
            console.print(f"[dim]LLM brain: provider="
                          f"{lcfg.get('provider') or bcfg.get('provider')} model={model}[/dim]")
            return LLMBrain(client=client, model=model)
        except Exception as e:
            console.print(f"[yellow]LLM brain unavailable ({e}); using rule-based.[/yellow]")
    from .brains.rule_based import RuleBasedBrain
    return RuleBasedBrain()


def _run_orchestrated(url, profile, brain_name, fail_on, allow_destructive=False,
                      credentials=None):
    from .orchestrator import Orchestrator
    brain = _make_brain(brain_name)
    console.print(f"[cyan]Orchestrated scan[/cyan] profile=[bold]{profile}[/bold] "
                  f"brain=[bold]{brain.__class__.__name__}[/bold]")
    if allow_destructive:
        console.print("[bold red]--allow-destructive:[/bold red] destructive "
                      "capabilities are ENABLED for this run")
    orc = Orchestrator(console=console, allow_destructive=allow_destructive)
    state = orc.run(url, profile=profile, brain=brain,
                     allow_destructive=allow_destructive, credentials=credentials)
    counts = {"VULNERABLE": 0, "SUSPICIOUS": 0, "PASS": 0, "UNKNOWN": 0}
    results = []
    for f in getattr(state, "findings", []) or []:
        v = f.verdict.value if hasattr(f.verdict, "value") else str(f.verdict)
        counts[v] = counts.get(v, 0) + 1
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        results.append({"verdict": v, "severity": sev})
    console.print(f"  iterations={getattr(state, 'iterations', 0)} "
                  f"capabilities={len(getattr(state, 'executed_capabilities', []) or [])} "
                  f"chains={len(getattr(state, 'chains', []) or [])}")
    console.print(f"  [bold red]VULNERABLE[/bold red]: {counts['VULNERABLE']}  "
                  f"[bold yellow]SUSPICIOUS[/bold yellow]: {counts['SUSPICIOUS']}  "
                  f"[bold green]PASS[/bold green]: {counts['PASS']}  "
                  f"[dim]UNKNOWN[/dim]: {counts['UNKNOWN']}")
    console.print(f"[dim]Run 'chains {url}' and 'coverage {url}' for detail.[/dim]")
    return _compute_fail_exit(results, fail_on)


def cmd_auto(args):
    if not args or "--help" in args or "-h" in args:
        console.print("[cyan]Usage: auto <url> [--min-severity X] [--adapter ID] "
                      "[--profile quick|standard|deep] [--brain rule|llm] "
                      "[--login user:pass] [--login-url URL][/cyan]")
        console.print("  --profile    orchestrated multi-pass scan with a budget (opt-in)")
        console.print("  --brain      rule (deterministic, default) or llm (opt-in, needs API key)")
        console.print("  --login      username:password — log in before scanning")
        console.print("  --login-url  explicit login endpoint (skip auto-discovery)")
        return 0
    from . import auto as auto_mod
    url = args[0]
    min_sev = "medium"
    skip = False
    adapter_override = None
    auto_baseline = False
    fail_on = None
    profile = None
    brain_name = None
    banking = False
    login_str = None
    login_url = None
    i = 1
    while i < len(args):
        if args[i] == "--min-severity" and i + 1 < len(args):
            min_sev = args[i + 1]
            i += 2
        elif args[i] == "--banking":
            banking = True
            i += 1
        elif args[i] == "--no-discovery":
            skip = True
            i += 1
        elif args[i] == "--adapter" and i + 1 < len(args):
            adapter_override = args[i + 1]
            i += 2
        elif args[i] == "--auto-baseline":
            auto_baseline = True
            i += 1
        elif args[i] == "--fail-on" and i + 1 < len(args):
            fail_on = args[i + 1]
            i += 2
        elif args[i] == "--profile" and i + 1 < len(args):
            profile = args[i + 1]
            i += 2
        elif args[i] == "--brain" and i + 1 < len(args):
            brain_name = args[i + 1]
            i += 2
        elif args[i] == "--login" and i + 1 < len(args):
            login_str = args[i + 1]
            i += 2
        elif args[i] == "--login-url" and i + 1 < len(args):
            login_url = args[i + 1]
            i += 2
        else:
            i += 1
    allow_destructive = bool(RUNTIME.get("allow_destructive"))
    credentials = None
    if login_str and ":" in login_str:
        username, _, password = login_str.partition(":")
        credentials = {"username": username, "password": password}
        if login_url:
            credentials["login_url"] = login_url
    if RUNTIME.get("dry_run"):
        console.print(f"[cyan]DRY RUN[/cyan] would scan: {url}")
        console.print(f"[dim]  min-severity={min_sev} "
                      f"allow-destructive={allow_destructive} "
                      f"skip-discovery={skip}[/dim]")
        return 0
    if profile or brain_name:
        return _run_orchestrated(url, profile or "standard", brain_name, fail_on,
                                  allow_destructive=allow_destructive,
                                  credentials=credentials)
    outcome = auto_mod.run_auto(url, min_severity=min_sev, skip_discovery=skip,
                                adapter_override=adapter_override,
                                auto_baseline=auto_baseline,
                                allow_destructive=allow_destructive,
                                banking=banking, credentials=credentials)
    results = (outcome or {}).get("results", [])
    return _compute_fail_exit(results, fail_on)


def cmd_profile(args):
    if not args:
        console.print("[red]Usage: profile <url> [--samples N][/red]")
        return
    url = args[0]
    samples = 50
    auth_str = None
    i = 1
    while i < len(args):
        if args[i] == "--samples" and i + 1 < len(args):
            samples = int(args[i + 1])
            i += 2
        elif args[i] == "--auth" and i + 1 < len(args):
            auth_str = args[i + 1]
            i += 2
        else:
            i += 1
    headers = _parse_auth(auth_str) or {}
    console.print(f"[cyan]Profiling:[/cyan] {url}")
    prof = baseline.profile_endpoint(url, samples=samples, headers=headers)
    if not prof:
        console.print("[red]No successful samples.[/red]")
        return
    t = Table(title="Baseline Profile")
    t.add_column("Metric", style="cyan")
    t.add_column("Value", style="white")
    for key in ["sample_count", "mean_ms", "stdev_ms", "min_ms", "max_ms",
                "p50_ms", "p95_ms", "p99_ms", "distinct_bodies"]:
        t.add_row(key, str(prof.get(key)))
    console.print(t)
    path = baseline.save_baseline(url, prof)
    console.print(f"[dim]Saved: {path}[/dim]")


def cmd_login(args):
    if not args:
        console.print("[red]Usage: login <target_name>[/red]")
        return
    name = args[0]
    spec = get_target(name)
    if not spec:
        console.print(f"[red]Target not found: {name}[/red]")
        return
    auth = spec.get("auth", {})
    if not isinstance(auth, dict):
        console.print("[red]Invalid auth config[/red]")
        return
    login_url = auth.get("login_url")
    username = auth.get("username")
    password = auth.get("password")
    if not (login_url and username and password):
        console.print("[red]Missing login_url/username/password[/red]")
        return
    console.print(f"[cyan]Login URL:[/cyan] {login_url}")
    result = auth_flow.perform_login(
        login_url, username, password,
        login_type=auth.get("login_type", "json"),
        username_field=auth.get("username_field", "email"),
        password_field=auth.get("password_field", "password"),
        token_path=auth.get("token_path"),
        token_header=auth.get("token_header", "Authorization"),
        token_prefix=auth.get("token_prefix", "Bearer "),
    )
    console.print()
    console.print(f"  Status : {result.get('status')}")
    if result.get("error"):
        console.print(f"  [red]Error: {result['error']}[/red]")
        return
    if result.get("token"):
        console.print(f"  [green]Token extracted[/green] ({len(result['token'])} chars)")
    elif result.get("cookies"):
        console.print(f"  [green]Cookies: {list(result['cookies'].keys())}[/green]")
    else:
        console.print("  [yellow]No token or cookies[/yellow]")
        preview = result.get("raw_body_preview", "")[:200]
        if preview:
            console.print(f"  [dim]{preview}[/dim]")
    path = save_session(name, result)
    console.print(f"  [dim]Session: {path}[/dim]")


def cmd_sessions(args):
    sessions = list_sessions()
    if not sessions:
        console.print("[yellow]No saved sessions.[/yellow]")
        return
    t = Table(title="Saved Sessions")
    t.add_column("Name", style="cyan")
    for s in sessions:
        t.add_row(s)
    console.print(t)


def cmd_enumerate(args):
    if not args:
        console.print("[red]Usage: enumerate <base_url>[/red]")
        return
    base_url = args[0]
    wordlist = "common_paths"
    session = None
    auth_str = None
    i = 1
    while i < len(args):
        if args[i] == "--wordlist" and i + 1 < len(args):
            wordlist = args[i + 1]
            i += 2
        elif args[i] == "--session" and i + 1 < len(args):
            session = args[i + 1]
            i += 2
        elif args[i] == "--auth" and i + 1 < len(args):
            auth_str = args[i + 1]
            i += 2
        else:
            i += 1
    headers, cookies, ok = _resolve_session(session, auth_str)
    if not ok:
        return
    console.print(f"[cyan]Base URL:[/cyan] {base_url}")
    results = route_enum.enumerate_routes(base_url, wordlist=wordlist,
                                            headers=headers, cookies=cookies)
    interesting = [r for r in results if r.get("interesting")]
    t = Table(title=f"Discovered ({len(interesting)} interesting / {len(results)} total)")
    t.add_column("Path", style="cyan")
    t.add_column("Status", style="yellow")
    t.add_column("Size", style="white")
    for r in interesting[:40]:
        t.add_row(r["path"], str(r.get("status")), str(r.get("content_length", 0)))
    console.print(t)


_LOOPBACK = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def _resolve_report_target(target):
    rows = ledger.findings_for_target(target)
    if rows:
        return target
    from urllib.parse import urlparse
    host = urlparse(target).hostname or ""
    if not host:
        return target
    host_is_loopback = host in _LOOPBACK
    for t in ledger.all_targets():
        t_host = urlparse(t).hostname or ""
        if t_host == host:
            return t
        if host_is_loopback and t_host in _LOOPBACK:
            return t
    return target


def cmd_report(args):
    if not args:
        console.print("[red]Usage: report <target> [--format html|md|pdf|sarif][/red]")
        return
    target = args[0]
    fmt = "html"
    i = 1
    while i < len(args):
        if args[i] == "--format" and i + 1 < len(args):
            fmt = args[i + 1]
            i += 2
        else:
            i += 1
    resolved = _resolve_report_target(target)
    if resolved != target:
        console.print(f"[dim]Resolved target: {resolved}[/dim]")
    path = report.generate(resolved, fmt=fmt)
    console.print(f"[green]Report:[/green] {path}")


def cmd_web(args):
    host = "127.0.0.1"
    port = 8900
    i = 0
    while i < len(args):
        if args[i] == "--port" and i + 1 < len(args):
            port = int(args[i + 1])
            i += 2
        elif args[i] == "--host" and i + 1 < len(args):
            host = args[i + 1]
            i += 2
        else:
            i += 1
    from . import webui
    httpd = webui.serve(host=host, port=port)
    url = f"http://{host}:{port}"
    console.print(f"[bold cyan]sec-checker web UI[/bold cyan]")
    console.print(f"  Open: [green]{url}[/green]")
    console.print(f"  [dim]Enter a target URL in the page. ROE scope still applies "
                  f"(configs/roe.yaml).[/dim]")
    console.print(f"  [dim]Ctrl+C to stop.[/dim]")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopping web UI...[/yellow]")
    finally:
        httpd.shutdown()
        httpd.server_close()


def cmd_smuggle(args):
    if not args:
        console.print("[red]Usage: smuggle <target_url> [--timeout N] "
                      "[--threshold-ms N] [--fail-on SEV][/red]")
        return
    target = args[0]
    timeout = 5.0
    threshold_ms = 3000.0
    fail_on = None
    i = 1
    while i < len(args):
        if args[i] == "--timeout" and i + 1 < len(args):
            timeout = float(args[i + 1])
            i += 2
        elif args[i] == "--threshold-ms" and i + 1 < len(args):
            threshold_ms = float(args[i + 1])
            i += 2
        elif args[i] == "--fail-on" and i + 1 < len(args):
            fail_on = args[i + 1]
            i += 2
        else:
            i += 1
    from . import smuggle
    console.print(f"[cyan]HTTP smuggling timing probe:[/cyan] {target}")
    out = smuggle.probe(target, timeout=timeout, threshold_ms=threshold_ms)
    if out.get("error"):
        console.print(f"  [dim]baseline note: {out['error']}[/dim]")
    result = out["result"]
    color = VERDICT_COLOR.get(result["verdict"], "white")
    console.print(f"  [{color}]{result['verdict']}[/{color}]  {result.get('reason')}")
    for d in (result.get("evidence", {}) or {}).get("delayed", []):
        console.print(f"    [yellow]{d['vector'].upper()}[/yellow]  "
                      f"{d['elapsed_ms']:.0f}ms  timed_out={d['timed_out']}")
    ledger.record_finding(
        pattern_id="http-request-smuggling", target=target,
        verdict=result["verdict"], severity="high",
        reason=result.get("reason", ""), evidence_path="",
        evidence_json=result.get("evidence", {}), category="sequence",
        wstg_id="WSTG-INPV-15", cwe_id="CWE-444")
    return _compute_fail_exit(
        [{"severity": "high", "verdict": result["verdict"]}], fail_on)


def cmd_explore(args):
    if not args:
        console.print("[red]Usage: explore <base_url> --paths /a,/b,/c "
                      "[--methods GET,POST] [--strategy pairwise|cartesian] "
                      "[--session NAME] [--auth X] [--fail-on SEV][/red]")
        return
    base = args[0]
    paths = ["/"]
    methods = ["GET"]
    strategy = "pairwise"
    auth_str = None
    session = None
    fail_on = None
    i = 1
    while i < len(args):
        if args[i] == "--paths" and i + 1 < len(args):
            paths = [p for p in args[i + 1].split(",") if p]
            i += 2
        elif args[i] == "--methods" and i + 1 < len(args):
            methods = [m.upper() for m in args[i + 1].split(",") if m]
            i += 2
        elif args[i] == "--strategy" and i + 1 < len(args):
            strategy = args[i + 1]
            i += 2
        elif args[i] == "--auth" and i + 1 < len(args):
            auth_str = args[i + 1]
            i += 2
        elif args[i] == "--session" and i + 1 < len(args):
            session = args[i + 1]
            i += 2
        elif args[i] == "--fail-on" and i + 1 < len(args):
            fail_on = args[i + 1]
            i += 2
        else:
            i += 1
    headers, cookies, ok = _resolve_session(session, auth_str)
    if not ok:
        return
    from . import combo
    dims = {"method": methods, "path": paths}
    console.print(f"[cyan]Combination explorer:[/cyan] {base}  "
                  f"({strategy}, {len(methods)} methods x {len(paths)} paths)")
    out = combo.explore(base, dims, strategy=strategy, headers=headers, cookies=cookies)
    console.print(f"  combos run: {out['combos_run']}")
    result = out["analysis"]
    color = VERDICT_COLOR.get(result["verdict"], "white")
    console.print(f"  [{color}]{result['verdict']}[/{color}]  {result.get('reason')}")
    for o in (result.get("evidence", {}) or {}).get("outliers", [])[:10]:
        console.print(f"    [yellow]outlier[/yellow] {o['status']}  {o['combo']}")
    ledger.record_finding(
        pattern_id="combination-explorer", target=base, verdict=result["verdict"],
        severity="medium", reason=result.get("reason", ""), evidence_path="",
        evidence_json=result.get("evidence", {}), category="combination")
    return _compute_fail_exit(
        [{"severity": "medium", "verdict": result["verdict"]}], fail_on)


def cmd_xss(args):
    if len(args) < 2:
        console.print("[red]Usage: xss <target_url> <param> "
                      "[--session NAME] [--auth X] [--fail-on SEV][/red]")
        return
    target = args[0]
    param = args[1]
    auth_str = None
    session = None
    fail_on = None
    i = 2
    while i < len(args):
        if args[i] == "--auth" and i + 1 < len(args):
            auth_str = args[i + 1]
            i += 2
        elif args[i] == "--session" and i + 1 < len(args):
            session = args[i + 1]
            i += 2
        elif args[i] == "--fail-on" and i + 1 < len(args):
            fail_on = args[i + 1]
            i += 2
        else:
            i += 1
    headers, cookies, ok = _resolve_session(session, auth_str)
    if not ok:
        return
    from . import xss
    console.print(f"[cyan]Blind XSS probe:[/cyan] {target}  param={param}")
    try:
        out = xss.probe(target, param, headers=headers, cookies=cookies)
    except Exception as e:
        console.print(f"[red]{type(e).__name__}: {e}[/red]")
        return 1
    console.print(f"  OOB listener: {out['oob_base']}")
    console.print(f"  payloads tried: {len(out['attempts'])}")
    result = out["result"]
    color = VERDICT_COLOR.get(result["verdict"], "white")
    console.print(f"  [{color}]{result['verdict']}[/{color}]  {result.get('reason')}")
    ledger.record_finding(
        pattern_id="blind-xss", target=target, verdict=result["verdict"],
        severity="high", reason=result.get("reason", ""), evidence_path="",
        evidence_json=result.get("evidence", {}), category="sequence",
        wstg_id="WSTG-INPV-01", cwe_id="CWE-79")
    return _compute_fail_exit(
        [{"severity": "high", "verdict": result["verdict"]}], fail_on)


def cmd_ssrf(args):
    if not args:
        console.print("[red]Usage: ssrf <target_url> [--method GET|POST] "
                      "[--session NAME] [--auth X] [--fail-on SEV][/red]")
        return
    target = args[0]
    auth_str = None
    session = None
    method = "GET"
    fail_on = None
    i = 1
    while i < len(args):
        if args[i] == "--auth" and i + 1 < len(args):
            auth_str = args[i + 1]
            i += 2
        elif args[i] == "--session" and i + 1 < len(args):
            session = args[i + 1]
            i += 2
        elif args[i] == "--method" and i + 1 < len(args):
            method = args[i + 1].upper()
            i += 2
        elif args[i] == "--fail-on" and i + 1 < len(args):
            fail_on = args[i + 1]
            i += 2
        else:
            i += 1
    headers, cookies, ok = _resolve_session(session, auth_str)
    if not ok:
        return
    from . import ssrf
    console.print(f"[cyan]Blind SSRF probe:[/cyan] {target}")
    out = ssrf.probe(target, method=method, headers=headers, cookies=cookies)
    console.print(f"  OOB listener: {out['oob_base']}")
    console.print(f"  vectors injected: {len(out['injected'])}")
    result = out["result"]
    color = VERDICT_COLOR.get(result["verdict"], "white")
    console.print(f"  [{color}]{result['verdict']}[/{color}]  {result.get('reason')}")
    for c in out["callbacks"]:
        console.print(f"    [red]callback[/red] via {c['vector']} ({c['hits']} hit(s))")
    ledger.record_finding(
        pattern_id="blind-ssrf", target=target, verdict=result["verdict"],
        severity="high", reason=result.get("reason", ""), evidence_path="",
        evidence_json=result.get("evidence", {}), category="sequence",
        wstg_id="WSTG-INPV-19", cwe_id="CWE-918")
    return _compute_fail_exit(
        [{"severity": "high", "verdict": result["verdict"]}], fail_on)


def cmd_idor(args):
    if len(args) < 2:
        console.print("[red]Usage: idor <identity_url> <resource_base> "
                      "[--session NAME] [--auth X] [--fail-on SEV][/red]")
        return
    identity_url = args[0]
    resource_base = args[1]
    auth_str = None
    session = None
    fail_on = None
    i = 2
    while i < len(args):
        if args[i] == "--auth" and i + 1 < len(args):
            auth_str = args[i + 1]
            i += 2
        elif args[i] == "--session" and i + 1 < len(args):
            session = args[i + 1]
            i += 2
        elif args[i] == "--fail-on" and i + 1 < len(args):
            fail_on = args[i + 1]
            i += 2
        else:
            i += 1
    headers, cookies, ok = _resolve_session(session, auth_str)
    if not ok:
        return
    from . import idor
    console.print(f"[cyan]IDOR probe[/cyan]  identity={identity_url}  "
                  f"resource={resource_base}")
    out = idor.run_probe(identity_url, resource_base, headers=headers, cookies=cookies)
    if out.get("error"):
        console.print(f"[red]{out['error']}[/red]")
    if out.get("ids_found"):
        console.print(f"  ids found: {out['ids_found']}")
    result = out.get("result") or {"verdict": "UNKNOWN", "reason": "no result"}
    color = VERDICT_COLOR.get(result["verdict"], "white")
    console.print(f"  [{color}]{result['verdict']}[/{color}]  {result.get('reason')}")
    ev = result.get("evidence") or {}
    if ev:
        console.print(f"  [dim]evidence: {json.dumps(ev, default=str)[:300]}[/dim]")
    ledger.record_finding(
        pattern_id="idor-live-probe", target=resource_base,
        verdict=result["verdict"], severity="high",
        reason=result.get("reason", ""), evidence_path="",
        evidence_json=ev, category="sequence",
        wstg_id="WSTG-ATHZ-04", cwe_id="CWE-639")
    return _compute_fail_exit(
        [{"severity": "high", "verdict": result["verdict"]}], fail_on)


def cmd_browser(args):
    if not args:
        console.print("[red]Usage: browser <url> [--session NAME] [--auth X] "
                      "[--no-screenshot][/red]")
        return
    url = args[0]
    auth_str = None
    session = None
    screenshot = True
    i = 1
    while i < len(args):
        if args[i] == "--auth" and i + 1 < len(args):
            auth_str = args[i + 1]
            i += 2
        elif args[i] == "--session" and i + 1 < len(args):
            session = args[i + 1]
            i += 2
        elif args[i] == "--no-screenshot":
            screenshot = False
            i += 1
        else:
            i += 1
    headers, cookies, ok = _resolve_session(session, auth_str)
    if not ok:
        return
    from . import browser
    console.print(f"[cyan]Browser capture:[/cyan] {url}")
    try:
        r = browser.capture(url, headers=headers, cookies=cookies, screenshot=screenshot)
    except browser.BrowserUnavailable as e:
        console.print(f"[red]{e}[/red]")
        return 2
    if r.get("error"):
        console.print(f"[red]{r['error']}[/red]")
        return 1
    console.print(f"  status      : {r['status']}")
    console.print(f"  title       : {r['title']}")
    console.print(f"  final_url   : {r['final_url']}")
    console.print(f"  console msgs: {len(r['console'])}")
    errs = browser.console_errors(r)
    if errs:
        console.print(f"  [yellow]console errors/warnings: {len(errs)}[/yellow]")
        for m in errs[:5]:
            console.print(f"    [dim]{m['type']}: {m['text'][:100]}[/dim]")
    if r["page_errors"]:
        console.print(f"  [red]JS errors: {len(r['page_errors'])}[/red]")
        for e in r["page_errors"][:5]:
            console.print(f"    [dim]{e[:120]}[/dim]")
    if r["failed_requests"]:
        console.print(f"  [yellow]failed requests: {len(r['failed_requests'])}[/yellow]")
    if r["screenshot"]:
        console.print(f"  [green]screenshot  :[/green] {r['screenshot']}")
    return 0


def cmd_history(args):
    target = None
    i = 0
    while i < len(args):
        if args[i] == "--target" and i + 1 < len(args):
            target = args[i + 1]
            i += 2
        else:
            i += 1
    rows = ledger.recent_findings(limit=30, target=target)
    if not rows:
        console.print("[yellow]No findings.[/yellow]")
        return
    t = Table(title="Recent Findings")
    t.add_column("ID", style="dim")
    t.add_column("When", style="dim")
    t.add_column("Pattern", style="cyan")
    t.add_column("Target", style="white")
    t.add_column("Verdict", style="bold")
    t.add_column("Severity", style="yellow")
    for r in rows:
        color = VERDICT_COLOR.get(r[4], "white")
        t.add_row(str(r[0]), r[1][:19], r[2], r[3][:40],
                   f"[{color}]{r[4]}[/{color}]", r[5])
    console.print(t)


def cmd_targets(args):
    targets = load_targets().get("targets", {})
    if not targets:
        console.print("[yellow]No targets configured.[/yellow]")
        return
    t = Table(title="Configured Targets")
    t.add_column("Name", style="cyan")
    t.add_column("URL", style="white")
    t.add_column("Auth", style="yellow")
    for name, spec in targets.items():
        auth = spec.get("auth", {})
        auth_type = auth.get("type", "none") if isinstance(auth, dict) else "none"
        t.add_row(name, spec.get("url", ""), auth_type)
    console.print(t)


def cmd_llm(args):
    # a2.py-patch:cmd_llm
    if not args or "--help" in args or "-h" in args:
        console.print("Usage: llm <url>")
        console.print("  Runs OWASP LLM Top 10 probes. Target must be in ROE scope.")
        return 0
    from . import llm_security as _mod
    try:
        from .roe_guard import ROEGuard
        from .config import load_engine
    except Exception as _e:
        console.print(f"[yellow]ROE guard init: {_e}[/yellow]")
    url = args[0]
    model = "gpt-3.5-turbo"
    api_key = None
    auth_str = None
    session = None
    fail_on = None
    i = 1
    while i < len(args):
        if args[i] == "--model" and i + 1 < len(args):
            model = args[i + 1]
            i += 2
        elif args[i] == "--api-key" and i + 1 < len(args):
            api_key = args[i + 1]
            i += 2
        elif args[i] == "--auth" and i + 1 < len(args):
            auth_str = args[i + 1]
            i += 2
        elif args[i] == "--session" and i + 1 < len(args):
            session = args[i + 1]
            i += 2
        elif args[i] == "--fail-on" and i + 1 < len(args):
            fail_on = args[i + 1]
            i += 2
        else:
            i += 1
    headers, cookies, ok = _resolve_session(session, auth_str)
    if not ok:
        return
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    headers["Content-Type"] = "application/json"
    from . import llm_security
    console.print(f"[cyan]LLM security scan:[/cyan] {url}")
    console.print(f"[dim]Model: {model}[/dim]")
    console.print()
    from .roe_guard import ROEGuard
    from .config import load_engine as _load_engine
    _guard = ROEGuard(engine_cfg=_load_engine())
    results = llm_security.scan(url, model=model, headers=headers, roe_guard=_guard)
    raw_results = []
    if isinstance(results, dict):
        raw_results = results.get("results") or results.get("items") or []
    elif hasattr(results, "raw"):
        raw = results.raw or {}
        raw_results = raw.get("results") or raw.get("items") or []
    if not raw_results and hasattr(results, "findings"):
        raw_results = [f.to_dict() for f in results.findings]
    t = Table(title="LLM Security Results")
    t.add_column("Category", style="cyan")
    t.add_column("OWASP", style="magenta")
    t.add_column("Severity", style="yellow")
    t.add_column("Verdict", style="bold")
    t.add_column("Reason", style="white")
    counts = {"VULNERABLE": 0, "SUSPICIOUS": 0, "PASS": 0, "UNKNOWN": 0}
    for r in raw_results:
        verdict = r["verdict"]
        counts[verdict] = counts.get(verdict, 0) + 1
        color = VERDICT_COLOR.get(verdict, "white")
        t.add_row(
            escape(r["category"]),
            escape(r.get("owasp", "")),
            escape(r["severity"]),
            f"[{color}]{verdict}[/{color}]",
            escape(r["reason"][:60]),
        )
    console.print(t)
    console.print()
    console.print(f"  [bold red]VULNERABLE[/bold red]: {counts['VULNERABLE']}")
    console.print(f"  [bold green]PASS[/bold green]      : {counts['PASS']}")
    console.print(f"  [dim]UNKNOWN[/dim]   : {counts['UNKNOWN']}")
    for r in results:
        ledger.record_finding(
            pattern_id=f"llm-{r['category']}",
            target=url,
            verdict=r["verdict"],
            severity=r["severity"],
            reason=r["reason"],
            evidence_path="",
            evidence_json=r.get("evidence", {}),
            category="llm",
        )
    return _compute_fail_exit(
        [{"severity": r["severity"], "verdict": r["verdict"]} for r in results],
        fail_on,
    )


def cmd_sca(args):
    # a2.py-patch:cmd_sca
    if not args or "--help" in args or "-h" in args:
        console.print("Usage: sca <path> [--sbom cyclonedx|spdx] [--out FILE] [--fail-on SEV]")
        console.print("  Supply chain / SCA scan via OSV.dev (external DB, not target-gated).")
        return 0
    from . import sca as _mod
    try:
        from .roe_guard import ROEGuard
        from .config import load_engine
    except Exception as _e:
        console.print(f"[yellow]ROE guard init: {_e}[/yellow]")
    if not args:
        console.print("[red]Usage: sca <path> [--sbom cyclonedx|spdx] "
                      "[--out FILE] [--fail-on SEV][/red]")
        return
    path = args[0]
    sbom_format = None
    out_file = None
    fail_on = None
    i = 1
    while i < len(args):
        if args[i] == "--sbom" and i + 1 < len(args):
            sbom_format = args[i + 1].lower()
            i += 2
        elif args[i] == "--out" and i + 1 < len(args):
            out_file = args[i + 1]
            i += 2
        elif args[i] == "--fail-on" and i + 1 < len(args):
            fail_on = args[i + 1]
            i += 2
        else:
            i += 1
    from . import sca, sbom
    console.print(f"[cyan]SCA scan:[/cyan] {path}")
    result = sca.scan_dependencies(path)
    files = result.get("files") or []
    deps = result.get("dependencies") or []
    findings = result.get("vulnerabilities") or []
    counts = result.get("summary") or {}
    console.print(f"[dim]Dependency files: {len(files)}[/dim]")
    for f in files:
        console.print(f"  [dim]{f}[/dim]")
    console.print(f"[dim]Dependencies: {len(deps)}[/dim]")
    console.print()
    if findings:
        t = Table(title="Vulnerable Dependencies")
        t.add_column("Severity", style="yellow")
        t.add_column("Package", style="cyan")
        t.add_column("Version", style="white")
        t.add_column("Vuln ID", style="magenta")
        t.add_column("CVE", style="magenta")
        t.add_column("Source", style="dim")
        for f in findings[:50]:
            color = "bold red" if f["severity"] in ("critical", "high") else "yellow"
            t.add_row(
                f"[{color}]{f['severity']}[/{color}]",
                escape(f["dependency"]["name"]),
                escape(f["dependency"].get("version", "")),
                escape(f["vuln_id"]),
                escape(f.get("cve", "")),
                escape(f.get("source_file", "")[:40]),
            )
        console.print(t)
        console.print()
    console.print(f"  [bold red]Critical[/bold red]: {counts.get('critical', 0)}")
    console.print(f"  [bold red]High[/bold red]    : {counts.get('high', 0)}")
    console.print(f"  [yellow]Medium[/yellow]    : {counts.get('medium', 0)}")
    console.print(f"  [dim]Low[/dim]       : {counts.get('low', 0)}")
    if sbom_format:
        if sbom_format == "spdx":
            p = sbom.save_spdx(path, out_path=out_file)
        else:
            p = sbom.save_cyclonedx(path, out_path=out_file)
        console.print(f"[green]SBOM:[/green] {p}")
    for f in findings:
        ledger.record_finding(
            pattern_id=f"sca-{f['vuln_id']}",
            target=path,
            verdict="VULNERABLE",
            severity=f["severity"],
            reason=f"{f['dependency']['name']}@{f['dependency'].get('version','')} — {f['summary'][:200]}",
            evidence_path="",
            evidence_json={"cve": f.get("cve", ""), "aliases": f.get("aliases", []),
                           "source_file": f.get("source_file", "")},
            category="sca",
            wstg_id="WSTG-CONF-03",
            cwe_id="CWE-1104",
        )
    return _compute_fail_exit(
        [{"severity": f["severity"], "verdict": "VULNERABLE"} for f in findings],
        fail_on,
    )



def cmd_jwt(args):
    # a2.py-patch:cmd_jwt
    if not args or "--help" in args or "-h" in args:
        console.print("Usage: jwt <url> <token>")
        console.print("  JWT attack suite. Target must be in ROE scope.")
        return 0
    from . import jwt_attacks as _mod
    try:
        from .roe_guard import ROEGuard
        from .config import load_engine
    except Exception as _e:
        console.print(f"[yellow]ROE guard init: {_e}[/yellow]")
    if not args:
        console.print("[red]Usage: jwt <target_url> "
                      "[--token JWT | --token-file FILE] "
                      "[--login-url URL --username U --password P] "
                      "[--public-key FILE] [--jwks URL] [--wordlist FILE] "
                      "[--claim K=V] [--method GET|POST] "
                      "[--session NAME] [--auth X] [--fail-on SEV][/red]")
        return
    target = args[0]
    token = None
    token_file = None
    login_url = None
    username = None
    password = None
    public_key_file = None
    jwks_url = None
    wordlist_file = None
    method = "GET"
    claims = {}
    auth_str = None
    session = None
    fail_on = None
    i = 1
    while i < len(args):
        if args[i] == "--token" and i + 1 < len(args):
            token = args[i + 1]
            i += 2
        elif args[i] == "--token-file" and i + 1 < len(args):
            token_file = args[i + 1]
            i += 2
        elif args[i] == "--login-url" and i + 1 < len(args):
            login_url = args[i + 1]
            i += 2
        elif args[i] == "--username" and i + 1 < len(args):
            username = args[i + 1]
            i += 2
        elif args[i] == "--password" and i + 1 < len(args):
            password = args[i + 1]
            i += 2
        elif args[i] == "--public-key" and i + 1 < len(args):
            public_key_file = args[i + 1]
            i += 2
        elif args[i] == "--jwks" and i + 1 < len(args):
            jwks_url = args[i + 1]
            i += 2
        elif args[i] == "--wordlist" and i + 1 < len(args):
            wordlist_file = args[i + 1]
            i += 2
        elif args[i] == "--method" and i + 1 < len(args):
            method = args[i + 1].upper()
            i += 2
        elif args[i] == "--claim" and i + 1 < len(args):
            kv = args[i + 1]
            if "=" in kv:
                k, v = kv.split("=", 1)
                if v.lower() in ("true", "false"):
                    v = v.lower() == "true"
                elif v.isdigit():
                    v = int(v)
                claims[k] = v
            i += 2
        elif args[i] == "--auth" and i + 1 < len(args):
            auth_str = args[i + 1]
            i += 2
        elif args[i] == "--session" and i + 1 < len(args):
            session = args[i + 1]
            i += 2
        elif args[i] == "--fail-on" and i + 1 < len(args):
            fail_on = args[i + 1]
            i += 2
        else:
            i += 1

    from . import jwt_attacks

    headers, cookies, ok = _resolve_session(session, auth_str)
    if not ok:
        return

    if token_file and not token:
        try:
            token = Path(token_file).read_text(encoding="utf-8").strip()
        except Exception as e:
            console.print(f"[red]Cannot read token file: {e}[/red]")
            return

    if not token and login_url and username and password:
        console.print(f"[dim]Logging in at {login_url}...[/dim]")
        from . import auth_flow
        r = auth_flow.perform_login(login_url, username, password,
                                    token_path="token")
        if r.get("token"):
            token = r["token"]
            console.print(f"[green]Token acquired[/green] ({len(token)} chars)")

    if not token:
        console.print("[red]No token provided. Use --token or --login-url.[/red]")
        return

    decoded = jwt_attacks.decode_jwt(token)
    if not decoded:
        console.print("[red]Invalid JWT format[/red]")
        return

    console.print(f"[cyan]JWT attack suite:[/cyan] {target}")
    console.print(f"  alg     : {decoded['header'].get('alg')}")
    console.print(f"  kid     : {decoded['header'].get('kid', '-')}")
    console.print(f"  claims  : {list(decoded['payload'].keys())}")

    public_key = None
    if public_key_file:
        try:
            public_key = Path(public_key_file).read_text(encoding="utf-8")
            console.print(f"  pubkey  : loaded from {public_key_file}")
        except Exception as e:
            console.print(f"  [yellow]pubkey load failed: {e}[/yellow]")

    if not public_key:
        jwks_target = jwks_url or target
        from .roe_guard import ROEGuard as _ROEGuard
        from .config import load_engine as _load_engine
        found = jwt_attacks.fetch_jwks(jwks_target, roe_guard=_ROEGuard(engine_cfg=_load_engine()))
        if found:
            console.print(f"  jwks    : {found['url']}")
            keys = found["jwks"].get("keys") or []
            for k in keys:
                pem = jwt_attacks.jwk_to_pem(k)
                if pem:
                    public_key = pem
                    break
            if not public_key:
                console.print("  [yellow]no RSA keys convertible to PEM[/yellow]")

    secrets_list = None
    if wordlist_file:
        try:
            secrets_list = [l.strip() for l in Path(wordlist_file).read_text(
                encoding="utf-8").splitlines() if l.strip()]
        except Exception as e:
            console.print(f"  [yellow]wordlist load failed: {e}[/yellow]")

    from .roe_guard import ROEGuard
    from .config import load_engine as _load_engine
    _guard = ROEGuard(engine_cfg=_load_engine())
    out = jwt_attacks.run_attack_suite(
        target, token, method=method, headers=headers,
        public_key=public_key, secrets=secrets_list,
        claim_overrides=claims or None, roe_guard=_guard,
    )

    results = out.get("results") or []
    counts = out.get("summary") or {}
    if not results:
        console.print("[yellow]No attack results[/yellow]")
        return

    t = Table(title="JWT Attack Results")
    t.add_column("Vector", style="cyan")
    t.add_column("Verdict", style="bold")
    t.add_column("Reason", style="white")
    for r in results:
        color = VERDICT_COLOR.get(r["verdict"], "white")
        t.add_row(escape(r["vector"][:45]),
                  f"[{color}]{r['verdict']}[/{color}]",
                  escape((r.get("reason") or "")[:70]))
    console.print(t)
    console.print()
    console.print(f"  [bold red]VULNERABLE[/bold red]: {counts.get('VULNERABLE', 0)}")
    console.print(f"  [bold yellow]SUSPICIOUS[/bold yellow]: {counts.get('SUSPICIOUS', 0)}")
    console.print(f"  [bold green]PASS[/bold green]      : {counts.get('PASS', 0)}")
    console.print(f"  [dim]UNKNOWN[/dim]   : {counts.get('UNKNOWN', 0)}")

    for r in results:
        if r["verdict"] not in ("VULNERABLE", "SUSPICIOUS"):
            continue
        sev = "critical" if r["vector"] in (
            "alg:none", "algorithm-confusion", "embedded-jwk"
        ) else "high"
        ledger.record_finding(
            pattern_id=f"jwt-{r['vector'].split('[')[0]}",
            target=target,
            verdict=r["verdict"],
            severity=sev,
            reason=r.get("reason", ""),
            evidence_path="",
            evidence_json={"vector": r["vector"], "secret": r.get("secret", "")},
            category="sequence",
            wstg_id="WSTG-SESS-10",
            cwe_id="CWE-347",
        )
    return _compute_fail_exit(
        [{"severity": "critical" if r["vector"] in
          ("alg:none", "algorithm-confusion", "embedded-jwk") else "high",
          "verdict": r["verdict"]} for r in results],
        fail_on,
    )


def cmd_graphql(args):
    if args and ("--help" in args or "-h" in args):
        console.print("[cyan]Usage: graphql <url> [--depth N] [--batch N] "
                      "[--session NAME] [--auth X] [--fail-on SEV][/cyan]")
        console.print("  --depth N         max depth to probe (default 110)")
        console.print("  --batch N         batch size (default 50)")
        console.print("  --session NAME    saved session name")
        console.print("  --auth X          inline auth (bearer:X, cookie:X)")
        console.print("  --fail-on SEV     exit 3 if finding >= severity")
        console.print("")
        console.print("Vectors: depth bypass, array/alias batching, form-CSRF,")
        console.print("         Apollo Federation interface bypass, field suggestions")
        return 0
    if not args:
        console.print("[red]Usage: graphql <url> [--depth N] [--batch N] "
                      "[--session NAME] [--auth X] [--fail-on SEV][/red]")
        return
    url = args[0]
    max_depth = 110
    batch_size = 50
    auth_str = None
    session = None
    fail_on = None
    i = 1
    while i < len(args):
        if args[i] == "--depth" and i + 1 < len(args):
            max_depth = int(args[i + 1])
            i += 2
        elif args[i] == "--batch" and i + 1 < len(args):
            batch_size = int(args[i + 1])
            i += 2
        elif args[i] == "--auth" and i + 1 < len(args):
            auth_str = args[i + 1]
            i += 2
        elif args[i] == "--session" and i + 1 < len(args):
            session = args[i + 1]
            i += 2
        elif args[i] == "--fail-on" and i + 1 < len(args):
            fail_on = args[i + 1]
            i += 2
        else:
            i += 1
    headers, cookies, ok = _resolve_session(session, auth_str)
    if not ok:
        return
    from . import graphql_security
    from .roe_guard import ROEGuard
    from .config import load_engine as _load_engine
    guard = ROEGuard(engine_cfg=_load_engine())
    console.print(f"[cyan]GraphQL deep scan:[/cyan] {url}")
    console.print(f"[dim]Depth probe: {max_depth}  Batch: {batch_size}[/dim]")
    console.print()
    out = graphql_security.scan(url, headers=headers, roe_guard=guard,
                                max_depth=max_depth, batch_size=batch_size)
    if not out.get("endpoint"):
        console.print(f"[yellow]{out.get('reason', 'no endpoint')}[/yellow]")
        return
    endpoint = out["endpoint"]
    console.print(f"[green]Endpoint:[/green] {endpoint}")
    results = out.get("results") or {}
    intro = results.get("introspection") or {}
    if intro.get("error"):
        console.print(f"  [dim]introspection: {intro['error']}[/dim]")
    else:
        types_count = len(intro.get("types") or [])
        console.print(f"  [dim]introspection: {types_count} types visible[/dim]")
    console.print(f"  [dim]recursive field: "
                  f"{results.get('recursive_field') or 'none'}[/dim]")
    console.print()

    t = Table(title="GraphQL Deep Security Results")
    t.add_column("Vector", style="cyan")
    t.add_column("Verdict", style="bold")
    t.add_column("Reason", style="white")
    order = ["depth_limit", "batch_array", "batch_alias", "csrf_form",
             "apollo_federation", "field_suggestion"]
    counts = {"VULNERABLE": 0, "SUSPICIOUS": 0, "PASS": 0, "UNKNOWN": 0}
    for key in order:
        r = results.get(key) or {}
        v = r.get("verdict", "UNKNOWN")
        counts[v] = counts.get(v, 0) + 1
        color = VERDICT_COLOR.get(v, "white")
        t.add_row(escape(key), f"[{color}]{v}[/{color}]",
                  escape((r.get("reason") or "")[:70]))
    console.print(t)
    console.print()
    console.print(f"  [bold red]VULNERABLE[/bold red]: {counts['VULNERABLE']}")
    console.print(f"  [bold yellow]SUSPICIOUS[/bold yellow]: {counts['SUSPICIOUS']}")
    console.print(f"  [bold green]PASS[/bold green]      : {counts['PASS']}")
    console.print(f"  [dim]UNKNOWN[/dim]   : {counts['UNKNOWN']}")
    sev_map = {"depth_limit": "high", "batch_array": "medium",
               "batch_alias": "medium", "csrf_form": "high",
               "apollo_federation": "high", "field_suggestion": "low"}
    for key in order:
        r = results.get(key) or {}
        if r.get("verdict") not in ("VULNERABLE", "SUSPICIOUS"):
            continue
        ledger.record_finding(
            pattern_id=f"graphql-{key.replace('_', '-')}",
            target=endpoint,
            verdict=r["verdict"],
            severity=sev_map.get(key, "medium"),
            reason=r.get("reason", ""),
            evidence_path="",
            evidence_json=r.get("evidence", {}),
            category="sequence",
            wstg_id="WSTG-APIT-99",
            cwe_id="CWE-770",
        )
    return _compute_fail_exit(
        [{"severity": sev_map.get(k, "medium"),
          "verdict": (results.get(k) or {}).get("verdict", "UNKNOWN")}
         for k in order],
        fail_on,
    )


def cmd_race(args):
    if args and ("--help" in args or "-h" in args):
        console.print("[cyan]Usage: race <url> [--method M] [--body JSON] "
                      "[--count N] [--modes M1,M2] "
                      "[--session NAME] [--auth X] [--fail-on SEV][/cyan]")
        console.print("  --method M       HTTP method (default POST)")
        console.print("  --body JSON      request body (JSON string)")
        console.print("  --count N        concurrent requests (default 20)")
        console.print("  --modes          barrier,single_packet,timing,replay")
        console.print("                   (default: all)")
        console.print("  --session NAME   saved session name")
        console.print("  --auth X         inline auth (bearer:X, cookie:X)")
        console.print("  --fail-on SEV    exit 3 if finding >= severity")
        console.print("")
        console.print("Techniques:")
        console.print("  barrier        threading.Barrier-synchronized burst")
        console.print("  single_packet  HTTP/2 single-packet attack (Kettle 2023)")
        console.print("  timing         response-timing histogram analysis")
        console.print("  replay         idempotency / state-machine replay test")
        return 0
    if not args:
        console.print("[red]Usage: race <url> [--method M] [--body JSON] "
                      "[--count N] [--modes M1,M2] "
                      "[--session NAME] [--auth X] [--fail-on SEV][/red]")
        return
    url = args[0]
    method = "POST"
    body = None
    count = 20
    modes = None
    auth_str = None
    session = None
    fail_on = None
    i = 1
    while i < len(args):
        if args[i] == "--method" and i + 1 < len(args):
            method = args[i + 1].upper()
            i += 2
        elif args[i] == "--body" and i + 1 < len(args):
            try:
                body = json.loads(args[i + 1])
            except Exception:
                body = args[i + 1]
            i += 2
        elif args[i] == "--count" and i + 1 < len(args):
            count = int(args[i + 1])
            i += 2
        elif args[i] == "--modes" and i + 1 < len(args):
            modes = [m.strip() for m in args[i + 1].split(",") if m.strip()]
            i += 2
        elif args[i] == "--auth" and i + 1 < len(args):
            auth_str = args[i + 1]
            i += 2
        elif args[i] == "--session" and i + 1 < len(args):
            session = args[i + 1]
            i += 2
        elif args[i] == "--fail-on" and i + 1 < len(args):
            fail_on = args[i + 1]
            i += 2
        else:
            i += 1
    headers, cookies, ok = _resolve_session(session, auth_str)
    if not ok:
        return
    from . import race_advanced
    from .roe_guard import ROEGuard
    from .config import load_engine as _load_engine
    guard = ROEGuard(engine_cfg=_load_engine())
    console.print(f"[cyan]Race condition scan:[/cyan] {url}")
    console.print(f"[dim]Method: {method}  Count: {count}  "
                  f"Modes: {','.join(modes or ['all'])}[/dim]")
    console.print()
    if race_advanced.HAS_H2:
        console.print("[dim]h2 library available — single-packet attack enabled[/dim]")
    else:
        console.print("[yellow]h2 library missing — single-packet attack "
                      "will return UNKNOWN[/yellow]")
    console.print()
    out = race_advanced.race_scan(url, method=method, body=body,
                                   headers=headers, count=count, modes=modes,
                                   roe_guard=guard)
    overall = out.get("overall", "UNKNOWN")
    color = VERDICT_COLOR.get(overall, "white")
    console.print(f"  Overall: [{color}]{overall}[/{color}]")
    console.print()
    t = Table(title="Race Condition Results")
    t.add_column("Technique", style="cyan")
    t.add_column("Verdict", style="bold")
    t.add_column("Reason", style="white")
    counts = {"VULNERABLE": 0, "SUSPICIOUS": 0, "PASS": 0, "UNKNOWN": 0}
    for key in ("barrier", "single_packet", "timing", "replay"):
        r = out["results"].get(key)
        if not r:
            continue
        v = r.get("verdict", "UNKNOWN")
        counts[v] = counts.get(v, 0) + 1
        c = VERDICT_COLOR.get(v, "white")
        t.add_row(escape(key), f"[{c}]{v}[/{c}]", escape((r.get("reason") or "")[:70]))
    console.print(t)
    console.print()
    console.print(f"  [bold red]VULNERABLE[/bold red]: {counts['VULNERABLE']}")
    console.print(f"  [bold yellow]SUSPICIOUS[/bold yellow]: {counts['SUSPICIOUS']}")
    console.print(f"  [bold green]PASS[/bold green]      : {counts['PASS']}")
    console.print(f"  [dim]UNKNOWN[/dim]   : {counts['UNKNOWN']}")
    sev_map = {"barrier": "high", "single_packet": "high",
               "timing": "medium", "replay": "medium"}
    for key in ("barrier", "single_packet", "timing", "replay"):
        r = out["results"].get(key)
        if not r:
            continue
        if r.get("verdict") not in ("VULNERABLE", "SUSPICIOUS"):
            continue
        ledger.record_finding(
            pattern_id=f"race-{key.replace('_', '-')}",
            target=url,
            verdict=r["verdict"],
            severity=sev_map.get(key, "medium"),
            reason=r.get("reason", ""),
            evidence_path="",
            evidence_json=r.get("evidence", {}),
            category="temporal",
            wstg_id="WSTG-BUSL-04",
            cwe_id="CWE-362",
        )
    return _compute_fail_exit(
        [{"severity": sev_map.get(k, "medium"),
          "verdict": (out["results"].get(k) or {}).get("verdict", "UNKNOWN")}
         for k in ("barrier", "single_packet", "timing", "replay")],
        fail_on,
    )


def cmd_domxss(args):
    if args and ("--help" in args or "-h" in args):
        console.print("[cyan]Usage: domxss <url> [--timeout MS] [--no-mxss] "
                      "[--session NAME] [--auth X] [--fail-on SEV][/cyan]")
        console.print("  --timeout MS     per-navigation timeout (default 15000)")
        console.print("  --no-mxss        skip mXSS round-trip probes")
        console.print("  --session NAME   saved session name")
        console.print("  --auth X         inline auth (bearer:X, cookie:X)")
        console.print("  --fail-on SEV    exit 3 if finding >= severity")
        console.print("")
        console.print("Techniques:")
        console.print("  source→sink      location.hash/search, referrer, window.name")
        console.print("  sinks            innerHTML, outerHTML, eval, Function,")
        console.print("                   document.write, setAttribute(on*),")
        console.print("                   insertAdjacentHTML, iframe.srcdoc,")
        console.print("                   setTimeout/setInterval(str), trustedTypes")
        console.print("  trusted types    CSP require-trusted-types-for 'script'")
        console.print("  mXSS             browser re-serialization mutations")
        return 0
    if not args:
        console.print("[red]Usage: domxss <url> [--timeout MS] [--no-mxss] "
                      "[--session NAME] [--auth X] [--fail-on SEV][/red]")
        return
    url = args[0]
    timeout_ms = 15000
    include_mxss = True
    auth_str = None
    session = None
    fail_on = None
    i = 1
    while i < len(args):
        if args[i] == "--timeout" and i + 1 < len(args):
            timeout_ms = int(args[i + 1])
            i += 2
        elif args[i] == "--no-mxss":
            include_mxss = False
            i += 1
        elif args[i] == "--auth" and i + 1 < len(args):
            auth_str = args[i + 1]
            i += 2
        elif args[i] == "--session" and i + 1 < len(args):
            session = args[i + 1]
            i += 2
        elif args[i] == "--fail-on" and i + 1 < len(args):
            fail_on = args[i + 1]
            i += 2
        else:
            i += 1
    headers, cookies, ok = _resolve_session(session, auth_str)
    if not ok:
        return
    from . import dom_xss
    from .roe_guard import ROEGuard
    from .config import load_engine as _load_engine
    guard = ROEGuard(engine_cfg=_load_engine())
    console.print(f"[cyan]DOM XSS scan:[/cyan] {url}")
    console.print(f"[dim]Timeout: {timeout_ms}ms  mXSS: {include_mxss}[/dim]")
    console.print()
    out = dom_xss.scan(url, headers=headers, timeout_ms=timeout_ms,
                       roe_guard=guard, include_mxss=include_mxss)
    verdict = out.get("verdict", "UNKNOWN")
    color = VERDICT_COLOR.get(verdict, "white")
    console.print(f"  [{color}]{verdict}[/{color}]  {out.get('reason', '')}")
    console.print()
    results = out.get("results") or {}
    source_rows = results.get("sources") or []
    if source_rows:
        t = Table(title="Source Probes")
        t.add_column("Source", style="cyan")
        t.add_column("Sink hits", style="white")
        t.add_column("XSS fired", style="yellow")
        t.add_column("Error", style="dim")
        for r in source_rows:
            hit = "[green]yes[/green]" if r.get("xss_hit") else "[dim]no[/dim]"
            t.add_row(r["source"], str(r.get("sink_hits", 0)), hit,
                      (r.get("error") or "")[:40])
        console.print(t)
        console.print()
    findings = results.get("flow_findings") or []
    if findings:
        t = Table(title="Flow Findings")
        t.add_column("Source", style="cyan")
        t.add_column("Kind", style="yellow")
        t.add_column("Sinks", style="white")
        for f in findings:
            t.add_row(f["source"], f["kind"], ", ".join(f.get("sinks") or [])[:60])
        console.print(t)
        console.print()
    csp = results.get("csp") or {}
    if csp:
        tt_status = "[green]enforced[/green]" if csp.get("enforced") else "[yellow]not enforced[/yellow]"
        console.print(f"  [dim]Trusted Types: {tt_status}[/dim]")
        console.print()
    mxss = results.get("mxss") or []
    if mxss:
        console.print(f"  [bold red]mXSS confirmed:[/bold red] {len(mxss)} payload(s)")
        for m in mxss[:3]:
            console.print(f"    [dim]via {m['source']} — {m['payload'][:80]}[/dim]")
        console.print()
    severity = "high" if verdict == "VULNERABLE" else "medium"
    if verdict in ("VULNERABLE", "SUSPICIOUS"):
        ledger.record_finding(
            pattern_id="dom-xss-advanced",
            target=url,
            verdict=verdict,
            severity=severity,
            reason=out.get("reason", ""),
            evidence_path="",
            evidence_json={"flow_findings": findings, "mxss": mxss,
                           "csp": csp},
            category="single",
            wstg_id="WSTG-CLNT-01",
            cwe_id="CWE-79",
        )
    return _compute_fail_exit(
        [{"severity": severity, "verdict": verdict}], fail_on)


def cmd_ssrfcloud(args):
    if args and ("--help" in args or "-h" in args):
        console.print("[cyan]Usage: ssrf-cloud [<base_url>] [--timeout N] "
                      "[--fuzz-param URL_WITH_FUZZ] [--protocols] "
                      "[--fail-on SEV][/cyan]")
        console.print("  <base_url>              optional SSRF endpoint to test bypasses against")
        console.print("  --timeout N             per-probe timeout (default 8s)")
        console.print("  --fuzz-param URL        SSRF endpoint with FUZZ placeholder")
        console.print("                          (required for --protocols)")
        console.print("  --protocols             test gopher/dict/file smuggling")
        console.print("  --fail-on SEV           exit 3 if finding >= severity")
        console.print("")
        console.print("Providers probed:")
        console.print("  AWS IMDSv1, AWS IMDSv2 (PUT token + header forwarding),")
        console.print("  AWS ECS / Lambda runtime, GCP metadata, Azure IMDS + MI tokens,")
        console.print("  DigitalOcean, Alibaba, Oracle Cloud, Kubernetes SA token")
        console.print("")
        console.print("Bypasses:")
        console.print("  decimal/hex/octal IP, DNS rebinding (nip.io/sslip.io/xip.io)")
        console.print("")
        console.print("ROE: cloud metadata IPs are non-routable. If your target")
        console.print("     is a local mock, add 127.0.0.1/169.254.169.254 to roe.yaml.")
        return 0
    base_url = None
    timeout = 8
    fuzz_param = None
    protocols = False
    fail_on = None
    i = 0
    while i < len(args):
        if args[i] == "--timeout" and i + 1 < len(args):
            timeout = int(args[i + 1])
            i += 2
        elif args[i] == "--fuzz-param" and i + 1 < len(args):
            fuzz_param = args[i + 1]
            i += 2
        elif args[i] == "--protocols":
            protocols = True
            i += 1
        elif args[i] == "--fail-on" and i + 1 < len(args):
            fail_on = args[i + 1]
            i += 2
        elif not args[i].startswith("--"):
            base_url = args[i]
            i += 1
        else:
            i += 1
    from . import ssrf_cloud
    from .roe_guard import ROEGuard
    from .config import load_engine as _load_engine
    guard = ROEGuard(engine_cfg=_load_engine())
    console.print(f"[cyan]Cloud metadata SSRF scan[/cyan]")
    if base_url:
        console.print(f"[dim]Base URL for bypasses: {base_url}[/dim]")
    console.print(f"[dim]Timeout: {timeout}s  Protocols: {protocols}[/dim]")
    console.print()
    out = ssrf_cloud.scan(base_url=base_url, timeout=timeout,
                           roe_guard=guard,
                           include_protocol_smuggling=protocols,
                           fuzz_param_url=fuzz_param)
    verdict = out.get("overall", "UNKNOWN")
    color = VERDICT_COLOR.get(verdict, "white")
    console.print(f"  Overall: [{color}]{verdict}[/{color}]  {out.get('reason', '')}")
    console.print()
    t = Table(title="Cloud Provider Probes")
    t.add_column("Provider", style="cyan")
    t.add_column("Mode", style="dim")
    t.add_column("Verdict", style="bold")
    t.add_column("Reason", style="white")
    for name, r in (out.get("providers") or {}).items():
        v = r.get("verdict", "UNKNOWN")
        c = VERDICT_COLOR.get(v, "white")
        t.add_row(name, r.get("mode", ""),
                  f"[{c}]{v}[/{c}]", (r.get("reason") or "")[:70])
    console.print(t)
    console.print()
    if out.get("bypasses"):
        t2 = Table(title="Bypass Techniques")
        t2.add_column("Bypass", style="cyan")
        t2.add_column("Verdict", style="bold")
        t2.add_column("Reason", style="white")
        for name, r in out["bypasses"].items():
            if not isinstance(r, dict):
                continue
            v = r.get("verdict", "UNKNOWN")
            c = VERDICT_COLOR.get(v, "white")
            t2.add_row(name, f"[{c}]{v}[/{c}]", (r.get("reason") or "")[:70])
        console.print(t2)
        console.print()
    if out.get("protocol_smuggling"):
        r = out["protocol_smuggling"]
        v = r.get("verdict", "UNKNOWN")
        c = VERDICT_COLOR.get(v, "white")
        console.print(f"  Protocol smuggling: [{c}]{v}[/{c}]  {r.get('reason', '')}")
        console.print()
    if verdict in ("VULNERABLE", "SUSPICIOUS"):
        severity = "critical" if verdict == "VULNERABLE" else "high"
        ledger.record_finding(
            pattern_id="ssrf-cloud-metadata",
            target=base_url or "(local)",
            verdict=verdict,
            severity=severity,
            reason=out.get("reason", ""),
            evidence_path="",
            evidence_json={"providers": out.get("providers"),
                           "bypasses": out.get("bypasses")},
            category="sequence",
            wstg_id="WSTG-INPV-19",
            cwe_id="CWE-918",
        )
    else:
        severity = "info"
    return _compute_fail_exit(
        [{"severity": severity, "verdict": verdict}], fail_on)


def cmd_openapi(args):
    if args and ("--help" in args or "-h" in args):
        console.print("[cyan]Usage: openapi <url> [--no-fuzz] [--max-endpoints N] "
                      "[--fuzz-per-endpoint N] [--timeout N] "
                      "[--session NAME] [--auth X] [--fail-on SEV][/cyan]")
        console.print("  --no-fuzz               discover spec only, skip fuzzing")
        console.print("  --max-endpoints N       cap endpoints to fuzz (default 50)")
        console.print("  --fuzz-per-endpoint N   cases per endpoint (default 40)")
        console.print("  --timeout N             per-request timeout (default 10s)")
        console.print("  --session NAME          saved session name")
        console.print("  --auth X                inline auth (bearer:X, cookie:X)")
        console.print("  --fail-on SEV           exit 3 if finding >= severity")
        console.print("")
        console.print("Discovery probes 20+ spec paths + Swagger UI pages.")
        console.print("Fuzzing generates boundary + injection payloads per schema.")
        console.print("Reports auth schemes and endpoint coverage.")
        return 0
    if not args:
        console.print("[red]Usage: openapi <url> [--no-fuzz] "
                      "[--max-endpoints N] [--fuzz-per-endpoint N] "
                      "[--timeout N] [--session NAME] [--auth X] "
                      "[--fail-on SEV][/red]")
        return
    url = args[0]
    fuzz = True
    max_endpoints = 50
    max_fuzz = 40
    timeout = 10
    auth_str = None
    session = None
    fail_on = None
    i = 1
    while i < len(args):
        if args[i] == "--no-fuzz":
            fuzz = False
            i += 1
        elif args[i] == "--max-endpoints" and i + 1 < len(args):
            max_endpoints = int(args[i + 1])
            i += 2
        elif args[i] == "--fuzz-per-endpoint" and i + 1 < len(args):
            max_fuzz = int(args[i + 1])
            i += 2
        elif args[i] == "--timeout" and i + 1 < len(args):
            timeout = int(args[i + 1])
            i += 2
        elif args[i] == "--auth" and i + 1 < len(args):
            auth_str = args[i + 1]
            i += 2
        elif args[i] == "--session" and i + 1 < len(args):
            session = args[i + 1]
            i += 2
        elif args[i] == "--fail-on" and i + 1 < len(args):
            fail_on = args[i + 1]
            i += 2
        else:
            i += 1
    headers, cookies, ok = _resolve_session(session, auth_str)
    if not ok:
        return
    from . import openapi_scanner
    from .roe_guard import ROEGuard
    from .config import load_engine as _load_engine
    guard = ROEGuard(engine_cfg=_load_engine())
    console.print(f"[cyan]OpenAPI scan:[/cyan] {url}")
    console.print(f"[dim]Fuzz: {fuzz}  Max endpoints: {max_endpoints}  "
                  f"Fuzz/endpoint: {max_fuzz}[/dim]")
    console.print()
    out = openapi_scanner.scan(url, timeout=timeout, roe_guard=guard,
                                headers=headers, fuzz=fuzz,
                                max_endpoints=max_endpoints,
                                max_fuzz_per_endpoint=max_fuzz)
    if not out.get("spec"):
        console.print(f"[yellow]{out.get('reason', 'no spec found')}[/yellow]")
        return
    spec = out["spec"]
    console.print(f"[green]Spec discovered:[/green] {spec['url']}")
    console.print(f"  [dim]format={spec['format']}  version={spec['version']}[/dim]")
    if spec.get("discovered_via"):
        console.print(f"  [dim]via Swagger UI: {spec['discovered_via']}[/dim]")
    console.print()
    cov = out.get("coverage") or {}
    t = Table(title="Endpoint Coverage")
    t.add_column("Metric", style="cyan")
    t.add_column("Value", style="white")
    t.add_row("Total endpoints", str(cov.get("total_endpoints", 0)))
    for method, count in (cov.get("methods") or {}).items():
        t.add_row(f"  {method}", str(count))
    t.add_row("With parameters", str(cov.get("endpoints_with_params", 0)))
    t.add_row("With request body", str(cov.get("endpoints_with_body", 0)))
    t.add_row("Missing security", str(len(cov.get("endpoints_without_security") or [])))
    console.print(t)
    console.print()
    auth_schemes = out.get("auth_schemes") or []
    if auth_schemes:
        t2 = Table(title="Auth Schemes")
        t2.add_column("Name", style="cyan")
        t2.add_column("Type", style="yellow")
        t2.add_column("Scheme", style="white")
        t2.add_column("Location", style="dim")
        for s in auth_schemes:
            t2.add_row(s["name"], AUTH_TYPE_LABEL.get(s["type"], s["type"]),
                       s.get("scheme") or "", s.get("in") or s.get("header_name") or "")
        console.print(t2)
        console.print()
    missing_sec = cov.get("endpoints_without_security") or []
    if missing_sec:
        console.print(f"[yellow]Endpoints without declared security "
                      f"({len(missing_sec)}):[/yellow]")
        for e in missing_sec[:10]:
            console.print(f"  [dim]{e}[/dim]")
        console.print()
    anomalies = out.get("anomalies") or []
    if anomalies:
        ta = Table(title=f"Fuzz Anomalies ({len(anomalies)})")
        ta.add_column("Type", style="yellow")
        ta.add_column("Endpoint", style="cyan")
        ta.add_column("Detail", style="white")
        for a in anomalies[:20]:
            case = a.get("case") or {}
            detail = (a.get("signature") or
                      f"status {a.get('status', '')}")
            ta.add_row(a.get("type", ""),
                       f"{case.get('kind','')}:{case.get('param', case.get('value_type',''))}",
                       detail[:60])
        console.print(ta)
        console.print()
    verdict = out.get("verdict", "UNKNOWN")
    color = VERDICT_COLOR.get(verdict, "white")
    console.print(f"  Overall: [{color}]{verdict}[/{color}]  {out.get('reason', '')}")
    if anomalies:
        ledger.record_finding(
            pattern_id="openapi-fuzz-anomalies",
            target=url,
            verdict="SUSPICIOUS",
            severity="medium",
            reason=out.get("reason", ""),
            evidence_path="",
            evidence_json={"spec": spec, "anomalies": anomalies[:20],
                           "coverage": cov},
            category="content",
            wstg_id="WSTG-APIT-01",
            cwe_id="CWE-20",
        )
    return _compute_fail_exit(
        [{"severity": "medium" if anomalies else "info",
          "verdict": verdict}], fail_on)


def cmd_bizlogic(args):
    if args and ("--help" in args or "-h" in args):
        console.print("[cyan]Usage: bizlogic <base_url> "
                      "[--price-endpoint URL --price-body JSON] "
                      "[--mass-endpoint URL --mass-body JSON] "
                      "[--workflow FILE] [--race-endpoint PATH --race-body JSON] "
                      "[--coupon CODE] [--protected PATH] "
                      "[--session NAME] [--auth X] [--fail-on SEV][/cyan]")
        console.print("  --price-endpoint URL    checkout/cart endpoint to fuzz price")
        console.print("  --price-body JSON       baseline JSON body for price test")
        console.print("  --mass-endpoint URL     endpoint to test mass assignment")
        console.print("  --mass-body JSON        baseline JSON body for mass assignment")
        console.print("  --workflow FILE         JSON file with workflow steps")
        console.print("  --race-endpoint PATH    path to race-test (coupon/transfer)")
        console.print("  --race-body JSON        JSON body for race test")
        console.print("  --coupon CODE           coupon code to test for reuse")
        console.print("  --protected PATH        path to test for verification bypass")
        console.print("  --session NAME          saved session name")
        console.print("  --auth X                inline auth (bearer:X, cookie:X)")
        console.print("  --fail-on SEV           exit 3 if finding >= severity")
        console.print("")
        console.print("Business logic flaw classes:")
        console.print("  BLA1  Action Limit Overrun      coupon/refund abuse")
        console.print("  BLA2  Concurrent Workflow Bypass  race + skip steps")
        console.print("  BLA3  Object State Manipulation  mass assignment")
        console.print("  BLA6  Missing Transition Validation  workflow bypass")
        return 0
    if not args:
        console.print("[red]Usage: bizlogic <base_url> "
                      "[--price-endpoint URL --price-body JSON] "
                      "[--mass-endpoint URL --mass-body JSON] "
                      "[--workflow FILE] [--race-endpoint PATH --race-body JSON] "
                      "[--coupon CODE] [--protected PATH] "
                      "[--session NAME] [--auth X] [--fail-on SEV][/red]")
        return
    base_url = args[0]
    price_endpoint = None
    price_body = None
    price_method = "POST"
    mass_endpoint = None
    mass_body = None
    workflow_file = None
    race_endpoint = None
    race_body = None
    race_count = 20
    coupon_code = None
    protected_path = None
    auth_str = None
    session = None
    fail_on = None
    i = 1
    while i < len(args):
        if args[i] == "--price-endpoint" and i + 1 < len(args):
            price_endpoint = args[i + 1]
            i += 2
        elif args[i] == "--price-body" and i + 1 < len(args):
            try:
                price_body = json.loads(args[i + 1])
            except Exception:
                price_body = None
            i += 2
        elif args[i] == "--mass-endpoint" and i + 1 < len(args):
            mass_endpoint = args[i + 1]
            i += 2
        elif args[i] == "--mass-body" and i + 1 < len(args):
            try:
                mass_body = json.loads(args[i + 1])
            except Exception:
                mass_body = None
            i += 2
        elif args[i] == "--workflow" and i + 1 < len(args):
            workflow_file = args[i + 1]
            i += 2
        elif args[i] == "--race-endpoint" and i + 1 < len(args):
            race_endpoint = args[i + 1]
            i += 2
        elif args[i] == "--race-body" and i + 1 < len(args):
            try:
                race_body = json.loads(args[i + 1])
            except Exception:
                race_body = None
            i += 2
        elif args[i] == "--race-count" and i + 1 < len(args):
            race_count = int(args[i + 1])
            i += 2
        elif args[i] == "--coupon" and i + 1 < len(args):
            coupon_code = args[i + 1]
            i += 2
        elif args[i] == "--protected" and i + 1 < len(args):
            protected_path = args[i + 1]
            i += 2
        elif args[i] == "--auth" and i + 1 < len(args):
            auth_str = args[i + 1]
            i += 2
        elif args[i] == "--session" and i + 1 < len(args):
            session = args[i + 1]
            i += 2
        elif args[i] == "--fail-on" and i + 1 < len(args):
            fail_on = args[i + 1]
            i += 2
        else:
            i += 1
    headers, cookies, ok = _resolve_session(session, auth_str)
    if not ok:
        return
    from . import bizlogic
    from .roe_guard import ROEGuard
    from .config import load_engine as _load_engine
    guard = ROEGuard(engine_cfg=_load_engine())
    console.print(f"[cyan]Business logic scan:[/cyan] {base_url}")
    console.print()

    endpoints = {}
    if price_endpoint and price_body:
        endpoints["price_endpoint"] = {"url": price_endpoint,
                                        "method": price_method,
                                        "baseline_body": price_body}
    if mass_endpoint and mass_body:
        endpoints["mass_assign_endpoint"] = {"url": mass_endpoint,
                                              "method": "POST",
                                              "baseline_body": mass_body}
    if workflow_file:
        try:
            wf = json.loads(Path(workflow_file).read_text(encoding="utf-8"))
            endpoints["workflow"] = wf
        except Exception as e:
            console.print(f"[yellow]workflow load failed: {e}[/yellow]")
    if race_endpoint:
        endpoints["race_endpoint"] = {"path": race_endpoint, "body": race_body,
                                       "count": race_count}
    if coupon_code:
        endpoints["coupon"] = {"code": coupon_code}
    if protected_path:
        endpoints["protected_path"] = protected_path

    if not endpoints:
        console.print("[yellow]No endpoints configured. Provide at least one "
                      "of --price-endpoint, --mass-endpoint, --workflow, "
                      "--race-endpoint, --coupon, --protected.[/yellow]")
        return

    out = bizlogic.scan(base_url, headers=headers, roe_guard=guard,
                         endpoints=endpoints)
    t = Table(title="Business Logic Results")
    t.add_column("Probe", style="cyan")
    t.add_column("Verdict", style="bold")
    t.add_column("Reason", style="white")
    counts = {"VULNERABLE": 0, "SUSPICIOUS": 0, "PASS": 0, "UNKNOWN": 0}
    for name, r in (out.get("probes") or {}).items():
        v = r.get("verdict", "UNKNOWN")
        counts[v] = counts.get(v, 0) + 1
        c = VERDICT_COLOR.get(v, "white")
        t.add_row(name, f"[{c}]{v}[/{c}]", (r.get("reason") or "")[:70])
    console.print(t)
    console.print()
    console.print(f"  [bold red]VULNERABLE[/bold red]: {counts['VULNERABLE']}")
    console.print(f"  [bold yellow]SUSPICIOUS[/bold yellow]: {counts['SUSPICIOUS']}")
    console.print(f"  [bold green]PASS[/bold green]      : {counts['PASS']}")
    console.print(f"  [dim]UNKNOWN[/dim]   : {counts['UNKNOWN']}")
    for name, r in (out.get("probes") or {}).items():
        v = r.get("verdict")
        if v not in ("VULNERABLE", "SUSPICIOUS"):
            continue
        ledger.record_finding(
            pattern_id=f"bizlogic-{name.replace('_', '-')}",
            target=base_url,
            verdict=v,
            severity="high" if v == "VULNERABLE" else "medium",
            reason=r.get("reason", ""),
            evidence_path="",
            evidence_json=r.get("evidence", {}),
            category="sequence",
            wstg_id="WSTG-BUSL-01",
            cwe_id="CWE-840",
        )
    return _compute_fail_exit(
        [{"severity": "high" if v == "VULNERABLE" else "medium",
          "verdict": v} for name, r in (out.get("probes") or {}).items()
         for v in [r.get("verdict", "UNKNOWN")]],
        fail_on,
    )


def cmd_workflow(args):
    if args and ("--help" in args or "-h" in args):
        console.print("[cyan]Usage:[/cyan]")
        console.print("  workflow record <url> --out FILE [--headless] [--auto N]")
        console.print("  workflow list-params <file>")
        console.print("  workflow replay <url> --in FILE [--set name=value ...] "
                      "[--headful] [--fail-on SEV]")
        console.print("  workflow tamper <url> --in FILE [--auto] [--headful] "
                      "[--fail-on SEV]")
        console.print("")
        console.print("Subcommands:")
        console.print("  record       Launch headful browser, capture clicks/inputs/submits")
        console.print("  list-params  Show modifiable parameters + critical flags")
        console.print("  replay       Replay with optional parameter substitution")
        console.print("  tamper       Auto-tamper business-critical params and replay")
        console.print("")
        console.print("Options:")
        console.print("  --out FILE   save recording JSON")
        console.print("  --in FILE    load recording JSON")
        console.print("  --set k=v    substitute param k with v (repeatable)")
        console.print("  --auto N     auto-record for N seconds (default: wait for Enter)")
        console.print("  --headful    show browser during replay")
        console.print("  --headless   hide browser during record (default: headful)")
        return 0
    if not args:
        console.print("[red]Usage: workflow <record|list-params|replay|tamper> "
                      "<url|file> [options][/red]")
        return
    sub = args[0]
    rest = args[1:]
    if sub == "record":
        return _cmd_workflow_record(rest)
    if sub == "list-params":
        return _cmd_workflow_list(rest)
    if sub == "replay":
        return _cmd_workflow_replay(rest)
    if sub == "tamper":
        return _cmd_workflow_tamper(rest)
    console.print(f"[red]Unknown subcommand: {sub}[/red]")
    return 1


def _cmd_workflow_record(args):
    if not args:
        console.print("[red]Usage: workflow record <url> --out FILE "
                      "[--auto N] [--headless][/red]")
        return
    url = args[0]
    out_file = None
    auto_seconds = None
    headless = False
    i = 1
    while i < len(args):
        if args[i] == "--out" and i + 1 < len(args):
            out_file = args[i + 1]
            i += 2
        elif args[i] == "--auto" and i + 1 < len(args):
            auto_seconds = int(args[i + 1])
            i += 2
        elif args[i] == "--headless":
            headless = True
            i += 1
        else:
            i += 1
    if not out_file:
        ts = time.strftime("%Y%m%dT%H%M%S")
        out_file = f"workflows/workflow_{ts}.json"
    from . import workflow_recorder
    from .roe_guard import ROEGuard
    from .config import load_engine as _load_engine
    guard = ROEGuard(engine_cfg=_load_engine())
    console.print(f"[cyan]Recording workflow:[/cyan] {url}")
    console.print(f"[dim]Output: {out_file}[/dim]")
    if auto_seconds:
        console.print(f"[dim]Auto-stop after {auto_seconds}s[/dim]")
    else:
        console.print("[dim]Press Enter to stop recording[/dim]")
    if headless:
        console.print("[yellow]Headless mode — no interaction possible; "
                      "only initial page load is captured[/yellow]")
    console.print()
    wait_for_enter = not bool(auto_seconds)
    timeout_ms = (auto_seconds * 1000) if auto_seconds else 600000
    out = workflow_recorder.record(url, out_file=out_file,
                                    timeout_ms=timeout_ms,
                                    roe_guard=guard, headless=headless,
                                    wait_for_enter=wait_for_enter)
    if out.get("error"):
        console.print(f"[red]{out['error']}[/red]")
        return 1
    events = out.get("events") or []
    console.print(f"[green]Recorded {len(events)} event(s)[/green]")
    for ev in events[:20]:
        t = ev.get("type")
        detail = ev.get("name") or ev.get("text") or ev.get("selector", "")[:40]
        console.print(f"  [dim]{t}[/dim] {detail}")
    if len(events) > 20:
        console.print(f"  [dim]... and {len(events) - 20} more[/dim]")
    if out.get("out_file"):
        console.print(f"[green]Saved:[/green] {out['out_file']}")
    return 0


def _cmd_workflow_list(args):
    if not args:
        console.print("[red]Usage: workflow list-params <file>[/red]")
        return
    from . import workflow_recorder
    wf = workflow_recorder.load_workflow(args[0])
    if not wf:
        console.print(f"[red]Cannot load workflow: {args[0]}[/red]")
        return
    params = workflow_recorder.list_modifiable_params(wf)
    if not params:
        console.print("[yellow]No modifiable parameters recorded[/yellow]")
        return
    t = Table(title=f"Parameters ({len(params)})")
    t.add_column("Name", style="cyan")
    t.add_column("Original", style="white")
    t.add_column("Critical", style="yellow")
    t.add_column("Selector", style="dim")
    for p in params:
        crit = "[bold red]YES[/bold red]" if p["critical"] else "no"
        t.add_row(p["name"], str(p.get("original"))[:40], crit,
                  (p.get("selector") or "")[:40])
    console.print(t)
    return 0


def _cmd_workflow_replay(args):
    if not args:
        console.print("[red]Usage: workflow replay <url> --in FILE "
                      "[--set name=value ...] [--headful][/red]")
        return
    url = args[0]
    wf_file = None
    substitutions = {}
    headless = True
    fail_on = None
    i = 1
    while i < len(args):
        if args[i] == "--in" and i + 1 < len(args):
            wf_file = args[i + 1]
            i += 2
        elif args[i] == "--set" and i + 1 < len(args):
            kv = args[i + 1]
            if "=" in kv:
                k, v = kv.split("=", 1)
                substitutions[k.strip()] = v.strip()
            i += 2
        elif args[i] == "--headful":
            headless = False
            i += 1
        elif args[i] == "--fail-on" and i + 1 < len(args):
            fail_on = args[i + 1]
            i += 2
        else:
            i += 1
    if not wf_file:
        console.print("[red]--in FILE is required[/red]")
        return
    from . import workflow_recorder
    from .roe_guard import ROEGuard
    from .config import load_engine as _load_engine
    guard = ROEGuard(engine_cfg=_load_engine())
    wf = workflow_recorder.load_workflow(wf_file)
    if not wf:
        console.print(f"[red]Cannot load workflow: {wf_file}[/red]")
        return
    console.print(f"[cyan]Replaying:[/cyan] {url}")
    if substitutions:
        for k, v in substitutions.items():
            console.print(f"  [dim]substitute {k} = {v}[/dim]")
    console.print()
    out = workflow_recorder.replay(url, wf, substitutions=substitutions,
                                    roe_guard=guard, headless=headless)
    if out.get("error"):
        console.print(f"[red]{out['error']}[/red]")
        return 1
    t = Table(title="Replay Steps")
    t.add_column("Event", style="cyan")
    t.add_column("OK", style="yellow")
    t.add_column("Substituted", style="magenta")
    t.add_column("Error", style="dim")
    for s in out.get("steps") or []:
        sub_str = ""
        if s.get("substituted_from") is not None:
            sub_str = f"{s['substituted_from']} → {s['substituted_to']}"
        t.add_row(s.get("event", ""),
                  "[green]yes[/green]" if s.get("ok") else "[red]no[/red]",
                  sub_str[:40], (s.get("error") or "")[:50])
    console.print(t)
    console.print()
    status = "[green]success[/green]" if out.get("success") else "[yellow]incomplete[/yellow]"
    console.print(f"  Final URL: {out.get('final_url')}")
    console.print(f"  Status: {status}")
    if out.get("substituted"):
        console.print(f"  Substitutions: {len(out['substituted'])}")
    return _compute_fail_exit(
        [{"severity": "medium",
          "verdict": "SUSPICIOUS" if out.get("substituted") and out.get("success") else "PASS"}],
        fail_on)


def _cmd_workflow_tamper(args):
    if not args:
        console.print("[red]Usage: workflow tamper <url> --in FILE "
                      "[--headful] [--fail-on SEV][/red]")
        return
    url = args[0]
    wf_file = None
    headless = True
    fail_on = None
    i = 1
    while i < len(args):
        if args[i] == "--in" and i + 1 < len(args):
            wf_file = args[i + 1]
            i += 2
        elif args[i] == "--headful":
            headless = False
            i += 1
        elif args[i] == "--fail-on" and i + 1 < len(args):
            fail_on = args[i + 1]
            i += 2
        else:
            i += 1
    if not wf_file:
        console.print("[red]--in FILE is required[/red]")
        return
    from . import workflow_recorder
    from .roe_guard import ROEGuard
    from .config import load_engine as _load_engine
    guard = ROEGuard(engine_cfg=_load_engine())
    wf = workflow_recorder.load_workflow(wf_file)
    if not wf:
        console.print(f"[red]Cannot load workflow: {wf_file}[/red]")
        return
    console.print(f"[cyan]Auto-tampering critical params:[/cyan] {url}")
    console.print()
    out = workflow_recorder.replay_with_critical_tampers(
        url, wf, roe_guard=guard, headless=headless)
    results = out.get("results") or []
    if not results:
        console.print("[yellow]No critical parameters detected in workflow[/yellow]")
        console.print("[dim]Record a workflow that fills price/quantity/role fields "
                      "to enable tamper testing[/dim]")
        return
    t = Table(title="Tamper Results")
    t.add_column("Param", style="cyan")
    t.add_column("Original", style="white")
    t.add_column("Tampered To", style="yellow")
    t.add_column("Outcome", style="bold")
    for r in results:
        outcome = "[green]completed[/green]" if r.get("success") else "[dim]failed[/dim]"
        t.add_row(r["param"], str(r.get("original"))[:20],
                  str(r.get("tampered_to")), outcome)
    console.print(t)
    console.print()
    v = out.get("verdict", "UNKNOWN")
    c = VERDICT_COLOR.get(v, "white")
    console.print(f"  [{c}]{v}[/{c}]  {out.get('reason', '')}")
    for r in results:
        if not r.get("success"):
            continue
        ledger.record_finding(
            pattern_id="bizlogic-workflow-tamper",
            target=url,
            verdict="SUSPICIOUS",
            severity="high",
            reason=(f"workflow completed with {r['param']} tampered from "
                    f"{r.get('original')} to {r.get('tampered_to')}"),
            evidence_path="",
            evidence_json=r,
            category="sequence",
            wstg_id="WSTG-BUSL-01",
            cwe_id="CWE-840",
        )
    return _compute_fail_exit(
        [{"severity": "high",
          "verdict": "SUSPICIOUS" if r.get("success") else "PASS"}
         for r in results],
        fail_on)


def cmd_compliance(args):
    if args and ("--help" in args or "-h" in args):
        console.print("[cyan]Usage: compliance <target> "
                      "[--format md|html|json] [--out FILE] "
                      "[--recalibrate] [--fail-on-gap][/cyan]")
        console.print("  --format md|html|json   output format (default: md to stdout)")
        console.print("  --out FILE              write report to file")
        console.print("  --recalibrate           recompute severity using 2025 floors")
        console.print("  --fail-on-gap           exit 3 if any OWASP 2025 category has zero findings")
        console.print("")
        console.print("Maps every finding to OWASP Top 10:2025, shows category coverage,")
        console.print("highlights gaps, and can recalibrate severity per category baseline.")
        return 0
    if not args:
        console.print("[red]Usage: compliance <target> [--format md|html|json] "
                      "[--out FILE] [--recalibrate] [--fail-on-gap][/red]")
        return
    target = args[0]
    fmt = "md"
    out_file = None
    recalibrate = False
    fail_on_gap = False
    i = 1
    while i < len(args):
        if args[i] == "--format" and i + 1 < len(args):
            fmt = args[i + 1].lower()
            i += 2
        elif args[i] == "--out" and i + 1 < len(args):
            out_file = args[i + 1]
            i += 2
        elif args[i] == "--recalibrate":
            recalibrate = True
            i += 1
        elif args[i] == "--fail-on-gap":
            fail_on_gap = True
            i += 1
        else:
            i += 1

    from . import owasp_2025
    resolved = _resolve_report_target(target)
    if resolved != target:
        console.print(f"[dim]Resolved target: {resolved}[/dim]")

    rows = ledger.findings_for_target(resolved)
    keys = ["id", "timestamp", "pattern_id", "category", "verdict",
            "severity", "reason", "wstg_id", "cwe_id", "evidence_path",
            "duration_ms"]
    findings = [dict(zip(keys, r)) for r in rows]

    if recalibrate:
        recalibrated = []
        for f in findings:
            new_sev, change = owasp_2025.recalibrate_severity(
                f.get("pattern_id"), f.get("severity", "info"))
            if change:
                f = dict(f)
                f["severity"] = new_sev
                f["_recalibration"] = change
                recalibrated.append(change)
        if recalibrated:
            console.print(f"[yellow]Recalibrated {len(recalibrated)} "
                          f"finding(s) to category floors[/yellow]")
            for c in recalibrated[:5]:
                console.print(f"  [dim]{c['reason']}[/dim]")
            console.print()

    report = owasp_2025.build_compliance_report(
        findings, complete_scan=False)

    if fmt == "json":
        text = json.dumps(report, indent=2, default=str)
    elif fmt == "html":
        text = owasp_2025.render_html(report, resolved)
    else:
        text = owasp_2025.render_markdown(report, resolved)

    if out_file:
        p = Path(out_file)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        console.print(f"[green]Report written:[/green] {p}")
    else:
        console.print(text)

    if fail_on_gap:
        missing = len(report.get("gaps") or [])
        if missing:
            console.print(f"[bold red]FAIL:[/bold red] {missing} OWASP 2025 "
                          f"category(ies) have zero findings")
            return 3
    return 0


def cmd_chain(args):
    if args and ("--help" in args or "-h" in args):
        console.print("[cyan]Usage: chain <url> [options][/cyan]")
        console.print("  --budget N         max seconds for entire run (default 900)")
        console.print("  --verbose          show per-step progress")
        console.print("  --kill-on-vuln     stop after first confirmed vulnerability")
        console.print("  --chain ID         run only specific chain (repeatable)")
        console.print("  --with-sca PATH    enable supply-chain chain on local path")
        console.print("  --json             output raw JSON report")
        console.print("  --fail-on SEV      exit 3 if a finding >= severity")
        console.print("  --export-nuclei ID export a chain to a Nuclei template")
        console.print("  --engage           authorize destructive tools for this run")
        console.print("  --harvest          adaptive extraction (walk until refused)")
        console.print("  --approval MODE    off | auto | interactive (default off)")
        console.print("  --nuclei PATH      load a Nuclei template and run it as a chain")
        console.print("")
        console.print("Global: --allow-destructive authorizes destructive chain tools.")
        console.print("")
        console.print("Recon first, then run attack chains sequentially. Each chain")
        console.print("has fallback steps: PASS/UNKNOWN continue, VULNERABLE stops")
        console.print("the chain and records a finding.")
        console.print("")
        console.print("Chains: jwt, graphql, ssrf, bizlogic, race, llm, xss, openapi, sca")
        return 0
    if not args:
        console.print("[red]Usage: chain <url> [--budget N] [--verbose] "
                      "[--chain ID] [--with-sca PATH] [--json] "
                      "[--fail-on SEV][/red]")
        return
    url = args[0]
    budget = 900
    verbose = False
    kill_on_vuln = False
    only_chains = []
    sca_path = None
    as_json = bool(RUNTIME.get("json_output"))
    fail_on = None
    export_nuclei = None
    engage = False
    harvest = False
    approval_mode = "off"
    nuclei_path = None
    i = 1
    while i < len(args):
        if args[i] == "--budget" and i + 1 < len(args):
            budget = int(args[i + 1])
            i += 2
        elif args[i] == "--verbose":
            verbose = True
            i += 1
        elif args[i] == "--kill-on-vuln":
            kill_on_vuln = True
            i += 1
        elif args[i] == "--chain" and i + 1 < len(args):
            only_chains.append(args[i + 1])
            i += 2
        elif args[i] == "--with-sca" and i + 1 < len(args):
            sca_path = args[i + 1]
            i += 2
        elif args[i] == "--json":
            as_json = True
            i += 1
        elif args[i] == "--export-nuclei" and i + 1 < len(args):
            export_nuclei = args[i + 1]
            i += 2
        elif args[i] == "--engage":
            engage = True
            i += 1
        elif args[i] == "--harvest":
            harvest = True
            i += 1
        elif args[i] == "--approval" and i + 1 < len(args):
            approval_mode = args[i + 1].lower()
            i += 2
        elif args[i] == "--nuclei" and i + 1 < len(args):
            nuclei_path = args[i + 1]
            i += 2
        elif args[i] == "--fail-on" and i + 1 < len(args):
            fail_on = args[i + 1]
            i += 2
        else:
            i += 1

    if export_nuclei:
        from . import nuclei_export
        from .chain_registry import get_all_chains as _get_chains
        _nuc_chain = next(
            (c for c in _get_chains() if c["id"] == export_nuclei), None)
        if not _nuc_chain:
            console.print(f"[red]No chain: {export_nuclei}[/red]")
            return 1
        _nuc_path = nuclei_export.save_nuclei(_nuc_chain)
        console.print(f"[green]Nuclei template:[/green] {_nuc_path}")
        return 0

    from . import chain_engine
    from .chain_registry import get_all_chains
    from .roe_guard import ROEGuard
    from .config import load_engine as _load_engine

    _engine_cfg = _load_engine()
    guard = ROEGuard(engine_cfg=_engine_cfg)
    console.print(f"[cyan]Attack chain scan:[/cyan] {url}")
    console.print(f"[dim]Budget: {budget}s  Verbose: {verbose}[/dim]")
    if only_chains:
        console.print(f"[dim]Restricting to chains: {', '.join(only_chains)}[/dim]")
    console.print()

    allow_destructive = bool(RUNTIME.get("allow_destructive"))
    if RUNTIME.get("dry_run"):
        console.print(f"[cyan]DRY RUN[/cyan] would run chains on: {url}")
        console.print(f"[dim]  budget={budget}s allow-destructive={allow_destructive}[/dim]")
        return 0
    if allow_destructive:
        console.print("[bold red]--allow-destructive:[/bold red] destructive "
                      "chain tools are ENABLED for this run")
    _triage_brain = None
    try:
        from .brains.llm import make_brain_from_config
        from .brains.rule_based import RuleBasedBrain
        _brain = make_brain_from_config(_engine_cfg.get("brain"))
        if not isinstance(_brain, RuleBasedBrain):
            _triage_brain = _brain
    except Exception:
        _triage_brain = None
    try:
        orch = chain_engine.ChainOrchestrator(
            url, roe_guard=guard, engine_cfg=_engine_cfg, max_budget_sec=budget,
            verbose=verbose, kill_on_vuln=kill_on_vuln,
            allow_destructive=allow_destructive, triage_brain=_triage_brain)
    except RuntimeError as e:
        console.print(f"[red]{e}[/red]")
        return 1

    extra_chains = []
    if nuclei_path:
        try:
            from . import nuclei_import
            nuclei_import.ensure_registered()
            loaded = nuclei_import.load_template(nuclei_path)
            chain = nuclei_import.template_to_chain(loaded, nuclei_path)
            extra_chains = [chain]
            orch.add_fact("nuclei_enabled", True, source="cli")
            console.print(f"[dim]nuclei template loaded: {chain['id']}[/dim]")
        except Exception as e:
            console.print(
                f"[red]failed to load nuclei template: "
                f"{type(e).__name__}: {e}[/red]"
            )
            return 1

    if engage:
        orch.allow_destructive = True
    if harvest:
        orch.harvest_mode = True
    if approval_mode == "interactive":
        orch.approval_mode = True
    elif approval_mode == "auto":
        orch.approval_mode = False

    if RUNTIME.get("legacy_scoring"):
        orch.legacy_scoring = True
        console.print("[dim]scoring: legacy heuristic (A/B)[/dim]")

    if sca_path:
        orch.add_fact("sca_requested", True, source="cli")
        orch.set_context("sca_path", sca_path)

    if only_chains:
        all_chains = get_all_chains()
        filtered = [c for c in all_chains if c["id"] in only_chains]
        filtered.extend(extra_chains)
        if not filtered:
            console.print(f"[red]No chains match: {only_chains}[/red]")
            return 1

        try:
            orch.run_recon()
        except Exception as e:
            console.print(f"[red]recon failed: {type(e).__name__}: {e}[/red]")
            return 1

        recon = orch.recon
        fw = recon.get("framework") or {}
        console.print("[bold]Recon summary[/bold]")
        console.print(f"  framework:  {fw.get('name', '?')}")
        console.print(f"  api_base:   {recon.get('api_base', '?')}")
        console.print(f"  js_bundles: {len(recon.get('js_urls') or [])}")
        console.print(f"  api_paths:  {len(recon.get('api_paths') or [])}")
        console.print(f"  live_paths: {len(recon.get('live_paths') or [])}")
        console.print()

        for chain in filtered:
            if orch._budget_exceeded():
                console.print("[yellow]budget exceeded, stopping[/yellow]")
                break
            orch.execute_chain(chain)
        report = orch._final_report()
    else:
        if extra_chains:
            run_chains = list(get_all_chains()) + list(extra_chains)
        else:
            run_chains = None
        report = orch.run(chains=run_chains)

    if as_json:
        import json as _json
        console.print(_json.dumps(report, indent=2, default=str))
    else:
        _print_chain_report(report)

    findings = report.get("findings") or []
    if findings:
        severity = "high"
        for f in findings:
            ev = f.get("evidence") or {}
            sev = ev.get("severity") or "high"
            if SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(severity, 0):
                severity = sev
        return _compute_fail_exit(
            [{"severity": severity, "verdict": "VULNERABLE"}], fail_on)
    return _compute_fail_exit([], fail_on)


def _print_chain_report(report):
    v = report.get("verdict", "UNKNOWN")
    color = VERDICT_COLOR.get(v, "white")
    console.print()
    console.print("[bold cyan]Attack Chain Report[/bold cyan]")
    console.print(f"  Target:   {report.get('target')}")
    console.print(f"  Duration: {report.get('duration_sec')}s")
    console.print(f"  Verdict:  [{color}]{v}[/{color}]")
    console.print()

    recon = report.get("recon") or {}
    fw = recon.get("framework") or {}
    if fw:
        console.print("[bold]Recon[/bold]")
        console.print(f"  Framework:  {fw.get('name', '?')} ({fw.get('id', '?')})")
        if recon.get("api_base"):
            console.print(f"  API base:   {recon['api_base']}")
        console.print(f"  JS bundles: {len(recon.get('js_urls') or [])}")
        console.print(f"  API paths:  {len(recon.get('api_paths') or [])}")
        console.print(f"  Live paths: {len(recon.get('live_paths') or [])}")
        console.print()

    facts = report.get("facts") or {}
    if facts:
        console.print(f"[bold]Facts[/bold] ({len(facts)})")
        for k, f in list(facts.items())[:20]:
            val = f.get("value") if isinstance(f, dict) else f
            if isinstance(val, (list, dict)):
                val = f"<{type(val).__name__} len={len(val)}>"
            console.print(f"  [dim]{k}[/dim] = {val}")
        if len(facts) > 20:
            console.print(f"  [dim]... and {len(facts) - 20} more[/dim]")
        console.print()

    plan = report.get("plan") or []
    if plan:
        console.print(f"[bold]Plan[/bold] ({len(plan)} chains)")
        for cid in plan:
            console.print(f"  \u2192 {cid}")
        console.print()

    chains = report.get("chain_results") or []
    if chains:
        t = Table(title="Chain Results")
        t.add_column("Chain", style="cyan")
        t.add_column("Verdict", style="bold")
        t.add_column("Steps", style="dim")
        t.add_column("Duration", style="dim")
        t.add_column("Reason", style="white")
        for c in chains:
            cv = c.get("verdict", "UNKNOWN")
            cc = VERDICT_COLOR.get(cv, "white")
            steps = ", ".join(
                f"{s['id']}:{s.get('verdict', '?')[:1]}"
                for s in (c.get("steps") or []))
            t.add_row(
                c.get("id", "?"),
                f"[{cc}]{cv}[/{cc}]",
                steps[:40],
                f"{c.get('duration_ms', 0):.0f}ms",
                (c.get("reason") or "")[:60],
            )
        console.print(t)
        console.print()

    findings = report.get("findings") or []
    if findings:
        console.print(f"[bold red]FINDINGS ({len(findings)})[/bold red]")
        for f in findings:
            console.print(
                f"  [bold red]\u25cf[/bold red] "
                f"{f['chain']}/{f['step']}: {f['reason'][:100]}")
        console.print()
    else:
        console.print("[dim]No confirmed vulnerabilities.[/dim]")
        console.print()


def cmd_cve(args):
    if not args or "--help" in args or "-h" in args:
        console.print("[cyan]Usage: cve <product> <version>[/cyan]")
        console.print("  Look up known CVEs for a component version against NVD.")
        console.print("  Set NVD_API_KEY in env to raise the rate limit.")
        console.print("  Example: python run.py cve nginx 1.18.0")
        return 0
    if len(args) < 2:
        console.print("[red]Usage: cve <product> <version>[/red]")
        return
    product, version = args[0], args[1]
    from . import cve_lookup
    console.print(f"[cyan]CVE lookup:[/cyan] {product} {version}")
    hits = cve_lookup.lookup(product, version)
    if not hits:
        console.print("  [dim]No CVEs found (unknown product, unknown version, "
                      "or NVD unreachable).[/dim]")
        return 0
    summary = cve_lookup.summarize(hits)
    t = Table(title=f"{product} {version} — {summary['total']} CVE(s)")
    t.add_column("CVE", style="cyan")
    t.add_column("Severity", style="yellow")
    t.add_column("Summary", style="white")
    for h in hits[:50]:
        color = {"critical": "bold red", "high": "red",
                 "medium": "yellow", "low": "dim"}.get(
                     (h.get("severity") or "").lower(), "white")
        t.add_row(h["id"], f"[{color}]{h.get('severity', '?')}[/{color}]",
                  (h.get("summary") or "")[:90])
    console.print(t)
    console.print(f"  critical={summary['critical']} high={summary['high']} "
                  f"medium={summary['medium']} low={summary['low']}")
    return 0


def cmd_bypass(args):
    if not args or "--help" in args or "-h" in args:
        console.print("[cyan]Usage: bypass <url>[/cyan]")
        console.print("  Test a 403/401 gate for bypass via header overrides "
                      "and path mutations.")
        return 0
    url = args[0]
    from .injection import access_bypass
    from .roe_guard import ROEGuard
    from .config import load_engine
    guard = ROEGuard(engine_cfg=load_engine())
    console.print(f"[cyan]Access bypass probe:[/cyan] {url}")
    r = access_bypass.scan(url, roe_guard=guard)
    color = VERDICT_COLOR.get(r["verdict"], "white")
    console.print(f"  [{color}]{r['verdict']}[/{color}]  {r.reason}")
    for f in (r.evidence or {}).get("findings", [])[:10]:
        label = f.get("header") or f.get("path") or "?"
        console.print(f"    [yellow]{f.get('type')}[/yellow] "
                      f"{label} -> HTTP {f.get('status')}")
    return 0


def cmd_cached(args):
    if not args or "--help" in args or "-h" in args:
        console.print("[cyan]Usage: cached <url>[/cyan]")
        console.print("  Probe for web cache deception: append cacheable "
                      "extensions to a sensitive 200 URL.")
        return 0
    url = args[0]
    from .injection import cache_deception
    from .roe_guard import ROEGuard
    from .config import load_engine
    guard = ROEGuard(engine_cfg=load_engine())
    console.print(f"[cyan]Cache deception probe:[/cyan] {url}")
    r = cache_deception.scan(url, roe_guard=guard)
    color = VERDICT_COLOR.get(r["verdict"], "white")
    console.print(f"  [{color}]{r['verdict']}[/{color}]  {r.reason}")
    for f in (r.evidence or {}).get("findings", [])[:5]:
        console.print(f"    [yellow]{f.get('ext')}[/yellow] "
                      f"cache_headers={f.get('cache_headers')}")
    return 0


def cmd_hunt(args):
    if not args or "--help" in args or "-h" in args:
        console.print("[cyan]Usage: hunt <target> [--budget N] "
                      "[--max-findings N] [--json] [--no-standalone][/cyan]")
        console.print()
        console.print("One-command hunter: recon + every relevant chain + "
                      "top-N summary.")
        console.print()
        console.print("  --budget N         max seconds for the run (default 600)")
        console.print("  --max-findings N   cap findings in report (default 25)")
        console.print("  --json             print raw JSON instead of the "
                      "formatted report")
        console.print("  --no-standalone    skip cloud storage enumeration")
        console.print()
        console.print("Examples:")
        console.print("  python run.py hunt https://nythosx.com")
        console.print("  python run.py hunt https://nythosx.com --budget 900")
        console.print("  python run.py hunt https://nythosx.com --json > report.json")
        return 0
    if not args:
        console.print("[red]Usage: hunt <target>[/red]")
        return

    target = args[0]
    budget = 600
    max_findings = 25
    as_json = bool(RUNTIME.get("json_output"))
    include_standalone = True
    banking = False

    i = 1
    while i < len(args):
        if args[i] == "--banking":
            banking = True; i += 1
        elif args[i] == "--budget" and i + 1 < len(args):
            budget = int(args[i + 1]); i += 2
        elif args[i] == "--max-findings" and i + 1 < len(args):
            max_findings = int(args[i + 1]); i += 2
        elif args[i] == "--json":
            as_json = True; i += 1
        elif args[i] == "--no-standalone":
            include_standalone = False; i += 1
        else:
            i += 1

    from .hunt import hunt as _hunt
    try:
        report = _hunt(
            target, budget_sec=budget, max_findings=max_findings,
            console=console, include_standalone=include_standalone,
            allow_destructive=bool(RUNTIME.get("allow_destructive")),
            banking=banking,
        )
    except RuntimeError as e:
        console.print(f"[red]{e}[/red]")
        return 1

    if as_json:
        import json as _json
        console.print(_json.dumps({
            "target": report["target"],
            "duration_sec": report["duration_sec"],
            "verdict": report["verdict"],
            "total_findings": report["total_findings"],
            "findings": report["findings"],
        }, indent=2, default=str))

    return 0


def cmd_help(args):
    console.print("[bold cyan]sec-checker MVP[/bold cyan]")
    console.print()
    console.print("[bold]Main[/bold]")
    console.print("  hunt <target>                     One-command hunter: recon + all chains + top-N report")
    console.print("  web [--port N]                    Launch web UI (single URL input)")
    console.print("  auto <url>                        Full auto-discovery + scan")
    console.print("  chain <url>                       Adaptive attack chain (recon \u2192 chains \u2192 report)")
    console.print("  chain-stats [--json]              Aggregated chain run statistics")
    console.print("  chains <target>                   Correlated attack chains from findings")
    console.print("  coverage <target>                 OWASP 2025 + surface coverage")
    console.print("  compliance <target>               OWASP 2025 compliance report")
    console.print("  adapters                          List framework adapters")
    console.print()
    console.print("[bold]Recon[/bold]")
    console.print("  enumerate <base_url>              Discover routes")
    console.print("  profile <url>                     Timing baseline")
    console.print()
    console.print("[bold]Auth[/bold]")
    console.print("  login <target_name>               Perform login")
    console.print("  sessions                          List sessions")
    console.print()
    console.print("[bold]Scan[/bold]")
    console.print("  list                              List patterns")
    console.print("  show <pattern_id>                 Pattern details")
    console.print("  validate                          Validate patterns")
    console.print("  scan <pattern> <target>           Single pattern")
    console.print("  scan-all <target>                 All patterns")
    console.print()
    console.print("[bold]Active probes[/bold]")
    console.print("  browser <url>                     Playwright capture (console/JS/screenshot)")
    console.print("  idor <identity_url> <resource>    IDOR live probe")
    console.print("  ssrf <target>                     Blind SSRF (OOB callback)")
    console.print("  ssrf-cloud [<base_url>]           Cloud metadata SSRF")
    console.print("  xss <target> <param>              Blind/reflected XSS (OOB + browser)")
    console.print("  domxss <url>                      DOM XSS source\u2192sink taint + mXSS")
    console.print("  graphql <url>                     GraphQL deep security")
    console.print("  jwt <url> [--token JWT]           JWT attack suite")
    console.print("  race <url>                        Advanced race testing")
    console.print("  openapi <url>                     OpenAPI discovery + schema fuzzing")
    console.print("  bizlogic <base>                   Business logic probes")
    console.print("  workflow <record|replay|tamper>   Browser workflow tooling")
    console.print("  weak-password-check <change_url>  Password policy + lockout probe")
    console.print("  explore <base> --paths /a,/b       Combination explorer (outliers)")
    console.print("  smuggle <target>                  HTTP smuggling timing probe (safe)")
    console.print("  llm <url>                         LLM/AI security scan (OWASP LLM Top 10)")
    console.print()
    console.print("[bold]Extraction[/bold]")
    console.print("  extract <url>                     Paginated data dump (masked)")
    console.print("  bola <base> <template>            Sequential-ID BOLA harvest")
    console.print("  blind <url>                       Blind SQLi value extraction")
    console.print("  mcp-scan <config>                 MCP poisoning + credential scan")
    console.print()
    console.print("[bold]Report[/bold]")
    console.print("  report <target>                   Generate report")
    console.print("  history [--target X]              Recent findings")
    console.print("  targets                           Configured targets")
    console.print()
    console.print("[bold]Flags[/bold]")
    console.print("  --adapter <id>                    Force framework adapter")
    console.print("  --min-severity <level>            critical|high|medium|low|info")
    console.print("  --session <name>                  Use saved session")
    console.print("  --auth user:pass|bearer:X|...     Inline auth")
    console.print("  --auto-baseline                   Profile target before scanning")
    console.print("  --fail-on <level>                 Exit 3 if finding >= level (CI)")
    console.print()
    console.print("[bold]Global flags (any command)[/bold]")
    console.print("  --allow-destructive               Enable destructive/opt-in capabilities")
    console.print("  --dry-run                         Plan only, do not execute")
    console.print("  --json                            Machine-readable output")
    console.print("  --kill-switch FILE                Abort if FILE exists")
    console.print("  --max-requests-per-host N         Per-host HTTP request cap")
    console.print("  --authorized-by NAME              Log the authorizer")
    console.print("  --target-owner ORG                Log the target owner")
    console.print("  --waf                             Enable WAF-aware payload encoding")
    console.print("  --no-waf                          Disable WAF encoder")
    console.print("  --confirm                         Enable exploitation confirmation gate")
    console.print("  --no-confirm                      Disable confirmation gate")
    console.print("  --iterate                         Enable coverage-driven iteration loop")
    console.print("  --iteration-max N                 Max sweeps for iteration loop")
    console.print()


def _target_findings(target):
    resolved = _resolve_report_target(target)
    if resolved != target:
        console.print(f"[dim]Resolved target: {resolved}[/dim]")
    rows = ledger.findings_for_target(resolved)
    keys = ["id", "timestamp", "pattern_id", "category", "verdict", "severity",
            "reason", "wstg_id", "cwe_id", "evidence_path", "duration_ms"]
    return resolved, [dict(zip(keys, r)) for r in rows]


def cmd_chains(args):
    if not args or "--help" in args or "-h" in args:
        console.print("[cyan]Usage: chains <target>[/cyan]")
        console.print("  Correlates findings into multi-step attack chains.")
        return 0
    from . import report
    target, findings = _target_findings(args[0])
    chains = report.build_chains(findings)
    if not chains:
        console.print("[dim]No attack chains correlated from current findings.[/dim]")
        return 0
    cv = {"CONFIRMED": "bold red", "LIKELY": "red", "THEORETICAL": "yellow",
          "INCOMPLETE": "dim"}
    t = Table(title=f"Attack Chains — {target}")
    t.add_column("Chain", style="cyan")
    t.add_column("Verdict", style="bold")
    t.add_column("Conf", justify="right")
    t.add_column("Prereqs", justify="right")
    for c in chains:
        color = cv.get(c.get("verdict"), "white")
        t.add_row(escape(c.get("name", "")),
                  f"[{color}]{c.get('verdict')}[/{color}]",
                  f"{(c.get('confidence') or 0) * 100:.0f}%",
                  f"{len(c.get('matched') or [])}/{len(c.get('prerequisites') or [])}")
    console.print(t)
    for c in chains:
        if c.get("verdict") in ("CONFIRMED", "LIKELY") and c.get("narrative_text"):
            console.print()
            console.print(f"[bold]{escape(c.get('name',''))}[/bold]")
            console.print(escape(c["narrative_text"]))
    return 0


def cmd_coverage(args):
    if not args or "--help" in args or "-h" in args:
        console.print("[cyan]Usage: coverage <target>[/cyan]")
        console.print("  Shows OWASP 2025 and attack-surface coverage: what was tested, what was not.")
        return 0
    from . import report
    target, findings = _target_findings(args[0])
    cov = report.build_coverage(target, findings)
    if not cov:
        console.print("[red]coverage module unavailable[/red]")
        return 1
    console.print(f"[bold]Coverage — {target}[/bold]  "
                  f"({cov['executed_count']}/{cov['total_count']} capabilities executed)")
    t = Table(title="OWASP Top 10:2025")
    t.add_column("Category", style="cyan")
    t.add_column("Coverage", justify="right")
    t.add_column("Executed/Total", justify="right")
    for code, c in cov["owasp"].items():
        pct = c["coverage_pct"]
        color = "green" if pct >= 50 else ("yellow" if pct > 0 else "red")
        t.add_row(code, f"[{color}]{pct:.0f}%[/{color}]", f"{c['covered']}/{c['total']}")
    console.print(t)
    if cov.get("untested_categories"):
        console.print(f"[yellow]Untested categories:[/yellow] "
                      f"{escape(', '.join(cov['untested_categories']))}")
    return 0


def _sr_field(res, name, default=None):
    try:
        v = getattr(res, name)
    except Exception:
        try:
            v = res[name]
        except Exception:
            return default
    return v.value if hasattr(v, "value") else v


def cmd_weak_password(args):
    if not args or "--help" in args or "-h" in args:
        console.print("[cyan]Usage: weak-password-check <change_url> "
                      "[--current-password P] [--change-path PATH] [--auth X] "
                      "[--lockout-login URL --username U][/cyan]")
        console.print("  Tests whether a self-service password change accepts a weak password.")
        console.print("  --lockout-login + --username  also probe for missing account lockout")
        console.print("    (opt-in: sends several failed logins; state-changing).")
        return 0
    from . import weak_password_policy
    target = args[0]
    current_password = None
    change_path = None
    auth_str = None
    lockout_login = None
    username = None
    i = 1
    while i < len(args):
        if args[i] == "--current-password" and i + 1 < len(args):
            current_password = args[i + 1]; i += 2
        elif args[i] == "--change-path" and i + 1 < len(args):
            change_path = args[i + 1]; i += 2
        elif args[i] == "--auth" and i + 1 < len(args):
            auth_str = args[i + 1]; i += 2
        elif args[i] == "--lockout-login" and i + 1 < len(args):
            lockout_login = args[i + 1]; i += 2
        elif args[i] == "--username" and i + 1 < len(args):
            username = args[i + 1]; i += 2
        else:
            i += 1

    from .roe_guard import ROEGuard as _ROEGuard
    guard = _ROEGuard(engine_cfg=load_engine())
    headers = _parse_auth(auth_str) or None
    rows = []
    res = weak_password_policy.scan(target, headers=headers, roe_guard=guard,
                                    change_path=change_path,
                                    current_password=current_password)
    rows.append(("weak-password-policy", res))

    if lockout_login and username:
        console.print("[yellow]Lockout probe is state-changing (sends failed logins). "
                      "Running because you passed --lockout-login + --username.[/yellow]")
        from . import lockout_probe
        lres = lockout_probe.scan(lockout_login, username, headers=headers,
                                  roe_guard=guard)
        rows.append(("lockout-probe", lres))
    elif lockout_login or username:
        console.print("[dim]Lockout probe skipped: needs BOTH --lockout-login and --username.[/dim]")

    t = Table(title="Weak Password Checks")
    t.add_column("Check", style="cyan")
    t.add_column("Verdict", style="bold")
    t.add_column("Severity")
    t.add_column("Reason")
    results_for_exit = []
    for name, res in rows:
        verdict = _sr_field(res, "verdict", "UNKNOWN")
        severity = _sr_field(res, "severity", "info")
        reason = _sr_field(res, "reason", "") or ""
        color = VERDICT_COLOR.get(verdict, "white")
        t.add_row(name, f"[{color}]{verdict}[/{color}]", escape(str(severity)),
                  escape(str(reason)[:80]))
        results_for_exit.append({"verdict": verdict, "severity": severity})
        if verdict in ("VULNERABLE", "SUSPICIOUS"):
            try:
                ledger.record_finding(
                    pattern_id=name, target=target, verdict=verdict,
                    severity=severity, reason=reason, evidence_path="",
                    evidence_json=_sr_field(res, "evidence", {}) or {},
                    category="auth", wstg_id="WSTG-ATHN-07", cwe_id="CWE-521")
            except Exception:
                pass
    console.print(t)
    return 0


def cmd_unauth_scan(args):
    if not args:
        console.print("[red]Usage: unauth-scan <base_url> [--max-paths N][/red]")
        return
    base = args[0]
    max_paths = 40
    i = 1
    while i < len(args):
        if args[i] == "--max-paths" and i + 1 < len(args):
            max_paths = int(args[i + 1])
            i += 2
        else:
            i += 1
    from engine.unauth_exposure import probe
    result = probe(base, max_paths=max_paths)
    color = VERDICT_COLOR.get(result["verdict"], "white")
    console.print(f"  [{color}]{result['verdict']}[/{color}]  "
                  f"{result['reason']}")
    for f in (result.get("evidence") or {}).get("findings", [])[:10]:
        console.print(f"    [red]{f['url']}[/red]  "
                      f"{f['extracted']}/{f['total_rows']} row(s)")
    return 0


def cmd_banking_hunt(args):
    if not args:
        console.print("[red]Usage: banking-hunt <url> [--budget N][/red]")
        return
    url = args[0]
    budget = 900
    i = 1
    while i < len(args):
        if args[i] == "--budget" and i + 1 < len(args):
            budget = int(args[i + 1])
            i += 2
        else:
            i += 1
    from engine.hunt import hunt as _hunt
    try:
        report = _hunt(url, budget_sec=budget, banking=True, verbose=True,
                       console=console)
    except RuntimeError as e:
        console.print(f"[red]{e}[/red]")
        return 1
    console.print(f"[cyan]Verdict:[/cyan] {report['verdict']}")
    console.print(f"[cyan]Total findings:[/cyan] {report['total_findings']}")
    for f in report["findings"]:
        console.print(f"  [{f['severity']}] {f['tool']} / {f['step']}")
        console.print(f"    {f['reason'][:200]}")
    return 0


def cmd_diagnose(args):
    if not args:
        console.print("[red]Usage: diagnose <url>[/red]")
        return
    url = args[0]
    from engine.roe_guard import ROEGuard
    from engine import budget as _budget
    from engine import ratelimit as _ratelimit
    guard = ROEGuard(engine_cfg=load_engine())
    allowed, reason = guard.walkthrough(url, "GET")
    color = "green" if allowed else "red"
    console.print(f"[cyan]ROE:[/cyan] [{color}]"
                  f"{'ALLOWED' if allowed else 'BLOCKED'}[/{color}]")
    console.print(f"  reason: {reason}")
    b = _budget.snapshot_human()
    console.print(f"[cyan]Budget:[/cyan] {b['requests']}/{b['max']} requests, "
                  f"{b['elapsed_seconds']}s elapsed")
    if b.get("reason"):
        console.print(f"  reason: {b['reason']}")
    r = _ratelimit.snapshot()
    console.print(f"[cyan]Rate limiter:[/cyan] {r['limiter_count']} "
                  f"shared limiter(s)")
    return 0


def cmd_chain_stats(args):
    if args and ("--help" in args or "-h" in args):
        console.print("[cyan]Usage: chain-stats [--limit N] [--json][/cyan]")
        console.print("  Aggregates chain_runs from the ledger to show which")
        console.print("  chains/steps produce findings over time.")
        return 0
    limit = 0
    as_json = False
    i = 0
    while i < len(args):
        if args[i] == "--limit" and i + 1 < len(args):
            limit = int(args[i + 1])
            i += 2
        elif args[i] == "--json":
            as_json = True
            i += 1
        else:
            i += 1
    stats = ledger.chain_stats(limit=limit)
    if as_json:
        import json as _json
        console.print(_json.dumps(stats, indent=2, default=str))
        return 0
    if not stats.get("chains"):
        console.print("[yellow]No chain runs recorded yet.[/yellow]")
        return 0
    t = Table(title="Chain Statistics")
    t.add_column("Chain", style="cyan")
    t.add_column("Runs", justify="right")
    t.add_column("Vuln", justify="right", style="bold red")
    t.add_column("Susp", justify="right", style="yellow")
    t.add_column("Pass", justify="right", style="bold green")
    t.add_column("Avg ms", justify="right", style="dim")
    for c in stats["chains"]:
        t.add_row(
            c["chain_id"], str(c["runs"]),
            str(c["vulnerable"]), str(c["suspicious"]),
            str(c["pass_count"]), f"{c['avg_duration_ms']:.0f}",
        )
    console.print(t)
    return 0


def cmd_verify_fix(args):
    if not args or "--help" in args or "-h" in args:
        console.print("[cyan]Usage: verify-fix <finding_id> "
                      "[--json][/cyan]")
        console.print("  Re-runs the minimal PoC for a confirmed finding.")
        console.print("  On PASS emits a signed 'fixed & verified' record "
                      "into findings/verified/.")
        return 0
    from . import evidence_synth, confirm as _confirm, ledger as _ledger
    from .roe_guard import ROEGuard as _ROEGuard
    from pathlib import Path as _Path
    _ROOT = _Path(__file__).parent.parent.absolute()
    finding_id = args[0]
    as_json = "--json" in args
    finding = _ledger.get_finding(finding_id)
    if finding is None:
        console.print(f"[red]No finding with id {finding_id}[/red]")
        return 1
    capability = finding.get("pattern_id") or ""
    target = finding.get("target") or ""
    ctx = {"target": target,
           "roe_guard": _ROEGuard(engine_cfg=load_engine())}

    def poc_runner():
        res = _confirm.confirm(capability, finding, ctx)
        return {"verdict": "VULNERABLE" if res.get("confirmed") else "PASS",
                "reason": res.get("reason")}

    record = evidence_synth.verify_fix(finding_id, poc_runner)
    out_dir = _ROOT / "findings" / "verified"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"finding_{evidence_synth._safe(finding_id)}.json"
    import json as _json
    out_path.write_text(_json.dumps(record, indent=2, default=str),
                        encoding="utf-8")
    if as_json:
        console.print(_json.dumps(record, indent=2, default=str))
    else:
        color = "green" if record["verdict"].startswith("fixed") else "red"
        console.print(f"[{color}]{record['verdict']}[/{color}] "
                      f"(finding {finding_id}) — {record.get('reason')}")
        console.print(f"[dim]Signed record: {out_path}[/dim]")
    return 0


def cmd_extract(args):
    if not args:
        console.print("[red]Usage: extract <url> [--rows N] [--pages N] [--token TOKEN] [--session NAME][/red]")
        return
    url = args[0]
    token = None
    session = None
    max_pages = 50
    max_rows = 50
    i = 1
    while i < len(args):
        if args[i] == "--token" and i + 1 < len(args):
            token = args[i + 1]; i += 2
        elif args[i] == "--session" and i + 1 < len(args):
            session = args[i + 1]; i += 2
        elif args[i] == "--pages" and i + 1 < len(args):
            max_pages = int(args[i + 1]); i += 2
        elif args[i] == "--rows" and i + 1 < len(args):
            max_rows = int(args[i + 1]); i += 2
        else:
            i += 1
    if session:
        sess = load_session(session)
        if sess:
            hdrs = auth_flow.build_headers_from_session(sess)
            if not token:
                for k, v in hdrs.items():
                    if k.lower() == "authorization":
                        token = v.split(" ", 1)[1] if " " in v else v
    from engine.data_extractor import extract_with_pagination
    console.print(f"[cyan]Pagination extract:[/cyan] {url}")
    result = extract_with_pagination(url, token=token, max_pages=max_pages)
    rows = result.get("rows") or []
    if not rows:
        console.print(f"  [yellow]no rows recovered[/yellow] "
                       f"({result.get('pages_fetched', 0)} page(s) tried)")
        return 0
    from rich.table import Table as _T
    t = _T(title=f"Extracted ({len(rows)} row(s) across "
                 f"{result.get('pages_fetched', 0)} page(s))")
    for col in list(rows[0].keys())[:6]:
        t.add_column(col, style="white", overflow="fold")
    from engine.util import mask_row
    for r in rows[:max_rows]:
        masked = mask_row(r)
        t.add_row(*[str(masked.get(k, ""))[:40] for k in list(r.keys())[:6]])
    console.print(t)
    try:
        from engine import ledger
        ledger.record_extracted(
            target=url, endpoint=url, method="GET",
            auth_used="authenticated" if token else "unauthenticated",
            status=200, total_rows=len(rows),
            extracted=min(len(rows), max_rows), rows=rows[:max_rows],
            source_pattern="cli-extract",
        )
    except Exception:
        pass
    return 0


def cmd_bola(args):
    if len(args) < 2:
        console.print("[red]Usage: bola <base_url> <endpoint_template> "
                      "[--token-a TOKEN] [--token-b TOKEN] [--max-records N][/red]")
        return
    base_url = args[0]
    template = args[1]
    token_a = None
    token_b = None
    max_records = 100
    i = 2
    while i < len(args):
        if args[i] == "--token-a" and i + 1 < len(args):
            token_a = args[i + 1]; i += 2
        elif args[i] == "--token-b" and i + 1 < len(args):
            token_b = args[i + 1]; i += 2
        elif args[i] == "--max-records" and i + 1 < len(args):
            max_records = int(args[i + 1]); i += 2
        else:
            i += 1
    token = token_b or token_a
    if not token:
        console.print("[red]bola: needs --token-a or --token-b[/red]")
        return 1
    from engine.bola_scanner import harvest_sequential_ids
    console.print(f"[cyan]BOLA harvest:[/cyan] {template} "
                   f"(max {max_records} records)")
    harvested = harvest_sequential_ids(
        base_url, template, token, max_records=max_records,
    )
    if not harvested:
        console.print("  [yellow]no records harvested across ID space[/yellow]")
        return 0
    owners = {str(h["owner_value"]) for h in harvested
              if h.get("owner_value") is not None}
    console.print(f"  [green]{len(harvested)} record(s) harvested[/green] "
                   f"across {len(owners)} distinct owner(s)")
    from rich.table import Table as _T
    t = _T(title="Harvested Records (masked)")
    t.add_column("ID", style="cyan")
    t.add_column("Owner", style="yellow")
    t.add_column("Sample Fields", style="white")
    from engine.util import mask_row
    for h in harvested[:20]:
        sample = h["rows"][0] if h.get("rows") else {}
        masked = mask_row(sample) if isinstance(sample, dict) else {}
        preview = ", ".join(f"{k}={str(v)[:20]}" for k, v in list(masked.items())[:4])
        t.add_row(str(h["id"]), str(h.get("owner_value", "-"))[:30], preview)
    console.print(t)
    try:
        from engine import ledger
        ledger.record_extracted(
            target=base_url, endpoint=template, method="GET",
            auth_used="user-b" if token_b else "user-a",
            status=200, total_rows=len(harvested),
            extracted=min(len(harvested), 20),
            rows=[h["rows"][0] for h in harvested if h.get("rows")][:20],
            source_pattern="cli-bola",
        )
    except Exception:
        pass
    return 0


def cmd_blind(args):
    if not args:
        console.print("[red]Usage: blind <url> --param q --table users "
                      "--column password [--dbms mysql][/red]")
        return
    url = args[0]
    param = "q"
    table = "users"
    column = "password"
    dbms = None
    max_length = 64
    i = 1
    while i < len(args):
        if args[i] == "--param" and i + 1 < len(args):
            param = args[i + 1]; i += 2
        elif args[i] == "--table" and i + 1 < len(args):
            table = args[i + 1]; i += 2
        elif args[i] == "--column" and i + 1 < len(args):
            column = args[i + 1]; i += 2
        elif args[i] == "--dbms" and i + 1 < len(args):
            dbms = args[i + 1]; i += 2
        elif args[i] == "--max-length" and i + 1 < len(args):
            max_length = int(args[i + 1]); i += 2
        else:
            i += 1
    from engine.blind_extract import fingerprint_dbms, extract_string
    console.print(f"[cyan]Blind extract:[/cyan] {url} param={param}")
    console.print(f"  target: {table}.{column}")
    if not dbms:
        console.print("  [dim]fingerprinting DBMS…[/dim]")
        dbms, fp = fingerprint_dbms(url, param)
        if not dbms:
            console.print(f"  [yellow]no timing signal — is param "
                           f"'{param}' injectable?[/yellow]")
            return 0
        console.print(f"  [green]detected: {dbms}[/green]")
    console.print(f"  [dim]extracting via {dbms} timing…[/dim]")
    result = extract_string(url, param, table, column, dbms=dbms,
                             max_length=max_length)
    extracted = result.get("extracted", "")
    if extracted:
        console.print(f"  [bold red]{table}.{column} = {extracted}[/bold red]")
        console.print(f"  [dim]{result.get('requests')} requests, "
                       f"baseline {result.get('baseline_ms')}ms[/dim]")
    else:
        console.print("  [yellow]no characters extracted[/yellow]")
    return 0


def cmd_mcp_scan(args):
    if not args:
        console.print("[red]Usage: mcp-scan <config_path> [--check poisoning|credentials][/red]")
        return
    config_path = args[0]
    check = "poisoning"
    i = 1
    while i < len(args):
        if args[i] == "--check" and i + 1 < len(args):
            check = args[i + 1]; i += 2
        else:
            i += 1
    from engine.mcp_security import _tool_mcp_security
    class _StubOrch:
        target = config_path
        roe_guard = None
    result = _tool_mcp_security(_StubOrch(), {"config_path": config_path,
                                               "check": check})
    v = result.get("verdict", "UNKNOWN")
    color = VERDICT_COLOR.get(v, "white")
    console.print(f"[cyan]MCP scan:[/cyan] {config_path} ({check})")
    console.print(f"  [{color}]{v}[/{color}]  {result.get('reason', '')}")
    for h in (result.get("evidence") or {}).get("hits") or []:
        console.print(f"    [yellow]{h.get('where')}[/yellow]: {h.get('match')}")
    for c in (result.get("evidence") or {}).get("credentials") or []:
        console.print(f"    [red]{c.get('type')}[/red]: {c.get('match')}")
    return 0


COMMANDS = {
    "list": cmd_list,
    "unauth-scan": cmd_unauth_scan,
    "banking-hunt": cmd_banking_hunt,
    "diagnose": cmd_diagnose,
    "show": cmd_show,
    "chains": cmd_chains,
    "coverage": cmd_coverage,
    "weak-password-check": cmd_weak_password,
    "validate": cmd_validate,
    "adapters": cmd_adapters,
    "scan": cmd_scan,
    "scan-all": cmd_scan_all,
    "auto": cmd_auto,
    "chain": cmd_chain,
    "chain-stats": cmd_chain_stats,
    "verify-fix": cmd_verify_fix,
    "profile": cmd_profile,
    "enumerate": cmd_enumerate,
    "login": cmd_login,
    "sessions": cmd_sessions,
    "report": cmd_report,
    "browser": cmd_browser,
    "idor": cmd_idor,
    "ssrf": cmd_ssrf,
    "xss": cmd_xss,
    "explore": cmd_explore,
    "smuggle": cmd_smuggle,
    "jwt": cmd_jwt,
    "graphql": cmd_graphql,
    "race": cmd_race,
    "domxss": cmd_domxss,
    "ssrf-cloud": cmd_ssrfcloud,
    "openapi": cmd_openapi,
    "bizlogic": cmd_bizlogic,
    "workflow": cmd_workflow,
    "compliance": cmd_compliance,
    "sca": cmd_sca,
    "llm": cmd_llm,
    "web": cmd_web,
    "history": cmd_history,
    "targets": cmd_targets,
    "cve": cmd_cve,
    "bypass": cmd_bypass,
    "cached": cmd_cached,
    "hunt": cmd_hunt,
    "extract": cmd_extract,
    "bola": cmd_bola,
    "blind": cmd_blind,
    "mcp-scan": cmd_mcp_scan,
    "help": cmd_help,
    "-h": cmd_help,
    "--help": cmd_help,
}


_GLOBAL_FLAGS = {
    "--allow-destructive": ("allow_destructive", "flag"),
    "--dry-run": ("dry_run", "flag"),
    "--json": ("json_output", "flag"),
    "--kill-switch": ("kill_switch", "value"),
    "--max-requests-per-host": ("max_requests_per_host", "int"),
    "--authorized-by": ("authorized_by", "value"),
    "--target-owner": ("target_owner", "value"),
    "--waf": ("waf_enabled", "flag"),
    "--no-waf": ("waf_disabled", "flag"),
    "--confirm": ("confirm_enabled", "flag"),
    "--no-confirm": ("confirm_disabled", "flag"),
    "--iterate": ("iterate_enabled", "flag"),
    "--iteration-max": ("iteration_max", "int"),
    "--duration": ("duration_override", "int"),
    "--max-requests": ("max_requests_override", "int"),
    "--legacy-scoring": ("legacy_scoring", "flag"),
}

RUNTIME = {
    "allow_destructive": False,
    "dry_run": False,
    "json_output": False,
    "kill_switch": None,
    "max_requests_per_host": None,
    "authorized_by": None,
    "target_owner": None,
    "waf_enabled": False,
    "waf_disabled": False,
    "confirm_enabled": False,
    "confirm_disabled": False,
    "iterate_enabled": False,
    "iteration_max": None,
    "duration_override": None,
    "max_requests_override": None,
    "legacy_scoring": False,
}


def _parse_global_flags(argv):
    if not argv:
        return []
    rest = []
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok in _GLOBAL_FLAGS:
            key, kind = _GLOBAL_FLAGS[tok]
            if kind == "flag":
                RUNTIME[key] = True
                i += 1
                continue
            if i + 1 >= len(argv):
                console.print(f"[red]{tok} requires a value[/red]")
                return None
            val = argv[i + 1]
            if kind == "int":
                try:
                    RUNTIME[key] = int(val)
                except ValueError:
                    console.print(f"[red]{tok} must be an integer[/red]")
                    return None
            else:
                RUNTIME[key] = val
            i += 2
            continue
        rest.append(tok)
        i += 1
    return rest


def _check_kill_switch():
    path = RUNTIME.get("kill_switch")
    if not path:
        return False
    from pathlib import Path as _P
    if _P(path).exists():
        console.print(f"[bold red]KILL SWITCH ACTIVE:[/bold red] {path} exists; "
                      f"aborting.")
        return True
    return False


def _apply_runtime():
    if RUNTIME.get("authorized_by"):
        console.print(f"[dim]authorized_by: {RUNTIME['authorized_by']}[/dim]")
    if RUNTIME.get("target_owner"):
        console.print(f"[dim]target_owner: {RUNTIME['target_owner']}[/dim]")
    _active = []
    if RUNTIME.get("waf_enabled"):
        _active.append("--waf")
    if RUNTIME.get("waf_disabled"):
        _active.append("--no-waf")
    if RUNTIME.get("confirm_enabled"):
        _active.append("--confirm")
    if RUNTIME.get("confirm_disabled"):
        _active.append("--no-confirm")
    if RUNTIME.get("iterate_enabled"):
        _active.append("--iterate")
    if RUNTIME.get("iteration_max") is not None:
        _active.append(f"--iteration-max {RUNTIME['iteration_max']}")
    if RUNTIME.get("duration_override") is not None:
        _active.append(f"--duration {RUNTIME['duration_override']}")
    if RUNTIME.get("max_requests_override") is not None:
        _active.append(f"--max-requests {RUNTIME['max_requests_override']}")
    if _active:
        console.print(f"[dim]runtime: {' '.join(_active)}[/dim]")
    try:
        from . import budget as _budget
        _budget.auto_configure_from_configs()
        _banking_mode = "--banking" in (sys.argv[1:] if hasattr(sys, "argv") else [])
        if _banking_mode and RUNTIME.get("max_requests_per_host") is None:
            RUNTIME["max_requests_per_host"] = 2500
        if RUNTIME.get("max_requests_per_host") or \
                RUNTIME.get("duration_override") or \
                RUNTIME.get("max_requests_override"):
            snap = _budget.snapshot()
            _budget.configure(
                max_requests=(int(RUNTIME["max_requests_override"])
                              if RUNTIME.get("max_requests_override")
                              else snap.get("max_requests")),
                max_per_host=(int(RUNTIME["max_requests_per_host"])
                              if RUNTIME.get("max_requests_per_host")
                              else snap.get("max_per_host")),
                max_duration_seconds=(int(RUNTIME["duration_override"])
                                      if RUNTIME.get("duration_override")
                                      else snap.get("max_duration_seconds")),
            )
    except Exception:
        pass


def main(argv):
    if not argv:
        cmd_help([])
        return 0
    rest = _parse_global_flags(list(argv))
    if rest is None:
        return 2
    if not rest:
        cmd_help([])
        return 0
    cmd = rest[0]
    handler = COMMANDS.get(cmd)
    if not handler:
        console.print(f"[red]Unknown command: {cmd}[/red]")
        cmd_help([])
        return 1
    if _check_kill_switch():
        return 4
    _apply_runtime()
    code = handler(rest[1:])
    return code or 0
