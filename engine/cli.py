import base64
import json
import time
from rich.console import Console
from rich.table import Table
from . import (loader, executor, oracle, evidence, ledger, report,
               baseline, auth_flow, route_enum, adapter_loader)
from .config import (load_engine, load_targets, get_target, save_session,
                     load_session, list_sessions)

console = Console()
SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
VERDICT_COLOR = {
    "VULNERABLE": "bold red",
    "SUSPICIOUS": "bold yellow",
    "PASS": "bold green",
    "UNKNOWN": "dim",
}
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


def cmd_auto(args):
    if not args:
        console.print("[red]Usage: auto <url> [--min-severity X] [--adapter ID][/red]")
        return
    from . import auto as auto_mod
    url = args[0]
    min_sev = "medium"
    skip = False
    adapter_override = None
    auto_baseline = False
    fail_on = None
    i = 1
    while i < len(args):
        if args[i] == "--min-severity" and i + 1 < len(args):
            min_sev = args[i + 1]
            i += 2
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
        else:
            i += 1
    outcome = auto_mod.run_auto(url, min_severity=min_sev, skip_discovery=skip,
                                adapter_override=adapter_override,
                                auto_baseline=auto_baseline)
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
        console.print("[red]Usage: report <target> [--format html|md|sarif][/red]")
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


def cmd_help(args):
    console.print("[bold cyan]sec-checker MVP[/bold cyan]")
    console.print()
    console.print("[bold]Main[/bold]")
    console.print("  auto <url>                        Full auto-discovery + scan")
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
    console.print("  xss <target> <param>              Blind/reflected XSS (OOB + browser)")
    console.print("  explore <base> --paths /a,/b       Combination explorer (outliers)")
    console.print("  smuggle <target>                  HTTP smuggling timing probe (safe)")
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


COMMANDS = {
    "list": cmd_list,
    "show": cmd_show,
    "validate": cmd_validate,
    "adapters": cmd_adapters,
    "scan": cmd_scan,
    "scan-all": cmd_scan_all,
    "auto": cmd_auto,
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
    "history": cmd_history,
    "targets": cmd_targets,
    "help": cmd_help,
    "-h": cmd_help,
    "--help": cmd_help,
}


def main(argv):
    if not argv:
        cmd_help([])
        return 0
    cmd = argv[0]
    handler = COMMANDS.get(cmd)
    if not handler:
        console.print(f"[red]Unknown command: {cmd}[/red]")
        cmd_help([])
        return 1
    code = handler(argv[1:])
    return code or 0
