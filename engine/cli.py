import base64
import json
import time
from rich.console import Console
from rich.markup import escape
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
    if not args:
        console.print("[red]Usage: llm <url> [--model MODEL] [--api-key KEY] "
                      "[--auth X] [--session NAME] [--fail-on SEV][/red]")
        return
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
    t = Table(title="LLM Security Results")
    t.add_column("Category", style="cyan")
    t.add_column("OWASP", style="magenta")
    t.add_column("Severity", style="yellow")
    t.add_column("Verdict", style="bold")
    t.add_column("Reason", style="white")
    counts = {"VULNERABLE": 0, "SUSPICIOUS": 0, "PASS": 0, "UNKNOWN": 0}
    for r in results:
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


def cmd_help(args):
    console.print("[bold cyan]sec-checker MVP[/bold cyan]")
    console.print()
    console.print("[bold]Main[/bold]")
    console.print("  web [--port N]                    Launch web UI (single URL input)")
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
    console.print("  llm <url>                         LLM/AI security scan (OWASP LLM Top 10)")
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
