import json
import time
from pathlib import Path
from rich.console import Console
from rich.table import Table
import httpx
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from . import (discovery, api_discovery, loader, executor, oracle,
               evidence, ledger, report, auth_flow, progress)
from .config import load_engine, save_session, discovery_config
from .util import safe_name

console = Console()
ROOT = Path(__file__).parent.parent.absolute()
CRED_FILE = ROOT / "configs" / "credentials.yaml"

SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
VERDICT_COLOR = {
    "VULNERABLE": "bold red",
    "SUSPICIOUS": "bold yellow",
    "PASS": "bold green",
    "UNKNOWN": "dim",
}


def _load_credentials():
    if not CRED_FILE.exists():
        return {}
    try:
        import yaml
        return yaml.safe_load(CRED_FILE.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}


def _find_creds_for(url):
    creds = _load_credentials()
    items = (creds.get("credentials") or {}).items()
    for pattern, spec in items:
        if pattern in url or pattern == "*":
            return spec
    return None


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


def _run_pattern(pid, target, headers=None, cookies=None, overrides=None,
                 negative_baseline=None):
    pattern = loader.load_pattern(pid)
    if not pattern:
        return None
    suffix = pattern.get("endpoint_suffix", "")
    if suffix:
        target = target.rstrip("/") + suffix
    if pattern.get("ignore_default_auth"):
        headers = {}
        cookies = {}
    headers = headers or {}
    cookies = cookies or {}
    overrides = overrides or {}
    inputs = _build_inputs(pattern, target, overrides)
    engine_cfg = load_engine()
    t0 = time.perf_counter()
    context = executor.execute_pattern(pattern, inputs, target,
                                        default_headers=headers,
                                        engine_config=engine_cfg,
                                        cookies=cookies,
                                        negative_baseline=negative_baseline)
    elapsed = (time.perf_counter() - t0) * 1000.0
    result = _pick_verdict(pattern, context)
    return {
        "pattern": pattern,
        "context": context,
        "result": result,
        "duration_ms": round(elapsed, 3),
    }


def _record(pid, target, out):
    pattern = out["pattern"]
    result = out["result"]
    tags = pattern.get("tags", [])
    wstg = next((t for t in tags if t.startswith("wstg-")), "")
    cwe = next((t for t in tags if t.startswith("cwe-")), "")
    path = evidence.save_evidence(pid, target, out["context"],
                                   result["verdict"], result)
    ledger.record_finding(
        pattern_id=pid,
        target=target,
        verdict=result["verdict"],
        severity=pattern.get("severity", "info"),
        reason=result.get("reason", ""),
        evidence_path=path,
        evidence_json=result.get("evidence", {}),
        category=pattern.get("_category", ""),
        wstg_id=wstg.upper() if wstg else "",
        cwe_id=cwe.upper() if cwe else "",
        duration_ms=out["duration_ms"],
    )
    return path


def _preflight_check(url, timeout=5):
    try:
        with httpx.Client(timeout=timeout, follow_redirects=False, verify=False) as c:
            r = c.get(url)
            return True, r.status_code, None
    except httpx.ConnectError as e:
        return False, None, f"ConnectError: {e}"
    except httpx.TimeoutException:
        return False, None, "Timeout"
    except Exception as e:
        return False, None, f"{type(e).__name__}: {e}"


def _safe_name(url):
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in url)[:80]


def _origin(url):
    from urllib.parse import urlparse
    p = urlparse(url)
    if not p.scheme or not p.hostname:
        return url.rstrip("/")
    netloc = p.hostname + (f":{p.port}" if p.port else "")
    return f"{p.scheme}://{netloc}"


def _score_login_path(path):
    pl = path.lower()
    score = 0
    if "login" in pl:
        score += 40
    if "signin" in pl:
        score += 35
    if "auth" in pl:
        score += 20
    if pl.startswith(("/api", "/v1", "/v2")):
        score += 25
    if "admin" in pl:
        score -= 10
    return score


def _resolve_role_targets(api_paths, frontend_url, api_base):
    roles = {}
    origin = _origin(api_base or frontend_url)
    login_candidates = [p for p in (api_paths or [])
                        if ("login" in p.lower() or "signin" in p.lower())]
    if login_candidates:
        best = max(login_candidates, key=_score_login_path)
        roles["login"] = origin + "/" + best.lstrip("/")
    return roles


def _get_login_url(login_info):
    if not isinstance(login_info, dict):
        return ""
    return login_info.get("url") or login_info.get("login_url") or ""


def _get_token_string(login_info):
    if not isinstance(login_info, dict):
        return ""
    t = login_info.get("token")
    if isinstance(t, str):
        return t
    if isinstance(t, dict):
        return t.get("token", "") or ""
    return ""


def _print_adapter_header(framework):
    adapter = framework.get("adapter") or {}
    score = framework.get("score", 0)
    name = adapter.get("name", "Generic")
    fw_id = adapter.get("id", "generic")
    color = "bold green" if fw_id != "generic" else "bold yellow"
    console.print(f"[bold]Framework:[/bold] [{color}]{name}[/{color}]  "
                   f"[dim](score={score}, id={fw_id})[/dim]")
    if framework.get("powered_by"):
        console.print(f"  X-Powered-By: {framework['powered_by']}")
    if framework.get("server"):
        console.print(f"  Server: {framework['server']}")
    ev = framework.get("evidence") or []
    for e in ev[:5]:
        console.print(f"  [dim]· {e}[/dim]")
    alts = framework.get("alternatives") or []
    if alts and len(alts) > 1:
        second = alts[1]
        if second["score"] > 0:
            console.print(f"  [dim]alt: {second['adapter'].get('name')} "
                           f"(score={second['score']})[/dim]")
    console.print()


def _resolve_targets(frontend_url, adapter, api_override=None):
    result = {
        "frontend": frontend_url,
        "api_base": api_override,
        "source": "override" if api_override else None,
        "port_scan": [],
        "catch_all": False,
        "soft_404": None,
    }
    if api_override:
        return result
    console.print("[bold]Discovering API base...[/bold]")
    disc = api_discovery.discover(frontend_url, adapter=adapter,
                                   config=discovery_config())
    result["port_scan"] = disc.get("port_scan") or []
    result["catch_all"] = bool(disc.get("catch_all"))
    result["soft_404"] = disc.get("soft_404")
    if disc.get("catch_all"):
        console.print("  [yellow]Catch-all page detected (soft-404) — "
                      "API-behavior probes will be treated as inconclusive[/yellow]")
    if disc.get("candidate_api_base"):
        result["api_base"] = disc["candidate_api_base"]
        result["source"] = disc["source"]
        console.print(f"  [green]{disc['candidate_api_base']}[/green]  "
                       f"([dim]{disc['source']}[/dim])")
    else:
        result["api_base"] = frontend_url
        result["source"] = "fallback:frontend"
        console.print("  [yellow]Not found — using frontend URL[/yellow]")
    if result["port_scan"]:
        console.print(f"  Port scan: {len(result['port_scan'])} live")
        for p in result["port_scan"][:5]:
            tag = "[green]JSON[/green]" if p["json"] else "[dim]HTML[/dim]"
            console.print(f"    :{p['port']:<6} {p['status']}  {tag}  "
                           f"{p.get('server', '')}")
    console.print()
    return result


def _attempt_login(frontend_url, api_base, adapter, api_paths):
    credentials = _find_creds_for(frontend_url) or _find_creds_for(api_base)
    if not credentials:
        console.print("[dim]No credentials — running unauthenticated[/dim]")
        console.print()
        return {}, {}, None

    username = credentials.get("username", "")
    password = credentials.get("password", "")
    if not (username and password):
        console.print("[dim]Credentials incomplete — unauthenticated[/dim]")
        console.print()
        return {}, {}, None

    console.print("[bold]Attempting auto-login...[/bold]")
    console.print(f"  Username: {username}")

    auth_headers = {}
    auth_cookies = {}
    login_info = None
    auth_cfg = adapter.get("auth", {}) or {}
    token_paths = auth_cfg.get("token_paths") or ["token", "access_token", "data.token"]
    default_header = auth_cfg.get("default_header", "Authorization")
    default_prefix = auth_cfg.get("default_prefix", "Bearer ")

    login_url_override = credentials.get("login_url")
    if login_url_override:
        console.print(f"  Login URL (from credentials): {login_url_override}")
        result = auth_flow.perform_login(
            login_url_override, username, password,
            login_type=credentials.get("login_type", "json"),
            username_field=credentials.get("username_field", "email"),
            password_field=credentials.get("password_field", "password"),
            token_path=credentials.get("token_path", token_paths[0]),
            token_header=default_header,
            token_prefix=default_prefix,
        )
        if result.get("token"):
            auth_headers[default_header] = f"{default_prefix}{result['token']}"
            auth_cookies.update(result.get("cookies") or {})
            console.print(f"  [green]Login OK[/green] via {login_url_override}")
        else:
            console.print(f"  [yellow]Login status {result.get('status')}[/yellow]")
            preview = result.get("raw_body_preview", "")[:150]
            if preview:
                console.print(f"  [dim]{preview}[/dim]")
        login_info = result
    else:
        login_info = discovery.find_login_endpoint(
            api_base or frontend_url, adapter, api_paths, username, password
        )
        if login_info and login_info.get("token"):
            tok = login_info["token"]
            auth_headers[default_header] = f"{default_prefix}{tok['token']}"
            auth_cookies.update(login_info.get("cookies") or {})
            console.print(f"  [green]Login OK[/green] via {login_info['path']}")
        elif login_info:
            console.print(f"  [yellow]Endpoint found: {login_info['path']}[/yellow]")
            console.print(f"  status={login_info['status']} note={login_info.get('note')}")
        else:
            console.print("  [yellow]No login endpoint discovered[/yellow]")

    console.print()
    return auth_headers, auth_cookies, login_info


def run_auto(url, min_severity="medium", credentials=None, skip_discovery=False,
             api_override=None, adapter_override=None, auto_baseline=False,
             job_id=None):
    def emit(t, d=None):
        progress.emit(job_id, t, d)

    progress.set_active_job(job_id)
    url = url.rstrip("/")
    console.rule("[bold cyan]AUTO-DISCOVERY[/bold cyan]")
    console.print(f"[cyan]Target:[/cyan] {url}")
    console.print()
    emit("start", {"url": url})

    emit("phase", {"name": "preflight", "status": "running"})
    console.print("[bold]Preflight check...[/bold]")
    ok, status, err = _preflight_check(url)
    if ok:
        console.print(f"  [green]Reachable[/green]  HTTP {status}")
        emit("phase", {"name": "preflight", "status": "done"})
        emit("preflight", {"ok": True, "status": status})
    else:
        console.print(f"  [red]UNREACHABLE[/red]  {err}")
        emit("phase", {"name": "preflight", "status": "failed"})
        emit("preflight", {"ok": False, "status": None, "error": err})
        console.print()
        console.print("[yellow]Target is not responding. Aborting scan.[/yellow]")
        console.print()
        console.print("[bold]Common causes:[/bold]")
        console.print("  - Dev server not running (php artisan serve / npm run dev)")
        console.print("  - Wrong URL or port")
        console.print("  - Firewall blocking the connection")
        console.print("  - Server crashed")
        console.print()
        emit("error", {"message": "Target unreachable", "detail": err})
        return
    console.print()

    emit("phase", {"name": "framework", "status": "running"})
    if adapter_override:
        from . import adapter_loader
        adapter = adapter_loader.get(adapter_override)
        if not adapter:
            console.print(f"[red]Adapter not found: {adapter_override}[/red]")
            emit("phase", {"name": "framework", "status": "failed"})
            emit("error", {"message": f"Adapter not found: {adapter_override}"})
            return
        framework = {
            "framework": adapter["id"],
            "name": adapter.get("name", adapter["id"]),
            "adapter": adapter,
            "score": 999,
            "evidence": ["forced by --adapter"],
            "alternatives": [],
            "landing_url": url,
            "server": "",
            "powered_by": "",
        }
        _print_adapter_header(framework)
    else:
        framework = discovery.detect_framework(url)
        _print_adapter_header(framework)

    adapter = framework["adapter"]
    emit("framework", {
        "id": adapter.get("id", "generic"),
        "name": adapter.get("name", "Generic"),
        "score": framework.get("score", 0),
        "powered_by": framework.get("powered_by", ""),
        "server": framework.get("server", ""),
        "evidence": (framework.get("evidence") or [])[:5],
    })
    emit("phase", {"name": "framework", "status": "done"})

    emit("phase", {"name": "discovery", "status": "running"})
    targets = _resolve_targets(url, adapter, api_override)
    api_base = targets["api_base"]
    emit("api_base", {
        "url": api_base,
        "source": targets["source"],
        "ports": targets.get("port_scan") or [],
    })

    js_urls = []
    api_paths = []
    if not skip_discovery:
        console.print("[bold]Extracting JS bundles...[/bold]")
        js_urls = discovery.extract_js_urls(url)
        console.print(f"  Found {len(js_urls)} script sources")
        emit("js_start", {"count": len(js_urls)})
        if js_urls:
            api_paths, bundles = discovery.crawl_js_for_paths(url, js_urls, adapter)
            total_kb = sum(b["size"] for b in bundles) // 1024
            console.print(f"  Analyzed {len(bundles)} bundles ({total_kb} KB)")
            console.print(f"  Extracted {len(api_paths)} candidate API paths")
            emit("js_done", {"count": len(bundles), "size_kb": total_kb,
                             "paths": len(api_paths)})
        console.print()
    emit("phase", {"name": "discovery", "status": "done"})

    emit("phase", {"name": "login", "status": "running"})
    if credentials:
        auth_headers = {}
        auth_cookies = {}
        login_info = credentials
        username = credentials.get("username", "")
        password = credentials.get("password", "")
        login_url_override = credentials.get("login_url")
        if username and password and login_url_override:
            result = auth_flow.perform_login(
                login_url_override, username, password,
                login_type=credentials.get("login_type", "json"),
                username_field=credentials.get("username_field", "email"),
                password_field=credentials.get("password_field", "password"),
                token_path=credentials.get("token_path", "token"),
            )
            if result.get("token"):
                auth_headers["Authorization"] = f"Bearer {result['token']}"
                auth_cookies.update(result.get("cookies") or {})
    else:
        auth_headers, auth_cookies, login_info = _attempt_login(
            url, api_base, adapter, api_paths
        )

    logged_in = bool(auth_headers or auth_cookies)
    emit("login", {
        "ok": logged_in,
        "url": _get_login_url(login_info),
        "token": _get_token_string(login_info)[:40] + ("..." if _get_token_string(login_info) else ""),
    })
    emit("phase", {"name": "login",
                    "status": "done" if logged_in else "skipped"})

    if auth_headers or auth_cookies:
        save_session("auto_" + _safe_name(url), {
            "login_url": _get_login_url(login_info),
            "auth_headers": auth_headers,
            "cookies": auth_cookies,
            "token": _get_token_string(login_info),
            "adapter": adapter.get("id"),
        })

    scan_target = api_base if api_base else url

    if auto_baseline:
        emit("phase", {"name": "baseline", "status": "running"})
        console.print("[bold]Profiling baseline...[/bold]")
        try:
            from . import baseline as _baseline
            prof = _baseline.profile_endpoint(scan_target, samples=20)
            if prof:
                _baseline.save_baseline(scan_target, prof)
                console.print(f"  [green]saved[/green]  "
                              f"mean={prof['mean_ms']}ms  "
                              f"stdev={prof['stdev_ms']}ms")
                emit("baseline", {"mean_ms": prof["mean_ms"],
                                   "stdev_ms": prof["stdev_ms"]})
            else:
                console.print("  [yellow]no baseline samples[/yellow]")
        except Exception as e:
            console.print(f"  [red]baseline error: {e}[/red]")
        console.print()
        emit("phase", {"name": "baseline", "status": "done"})

    patterns = loader.list_patterns()
    threshold = SEVERITY_RANK.get(min_severity, 1)
    patterns = [p for p in patterns if SEVERITY_RANK.get(p["severity"], 0) >= threshold]
    patterns.sort(key=lambda p: -SEVERITY_RANK.get(p["severity"], 0))

    console.print(f"[bold]Running {len(patterns)} patterns on {scan_target}[/bold]")
    console.print()

    t = Table(title="Scan Results")
    t.add_column("Pattern", style="cyan")
    t.add_column("Severity", style="yellow")
    t.add_column("Verdict", style="bold")
    t.add_column("Reason", style="white")

    engine_cfg_local = load_engine()
    max_workers = int(engine_cfg_local.get("concurrency", {}).get("max_workers", 8))

    role_targets = _resolve_role_targets(api_paths, url, api_base)
    if role_targets.get("login"):
        console.print(f"[dim]Login endpoint for probes: {role_targets['login']}[/dim]")
        progress.activity(f"Login endpoint resolved: {role_targets['login']}",
                          stage="scanning")

    work = []
    for p in patterns:
        pid = p["id"]
        full = loader.load_pattern(pid) or {}
        role = full.get("target_role")
        if pid == "js-bundle-secrets" and js_urls:
            for js_url in js_urls[:30]:
                work.append((p, {"target_url": js_url}, js_url))
        elif role and role_targets.get(role):
            role_url = role_targets[role]
            work.append((p, {"target_url": role_url}, role_url))
        else:
            work.append((p, {}, scan_target))
    max_workers = max(1, min(max_workers, len(work)))
    console.print(f"[dim]Workers: {max_workers} | tasks: {len(work)}[/dim]")

    emit("phase", {"name": "scanning", "status": "running"})
    emit("scan_start", {
        "target": scan_target,
        "total_patterns": len(patterns),
        "total_work": len(work),
        "workers": max_workers,
    })

    negative_baseline = targets.get("soft_404")

    def _one(item):
        p, ov, rec_target = item
        emit("pattern_start", {"id": p["id"], "severity": p["severity"]})
        try:
            out = _run_pattern(p["id"], scan_target, headers=auth_headers,
                               cookies=auth_cookies, overrides=ov,
                               negative_baseline=negative_baseline)
            return (p, out, rec_target)
        except Exception as e:
            console.print(f"[red]worker error on {p['id']}: {e}[/red]")
            emit("worker_error", {"id": p["id"], "message": str(e)})
            return (p, None, rec_target)

    t0 = time.perf_counter()
    collected = []
    completed = 0
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_one, w): w for w in work}
        for f in as_completed(futures):
            p, out, rec_target = f.result()
            completed += 1
            if out:
                verdict = out["result"]["verdict"]
                reason = out["result"].get("reason") or ""
                emit("pattern_done", {
                    "id": p["id"],
                    "severity": p["severity"],
                    "verdict": verdict,
                    "reason": reason[:240],
                    "duration_ms": out["duration_ms"],
                })
            emit("progress", {"done": completed, "total": len(work)})
            collected.append((p, out, rec_target))

    grouped = defaultdict(list)
    for p, out, rec_target in collected:
        if out:
            grouped[p["id"]].append((p, out, rec_target))

    rank = {"VULNERABLE": 3, "SUSPICIOUS": 2, "PASS": 1, "UNKNOWN": 0}
    counts = {"VULNERABLE": 0, "SUSPICIOUS": 0, "PASS": 0, "UNKNOWN": 0}
    scan_results = []
    for p in patterns:
        pid = p["id"]
        group = grouped.get(pid, [])
        if not group:
            continue
        best = None
        for pat, out, rec_target in group:
            _record(pid, rec_target, out)
            if best is None or rank.get(out["result"]["verdict"], 0) > rank.get(best[1]["result"]["verdict"], 0):
                best = (pat, out, rec_target)
        result = best[1]["result"]
        verdict = result["verdict"]
        counts[verdict] = counts.get(verdict, 0) + 1
        scan_results.append({"severity": p["severity"], "verdict": verdict})
        color = VERDICT_COLOR.get(verdict, "white")
        t.add_row(pid, p["severity"], f"[{color}]{verdict}[/{color}]",
                   (result.get("reason") or "")[:60])

    elapsed = (time.perf_counter() - t0) * 1000.0
    console.print(t)
    console.print()
    console.print(f"  [bold red]VULNERABLE[/bold red]: {counts['VULNERABLE']}")
    console.print(f"  [bold yellow]SUSPICIOUS[/bold yellow]: {counts['SUSPICIOUS']}")
    console.print(f"  [bold green]PASS[/bold green]      : {counts['PASS']}")
    console.print(f"  [dim]UNKNOWN[/dim]   : {counts['UNKNOWN']}")
    console.print(f"  [dim]Duration  : {elapsed:.0f}ms[/dim]")
    ledger.record_run(scan_target, len(patterns), counts["VULNERABLE"], elapsed)
    emit("phase", {"name": "scanning", "status": "done"})
    emit("summary", {"counts": counts, "duration_ms": round(elapsed, 1)})

    emit("phase", {"name": "report", "status": "running"})
    console.print()
    console.print("[bold]Generating report...[/bold]")
    rpath = report.generate(scan_target, fmt="html")
    console.print(f"  [green]{rpath}[/green]")
    emit("report", {"path": str(rpath)})
    emit("phase", {"name": "report", "status": "done"})

    outcome = {
        "framework": framework,
        "targets": targets,
        "api_paths": api_paths,
        "login": login_info,
        "counts": counts,
        "results": scan_results,
        "report": rpath,
    }
    emit("done", {"counts": counts, "report": str(rpath)})
    return outcome