from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from rich.console import Console
from rich.table import Table

from . import (api_discovery, auth_flow, discovery, evidence, executor,
               ledger, loader, oracle, progress, report)
from . import coverage as coverage_mod
from .config import discovery_config, load_engine, save_session
from .contract import (SEVERITY_RANK, VERDICT_RANK, ScanBudget, ScanResult)
from .state import CoverageReport, Hypothesis, ScanState
from .util import safe_name

try:
    from .correlator import resolve_chains
except Exception:
    def resolve_chains(findings):
        return []


ROOT = Path(__file__).parent.parent.absolute()
CRED_FILE = ROOT / "configs" / "credentials.yaml"

from .contract import VERDICT_COLOR  # noqa: E402,F401


def _vstr(v):
    if hasattr(v, "value"):
        return v.value
    return str(v) if v is not None else "UNKNOWN"


def _sstr(v):
    if hasattr(v, "value"):
        return v.value
    return str(v) if v is not None else "info"


class Orchestrator:
    def __init__(self, runner=None, brain=None, on_event=None,
                 engine_cfg=None, console=None, allow_destructive=False):
        self.runner = runner or self._default_runner
        self.brain = brain
        self.on_event = on_event
        self.cfg = engine_cfg if engine_cfg is not None else load_engine()
        self.console = console or Console()
        self.allow_destructive = bool(allow_destructive)
        self._default_headers = {}
        self._default_cookies = {}
        self._negative_baseline = None
        self._scan_target = ""

    def run(self, target, profile="standard", brain=None, job_id=None,
            initial_state=None, allow_destructive=None):
        from .brains.rule_based import RuleBasedBrain
        from . import budget as _budget
        try:
            _budget.auto_configure_from_configs()
        except Exception:
            pass
        if allow_destructive is not None:
            self.allow_destructive = bool(allow_destructive)
        brain = brain or self.brain or RuleBasedBrain()
        if initial_state is not None:
            state = initial_state
            if not state.framework:
                self._recon(state, job_id)
        else:
            state = ScanState(target=target, budget=self._budget_for(profile))
            self._recon(state, job_id)
        self._scan_target = target

        max_workers = int(
            ((self.cfg.get("concurrency") or {}).get("max_workers", 8))
        )
        t0 = time.perf_counter()
        last_new_iter = 0

        for iteration in range(state.budget.max_iterations):
            if self._budget_exhausted(state, t0):
                break
            state.iterations = iteration + 1
            state.elapsed_seconds = time.perf_counter() - t0

            try:
                hypotheses = brain.propose(state) or []
            except Exception:
                hypotheses = []
            hypotheses = self._prune_visited(hypotheses, state)
            hypotheses = hypotheses[:state.budget.max_hypotheses_per_iter]
            if not hypotheses:
                break

            results = self._fan_out(hypotheses, state, job_id, max_workers)
            if results:
                last_new_iter = iteration + 1
            state.add_findings(results)
            for r in results:
                cap = getattr(r, "capability", None)
                if cap:
                    state.executed_capabilities.add(cap)
                    state.mark_visited(cap, target)

            try:
                state.chains = resolve_chains(state.findings)
            except Exception:
                state.chains = []

            try:
                if brain.should_stop(state):
                    break
            except Exception:
                pass

            if (iteration + 1) - last_new_iter >= state.budget.convergence_window:
                break

        state.elapsed_seconds = time.perf_counter() - t0
        try:
            state.coverage = coverage_mod.build_coverage_report(
                target=target,
                findings=state.findings,
                executed_caps=state.executed_capabilities,
                profile=profile,
                duration=state.elapsed_seconds,
            )
        except Exception:
            state.coverage = CoverageReport().to_dict()

        try:
            from . import iteration as _iter
            sweep_count = 0
            while _iter.should_iterate(state, sweep_count):
                gaps = _iter.generate_hypotheses(state, limit=5)
                if not gaps:
                    break
                self._sweep_gaps(state, gaps, job_id, max_workers)
                try:
                    state.coverage = coverage_mod.build_coverage_report(
                        target=target,
                        findings=state.findings,
                        executed_caps=state.executed_capabilities,
                        profile=profile,
                        duration=state.elapsed_seconds,
                    )
                except Exception:
                    pass
                sweep_count += 1
        except Exception:
            pass

        return state

    def _sweep_gaps(self, state, hypotheses, job_id, max_workers):
        results = self._fan_out(hypotheses, state, job_id, max_workers)
        state.add_findings(results)
        for r in results:
            cap = getattr(r, "capability", None)
            if cap:
                state.executed_capabilities.add(cap)
                state.mark_visited(cap, state.target)
        try:
            from .correlator import resolve_chains
            state.chains = resolve_chains(state.findings)
        except Exception:
            pass

    def _budget_for(self, profile):
        defaults = {
            "quick": dict(max_iterations=1, max_http_requests=100,
                          max_duration_seconds=60.0,
                          max_hypotheses_per_iter=10, convergence_window=1),
            "standard": dict(max_iterations=5, max_http_requests=500,
                             max_duration_seconds=300.0,
                             max_hypotheses_per_iter=20, convergence_window=2),
            "deep": dict(max_iterations=10, max_http_requests=2000,
                         max_duration_seconds=900.0,
                         max_hypotheses_per_iter=30, convergence_window=3),
        }
        merged = defaults.get(profile, defaults["standard"]).copy()
        cfg_budget = (self.cfg.get("orchestrator") or {}).get("budget") or {}
        for k, v in cfg_budget.items():
            if v is not None:
                merged[k] = v
        return ScanBudget(
            max_iterations=int(merged.get("max_iterations", 5)),
            max_http_requests=int(merged.get("max_http_requests", 500)),
            max_duration_seconds=float(merged.get("max_duration_seconds", 300.0)),
            max_hypotheses_per_iter=int(merged.get("max_hypotheses_per_iter", 20)),
            convergence_window=int(merged.get("convergence_window", 2)),
        )

    def _used_http(self, state):
        try:
            from . import budget as _budget
            snap = _budget.snapshot()
            recorded = int(snap.get("requests") or 0)
            if recorded:
                return recorded
        except Exception:
            pass
        used = 0
        for f in state.findings:
            cu = getattr(f, "cost_used", None) or {}
            used += int(cu.get("http_requests", 0) or 0)
        return used

    def _budget_exhausted(self, state, t0):
        if (time.perf_counter() - t0) >= state.budget.max_duration_seconds:
            return True
        return self._used_http(state) >= state.budget.max_http_requests

    def _prune_visited(self, hypotheses, state):
        return [
            h for h in hypotheses
            if not state.is_visited(h.capability, h.target or state.target)
        ]

    def _fan_out(self, hypotheses, state, job_id, max_workers):
        results = []
        if not hypotheses:
            return results
        workers = max(1, min(max_workers, len(hypotheses)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {}
            for h in hypotheses:
                tgt = h.target or state.target
                futures[pool.submit(self._safe_run, h.capability, tgt,
                                     h.params)] = h
            for fut in as_completed(futures):
                h = futures[fut]
                self._emit(job_id, "pattern_start",
                           {"id": h.capability, "severity": "info"})
                try:
                    r = fut.result()
                except Exception as e:
                    self._emit(job_id, "worker_error",
                               {"id": h.capability, "message": str(e)})
                    r = ScanResult(capability=h.capability,
                                   target=h.target or state.target,
                                   verdict="UNKNOWN",
                                   reason=f"runner error: {e}")
                results.append(r)
                self._emit(job_id, "pattern_done", {
                    "id": h.capability,
                    "severity": _sstr(getattr(r, "severity", "info")),
                    "verdict": _vstr(getattr(r, "verdict", "UNKNOWN")),
                    "reason": str(getattr(r, "reason", ""))[:240],
                    "duration_ms": float(getattr(r, "duration_ms", 0.0) or 0.0),
                })
                try:
                    self._record_capability(h.capability,
                                             h.target or state.target, r)
                except Exception:
                    pass
            self._emit(job_id, "progress",
                       {"done": len(results), "total": len(hypotheses)})
        return results

    def _safe_run(self, capability, target, params):
        try:
            return self.runner(capability, target, params or {})
        except Exception as e:
            return ScanResult(capability=capability, target=target,
                              verdict="UNKNOWN",
                              reason=f"runner raised {type(e).__name__}: {e}")

    def _record_capability(self, capability, target, result):
        try:
            verdict = _vstr(getattr(result, "verdict", "UNKNOWN"))
            if verdict not in ("VULNERABLE", "SUSPICIOUS"):
                return
            ledger.record_finding(
                pattern_id=capability,
                target=target,
                verdict=verdict,
                severity=_sstr(getattr(result, "severity", "info")),
                reason=str(getattr(result, "reason", "")),
                evidence_path="",
                evidence_json=getattr(result, "evidence", {}) or {},
                category="orchestrator",
                wstg_id="",
                cwe_id="",
                duration_ms=float(getattr(result, "duration_ms", 0.0) or 0.0),
            )
        except Exception:
            pass

    @staticmethod
    def _is_destructive_pattern(pattern):
        if not isinstance(pattern, dict):
            return False
        return bool(pattern.get("destructive") or pattern.get("opt_in"))

    def _default_runner(self, capability, target, params):
        pattern = loader.load_pattern(capability)
        if pattern is None:
            return ScanResult(
                capability=capability,
                target=target,
                verdict="UNKNOWN",
                reason=f"unknown capability '{capability}'",
            )
        if self._is_destructive_pattern(pattern) and not self.allow_destructive:
            return ScanResult(
                capability=capability,
                target=target,
                verdict="UNKNOWN",
                reason=(f"skipped: capability '{capability}' is destructive/opt-in; "
                        f"re-run with --allow-destructive to authorize"),
                evidence={"skipped": True, "reason": "destructive_gate"},
            )
        return self._run_pattern(capability, target, params or {}, pattern)

    def _run_pattern(self, capability, target, params, pattern):
        suffix = pattern.get("endpoint_suffix", "")
        scan_target = target
        if suffix:
            scan_target = target.rstrip("/") + suffix
        headers = dict(self._default_headers or {})
        cookies = dict(self._default_cookies or {})
        if pattern.get("ignore_default_auth"):
            headers = {}
            cookies = {}
        inputs = self._build_inputs(pattern, scan_target, params)
        t0 = time.perf_counter()
        try:
            ctx = executor.execute_pattern(
                pattern, inputs, scan_target,
                default_headers=headers, engine_config=self.cfg,
                cookies=cookies, negative_baseline=self._negative_baseline,
            )
        except Exception as e:
            return ScanResult(capability=capability, target=scan_target,
                              verdict="UNKNOWN",
                              reason=f"executor error: {type(e).__name__}: {e}")
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        verdict, reason, ev = self._pick_verdict(pattern, ctx)
        return ScanResult(
            capability=capability,
            target=scan_target,
            verdict=verdict,
            severity=pattern.get("severity", "info"),
            reason=reason,
            evidence=ev,
            duration_ms=round(elapsed_ms, 3),
            cost_used={"http_requests": len(ctx.get("steps", []))},
        )

    @staticmethod
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

    @staticmethod
    def _pick_verdict(pattern, context):
        oracles = pattern.get("oracles", [])
        rank = {"VULNERABLE": 3, "SUSPICIOUS": 2, "PASS": 1, "UNKNOWN": 0}
        best = None
        for o in oracles:
            r = oracle.evaluate(o, context)
            rv = r.get("verdict") if hasattr(r, "get") else getattr(r, "verdict", "UNKNOWN")
            if best is None:
                best = (rv, r)
                continue
            if rank.get(rv, 0) > rank.get(best[0], 0):
                best = (rv, r)
        if best is None:
            return "UNKNOWN", "no oracles evaluated", {}
        rv, r = best
        reason = r.get("reason") if hasattr(r, "get") else getattr(r, "reason", "")
        ev = r.get("evidence") if hasattr(r, "get") else getattr(r, "evidence", {})
        return rv, reason, ev

    def _recon(self, state, job_id=None):
        from . import api_discovery
        from .config import discovery_config

        self._emit(job_id, "phase", {"name": "framework", "status": "running"})
        try:
            fw = discovery.detect_framework(state.target)
        except Exception:
            fw = {"adapter": {"id": "generic", "name": "Generic"}, "score": 0}
        state.framework = fw
        adapter = fw.get("adapter") or {}
        self._emit(job_id, "framework", {
            "id": adapter.get("id", "generic"),
            "name": adapter.get("name", "Generic"),
            "score": fw.get("score", 0),
        })
        self._emit(job_id, "phase", {"name": "framework", "status": "done"})

        self._emit(job_id, "phase", {"name": "discovery", "status": "running"})
        api_base = state.target
        try:
            disc = api_discovery.discover(
                state.target, adapter=adapter, config=discovery_config())
            api_base = disc.get("candidate_api_base") or state.target
            state.api_base = api_base
            state.api_source = disc.get("source", "unknown")
            state.catch_all = bool(disc.get("catch_all"))
            state.soft_404 = disc.get("soft_404")
            state.port_scan = disc.get("port_scan") or []
        except Exception:
            state.api_base = state.target
            state.api_source = "fallback"
            state.catch_all = False
            state.port_scan = []

        js_urls = []
        api_paths = []
        try:
            js_urls = discovery.extract_js_urls(state.target)
            if js_urls:
                api_paths, _bundles = discovery.crawl_js_for_paths(
                    state.target, js_urls, adapter)
        except Exception:
            pass
        state.js_urls = list(js_urls or [])
        state.api_paths = list(api_paths or [])
        seen = set(state.discovered_endpoints or [])
        for p in api_paths or []:
            if p not in seen:
                state.discovered_endpoints.append(p)
                seen.add(p)

        self._emit(job_id, "api_base", {
            "url": api_base,
            "source": getattr(state, "api_source", "unknown"),
            "ports": getattr(state, "port_scan", []),
        })
        self._emit(job_id, "phase", {"name": "discovery", "status": "done"})

    def _emit(self, job_id, event_type, data=None):
        if job_id:
            try:
                progress.emit(job_id, event_type, data or {})
            except Exception:
                pass
        if self.on_event:
            try:
                self.on_event(event_type, data or {})
            except Exception:
                pass

    def run_auto_compat(self, url, min_severity="medium", credentials=None,
                        skip_discovery=False, api_override=None,
                        adapter_override=None, auto_baseline=False,
                        job_id=None, allow_destructive=None):
        if allow_destructive is not None:
            self.allow_destructive = bool(allow_destructive)
        return _run_auto_compat(
            self, url=url, min_severity=min_severity, credentials=credentials,
            skip_discovery=skip_discovery, api_override=api_override,
            adapter_override=adapter_override, auto_baseline=auto_baseline,
            job_id=job_id,
        )


def _run_auto_compat(orc, url, min_severity, credentials, skip_discovery,
                     api_override, adapter_override, auto_baseline, job_id):
    import time as _time
    from collections import defaultdict

    from . import adapter_loader

    console = orc.console

    def emit(t, d=None):
        orc._emit(job_id, t, d or {})

    try:
        progress.set_active_job(job_id)
    except Exception:
        pass

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
        emit("error", {"message": "Target unreachable", "detail": err})
        return
    console.print()

    emit("phase", {"name": "framework", "status": "running"})
    if adapter_override:
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
        _print_adapter_header(console, framework)
    else:
        framework = discovery.detect_framework(url)
        _print_adapter_header(console, framework)

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
    targets = _resolve_targets(console, url, adapter, api_override)
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
    auth_headers = {}
    auth_cookies = {}
    login_info = None
    if credentials:
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
            login_info = result
    else:
        auth_headers, auth_cookies, login_info = _attempt_login(
            console, url, api_base, adapter, api_paths
        )

    logged_in = bool(auth_headers or auth_cookies)
    token_str = ""
    if isinstance(login_info, dict):
        t = login_info.get("token")
        if isinstance(t, str):
            token_str = t
        elif isinstance(t, dict):
            token_str = t.get("token", "")
    login_url = ""
    if isinstance(login_info, dict):
        login_url = login_info.get("url") or login_info.get("login_url") or ""
    emit("login", {
        "ok": logged_in,
        "url": login_url,
        "token": (token_str[:40] + "...") if token_str else "",
    })
    emit("phase", {"name": "login",
                    "status": "done" if logged_in else "skipped"})

    if auth_headers or auth_cookies:
        try:
            save_session("auto_" + safe_name(url), {
                "login_url": login_url,
                "auth_headers": auth_headers,
                "cookies": auth_cookies,
                "token": token_str,
                "adapter": adapter.get("id"),
            })
        except Exception:
            pass

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
    patterns = [p for p in patterns
                if SEVERITY_RANK.get(p["severity"], 0) >= threshold]
    skipped_destructive = []
    if not orc.allow_destructive:
        keep = []
        for p in patterns:
            full = loader.load_pattern(p["id"]) or {}
            if full.get("destructive") or full.get("opt_in"):
                skipped_destructive.append(p["id"])
                continue
            keep.append(p)
        patterns = keep
        if skipped_destructive:
            console.print(
                f"[yellow]Skipping {len(skipped_destructive)} destructive/opt-in "
                f"pattern(s): {', '.join(skipped_destructive[:5])}"
                f"{'...' if len(skipped_destructive) > 5 else ''}[/yellow]")
            console.print("[dim]  pass --allow-destructive to authorize them[/dim]")
    patterns.sort(key=lambda p: -SEVERITY_RANK.get(p["severity"], 0))

    console.print(f"[bold]Running {len(patterns)} patterns on {scan_target}[/bold]")
    console.print()

    table = Table(title="Scan Results")
    table.add_column("Pattern", style="cyan")
    table.add_column("Severity", style="yellow")
    table.add_column("Verdict", style="bold")
    table.add_column("Reason", style="white")

    max_workers = int(
        ((orc.cfg.get("concurrency") or {}).get("max_workers", 8))
    )

    orc._scan_target = scan_target
    orc._default_headers = auth_headers or {}
    orc._default_cookies = auth_cookies or {}
    orc._negative_baseline = targets.get("soft_404")

    work = []
    for p in patterns:
        pid = p["id"]
        full = loader.load_pattern(pid) or {}
        role = full.get("target_role")
        if pid == "js-bundle-secrets" and js_urls:
            for js_url in js_urls[:30]:
                work.append((p, {"target_url": js_url}, js_url))
        else:
            work.append((p, {}, scan_target))

    max_workers = max(1, min(max_workers, len(work) or 1))
    console.print(f"[dim]Workers: {max_workers} | tasks: {len(work)}[/dim]")

    emit("phase", {"name": "scanning", "status": "running"})
    emit("scan_start", {
        "target": scan_target,
        "total_patterns": len(patterns),
        "total_work": len(work),
        "workers": max_workers,
    })

    def _one(item):
        p, ov, rec_target = item
        emit("pattern_start", {"id": p["id"], "severity": p["severity"]})
        try:
            out = _run_single_pattern(orc, p["id"], scan_target,
                                       overrides=ov, rec_target=rec_target)
            return (p, out, rec_target)
        except Exception as e:
            console.print(f"[red]worker error on {p['id']}: {e}[/red]")
            emit("worker_error", {"id": p["id"], "message": str(e)})
            return (p, None, rec_target)

    t0 = _time.perf_counter()
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
            if best is None or rank.get(out["result"]["verdict"], 0) > rank.get(
                    best[1]["result"]["verdict"], 0):
                best = (pat, out, rec_target)
        result = best[1]["result"]
        verdict = result["verdict"]
        counts[verdict] = counts.get(verdict, 0) + 1
        scan_results.append({"severity": p["severity"], "verdict": verdict})
        color = VERDICT_COLOR.get(verdict, "white")
        table.add_row(pid, p["severity"], f"[{color}]{verdict}[/{color}]",
                       (result.get("reason") or "")[:60])

    elapsed = (_time.perf_counter() - t0) * 1000.0
    console.print(table)
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


def _preflight_check(url, timeout=5):
    from . import http as _http
    from . import budget as _budget
    try:
        _budget.auto_configure_from_configs()
    except Exception:
        pass
    try:
        with _http.Client(timeout=timeout, follow_redirects=False) as c:
            r = c.get(url)
            return True, r.status_code, None
    except _http.ROEBlock as e:
        return False, None, f"ROE_BLOCK: {e}"
    except _http.ConnectError as e:
        return False, None, f"ConnectError: {e}"
    except _http.TimeoutException:
        return False, None, "Timeout"
    except Exception as e:
        return False, None, f"{type(e).__name__}: {e}"


def _print_adapter_header(console, framework):
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
    for e in (framework.get("evidence") or [])[:5]:
        console.print(f"  [dim]\u00b7 {e}[/dim]")
    alts = framework.get("alternatives") or []
    if alts and len(alts) > 1:
        second = alts[1]
        if second.get("score", 0) > 0:
            console.print(f"  [dim]alt: {second['adapter'].get('name')} "
                           f"(score={second['score']})[/dim]")
    console.print()


def _resolve_targets(console, frontend_url, adapter, api_override=None):
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
        console.print("  [yellow]Catch-all page detected (soft-404)[/yellow]")
    if disc.get("candidate_api_base"):
        result["api_base"] = disc["candidate_api_base"]
        result["source"] = disc["source"]
        console.print(f"  [green]{disc['candidate_api_base']}[/green]  "
                       f"([dim]{disc['source']}[/dim])")
    else:
        result["api_base"] = frontend_url
        result["source"] = "fallback:frontend"
        console.print("  [yellow]Not found \u2014 using frontend URL[/yellow]")
    if result["port_scan"]:
        console.print(f"  Port scan: {len(result['port_scan'])} live")
    console.print()
    return result


def _find_creds_for(url):
    try:
        import yaml
        if not CRED_FILE.exists():
            return None
        creds = yaml.safe_load(CRED_FILE.read_text(encoding="utf-8")) or {}
        for pattern, spec in (creds.get("credentials") or {}).items():
            if pattern in url or pattern == "*":
                return spec
    except Exception:
        pass
    return None


def _attempt_login(console, frontend_url, api_base, adapter, api_paths):
    creds = _find_creds_for(frontend_url) or _find_creds_for(api_base)
    if not creds:
        console.print("[dim]No credentials \u2014 running unauthenticated[/dim]")
        console.print()
        return {}, {}, None
    username = creds.get("username", "")
    password = creds.get("password", "")
    if not (username and password):
        console.print("[dim]Credentials incomplete \u2014 unauthenticated[/dim]")
        console.print()
        return {}, {}, None

    console.print("[bold]Attempting auto-login...[/bold]")
    console.print(f"  Username: {username}")

    auth_headers = {}
    auth_cookies = {}
    login_info = None
    auth_cfg = adapter.get("auth", {}) or {}
    token_paths = auth_cfg.get("token_paths") or ["token", "access_token",
                                                   "data.token"]
    default_header = auth_cfg.get("default_header", "Authorization")
    default_prefix = auth_cfg.get("default_prefix", "Bearer ")

    login_url_override = creds.get("login_url")
    if login_url_override:
        result = auth_flow.perform_login(
            login_url_override, username, password,
            login_type=creds.get("login_type", "json"),
            username_field=creds.get("username_field", "email"),
            password_field=creds.get("password_field", "password"),
            token_path=creds.get("token_path", token_paths[0]),
            token_header=default_header,
            token_prefix=default_prefix,
        )
        if result.get("token"):
            auth_headers[default_header] = f"{default_prefix}{result['token']}"
            auth_cookies.update(result.get("cookies") or {})
            console.print(f"  [green]Login OK[/green] via {login_url_override}")
        else:
            console.print(f"  [yellow]Login status {result.get('status')}[/yellow]")
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
        else:
            console.print("  [yellow]No login endpoint discovered[/yellow]")
    console.print()
    return auth_headers, auth_cookies, login_info


def _run_single_pattern(orc, pid, scan_target, overrides=None, rec_target=None):
    import time as _time
    pattern = loader.load_pattern(pid)
    if not pattern:
        return None
    suffix = pattern.get("endpoint_suffix", "")
    target = scan_target
    if suffix:
        target = scan_target.rstrip("/") + suffix
    headers = dict(orc._default_headers or {})
    cookies = dict(orc._default_cookies or {})
    if pattern.get("ignore_default_auth"):
        headers = {}
        cookies = {}
    inputs = Orchestrator._build_inputs(pattern, target, overrides or {})
    t0 = _time.perf_counter()
    ctx = executor.execute_pattern(
        pattern, inputs, target,
        default_headers=headers, engine_config=orc.cfg,
        cookies=cookies, negative_baseline=orc._negative_baseline,
    )
    elapsed = (_time.perf_counter() - t0) * 1000.0
    verdict, reason, ev = Orchestrator._pick_verdict(pattern, ctx)
    return {
        "pattern": pattern,
        "context": ctx,
        "result": {"verdict": verdict, "reason": reason, "evidence": ev},
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
        pattern_id=pid, target=target, verdict=result["verdict"],
        severity=pattern.get("severity", "info"), reason=result.get("reason", ""),
        evidence_path=path, evidence_json=result.get("evidence", {}),
        category=pattern.get("_category", ""),
        wstg_id=wstg.upper() if wstg else "",
        cwe_id=cwe.upper() if cwe else "",
        duration_ms=out["duration_ms"],
    )
    return path


__all__ = ["Orchestrator"]
