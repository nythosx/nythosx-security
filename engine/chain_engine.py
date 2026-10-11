
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

from .config import load_engine, load_targets, discovery_config
from .roe_guard import ROEGuard, ROEViolation
from . import progress
from .facts import FactStore
from .scoring import rank_chains, load_history

ROOT = Path(__file__).parent.parent.absolute()

_CONF_MAP = {"high": 1.0, "medium": 0.6, "low": 0.3, "info": 0.4}


def _confidence_to_float(c):
    if isinstance(c, (int, float)) and not isinstance(c, bool):
        return max(0.0, min(1.0, float(c)))
    if isinstance(c, str):
        return _CONF_MAP.get(c.lower(), 0.5)
    return 0.5


_EXTRA_HANDLERS = {}


def register_tool(name, handler):
    _EXTRA_HANDLERS[name] = handler
    cls = globals().get("ChainOrchestrator")
    if cls is not None and hasattr(cls, "_TOOL_HANDLERS"):
        cls._TOOL_HANDLERS[name] = handler


def _default_chains():
    try:
        from .chain_registry import get_all_chains
    except ImportError:
        return []
    return get_all_chains()


_UNKNOWN_UNREACHABLE_MARKERS = (
    "connection refused", "connect error", "connection error",
    "unreachable", "name or service not known", "no route to host",
    "connection reset", "target unreachable", "roe_block", "roe block",
    "network is unreachable", "cannot connect",
)

_UNKNOWN_TIMEOUT_MARKERS = (
    "timeout", "timed out", "read timeout", "connect timeout",
    "request timeout", "timedout",
)


def _classify_unknown(result):
    """Classify an UNKNOWN verdict into unreachable / timeout / ambiguous."""
    reason = (result.get("reason") or "").lower()
    err = (result.get("error") or "").lower()
    text = reason + " " + err
    for m in _UNKNOWN_UNREACHABLE_MARKERS:
        if m in text:
            return "unreachable"
    for m in _UNKNOWN_TIMEOUT_MARKERS:
        if m in text:
            return "timeout"
    return "ambiguous"


class ChainOrchestrator:
    def __init__(self, target, roe_guard=None, engine_cfg=None, job_id=None,
                 max_budget_sec=900, verbose=False, kill_on_vuln=False,
                 allow_destructive=False):
        self.target = target.rstrip("/")
        self.job_id = job_id
        self.engine_cfg = engine_cfg if engine_cfg is not None else load_engine()
        self.roe_guard = (roe_guard if roe_guard is not None
                          else ROEGuard(engine_cfg=self.engine_cfg))
        self.max_budget_sec = max_budget_sec
        self.verbose = verbose
        self.kill_on_vuln = kill_on_vuln
        self.allow_destructive = bool(allow_destructive)
        self.stopped_reason = None
        self.started = time.monotonic()
        try:
            from . import budget as _budget
            _budget.auto_configure_from_configs()
        except Exception:
            pass

        self.facts = {}
        self.fact_store = FactStore()
        self.findings = []
        self.attempts = []
        self.context = {}
        self.chain_results = []
        self.plan = []
        self.recon = {
            "framework": None,
            "api_base": None,
            "js_urls": [],
            "api_paths": [],
            "live_paths": [],
            "errors": [],
        }

        try:
            self.roe_guard.check_url(self.target, "GET")
        except ROEViolation as e:
            raise RuntimeError(f"ROE_BLOCK: {e}")

    def _emit(self, etype, data=None):
        if self.job_id:
            progress.emit(self.job_id, etype, data or {})

    def _activity(self, msg, stage=None):
        if self.job_id:
            progress.activity(msg, stage=stage)

    def _budget_left(self):
        return self.max_budget_sec - (time.monotonic() - self.started)

    def _http_budget_exceeded(self):
        try:
            from . import budget as _budget
            snap = _budget.snapshot()
        except Exception:
            return False
        max_requests = snap.get("max_requests")
        if max_requests and int(snap.get("requests") or 0) >= int(max_requests):
            self.stopped_reason = (
                f"http budget exceeded ({snap['requests']}/{max_requests})")
            return True
        max_dur = snap.get("max_duration_seconds")
        started = snap.get("started_at_monotonic")
        if max_dur and started:
            elapsed = time.monotonic() - started
            if elapsed > float(max_dur):
                self.stopped_reason = (
                    f"http duration budget exceeded ({elapsed:.0f}s/{max_dur}s)")
                return True
        return False

    def _budget_exceeded(self):
        if self._budget_left() <= 0:
            return True
        return self._http_budget_exceeded()

    def _stop_condition(self):
        if self._budget_exceeded():
            self.stopped_reason = "budget exceeded"
            return True
        if self.kill_on_vuln and self.findings:
            self.stopped_reason = "kill_on_vuln: first finding recorded"
            return True
        return False

    def add_fact(self, key, value, source="recon", confidence="high"):
        self.facts[key] = {
            "key": key,
            "value": value,
            "source": source,
            "confidence": confidence,
            "ts": time.time(),
        }
        try:
            self.fact_store.add(key, value, source=source,
                                confidence=_confidence_to_float(confidence))
        except Exception:
            pass
        self._emit("fact", {"key": key, "value": value, "source": source})

    def has_fact(self, key, value=None):
        if key not in self.facts:
            return False
        if value is None:
            return True
        return self.facts[key]["value"] == value

    def get_fact(self, key, default=None):
        return self.facts.get(key, {}).get("value", default)

    def set_context(self, key, value):
        self.context[key] = value

    def get_context(self, key, default=None):
        return self.context.get(key, default)

    def run_recon(self):
        from . import discovery, api_discovery

        self._emit("phase", {"name": "recon", "status": "running"})
        self._activity("Fingerprinting framework", stage="recon")

        adapter = None
        try:
            fw = discovery.detect_framework(self.target)
            adapter = fw.get("adapter") or {}
            self.recon["framework"] = {
                "id": adapter.get("id", "generic"),
                "name": adapter.get("name", "Generic"),
                "score": fw.get("score", 0),
            }
            self.add_fact("framework", adapter.get("id", "generic"))
            self.add_fact("framework_name", adapter.get("name", "Generic"))
            if fw.get("powered_by"):
                self.add_fact("powered_by", fw["powered_by"])
            if fw.get("server"):
                self.add_fact("server", fw["server"])
            try:
                versions = self._extract_versions(
                    fw.get("server", ""), fw.get("powered_by", ""))
                for vk, vv in versions.items():
                    self.add_fact(vk, vv, source="headers")
            except Exception:
                pass
        except Exception as e:
            self.recon["errors"].append(f"fingerprint: {e}")

        self._activity("Discovering API base", stage="recon")
        api_base = self.target
        try:
            disc = api_discovery.discover(self.target, adapter=adapter,
                                          config=discovery_config())
            api_base = disc.get("candidate_api_base") or self.target
            self.recon["api_base"] = api_base
            self.add_fact("api_base", api_base)
            self.add_fact("api_source", disc.get("source", "unknown"))
            if disc.get("catch_all"):
                self.add_fact("catch_all", True)
            if disc.get("port_scan"):
                self.add_fact("open_ports",
                              [p["port"] for p in disc["port_scan"]])
        except Exception as e:
            self.recon["errors"].append(f"api_discovery: {e}")
            self.add_fact("api_base", api_base)

        self._activity("Extracting JS bundles", stage="recon")
        try:
            js_urls = discovery.extract_js_urls(self.target)
            self.recon["js_urls"] = js_urls
            self.add_fact("js_bundle_count", len(js_urls))
            if js_urls:
                api_paths, bundles = discovery.crawl_js_for_paths(
                    self.target, js_urls, adapter or {})
                self.recon["api_paths"] = api_paths
                self.add_fact("api_paths", api_paths[:200])
                self.add_fact("js_total_kb",
                              sum(b["size"] for b in bundles) // 1024)
                self._infer_facts_from_paths(api_paths)
        except Exception as e:
            self.recon["errors"].append(f"js_extraction: {e}")

        self._activity("Probing common endpoints", stage="recon")
        try:
            self._probe_endpoint_facts(api_base, adapter or {})
        except Exception as e:
            self.recon["errors"].append(f"endpoint_probe: {e}")

        self._activity("Acquiring baselines", stage="recon")
        try:
            self._acquire_baselines(api_base)
        except Exception as e:
            self.recon["errors"].append(f"baseline: {e}")

        self._activity("Attempting login for tokens", stage="recon")
        try:
            self._attempt_login(api_base, adapter or {})
        except Exception as e:
            self.recon["errors"].append(f"login: {e}")

        self._emit("phase", {"name": "recon", "status": "done"})

    def _infer_facts_from_paths(self, paths):
        combined = " ".join(str(p) for p in paths).lower()
        if any(k in combined for k in ("/login", "/signin", "/auth", "/token")):
            self.add_fact("has_login", True, source="js_paths")
        if any(k in combined for k in ("jwt", "bearer")):
            self.add_fact("has_jwt_hint", True, source="js_paths")
        if any(k in combined for k in ("/graphql", "/gql", "/query")):
            self.add_fact("has_graphql_hint", True, source="js_paths")
        if any(k in combined for k in ("/cart", "/checkout", "/order", "/payment")):
            self.add_fact("has_ecommerce", True, source="js_paths")
        if any(k in combined for k in ("/coupon", "/promo", "/discount", "/redeem")):
            self.add_fact("has_coupon", True, source="js_paths")
        if any(k in combined for k in ("/transfer", "/pay", "/purchase", "/refund")):
            self.add_fact("has_financial", True, source="js_paths")
        if any(k in combined for k in ("/admin", "/manage", "/internal")):
            self.add_fact("has_admin_paths", True, source="js_paths")
        if any(k in combined for k in ("url=", "redirect", "callback",
                                        "webhook", "/fetch")):
            self.add_fact("has_ssrf_hint", True, source="js_paths")
        if any(k in combined for k in ("/chat", "/completions", "/messages",
                                        "/generate")):
            self.add_fact("has_llm_hint", True, source="js_paths")
        if any(k in combined for k in ("/register", "/verify", "/confirm",
                                        "/reset")):
            self.add_fact("has_workflow", True, source="js_paths")
        if any(k in combined for k in ("/search", "/query", "/filter")):
            self.add_fact("has_search", True, source="js_paths")
        if any(k in combined for k in ("/upload", "/import", "/file")):
            self.add_fact("has_upload", True, source="js_paths")
        if any(k in combined for k in ("/oauth", "/authorize", "/oidc",
                                        "/.well-known/openid")):
            self.add_fact("has_oauth_hint", True, source="js_paths")
        if any(k in combined for k in ("/ws", "/websocket", "/socket.io",
                                        "/sockjs")):
            self.add_fact("has_websocket_hint", True, source="js_paths")
        if any(k in combined for k in ("/redirect", "/return_url", "/returnurl",
                                        "redirect_uri")):
            self.add_fact("has_redirect_hint", True, source="js_paths")
        if any(k in combined for k in ("/template", "/render", "/view")):
            self.add_fact("has_ssti_hint", True, source="js_paths")
        if any(k in combined for k in ("/xml", "/soap", "/rss", "/atom")):
            self.add_fact("has_xml_hint", True, source="js_paths")
        if any(k in combined for k in ("/grpc", "/h2", "/http2")):
            self.add_fact("has_http2_hint", True, source="js_paths")

    def _extract_versions(self, server, powered_by):
        import re
        versions = {}
        pat = re.compile(
            r"([a-zA-Z][a-zA-Z\-]*)/([0-9][0-9a-zA-Z.\-]*)")
        if server:
            m = pat.search(server)
            if m:
                versions["server_product"] = m.group(1)
                versions["server_version"] = m.group(2)
        if powered_by:
            m = pat.search(powered_by)
            if m:
                versions["powered_product"] = m.group(1)
                versions["powered_version"] = m.group(2)
        return versions

    def _probe_endpoint_facts(self, api_base, adapter):
        from . import route_enum

        try:
            results = route_enum.enumerate_routes(
                api_base, wordlist="common_paths",
                headers={}, cookies={}, delay_ms=5, max_paths=40)
            live = [r for r in results
                    if r.get("interesting")
                    and r.get("status") in (200, 201, 401, 403)]
            self.recon["live_paths"] = [r["path"] for r in live]
            for r in live:
                path = r["path"]
                low = path.lower()
                url = api_base.rstrip("/") + "/" + path.lstrip("/")
                if "graphql" in low or "gql" in low:
                    self.add_fact("has_graphql", True, source="route_probe")
                    self.set_context("graphql_url", url)
                if any(k in low for k in ("openapi", "swagger", "api-docs")):
                    self.add_fact("has_openapi", True, source="route_probe")
                if "admin" in low:
                    self.add_fact("has_admin", True, source="route_probe")
                    self.set_context("admin_url", url)
                if any(k in low for k in ("login", "signin", "auth")):
                    self.add_fact("has_login", True, source="route_probe")
                    self.set_context("login_url", url)
                if any(k in low for k in ("cart", "checkout")):
                    self.add_fact("has_cart", True, source="route_probe")
                    self.set_context("cart_url", url)
                if any(k in low for k in ("coupon", "promo", "redeem")):
                    self.add_fact("has_coupon_endpoint", True,
                                  source="route_probe")
                    self.set_context("coupon_url", url)
                if any(k in low for k in ("oauth", "authorize", "oidc")):
                    self.add_fact("has_oauth_hint", True, source="route_probe")
                    self.set_context("oauth_auth_endpoint", url)
                if any(k in low for k in ("websocket", "socket.io", "sockjs")):
                    self.add_fact("has_websocket_hint", True, source="route_probe")
                    self.set_context("websocket_url", url)
                if "upload" in low or low.endswith("/import"):
                    self.add_fact("has_upload", True, source="route_probe")
                    self.set_context("upload_url", url)
        except Exception:
            pass

    def _acquire_baselines(self, api_base):
        try:
            from .baseline import BaselineEngine
        except Exception:
            return
        try:
            be = BaselineEngine(samples=5)
        except Exception:
            return
        urls = set()
        if api_base:
            urls.add(api_base)
        for p in (self.recon.get("live_paths") or [])[:10]:
            if not p:
                continue
            u = api_base.rstrip("/") + "/" + str(p).lstrip("/")
            urls.add(u)
        count = 0
        for url in list(urls)[:15]:
            try:
                if be.acquire_and_save(self.target, url, method="GET"):
                    count += 1
            except Exception:
                continue
        if count:
            self.add_fact("baselines_acquired", count, source="recon",
                          confidence="high")

    def _attempt_login(self, api_base, adapter):
        from . import discovery

        creds = {}
        try:
            targets = load_targets().get("targets", {})
            for name, spec in targets.items():
                if spec.get("url", "").startswith(api_base):
                    creds = spec.get("auth", {})
                    break
        except Exception:
            pass

        username = creds.get("username", "")
        password = creds.get("password", "")
        if not (username and password):
            return

        api_paths = list(self.get_fact("api_paths", []) or [])
        login_info = discovery.find_login_endpoint(
            api_base, adapter, api_paths, username, password)
        if login_info and login_info.get("token"):
            tok = login_info["token"]
            if isinstance(tok, dict):
                tok = tok.get("token", "")
            self.set_context("jwt_token", tok)
            self.set_context("jwt_token_source", "login")
            self.set_context("login_info", login_info)
            self.add_fact("has_jwt_token", True, source="login")

    def select_chains(self, chains=None):
        if chains is None:
            chains = _default_chains()
        try:
            history = load_history()
            coverage = self._coverage_summary()
            selected = rank_chains(chains, self.fact_store, history, coverage)
            if selected:
                self.plan = [c["id"] for c in selected]
                return selected
        except Exception:
            pass
        selected = []
        for chain in chains:
            if self._matches_trigger(chain.get("trigger", {})):
                selected.append(chain)
        selected.sort(key=lambda c: -c.get("priority", 0))
        self.plan = [c["id"] for c in selected]
        return selected

    def _coverage_summary(self):
        try:
            from . import coverage as _cov
            executed = sorted(set(
                (a.get("tool") or "").strip()
                for a in self.attempts if a.get("tool")))
            return _cov.build_coverage_report(
                target=self.target, findings=self.findings,
                executed_caps=executed)
        except Exception:
            return None

    def _matches_trigger(self, trigger):
        mode = trigger.get("mode", "any")
        conditions = trigger.get("conditions", [])
        if not conditions:
            return False
        results = []
        for cond in conditions:
            key = cond.get("fact")
            expected = cond.get("value")
            if expected is None:
                results.append(self.has_fact(key))
            else:
                results.append(self.get_fact(key) == expected)
        if mode == "all":
            return all(results)
        if mode == "none":
            return not any(results)
        return any(results)

    def execute_chain(self, chain):
        chain_id = chain["id"]
        chain_name = chain.get("name", chain_id)

        self._emit("chain_start", {"id": chain_id, "name": chain_name})
        self._activity(f"Chain: {chain_name}", stage="chain")

        result = {
            "id": chain_id,
            "name": chain_name,
            "steps": [],
            "verdict": "UNKNOWN",
            "reason": "",
            "finding": None,
            "duration_ms": 0,
            "reduced_confidence": False,
            "aborted": False,
        }
        t0 = time.monotonic()

        for step in chain.get("steps", []):
            if self._stop_condition():
                if not result["reason"]:
                    result["reason"] = self.stopped_reason or "stopped"
                break

            if self._step_should_skip(step):
                result["steps"].append({
                    "id": step["id"],
                    "verdict": "SKIP",
                    "reason": "precondition not met",
                })
                continue

            if self._step_skipped_by_previous(step, result["steps"]):
                result["steps"].append({
                    "id": step["id"],
                    "verdict": "SKIP",
                    "reason": "if_previous condition not met",
                })
                continue

            step_result = self._execute_step(chain_id, step)
            result["steps"].append(step_result)
            self.attempts.append({
                "chain": chain_id,
                "step": step["id"],
                "tool": step["tool"],
                "verdict": step_result.get("verdict", "UNKNOWN"),
                "ts": time.time(),
            })
            try:
                from . import ledger as _ledger
                _ledger.record_chain_step(
                    chain_id=chain_id, step_id=step["id"],
                    tool=step["tool"],
                    verdict=step_result.get("verdict", "UNKNOWN"),
                    duration_ms=step_result.get("duration_ms", 0),
                )
            except Exception:
                pass

            # --- Tier 2.2: unknown kind classification & retry ---
            if step_result.get("verdict") == "UNKNOWN":
                kind = step_result.get("unknown_kind") or _classify_unknown(step_result)
                if kind == "timeout":
                    time.sleep(2.0)
                    retry = self._execute_step(chain_id, step)
                    retry["retried"] = True
                    retry["unknown_kind"] = "timeout"
                    result["steps"].append(retry)
                    if retry.get("verdict") != "UNKNOWN":
                        step_result = retry
                        kind = retry.get("unknown_kind") or "timeout"
                    else:
                        kind = "ambiguous"
                step_result["unknown_kind"] = kind
                if kind == "unreachable":
                    result["verdict"] = "UNKNOWN"
                    result["reason"] = (f"chain aborted: step '{step['id']}' "
                                        f"could not reach target")
                    result["aborted"] = True
                    break
                if kind == "ambiguous":
                    result["reduced_confidence"] = True

            v = step_result.get("verdict", "UNKNOWN")
            if v == "VULNERABLE":
                result["verdict"] = "VULNERABLE"
                result["reason"] = step_result.get("reason", "")
                result["finding"] = step_result
                self._record_finding(chain_id, step, step_result)
                if result.get("reduced_confidence") and self.findings:
                    f = self.findings[-1]
                    f["confidence"] = round(
                        float(f.get("confidence", 0.9)) * 0.7, 3)
                    f["reduced_confidence"] = True
                self._apply_step_context(step, step_result)
                break
            if v == "SUSPICIOUS":
                if result["verdict"] != "VULNERABLE":
                    result["verdict"] = "SUSPICIOUS"
                    result["reason"] = step_result.get("reason", "")
            self._apply_step_context(step, step_result)
            if v == "PASS" and step.get("on_fail") == "abort":
                break

        result["duration_ms"] = round((time.monotonic() - t0) * 1000, 1)
        self._emit("chain_done", {
            "id": chain_id,
            "verdict": result["verdict"],
            "reason": result["reason"][:200],
            "duration_ms": result["duration_ms"],
        })
        self.chain_results.append(result)
        return result

    def _step_skipped_by_previous(self, step, prev_steps):
        cond = step.get("if_previous")
        if not cond:
            return False
        target_step_id = cond.get("step")
        required_verdict = cond.get("verdict")
        if not target_step_id or not required_verdict:
            return False
        prev = next(
            (s for s in prev_steps if s.get("id") == target_step_id),
            None)
        if prev is None:
            return True
        return prev.get("verdict") != required_verdict

    def _step_should_skip(self, step):
        pre = step.get("precondition")
        if not pre:
            return False
        mode = pre.get("mode", "any")
        conditions = pre.get("conditions", [])
        results = []
        for cond in conditions:
            key = cond.get("fact")
            expected = cond.get("value")
            if expected is None:
                results.append(self.has_fact(key))
            else:
                results.append(self.get_fact(key) == expected)
        if mode == "all":
            return not all(results)
        if mode == "none":
            return any(results)
        return not any(results)

    def _execute_step(self, chain_id, step):
        step_id = step["id"]
        tool = step["tool"]

        self._emit("step_start", {"chain": chain_id, "step": step_id,
                                   "tool": tool})
        if self.verbose:
            self._activity(f"Step {step_id}: {tool}", stage="chain")

        start = time.monotonic()
        try:
            result = self._dispatch_tool(tool, step.get("args", {}))
            if not isinstance(result, dict):
                result = {"verdict": "UNKNOWN",
                          "reason": "tool returned non-dict"}
            result["duration_ms"] = round(
                (time.monotonic() - start) * 1000, 1)
            self._emit("step_done", {
                "chain": chain_id,
                "step": step_id,
                "verdict": result.get("verdict", "UNKNOWN"),
                "duration_ms": result["duration_ms"],
            })
            return result
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
            self._emit("step_error", {
                "chain": chain_id,
                "step": step_id,
                "error": err,
            })
            return {
                "verdict": "UNKNOWN",
                "reason": err,
                "error": traceback.format_exc()[:500],
                "duration_ms": round((time.monotonic() - start) * 1000, 1),
            }

    def _resolve_args(self, args):
        return {k: self._resolve_value(v) for k, v in args.items()}

    def _resolve_value(self, v):
        if isinstance(v, str) and v.startswith("{{") and v.endswith("}}"):
            key = v[2:-2].strip()
            val = self.context.get(key)
            if val is not None:
                return val
            if key == "target":
                return self.target
            val = self.get_fact(key)
            return val if val is not None else ""
        if isinstance(v, dict):
            return {k: self._resolve_value(x) for k, x in v.items()}
        if isinstance(v, list):
            return [self._resolve_value(x) for x in v]
        return v

    _DESTRUCTIVE_TOOLS = {
        "bizlogic_price", "bizlogic_coupon", "race_coupon",
        "race_scan", "skip_workflow_step", "timing_injection",
        "blind_ssrf", "blind_xss", "second_order_check",
    }

    def _dispatch_tool(self, tool, args):
        if tool in self._DESTRUCTIVE_TOOLS and not self.allow_destructive:
            return {
                "verdict": "UNKNOWN",
                "reason": (f"skipped: tool '{tool}' is destructive/opt-in; "
                           f"re-run with allow_destructive=True to authorize"),
                "evidence": {"skipped": True, "reason": "destructive_gate"},
            }
        resolved = self._resolve_args(args)
        handler = _EXTRA_HANDLERS.get(tool) or self._TOOL_HANDLERS.get(tool)
        if not handler:
            return {"verdict": "UNKNOWN", "reason": f"unknown tool: {tool}"}
        return handler(self, resolved)

    def _tool_jwt_attack(self, args):
        from . import jwt_attacks

        target = args.get("target") or self.target
        token = args.get("token")
        vector = args.get("vector", "all")
        if not token:
            return {"verdict": "UNKNOWN",
                    "reason": "no JWT token available"}

        public_key = args.get("public_key")
        if not public_key:
            try:
                found = jwt_attacks.fetch_jwks(target,
                                                roe_guard=self.roe_guard)
                if found:
                    for k in (found.get("jwks") or {}).get("keys") or []:
                        pem = jwt_attacks.jwk_to_pem(k)
                        if pem:
                            public_key = pem
                            break
            except Exception:
                pass

        out = jwt_attacks.run_attack_suite(
            target, token, method="GET",
            public_key=public_key,
            roe_guard=self.roe_guard,
        )
        results = []
        raw = getattr(out, "raw", None) or {}
        if isinstance(raw, dict):
            results = raw.get("results") or []
        if vector != "all":
            results = [r for r in results
                       if vector.lower() in (r.get("vector") or "").lower()]

        vuln = [r for r in results if r.get("verdict") == "VULNERABLE"]
        susp = [r for r in results if r.get("verdict") == "SUSPICIOUS"]
        if vuln:
            best = vuln[0]
            if best.get("secret"):
                self.set_context("jwt_cracked_secret", best["secret"])
            return {
                "verdict": "VULNERABLE",
                "reason": f"JWT {best.get('vector', '?')}: "
                          f"{(best.get('reason') or '')[:120]}",
                "evidence": best,
            }
        if susp:
            return {"verdict": "SUSPICIOUS",
                    "reason": f"{len(susp)} suspicious vector(s)",
                    "evidence": susp[0]}
        if any(r.get("verdict") == "PASS" for r in results):
            return {"verdict": "PASS",
                    "reason": "all JWT attacks rejected"}
        return {"verdict": "UNKNOWN",
                "reason": "no conclusive JWT result"}

    def _tool_graphql_scan(self, args):
        from . import graphql_security

        target = (args.get("target") or self.get_context("graphql_url")
                  or self.target)
        out = graphql_security.scan(target, roe_guard=self.roe_guard)
        raw = getattr(out, "raw", None) or {}
        if isinstance(raw, dict) and raw.get("endpoint"):
            results = raw.get("results") or {}
            vuln_keys = [k for k, v in results.items()
                         if isinstance(v, dict)
                         and v.get("verdict") == "VULNERABLE"]
            if vuln_keys:
                return {
                    "verdict": "VULNERABLE",
                    "reason": f"GraphQL: {', '.join(vuln_keys)}",
                    "evidence": {k: results[k] for k in vuln_keys},
                }
            susp_keys = [k for k, v in results.items()
                         if isinstance(v, dict)
                         and v.get("verdict") == "SUSPICIOUS"]
            if susp_keys:
                return {"verdict": "SUSPICIOUS",
                        "reason": f"GraphQL: {', '.join(susp_keys)}"}
            return {"verdict": "PASS",
                    "reason": "no GraphQL issues"}

        v = getattr(out, "verdict", None)
        v = v.value if hasattr(v, "value") else str(v or "UNKNOWN")
        return {"verdict": v if v != "UNKNOWN" else "UNKNOWN",
                "reason": getattr(out, "reason", "") or "no graphql endpoint"}

    def _tool_ssrf_cloud(self, args):
        from . import ssrf_cloud

        base = args.get("base_url") or self.target
        out = ssrf_cloud.scan(base_url=base, timeout=8,
                               roe_guard=self.roe_guard)
        raw = getattr(out, "raw", None) or {}
        if isinstance(raw, dict):
            verdict = raw.get("overall", "UNKNOWN")
            if verdict == "VULNERABLE":
                provs = [k for k, v in (raw.get("providers") or {}).items()
                         if v.get("verdict") == "VULNERABLE"]
                return {
                    "verdict": "VULNERABLE",
                    "reason": f"Cloud metadata reachable: {', '.join(provs)}",
                    "evidence": {"providers": raw.get("providers")},
                }
            if verdict == "SUSPICIOUS":
                return {"verdict": "SUSPICIOUS",
                        "reason": raw.get("reason", "")}
            if verdict == "PASS":
                return {"verdict": "PASS",
                        "reason": raw.get("reason", "")}

        v = getattr(out, "verdict", None)
        v = v.value if hasattr(v, "value") else str(v or "UNKNOWN")
        return {"verdict": v,
                "reason": getattr(out, "reason", "") or "ssrf_cloud inconclusive"}

    def _tool_race_scan(self, args):
        from . import race_advanced

        url = args.get("url") or self.target
        method = args.get("method", "POST")
        body = args.get("body")
        count = int(args.get("count", 20))
        modes = args.get("modes") or ["barrier", "single_packet"]
        out = race_advanced.race_scan(url, method=method, body=body,
                                       count=count, modes=modes,
                                       roe_guard=self.roe_guard)
        raw = getattr(out, "raw", None) or {}
        if isinstance(raw, dict):
            overall = raw.get("overall", "UNKNOWN")
            if overall == "VULNERABLE":
                return {
                    "verdict": "VULNERABLE",
                    "reason": "Race condition confirmed",
                    "evidence": raw.get("results"),
                }
            if overall == "SUSPICIOUS":
                return {"verdict": "SUSPICIOUS",
                        "reason": "Timing anomaly detected"}
            if overall == "PASS":
                return {"verdict": "PASS",
                        "reason": "no race condition detected"}

        v = getattr(out, "verdict", None)
        v = v.value if hasattr(v, "value") else str(v or "UNKNOWN")
        return {"verdict": v if v != "UNKNOWN" else "UNKNOWN",
                "reason": getattr(out, "reason", "") or "race scan inconclusive"}

    def _tool_domxss_scan(self, args):
        from . import dom_xss

        url = args.get("url") or self.target
        out = dom_xss.scan(url, roe_guard=self.roe_guard, include_mxss=False)
        v = getattr(out, "verdict", None)
        v = v.value if hasattr(v, "value") else str(v or "UNKNOWN")
        return {"verdict": v,
                "reason": getattr(out, "reason", "") or ""}

    def _tool_llm_scan(self, args):
        from . import llm_security

        url = args.get("url") or self.target
        model = args.get("model", "gpt-3.5-turbo")
        out = llm_security.scan(url, model=model, roe_guard=self.roe_guard)
        v = getattr(out, "verdict", None)
        v = v.value if hasattr(v, "value") else str(v or "UNKNOWN")
        reason = getattr(out, "reason", "") or ""
        if v == "VULNERABLE":
            return {"verdict": "VULNERABLE",
                    "reason": reason or "LLM vulnerability detected",
                    "evidence": getattr(out, "evidence", {}) or {}}
        return {"verdict": v, "reason": reason}

    def _tool_openapi_scan(self, args):
        from . import openapi_scanner

        url = args.get("url") or self.target
        out = openapi_scanner.scan(url, roe_guard=self.roe_guard, fuzz=False)
        raw = getattr(out, "raw", None) or {}
        if not isinstance(raw, dict):
            raw = {}
        spec = raw.get("spec")
        if not spec:
            v = getattr(out, "verdict", None)
            v = v.value if hasattr(v, "value") else str(v or "UNKNOWN")
            return {"verdict": "UNKNOWN" if v == "UNKNOWN" else v,
                    "reason": getattr(out, "reason", "") or "no spec found"}
        endpoints = raw.get("endpoints") or []
        self.set_context("openapi_spec", spec)
        self.set_context("openapi_endpoints", endpoints)
        self.add_fact("has_openapi_spec", True, source="openapi")
        if endpoints:
            return {
                "verdict": "SUSPICIOUS",
                "reason": f"Spec exposed with {len(endpoints)} endpoints",
                "evidence": {"spec": spec, "endpoints": endpoints[:20]},
            }
        return {"verdict": "PASS", "reason": "spec parsed, no findings"}

    def _tool_sca_scan(self, args):
        from . import sca

        path = args.get("path") or str(ROOT)
        out = sca.scan_dependencies(path)
        raw = getattr(out, "raw", None) or {}
        if not isinstance(raw, dict):
            raw = {}
        vulns = raw.get("vulnerabilities") or []
        if not vulns:
            return {"verdict": "PASS",
                    "reason": "no vulnerable dependencies"}
        self.set_context("sca_vulns", vulns)
        crit = [v for v in vulns
                if v.get("severity") in ("critical", "high")]
        return {
            "verdict": "VULNERABLE" if crit else "SUSPICIOUS",
            "reason": (f"{len(vulns)} vulnerable dependencies "
                       f"({len(crit)} critical/high)"),
            "evidence": {"vulns": vulns[:10]},
        }

    def _tool_bizlogic_price(self, args):
        from . import bizlogic

        url = args.get("url")
        body = args.get("body")
        if not url or not body:
            return {"verdict": "UNKNOWN",
                    "reason": "no price endpoint configured"}
        out = bizlogic.probe_price_tampering(
            url, method="POST", baseline_body=body,
            roe_guard=self.roe_guard)
        return {"verdict": out.get("verdict", "UNKNOWN"),
                "reason": out.get("reason", ""),
                "evidence": out.get("findings")}

    def _tool_bizlogic_coupon(self, args):
        from . import bizlogic

        code = args.get("code")
        if not code:
            return {"verdict": "UNKNOWN", "reason": "no coupon code"}
        out = bizlogic.probe_coupon_abuse(
            self.target, code, roe_guard=self.roe_guard)
        return {"verdict": out.get("verdict", "UNKNOWN"),
                "reason": out.get("reason", "")}

    def _tool_race_coupon(self, args):
        from . import bizlogic

        code = args.get("code")
        if not code:
            return {"verdict": "UNKNOWN", "reason": "no coupon code"}
        out = bizlogic.probe_race_business(
            self.target, "/api/cart/apply-coupon",
            body={"code": code}, count=20, roe_guard=self.roe_guard)
        return {"verdict": out.get("verdict", "UNKNOWN"),
                "reason": out.get("reason", "")}

    def _tool_skip_workflow_step(self, args):
        from . import bizlogic

        target_path = args.get("final_path")
        if not target_path:
            return {"verdict": "UNKNOWN", "reason": "no final path"}
        url = self.target.rstrip("/") + "/" + target_path.lstrip("/")
        r = bizlogic._request(url, method=args.get("method", "POST"),
                              json_body=args.get("body"),
                              roe_guard=self.roe_guard)
        if bizlogic._looks_like_success(r):
            return {
                "verdict": "VULNERABLE",
                "reason": (f"Final step '{target_path}' reachable "
                           f"without prior steps"),
                "evidence": {"status": r.get("status"),
                             "body_preview": (r.get("body") or "")[:200]},
            }
        return {"verdict": "PASS",
                "reason": f"final step rejected (HTTP {r.get('status')})"}

    def _tool_blind_ssrf(self, args):
        from . import ssrf
        from .oob_registry import get_shared_oob

        url = args.get("url") or self.target
        params = args.get("params")
        if isinstance(params, str):
            params = [p.strip() for p in params.split(",") if p.strip()]
        try:
            oob = get_shared_oob()
        except Exception as e:
            return {"verdict": "UNKNOWN",
                    "reason": f"OOB registry unavailable: {e}"}
        try:
            out = ssrf.probe(url, oob_server=oob, params=params,
                             engine_cfg=self.engine_cfg)
        except Exception as e:
            return {"verdict": "UNKNOWN",
                    "reason": f"ssrf probe failed: {type(e).__name__}: {e}"}
        raw = getattr(out, "raw", None) or {}
        if isinstance(raw, dict):
            r = raw.get("result") or {}
            if r:
                return {
                    "verdict": r.get("verdict", "UNKNOWN"),
                    "reason": r.get("reason", "") or "ssrf inconclusive",
                    "evidence": r.get("evidence") or {},
                }
        v = getattr(out, "verdict", None)
        v = v.value if hasattr(v, "value") else str(v or "UNKNOWN")
        return {"verdict": v, "reason": getattr(out, "reason", "") or ""}

    def _tool_blind_xss(self, args):
        from . import xss
        from .oob_registry import get_shared_oob

        url = args.get("url") or self.target
        param = args.get("param")
        if not param:
            return {"verdict": "UNKNOWN",
                    "reason": "no param specified for blind XSS"}
        try:
            oob = get_shared_oob()
        except Exception as e:
            return {"verdict": "UNKNOWN",
                    "reason": f"OOB registry unavailable: {e}"}
        try:
            out = xss.probe(url, param, oob_server=oob,
                            engine_cfg=self.engine_cfg)
        except Exception as e:
            return {"verdict": "UNKNOWN",
                    "reason": f"xss probe failed: {type(e).__name__}: {e}"}
        raw = getattr(out, "raw", None) or {}
        if isinstance(raw, dict):
            r = raw.get("result") or {}
            if r:
                return {
                    "verdict": r.get("verdict", "UNKNOWN"),
                    "reason": r.get("reason", "") or "xss inconclusive",
                    "evidence": r.get("evidence") or {},
                }
        v = getattr(out, "verdict", None)
        v = v.value if hasattr(v, "value") else str(v or "UNKNOWN")
        return {"verdict": v, "reason": getattr(out, "reason", "") or ""}

    def _tool_second_order_check(self, args):
        from . import second_order
        marker = args.get("marker")
        if not marker:
            return {"verdict": "UNKNOWN",
                    "reason": "no marker provided for second-order check"}
        endpoints = args.get("endpoints") or []
        if isinstance(endpoints, str):
            endpoints = [e.strip() for e in endpoints.split(",") if e.strip()]
        if not endpoints:
            endpoints = self.get_context("candidate_render_endpoints") or []
        if not endpoints:
            return {"verdict": "UNKNOWN",
                    "reason": "no candidate endpoints for second-order check"}
        base = args.get("target") or self.target
        return second_order.check_propagation(
            base, endpoints, marker, roe_guard=self.roe_guard)

    def _tool_timing_injection(self, args):
        from . import oracles_timing
        kind = (args.get("kind") or "sqli").lower()
        url = args.get("url") or self.target
        param = args.get("param")
        method = (args.get("method") or "GET").upper()
        if kind == "sqli":
            return oracles_timing.timing_sqli(
                url, param=param, method=method, roe_guard=self.roe_guard)
        if kind == "ssti":
            return oracles_timing.timing_ssti(
                url, param=param, method=method, roe_guard=self.roe_guard)
        if kind == "xxe":
            return oracles_timing.timing_xxe(url, roe_guard=self.roe_guard)
        return {"verdict": "UNKNOWN",
                "reason": f"unknown timing kind: {kind}"}

    @staticmethod
    def _normalize_scanner_result(r):
        if hasattr(r, "to_dict"):
            d = r.to_dict()
        elif isinstance(r, dict):
            d = r
        else:
            return {"verdict": "UNKNOWN",
                    "reason": "non-dict scanner result", "evidence": {}}
        v = d.get("verdict", "UNKNOWN")
        if hasattr(v, "value"):
            v = v.value
        reason = d.get("reason", "") or ""
        evidence = d.get("evidence", {}) or {}
        return {"verdict": str(v or "UNKNOWN"), "reason": str(reason),
                "evidence": evidence}

    def _tool_oauth_discovery(self, args):
        from .oauth import discovery as _m
        try:
            r = _m.scan(args.get("base_url") or self.target,
                        roe_guard=self.roe_guard)
        except Exception as e:
            return {"verdict": "UNKNOWN", "reason": f"{type(e).__name__}: {e}"}
        return self._normalize_scanner_result(r)

    def _tool_oauth_redirect(self, args):
        from .oauth import redirect_uri as _m
        try:
            r = _m.scan(args.get("auth_endpoint") or self.target,
                        roe_guard=self.roe_guard)
        except Exception as e:
            return {"verdict": "UNKNOWN", "reason": f"{type(e).__name__}: {e}"}
        return self._normalize_scanner_result(r)

    def _tool_oauth_state(self, args):
        from .oauth import state_probe as _m
        try:
            r = _m.scan(args.get("auth_endpoint") or self.target,
                        roe_guard=self.roe_guard)
        except Exception as e:
            return {"verdict": "UNKNOWN", "reason": f"{type(e).__name__}: {e}"}
        return self._normalize_scanner_result(r)

    def _tool_oauth_pkce(self, args):
        from .oauth import pkce_probe as _m
        try:
            r = _m.scan(args.get("auth_endpoint") or self.target,
                        roe_guard=self.roe_guard)
        except Exception as e:
            return {"verdict": "UNKNOWN", "reason": f"{type(e).__name__}: {e}"}
        return self._normalize_scanner_result(r)

    def _tool_websocket_scan(self, args):
        from . import websocket_probe as _m
        try:
            r = _m.scan(args.get("target_url") or self.target,
                        roe_guard=self.roe_guard)
        except Exception as e:
            return {"verdict": "UNKNOWN", "reason": f"{type(e).__name__}: {e}"}
        return self._normalize_scanner_result(r)

    def _tool_upload_scan(self, args):
        from . import upload_probe as _m
        try:
            r = _m.scan(args.get("upload_url") or self.target,
                        field_name=args.get("field_name") or "file",
                        roe_guard=self.roe_guard)
        except Exception as e:
            return {"verdict": "UNKNOWN", "reason": f"{type(e).__name__}: {e}"}
        return self._normalize_scanner_result(r)

    def _tool_weak_password_scan(self, args):
        from . import weak_password_policy as _m
        try:
            r = _m.scan(args.get("target_url") or self.target,
                        roe_guard=self.roe_guard)
        except Exception as e:
            return {"verdict": "UNKNOWN", "reason": f"{type(e).__name__}: {e}"}
        return self._normalize_scanner_result(r)

    def _tool_lockout_scan(self, args):
        from . import lockout_probe as _m
        try:
            r = _m.scan(args.get("login_url") or self.target,
                        args.get("username") or "probe@example.com",
                        roe_guard=self.roe_guard)
        except Exception as e:
            return {"verdict": "UNKNOWN", "reason": f"{type(e).__name__}: {e}"}
        return self._normalize_scanner_result(r)

    def _tool_http2_scan(self, args):
        from . import http2_probe as _m
        try:
            r = _m.scan(args.get("target_url") or self.target,
                        method=args.get("method") or "POST",
                        roe_guard=self.roe_guard)
        except Exception as e:
            return {"verdict": "UNKNOWN", "reason": f"{type(e).__name__}: {e}"}
        return self._normalize_scanner_result(r)

    def _tool_crlf_scan(self, args):
        from .injection import crlf as _m
        try:
            r = _m.scan(args.get("target_url") or self.target,
                        roe_guard=self.roe_guard)
        except Exception as e:
            return {"verdict": "UNKNOWN", "reason": f"{type(e).__name__}: {e}"}
        return self._normalize_scanner_result(r)

    def _tool_open_redirect_scan(self, args):
        from .injection import open_redirect as _m
        try:
            r = _m.scan(args.get("target_url") or self.target,
                        roe_guard=self.roe_guard)
        except Exception as e:
            return {"verdict": "UNKNOWN", "reason": f"{type(e).__name__}: {e}"}
        return self._normalize_scanner_result(r)

    def _tool_host_header_scan(self, args):
        from .injection import host_header as _m
        try:
            r = _m.scan(args.get("target_url") or self.target,
                        roe_guard=self.roe_guard)
        except Exception as e:
            return {"verdict": "UNKNOWN", "reason": f"{type(e).__name__}: {e}"}
        return self._normalize_scanner_result(r)

    def _tool_ssti_scan(self, args):
        from .injection import ssti as _m
        try:
            r = _m.scan(args.get("target_url") or self.target,
                        roe_guard=self.roe_guard)
        except Exception as e:
            return {"verdict": "UNKNOWN", "reason": f"{type(e).__name__}: {e}"}
        return self._normalize_scanner_result(r)

    def _tool_nosql_scan(self, args):
        from .injection import nosql as _m
        try:
            r = _m.scan(args.get("login_url") or self.target,
                        roe_guard=self.roe_guard)
        except Exception as e:
            return {"verdict": "UNKNOWN", "reason": f"{type(e).__name__}: {e}"}
        return self._normalize_scanner_result(r)

    def _tool_xxe_scan(self, args):
        from .injection import xxe as _m
        try:
            r = _m.scan(args.get("target_url") or self.target,
                        roe_guard=self.roe_guard)
        except Exception as e:
            return {"verdict": "UNKNOWN", "reason": f"{type(e).__name__}: {e}"}
        return self._normalize_scanner_result(r)

    _TOOL_HANDLERS = {
        "jwt_attack": _tool_jwt_attack,
        "graphql_scan": _tool_graphql_scan,
        "ssrf_cloud": _tool_ssrf_cloud,
        "race_scan": _tool_race_scan,
        "domxss_scan": _tool_domxss_scan,
        "llm_scan": _tool_llm_scan,
        "openapi_scan": _tool_openapi_scan,
        "sca_scan": _tool_sca_scan,
        "bizlogic_price": _tool_bizlogic_price,
        "bizlogic_coupon": _tool_bizlogic_coupon,
        "race_coupon": _tool_race_coupon,
        "skip_workflow_step": _tool_skip_workflow_step,
        "blind_ssrf": _tool_blind_ssrf,
        "blind_xss": _tool_blind_xss,
        "second_order_check": _tool_second_order_check,
        "timing_injection": _tool_timing_injection,
        "oauth_discovery": _tool_oauth_discovery,
        "oauth_redirect": _tool_oauth_redirect,
        "oauth_state": _tool_oauth_state,
        "oauth_pkce": _tool_oauth_pkce,
        "websocket_scan": _tool_websocket_scan,
        "upload_scan": _tool_upload_scan,
        "weak_password_scan": _tool_weak_password_scan,
        "lockout_scan": _tool_lockout_scan,
        "http2_scan": _tool_http2_scan,
        "crlf_scan": _tool_crlf_scan,
        "open_redirect_scan": _tool_open_redirect_scan,
        "host_header_scan": _tool_host_header_scan,
        "ssti_scan": _tool_ssti_scan,
        "nosql_scan": _tool_nosql_scan,
        "xxe_scan": _tool_xxe_scan,
    }

    def _apply_step_context(self, step, result):
        exports = step.get("exports") or {}
        for key, path in exports.items():
            value = result
            for part in path.split("."):
                if isinstance(value, dict):
                    value = value.get(part)
                else:
                    value = None
                if value is None:
                    break
            if value is not None:
                self.set_context(key, value)
                fact_val = (value if not isinstance(value, (list, dict))
                            else f"<{type(value).__name__}>")
                self.add_fact(key, fact_val, source=step["id"])

    def _record_finding(self, chain_id, step, result):
        confidence = result.get("confidence")
        if confidence is None:
            confidence = self._step_confidence(step, result)
        try:
            confidence = float(confidence)
        except (TypeError, ValueError):
            confidence = 0.5
        confidence = max(0.0, min(1.0, confidence))
        self.findings.append({
            "chain": chain_id,
            "step": step["id"],
            "tool": step["tool"],
            "verdict": "VULNERABLE",
            "reason": result.get("reason", ""),
            "evidence": result.get("evidence") or {},
            "confidence": confidence,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def _step_confidence(self, step, result):
        v = result.get("verdict", "UNKNOWN")
        return {
            "VULNERABLE": 0.9,
            "SUSPICIOUS": 0.6,
            "PASS": 0.8,
            "UNKNOWN": 0.3,
        }.get(v, 0.5)

    def run(self, chains=None):
        try:
            self.run_recon()
        except Exception as e:
            self._emit("error", {"message": f"recon failed: {e}"})
            return self._final_report()

        executed_ids = set()
        seen_plan = []
        while not self._stop_condition():
            selected = self.select_chains(chains)
            pending = [c for c in selected if c["id"] not in executed_ids]
            if not pending:
                break
            for c in pending:
                if c["id"] not in seen_plan:
                    seen_plan.append(c["id"])
            self._emit("plan", {"chains": [c["id"] for c in pending],
                                 "iteration": len(executed_ids)})
            for chain in pending:
                if self._stop_condition():
                    break
                executed_ids.add(chain["id"])
                self.execute_chain(chain)

        self.plan = seen_plan
        return self._final_report()

    def _final_report(self):
        rank = {"VULNERABLE": 3, "SUSPICIOUS": 2, "PASS": 1, "UNKNOWN": 0}
        overall = "UNKNOWN"
        for c in self.chain_results:
            if rank.get(c["verdict"], 0) > rank.get(overall, 0):
                overall = c["verdict"]
        if self.findings:
            overall = "VULNERABLE"

        coverage = None
        try:
            from . import coverage as _cov
            executed = sorted(set(
                (a.get("tool") or "").strip()
                for a in self.attempts if a.get("tool")))
            coverage = _cov.build_coverage_report(
                target=self.target,
                findings=self.findings,
                executed_caps=executed,
            )
        except Exception:
            coverage = None

        return {
            "target": self.target,
            "duration_sec": round(time.monotonic() - self.started, 1),
            "verdict": overall,
            "facts": self.facts,
            "context": self.context,
            "recon": self.recon,
            "plan": self.plan,
            "chain_results": self.chain_results,
            "findings": self.findings,
            "attempts_count": len(self.attempts),
            "coverage": coverage,
        }


def run_chain(target, roe_guard=None, engine_cfg=None, job_id=None,
              max_budget_sec=900, verbose=False, chains=None,
              allow_destructive=False):
    orch = ChainOrchestrator(
        target, roe_guard=roe_guard, engine_cfg=engine_cfg, job_id=job_id,
        max_budget_sec=max_budget_sec, verbose=verbose,
        allow_destructive=allow_destructive)
    return orch.run(chains=chains)
