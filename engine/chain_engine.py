
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

from .config import load_engine, load_targets, discovery_config
from .roe_guard import ROEGuard, ROEViolation
from . import progress
from .facts import FactStore
from .scoring import rank_chains, load_history
from . import hooks as _hooks

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
                 allow_destructive=False, credentials=None, triage_brain=None):
        self.target = target.rstrip("/")
        self.job_id = job_id
        self.engine_cfg = engine_cfg if engine_cfg is not None else load_engine()
        self.roe_guard = (roe_guard if roe_guard is not None
                          else ROEGuard(engine_cfg=self.engine_cfg))
        self.max_budget_sec = max_budget_sec
        self.verbose = verbose
        self.kill_on_vuln = kill_on_vuln
        self.allow_destructive = bool(allow_destructive)
        try:
            self.legacy_scoring = bool(
                (self.engine_cfg.get("scoring") or {}).get("legacy", False))
        except Exception:
            self.legacy_scoring = False
        self.credentials = credentials if isinstance(credentials, dict) else {}
        self.triage_brain = triage_brain
        if triage_brain is not None and hasattr(triage_brain, "on_call"):
            try:
                triage_brain.on_call = self._emit_llm
            except Exception:
                pass
        self.stopped_reason = None
        self.started = time.monotonic()
        try:
            from . import budget as _budget
            _budget.auto_configure_from_configs()
            _budget.raise_duration_ceiling(max_budget_sec)
        except Exception:
            pass

        self.facts = {}
        self.fact_store = FactStore()
        try:
            from .oracles.controls import OracleGate
            self._oracle_gate = OracleGate(fact_store=self.fact_store)
        except Exception:
            self._oracle_gate = None
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
            "endpoint_probes": [],
            "errors": [],
        }
        self.diagnostics = []

        try:
            self.roe_guard.check_url(self.target, "GET")
        except ROEViolation as e:
            raise RuntimeError(f"ROE_BLOCK: {e}")

    def _emit(self, etype, data=None):
        if self.job_id:
            progress.emit(self.job_id, etype, data or {})

    def _emit_llm(self, info):
        try:
            self._emit("llm", {
                "model": getattr(self.triage_brain, "model", ""),
                "prompt": (info.get("prompt") or "")[:4000],
                "response": (info.get("response") or "")[:4000],
                "error": info.get("error"),
            })
        except Exception:
            pass

    def _activity(self, msg, stage=None):
        if self.job_id:
            progress.activity(msg, stage=stage)

    def _warn(self, code, detail, **extra):
        entry = {"code": code, "detail": detail}
        entry.update(extra)
        self.diagnostics.append({"severity": "warning", **entry})
        self._emit("warning", entry)
        if not self.job_id:
            import sys as _sys
            _sys.stderr.write(f"[sec-checker] warning {code}: {detail}\n")

    def _diag(self, category, severity, detail, **extra):
        entry = {"category": category, "severity": severity, "detail": detail}
        entry.update(extra)
        self.diagnostics.append(entry)
        self._emit("diagnostic", entry)
        if not self.job_id:
            import sys as _sys
            _sys.stderr.write(
                f"[sec-checker] {severity} {category}: {detail}\n")

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

    def _budget_dead(self):
        try:
            from . import budget as _b
            snap = _b.snapshot_human()
            return snap.get("reason") is not None
        except Exception:
            return False

    def _stop_condition(self):
        if self._budget_exceeded():
            if not self.stopped_reason:
                self.stopped_reason = "budget exceeded"
            return True
        if self.kill_on_vuln and self.findings:
            if not self.stopped_reason:
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
        from .recon import wayback as _wayback

        try:
            from . import budget as _b
            _b.set_phase("recon")
        except Exception:
            pass

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
                try:
                    self._run_bundle_analysis(bundles)
                except Exception as e:
                    self.recon["errors"].append(f"bundle_analysis: {e}")
        except Exception as e:
            self.recon["errors"].append(f"js_extraction: {e}")

        if self._budget_dead():
            self._warn("budget_exceeded",
                       "recon aborted after JS extraction: duration or request budget exhausted")
            self.recon["errors"].append("recon aborted: budget exhausted")
            self._emit("phase", {"name": "recon", "status": "done"})
            return

        self._activity("Verifying candidate API paths", stage="recon")
        try:
            if self.recon.get("api_paths"):
                probes = discovery.probe_paths(api_base, self.recon["api_paths"])
                self.recon["endpoint_probes"] = probes
                live = [p for p in probes
                        if p["verdict"] in ("live_api", "exists", "auth_required")]
                self.add_fact("verified_endpoint_count", len(live),
                              source="endpoint_probe")
        except Exception as e:
            self.recon["errors"].append(f"candidate_path_probe: {e}")

        self._activity("Querying CT logs", stage="recon")
        try:
            from .recon import ct_logs as _ct
            ct = _ct.harvest(self.target)
            if ct and ct.get("count"):
                self.add_fact("ct_subdomain_count", ct["count"],
                              source="ct_logs")
                live = ct.get("live") or []
                if live:
                    self.add_fact("live_subdomains",
                                  [x["name"] for x in live][:50],
                                  source="ct_logs")
        except Exception as e:
            self.recon["errors"].append(f"ct_logs: {e}")

        self._activity("Harvesting historic URLs", stage="recon")
        try:
            wb = _wayback.harvest(self.target)
            if wb:
                self.recon["historic"] = wb
                self.add_fact("has_historic_paths", True, source="wayback")
                self.add_fact("historic_path_count", len(wb.get("paths") or []),
                              source="wayback")
                if wb.get("params"):
                    self.add_fact("historic_params", wb["params"][:50],
                                  source="wayback")
                for p in (wb.get("priority_paths") or [])[:30]:
                    if p not in self.recon["api_paths"]:
                        self.recon["api_paths"].append(p)
        except Exception as e:
            self.recon["errors"].append(f"wayback: {e}")

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

        if self._budget_dead():
            self._warn("budget_exceeded",
                       "recon aborted before banking probe: budget exhausted")
            self._emit("phase", {"name": "recon", "status": "done"})
            return

        self._activity("Probing banking-specific paths", stage="recon")
        try:
            from . import banking_recon
            banking_recon.probe_banking_paths(self)
        except ImportError:
            pass
        except Exception as e:
            self.recon["errors"].append(f"banking_recon: {e}")
            self._diag("recon", "warning", f"banking_recon failed: {e}")

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
        source = "targets.yaml"
        if isinstance(self.credentials, dict) and self.credentials:
            creds = dict(self.credentials)
            source = "ui"
        if not creds:
            try:
                targets = load_targets().get("targets", {})
                for name, spec in targets.items():
                    if spec.get("url", "").startswith(api_base):
                        creds = spec.get("auth", {})
                        break
            except Exception:
                pass

        direct_token = creds.get("token")
        if isinstance(direct_token, str) and len(direct_token) > 15:
            self.set_context("jwt_token", direct_token)
            self.set_context("jwt_token_source", source)
            self.add_fact("has_jwt_token", True, source="login")
            self._diag("auth", "info",
                       f"using provided bearer token from {source}")
            return

        username = creds.get("username", "")
        password = creds.get("password", "")
        if not (username and password):
            self._warn("auth_skipped",
                       f"credentials from {source} missing username or password",
                       api_base=api_base)
            return

        login_url_override = creds.get("login_url")
        if login_url_override:
            from . import auth_flow
            result = auth_flow.perform_login(
                login_url_override, username, password,
                login_type=creds.get("login_type", "json"),
                username_field=creds.get("username_field", "email"),
                password_field=creds.get("password_field", "password"),
                token_path=creds.get("token_path", "token"),
                token_header=creds.get("token_header", "Authorization"),
                token_prefix=creds.get("token_prefix", "Bearer "),
            )
            if result.get("token"):
                self.set_context("jwt_token", result["token"])
                self.set_context("jwt_token_source", source)
                self.set_context("login_info", result)
                self.add_fact("has_jwt_token", True, source="login")
                self._diag("auth", "info",
                           f"authenticated via {login_url_override}")
                return
            self._warn("auth_failed",
                       f"login at {login_url_override} did not yield a token",
                       api_base=api_base, status=result.get("status"))
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
        else:
            self._warn("auth_failed",
                       "login attempt did not yield a usable token",
                       api_base=api_base)

    def select_chains(self, chains=None):
        if chains is None:
            chains = _default_chains()
        try:
            history = load_history()
            coverage = self._coverage_summary()
            selected = rank_chains(chains, self.fact_store, history, coverage)
            if selected and not getattr(self, "legacy_scoring", False):
                try:
                    from . import chainscore
                    framework = self.get_fact("framework")
                    selected = chainscore.rank_chains_ev(selected,
                                                         framework=framework)
                except Exception:
                    pass
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
                if self.stopped_reason and "budget" in self.stopped_reason.lower():
                    self._warn("budget_exceeded", self.stopped_reason,
                               chain=chain_id, step=step.get("id"))
                break

            if self._step_should_skip(step):
                skip_entry = {
                    "id": step["id"],
                    "verdict": "SKIP",
                    "reason": "precondition not met",
                }
                result["steps"].append(skip_entry)
                if len(result["steps"]) == 1:
                    self._warn("chain_precondition_skip",
                               f"first step '{step['id']}' precondition not met",
                               chain=chain_id, step=step["id"])
                continue

            if self._step_skipped_by_previous(step, result["steps"]):
                result["steps"].append({
                    "id": step["id"],
                    "verdict": "SKIP",
                    "reason": "if_previous condition not met",
                })
                continue

            step_result = self._execute_step(chain_id, step)
            if (step_result.get("verdict") == "VULNERABLE"
                    and "confirmation_status" not in step_result
                    and self._is_idempotent_tool(step["tool"])
                    and not self._budget_exceeded()):
                step_result = self._confirm_step(chain_id, step, step_result)
            if (step_result.get("verdict") == "SUSPICIOUS"
                    and self.triage_brain is not None
                    and not self._budget_exceeded()):
                step_result = self._triage_suspicious(chain_id, step, step_result)
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
                    result["steps"].append(retry)
                    if retry.get("verdict") != "UNKNOWN":
                        step_result = retry
                        kind = None
                    else:
                        kind = _classify_unknown(retry)
                        retry["unknown_kind"] = kind
                        step_result = retry
                if kind is not None:
                    step_result["unknown_kind"] = kind
                    try:
                        _hooks.fire_post_unknown(self, chain_id, step, step_result)
                    except Exception:
                        pass
                    if kind == "unreachable":
                        result["verdict"] = "UNKNOWN"
                        result["reason"] = (f"chain aborted: step '{step['id']}' "
                                            f"could not reach target")
                        result["aborted"] = True
                        self._warn("chain_aborted", result["reason"],
                                   chain=chain_id, step=step["id"])
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
        try:
            _hooks.fire_post_chain(self, result)
        except Exception:
            pass
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
            _ev = result.get("evidence") or {}
            self._emit("step_done", {
                "chain": chain_id,
                "step": step_id,
                "verdict": result.get("verdict", "UNKNOWN"),
                "duration_ms": result["duration_ms"],
                "reason": result.get("reason", ""),
                "evidence": _ev,
                "payload": _ev.get("payload") or _ev.get("sent"),
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

    def _tool_cve_correlation(self, args):
        from . import cve_lookup
        product = (args.get("product")
                   or self.get_fact("powered_product")
                   or self.get_fact("server_product"))
        version = (args.get("version")
                   or self.get_fact("powered_version")
                   or self.get_fact("server_version"))
        if not product or not version:
            return {"verdict": "UNKNOWN",
                    "reason": "no version facts available",
                    "evidence": {}}
        hits = cve_lookup.lookup(product, version)
        if not hits:
            return {"verdict": "PASS",
                    "reason": f"no CVEs for {product} {version}"}
        critical = [h for h in hits
                    if h.get("severity") in ("critical", "high")]
        if critical:
            return {
                "verdict": "VULNERABLE",
                "reason": (f"{len(critical)} high/critical CVE(s) for "
                           f"{product} {version}: "
                           + ", ".join(h["id"] for h in critical[:3])),
                "evidence": {"product": product, "version": version,
                             "cves": hits,
                             "summary": cve_lookup.summarize(hits)},
            }
        return {
            "verdict": "SUSPICIOUS",
            "reason": (f"{len(hits)} CVE(s) for {product} {version}, "
                       f"none critical/high"),
            "evidence": {"product": product, "version": version,
                         "cves": hits},
        }

    def _tool_deserialization(self, args):
        from . import deserialization
        url = args.get("url") or self.target
        method = args.get("method", "POST")
        r = deserialization.scan(url, method=method, roe_guard=self.roe_guard)
        return {"verdict": r["verdict"], "reason": r.reason,
                "evidence": r.evidence or {}}

    def _tool_graphql_schema(self, args):
        from . import graphql_schema
        endpoint = (args.get("url")
                    or self.get_context("graphql_url")
                    or self.target)
        r = graphql_schema.scan(endpoint, roe_guard=self.roe_guard)
        if r["verdict"] in ("SUSPICIOUS", "VULNERABLE"):
            fields = (r.evidence or {}).get("discovered_fields") or []
            if fields:
                self.set_context("graphql_root_fields", fields)
                self.add_fact("graphql_field_count", len(fields),
                              source="graphql_schema")
        return {"verdict": r["verdict"], "reason": r.reason,
                "evidence": r.evidence or {}}

    def _tool_sourcemap_mine(self, args):
        from .recon import sourcemaps
        js_urls = args.get("js_urls")
        if isinstance(js_urls, str):
            js_urls = [u.strip() for u in js_urls.split(",") if u.strip()]
        if not js_urls:
            js_urls = list(self.recon.get("js_urls") or [])
        if not js_urls:
            return {"verdict": "UNKNOWN",
                    "reason": "no JS URLs available to mine"}
        r = sourcemaps.mine(js_urls, roe_guard=self.roe_guard)
        maps = r.get("maps_found") or []
        if not maps:
            return {"verdict": "PASS",
                    "reason": (f"no readable source maps across "
                               f"{min(len(js_urls), 20)} JS bundle(s)"),
                    "evidence": {"errors": r.get("errors") or []}}
        total_params = set()
        total_paths = set()
        for m in maps:
            total_params.update(m.get("params") or [])
            total_paths.update(m.get("paths") or [])
        if total_params or total_paths:
            self.set_context("sourcemap_params", sorted(total_params))
            self.set_context("sourcemap_paths", sorted(total_paths))
            self.add_fact("sourcemap_params_count", len(total_params),
                          source="sourcemap")
            for p in sorted(total_paths)[:30]:
                if p not in self.recon["api_paths"]:
                    self.recon["api_paths"].append(p)
        return {
            "verdict": "SUSPICIOUS",
            "reason": (f"{len(maps)} source map(s) exposed — recovered "
                       f"{len(total_params)} param(s) and "
                       f"{len(total_paths)} path(s)"),
            "evidence": {"maps": maps[:10],
                         "total_params": len(total_params),
                         "total_paths": len(total_paths)},
        }

    def _tool_ct_subdomain(self, args):
        from .recon import ct_logs
        domain = args.get("domain") or self.target
        r = ct_logs.harvest(domain)
        if not r:
            return {"verdict": "UNKNOWN",
                    "reason": "crt.sh unreachable or returned no certificates",
                    "evidence": {}}
        count = r.get("count") or 0
        live = r.get("live") or []
        if count:
            self.set_context("ct_subdomains", r.get("subdomains"))
            self.add_fact("ct_subdomain_count", count, source="ct_logs")
            if live:
                self.add_fact("live_subdomains",
                              [x["name"] for x in live][:50],
                              source="ct_logs")
        return {
            "verdict": "SUSPICIOUS" if count > 0 else "PASS",
            "reason": (f"{count} subdomain(s) from CT logs, "
                       f"{len(live)} resolve"),
            "evidence": {
                "count": count,
                "subdomains": (r.get("subdomains") or [])[:50],
                "live": live[:30],
            },
        }

    def _tool_subdomain_takeover(self, args):
        from . import subdomain_takeover
        subs = args.get("subdomains") or self.get_context("live_subdomains") or []
        urls = []
        for s in subs:
            name = s.get("name") if isinstance(s, dict) else str(s)
            if name:
                urls.append("https://" + name)
        if not urls:
            return {"verdict": "UNKNOWN",
                    "reason": "no subdomains available to check"}
        r = subdomain_takeover.scan(urls, roe_guard=self.roe_guard)
        if r["verdict"] == "VULNERABLE":
            self.add_fact("has_subdomain_takeover", True,
                          source="subdomain_takeover")
        return {"verdict": r["verdict"], "reason": r.reason,
                "evidence": r.evidence or {}}

    def _tool_cloud_storage(self, args):
        from . import cloud_storage
        domain = args.get("domain") or self.target
        r = cloud_storage.scan(domain)
        if r["verdict"] == "VULNERABLE":
            self.add_fact("has_public_bucket", True, source="cloud_storage")
        return {"verdict": r["verdict"], "reason": r.reason,
                "evidence": r.evidence or {}}

    def _tool_hpp(self, args):
        from .injection import hpp
        url = args.get("url") or self.target
        params = args.get("params")
        if isinstance(params, str):
            params = [p.strip() for p in params.split(",") if p.strip()]
        r = hpp.scan(url, params=params, roe_guard=self.roe_guard)
        if r["verdict"] == "SUSPICIOUS":
            self.add_fact("has_hpp_signal", True, source="hpp")
        return {"verdict": r["verdict"], "reason": r.reason,
                "evidence": r.evidence or {}}

    _NON_IDEMPOTENT_TOOLS = {"second_order_check", "timing_injection"}

    def _is_idempotent_tool(self, tool_name):
        if tool_name in self._NON_IDEMPOTENT_TOOLS:
            return False
        cap_name = self._TOOL_CAPABILITY_NAMES.get(tool_name, tool_name)
        try:
            from . import registry
            cap = registry.get(cap_name)
            if cap is None:
                return False
            return bool(cap.idempotent) and not cap.destructive
        except Exception:
            return False

    def _oracle_name(self, step):
        return step.get("oracle") or step.get("tool") or ""

    def _negative_control_args(self, step):
        """Synthesise negative-control args for an oracle-tagged step.

        Only used when the step names an `oracle` and a `payload_arg` (or a
        conventional payload key) so we know which argument to mutate. The
        mutation must NOT fire if the oracle is sound.
        """
        try:
            from .oracles.controls import negative_control
        except Exception:
            return None
        oracle = step.get("oracle")
        if not oracle:
            return None
        args = dict(step.get("args") or {})
        payload_arg = step.get("payload_arg")
        if payload_arg is None:
            for cand in ("payload", "value", "param_value", "q", "input"):
                if cand in args:
                    payload_arg = cand
                    break
        if payload_arg is None or payload_arg not in args:
            return None
        args[payload_arg] = negative_control(oracle, args.get(payload_arg))
        return args

    def _confirm_step(self, chain_id, step, original):
        import time as _t
        oracle = self._oracle_name(step)
        gate = getattr(self, "_oracle_gate", None)
        if gate is not None and oracle and gate.is_disabled(oracle):
            original["confirmation_status"] = "oracle_disabled"
            original["verdict"] = "PASS"
            original["reason"] = ("[oracle_unsound: disabled for session] "
                                  + (original.get("reason") or ""))
            return original

        # Stage 1 — benign-args check (opt-in via step["benign_args"]).
        benign_args = step.get("benign_args")
        if benign_args is not None:
            try:
                benign = self._dispatch_tool(step["tool"], benign_args)
            except Exception as e:
                benign = {"verdict": "UNKNOWN", "reason": f"benign error: {e}"}
            if isinstance(benign, dict) and benign.get("verdict") == "VULNERABLE":
                if gate is not None and oracle:
                    gate.disable_oracle(oracle, "fires on benign args")
                original["confirmation_status"] = "tool_unsound"
                original["verdict"] = "PASS"
                original["reason"] = ("[tool_unsound: benign args returned "
                                      "VULNERABLE] "
                                      + (original.get("reason") or ""))
                self._diag("confirmation", "warning",
                           f"tool '{step['tool']}' fired on benign args; "
                           f"suppressing finding")
                return original

        # Stage 2 — negative control (explicit control_args, else synthesised
        # from the oracle's declared negative-control mutation).
        control_args = step.get("control_args")
        if control_args is None:
            control_args = self._negative_control_args(step)
        if control_args is not None:
            try:
                control = self._dispatch_tool(step["tool"], control_args)
            except Exception as e:
                control = {"verdict": "UNKNOWN",
                           "reason": f"control error: {e}"}
            if not isinstance(control, dict):
                control = {"verdict": "UNKNOWN"}
            cv = control.get("verdict")
            original["confirmation_control_verdict"] = cv or "UNKNOWN"
            if cv == "VULNERABLE":
                if gate is not None and oracle:
                    gate.disable_oracle(
                        oracle, "negative control fired (over-matching)")
                original["confirmation_status"] = "tool_unsound"
                original["verdict"] = "PASS"
                original["reason"] = ("[tool_unsound: control payload "
                                      "returned VULNERABLE] "
                                      + (original.get("reason") or ""))
                self._diag("confirmation", "warning",
                           f"tool '{step['tool']}' returned VULNERABLE on "
                           f"negative control; suppressing finding")
                return original
        _t.sleep(1.5)
        try:
            retry = self._dispatch_tool(step["tool"], step.get("args", {}))
        except Exception as e:
            retry = {"verdict": "UNKNOWN",
                     "reason": f"confirmation error: {e}"}
        if not isinstance(retry, dict):
            retry = {"verdict": "UNKNOWN"}
        rv = retry.get("verdict")
        original["confirmation_retry_verdict"] = rv or "UNKNOWN"
        if rv == "VULNERABLE":
            original["confirmation_status"] = "confirmed"
            original["confidence"] = self._confidence_from_retry(original, retry)
        else:
            original["confirmation_status"] = "unconfirmed"
            original["verdict"] = "SUSPICIOUS"
            original["reason"] = ("[unconfirmed: retry returned "
                                  + str(rv) + "] "
                                  + (original.get("reason") or ""))
        return original

    def _confidence_from_retry(self, original, retry):
        base = 0.9
        ev1 = original.get("evidence") or {}
        ev2 = retry.get("evidence") or {}
        sig1 = ev1.get("signal_strength")
        sig2 = ev2.get("signal_strength")
        if isinstance(sig1, (int, float)) and isinstance(sig2, (int, float)):
            avg = (float(sig1) + float(sig2)) / 2.0
            return max(0.5, min(1.0, avg))
        return base

    def _tool_framework_probe(self, args):
        from .frameworks import scan_all
        base = args.get("base_url") or self.target
        adapter_id = args.get("adapter") or self.get_fact("framework")
        neg_fp = self.recon.get("soft_404") if isinstance(self.recon, dict) else None
        r = scan_all(base, adapter_id=adapter_id, roe_guard=self.roe_guard,
                     neg_fp=neg_fp)
        findings = r.get("findings") or []
        if findings:
            severities = {f.get("severity", "medium") for f in findings}
            worst = ("critical" if "critical" in severities else
                     "high" if "high" in severities else "medium")
            self.add_fact("framework_findings", len(findings),
                          source="framework_probe")
            return {
                "verdict": "VULNERABLE",
                "reason": (f"{len(findings)} framework surface finding(s): "
                           + ", ".join(f["probe"] for f in findings[:4])),
                "evidence": {
                    "severity": worst,
                    "findings": findings,
                    "modules_run": r.get("modules_run"),
                    "probes_count": len(r.get("probes") or []),
                },
            }
        live = [p for p in (r.get("probes") or [])
                if p.get("status") is not None]
        if not live and r.get("errors"):
            return {"verdict": "UNKNOWN",
                    "reason": "; ".join(r["errors"][:2]),
                    "evidence": {}}
        return {"verdict": "PASS",
                "reason": (f"no framework surface findings across "
                           f"{len(live)} probe(s)")}

    def _tool_timing_robust(self, args):
        from .stats import payload_is_slower_than_baseline
        from . import oracles_timing as _ot
        kind = (args.get("kind") or "sqli").lower()
        url = args.get("url") or self.target
        param = args.get("param")
        if not param:
            return {"verdict": "UNKNOWN",
                    "reason": "no param provided for robust timing probe"}
        baseline_samples = int(args.get("baseline_samples") or 10)
        payload_samples = int(args.get("payload_samples") or 10)
        delay_seconds = int(args.get("delay_seconds") or 4)
        baselines = []
        for _ in range(baseline_samples):
            r = _ot._send(url, args.get("method", "GET"),
                          params={param: "1"},
                          timeout=args.get("timeout", 15),
                          roe_guard=self.roe_guard)
            if r.get("blocked"):
                return {"verdict": "UNKNOWN", "reason": r["error"],
                        "evidence": {}}
            if r.get("status") is not None:
                baselines.append(r.get("elapsed_ms", 0.0))
        if len(baselines) < 3:
            return {"verdict": "UNKNOWN",
                    "reason": "baseline requests did not complete",
                    "evidence": {}}
        payloads = []
        if kind == "sqli":
            payload = f"' OR SLEEP({delay_seconds})-- -"
        elif kind == "ssti":
            payload = "{{ ''.join([str(i) for i in range(20000000)]) }}"
        else:
            return {"verdict": "UNKNOWN",
                    "reason": f"unknown timing kind: {kind}"}
        for _ in range(payload_samples):
            r = _ot._send(url, args.get("method", "GET"),
                          params={param: payload},
                          timeout=args.get("timeout", 15) + delay_seconds + 3,
                          roe_guard=self.roe_guard)
            if r.get("blocked"):
                return {"verdict": "UNKNOWN", "reason": r["error"],
                        "evidence": {}}
            if r.get("status") is not None:
                payloads.append(r.get("elapsed_ms", 0.0))
        if len(payloads) < 3:
            return {"verdict": "UNKNOWN",
                    "reason": "payload requests did not complete",
                    "evidence": {"baseline_samples": baselines}}
        decision, ev = payload_is_slower_than_baseline(baselines, payloads)
        ev["kind"] = kind
        ev["param"] = param
        if decision:
            return {"verdict": "SUSPICIOUS",
                    "reason": (f"robust timing oracle: {kind} on param "
                               f"'{param}' (delta={ev['delta_ms']:.0f}ms)"),
                    "evidence": ev}
        return {"verdict": "PASS",
                "reason": (f"no robust timing signal ({kind} on '{param}'; "
                           f"delta={ev['delta_ms']:.0f}ms)"),
                "evidence": ev}

    def _tool_differential(self, args):
        from . import differential
        endpoints = args.get("endpoints")
        if isinstance(endpoints, str):
            endpoints = [e.strip() for e in endpoints.split(",") if e.strip()]
        base = args.get("base_url") or self.target
        r = differential.scan(
            base, endpoints=endpoints or None,
            signup_base=args.get("signup_base"),
            roe_guard=self.roe_guard,
        )
        return {"verdict": r["verdict"], "reason": r.reason,
                "evidence": r.evidence or {}}

    def _tool_wayback(self, args):
        from .recon import wayback
        base = args.get("base_url") or self.target
        result = wayback.harvest(base)
        if not result:
            return {"verdict": "PASS",
                    "reason": "no historic URLs found in Wayback/CommonCrawl",
                    "evidence": {}}
        count = len(result.get("paths") or [])
        priority = len(result.get("priority_paths") or [])
        self.set_context("historic_paths", result.get("paths"))
        self.set_context("historic_params", result.get("params"))
        self.add_fact("historic_path_count", count, source="wayback")
        if result.get("params"):
            self.add_fact("historic_params", result["params"][:50],
                          source="wayback")
        return {
            "verdict": "SUSPICIOUS" if priority else "PASS",
            "reason": (f"{count} historic path(s), {priority} priority "
                       f"({', '.join(result.get('sources') or [])})"),
            "evidence": {
                "total_urls_seen": result.get("total_urls_seen"),
                "priority_paths": result.get("priority_paths", [])[:20],
                "params": result.get("params", [])[:30],
                "sources": result.get("sources"),
            },
        }

    def _tool_access_bypass(self, args):
        from .injection import access_bypass
        url = args.get("url") or ""
        if not url:
            base = self.target if self.target.endswith("/") else self.target + "/"
            url = base + "admin"
        r = access_bypass.scan(url, roe_guard=self.roe_guard)
        return {"verdict": r["verdict"], "reason": r.reason,
                "evidence": r.evidence or {}}

    def _tool_cache_deception(self, args):
        from .injection import cache_deception
        url = args.get("url") or ""
        if not url:
            base = self.target.rstrip("/")
            url = base + "/api/me"
        r = cache_deception.scan(url, roe_guard=self.roe_guard)
        return {"verdict": r["verdict"], "reason": r.reason,
                "evidence": r.evidence or {}}

    _TOOL_CAPABILITY_NAMES = {
        "cloud_storage": "cloud_storage_enum",
        "hpp": "hpp_scan",
        "deserialization": "deserialization_scan",
        "graphql_schema": "graphql_schema_walk",
        "differential": "differential_scan",
        "wayback": "wayback_mining",
        "access_bypass": "access_bypass_scan",
        "cache_deception": "cache_deception_scan",
        "ssrf_cloud": "ssrf_cloud_scan",
        "bizlogic_price": "bizlogic_scan",
        "bizlogic_coupon": "bizlogic_scan",
        "race_coupon": "bizlogic_scan",
        "skip_workflow_step": "bizlogic_scan",
        "blind_ssrf": "ssrf_scan",
        "blind_xss": "xss_scan",
        "oauth_redirect": "oauth_redirect_uri_scan",
        "oauth_state": "oauth_state_scan",
        "oauth_pkce": "oauth_pkce_scan",
        "lockout_scan": "lockout_probe",
    }

    _TOOL_HANDLERS = {
        "jwt_attack": _tool_jwt_attack,
        "subdomain_takeover": _tool_subdomain_takeover,
        "cloud_storage": _tool_cloud_storage,
        "hpp": _tool_hpp,
        "deserialization": _tool_deserialization,
        "graphql_schema": _tool_graphql_schema,
        "sourcemap_mine": _tool_sourcemap_mine,
        "ct_subdomain": _tool_ct_subdomain,
        "framework_probe": _tool_framework_probe,
        "timing_robust": _tool_timing_robust,
        "differential": _tool_differential,
        "wayback": _tool_wayback,
        "cve_correlation": _tool_cve_correlation,
        "access_bypass": _tool_access_bypass,
        "cache_deception": _tool_cache_deception,
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

    def _triage_suspicious(self, chain_id, step, result):
        finding = {
            "tool": step.get("tool"),
            "chain": chain_id,
            "verdict": result.get("verdict", "SUSPICIOUS"),
            "reason": result.get("reason", ""),
            "evidence": result.get("evidence") or {},
        }
        try:
            decision = self.triage_brain.triage_finding(finding)
        except Exception as e:
            self._diag("triage", "warning",
                       f"triage failed: {type(e).__name__}: {e}")
            return result
        if decision is None:
            return result
        genuine = bool(getattr(decision, "escalate", True))
        reason = getattr(decision, "reason", "") or ""
        if not genuine:
            result["verdict"] = "PASS"
            result["triage_override"] = True
            result["triage_reason"] = reason[:300]
            self._diag("triage", "info",
                       f"{step.get('tool')}: triage downgraded SUSPICIOUS "
                       f"→ PASS ({reason[:120]})")
        else:
            result["triage_confirmed"] = True
            if reason:
                result["triage_reason"] = reason[:300]
        return result

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
        try:
            from . import ledger as _ledger
            _ledger.record_finding(
                pattern_id=f"chain-{step['tool']}",
                target=self.target,
                verdict="VULNERABLE",
                severity=(result.get("evidence") or {}).get("severity", "high"),
                reason=result.get("reason", ""),
                evidence_path="",
                evidence_json=result.get("evidence") or {},
                category="chain",
                duration_ms=float(result.get("duration_ms", 0.0) or 0.0),
            )
        except Exception:
            pass
        try:
            _hooks.fire_post_finding(self, chain_id, step, result)
        except Exception:
            pass

    def _step_confidence(self, step, result):
        v = result.get("verdict", "UNKNOWN")
        return {
            "VULNERABLE": 0.9,
            "SUSPICIOUS": 0.6,
            "PASS": 0.8,
            "UNKNOWN": 0.3,
        }.get(v, 0.5)

    def run(self, chains=None, parallel=False):
        try:
            self.run_recon()
        except Exception as e:
            self._emit("error", {"message": f"recon failed: {e}"})
            return self._final_report()

        try:
            from . import budget as _b
            _b.set_phase("chains")
        except Exception:
            pass

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
            if parallel and len(pending) > 1:
                self._run_pending_parallel(pending)
                for c in pending:
                    executed_ids.add(c["id"])
            else:
                for chain in pending:
                    if self._stop_condition():
                        break
                    executed_ids.add(chain["id"])
                    try:
                        allowed = _hooks.fire_pre_chain(self, chain)
                    except Exception:
                        allowed = True
                    if not allowed:
                        self._emit("chain_skip",
                                    {"id": chain["id"],
                                     "reason": "pre_chain hook"})
                        continue
                    try:
                        self.execute_chain(chain)
                    except Exception as e:
                        self._diag("sequential", "warning",
                                   f"chain {chain.get('id')} raised "
                                   f"{type(e).__name__}: {e}")

        try:
            self._run_planner_phase()
        except Exception as e:
            self._diag("planner", "warning",
                       f"planner phase failed: {type(e).__name__}: {e}")

        self.plan = seen_plan
        self._persist_ev_stats()
        return self._final_report()

    def _persist_ev_stats(self):
        """Append per-chain EV stats to stats/chains.jsonl (Phase 6)."""
        if getattr(self, "legacy_scoring", False):
            return
        try:
            cfg = (self.engine_cfg.get("scoring") or {})
            if cfg.get("persist_stats", True) is False:
                return
            from . import chainscore
            framework = self.get_fact("framework") or "generic"
            entries = []
            for res in self.chain_results:
                cid = res.get("chain_id") or res.get("id")
                if not cid:
                    continue
                verdict = res.get("verdict")
                entries.append({
                    "chain_id": cid,
                    "vuln_class": chainscore._vuln_class({"id": cid}),
                    "framework": framework,
                    "attempts": 1,
                    "hits": 1 if verdict == "VULNERABLE" else 0,
                })
                for step in res.get("steps") or []:
                    orc = step.get("oracle") or step.get("tool")
                    if not orc:
                        continue
                    status = step.get("confirmation_status")
                    sv = step.get("verdict")
                    confirmed = 1 if (sv == "VULNERABLE"
                                      and status == "confirmed") else 0
                    fp = 1 if status in ("tool_unsound", "oracle_disabled",
                                         "unconfirmed") else 0
                    if confirmed or fp:
                        entries.append({"oracle": orc, "confirmed": confirmed,
                                        "fp": fp})
            if entries:
                chainscore.record_run(entries)
        except Exception:
            pass

    def _run_bundle_analysis(self, bundles):
        try:
            from . import llm_service
            client = llm_service.get_client("bundle_analyst")
        except Exception:
            client = None
        if client is None or not bundles:
            return
        from .brains.bundle_analyst import BundleAnalyst
        from . import discovery as _disc
        analyst = BundleAnalyst(client=client)
        top = sorted(bundles, key=lambda b: b.get("size", 0),
                     reverse=True)[:2]
        all_eps, all_secrets, all_taints, auth_seq = [], [], [], []
        for b in top:
            try:
                text = _disc.fetch_js_text(b["url"])
            except Exception:
                text = ""
            if not text:
                continue
            try:
                a = analyst.analyze(text)
                t = analyst.trace(text)
            except Exception:
                continue
            all_eps.extend(a.get("endpoints") or [])
            all_secrets.extend(a.get("secrets") or [])
            all_taints.extend(t.get("taints") or [])
            if not auth_seq:
                auth_seq = t.get("auth_sequence") or []
        if all_eps:
            self.add_fact("bundle_endpoints", all_eps[:100],
                          source="bundle_analyst")
        if all_secrets:
            self.add_fact("bundle_secret_count", len(all_secrets),
                          source="bundle_analyst")
        if all_taints:
            self.recon["bundle_taints"] = all_taints
            self.add_fact("bundle_taint_count", len(all_taints),
                          source="bundle_analyst")
        if auth_seq:
            self.recon["auth_sequence"] = auth_seq

    def _run_planner_phase(self):
        try:
            from . import llm_service
            client = llm_service.get_client("exploit_planner")
        except Exception:
            client = None
        if client is None:
            return
        from urllib.parse import urlparse
        from .brains.exploit_planner import ExploitPlanner
        from . import http as _http
        host = (urlparse(self.target).hostname or "").lower()
        if not host:
            return
        planner = ExploitPlanner(
            client=client, roe_guard=self.roe_guard,
            allowed_hosts=[host], allow_write_methods=False)
        try:
            facts = self.fact_store.to_dict()
        except Exception:
            facts = {}
        pstate = {"target": self.target, "history": [], "facts": facts}
        last_response = None
        self._emit("phase", {"name": "planner", "status": "running"})
        for _ in range(planner.max_turns):
            try:
                step = planner.next_step(pstate, last_response)
            except Exception:
                step = None
            if not step:
                break
            try:
                with _http.Client(timeout=10, follow_redirects=False) as c:
                    r = c.request(step["method"], step["url"])
                last_response = {"status": r.status_code,
                                 "body_preview": (r.text or "")[:800]}
            except Exception as e:
                last_response = {"status": None,
                                 "body_preview": f"{type(e).__name__}: {e}"[:200]}
            pstate["history"].append({
                "method": step["method"], "url": step["url"],
                "reason": step.get("reason"),
                "status": last_response.get("status")})
            self._emit("activity", {
                "message": "planner: %s %s -> %s" % (
                    step["method"], step["url"], last_response.get("status"))})
        if pstate["history"]:
            try:
                self.recon["planner_trace"] = pstate["history"]
            except Exception:
                pass
            self._emit("diagnostic", {
                "category": "planner",
                "message": "planner explored %d step(s)" % len(pstate["history"]),
                "history": pstate["history"]})
        self._emit("phase", {"name": "planner", "status": "done"})

    def _run_pending_parallel(self, chains, max_workers=4):
        from concurrent.futures import ThreadPoolExecutor, as_completed
        workers = max(1, min(int(max_workers), len(chains)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {}
            for chain in chains:
                try:
                    allowed = _hooks.fire_pre_chain(self, chain)
                except Exception:
                    allowed = True
                if not allowed:
                    self._emit("chain_skip",
                                {"id": chain["id"],
                                 "reason": "pre_chain hook"})
                    continue
                futures[pool.submit(self.execute_chain, chain)] = chain
            for fut in as_completed(futures):
                try:
                    fut.result()
                except Exception as e:
                    chain = futures[fut]
                    self._diag("parallel", "warning",
                               f"chain {chain.get('id')} raised "
                               f"{type(e).__name__}: {e}")

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
            "stopped_reason": self.stopped_reason,
            "diagnostics": self.diagnostics,
        }


def run_chain(target, roe_guard=None, engine_cfg=None, job_id=None,
              max_budget_sec=900, verbose=False, chains=None,
              allow_destructive=False):
    orch = ChainOrchestrator(
        target, roe_guard=roe_guard, engine_cfg=engine_cfg, job_id=job_id,
        max_budget_sec=max_budget_sec, verbose=verbose,
        allow_destructive=allow_destructive)
    return orch.run(chains=chains)
