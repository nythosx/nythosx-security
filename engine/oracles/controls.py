"""Phase 3 — Negative-Control Oracle Gate.

Generalises the confirmation gate so each oracle family declares a
`negative_control(payload) -> mutation` that SHOULD fail if the oracle is
sound. When a VULNERABLE verdict is reached we re-run the negative control
with identical routing; if it ALSO fires, the oracle is over-matching — the
finding is suppressed, an `oracle_unsound:<name>` fact is recorded, and the
oracle is disabled for the rest of the session.

A finding is CONFIRMED only when either:
  * >= 2 independent oracle families agree, or
  * one family reports confidence >= 0.95 AND its negative control passes
    (i.e. the control did NOT fire).
Otherwise it is downgraded to SUSPICIOUS.

The gate runs, in order and short-circuiting on failure:
  benign-args check  ->  negative control  ->  1.5s re-run
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

CONFIRMED = "CONFIRMED"
SUSPICIOUS = "SUSPICIOUS"
SUPPRESSED = "SUPPRESSED"

HIGH_CONFIDENCE = 0.95
RERUN_DELAY_SECONDS = 1.5


# ---- per-family negative-control mutators --------------------------------
# Each takes the exploit payload string and returns a mutation that a SOUND
# oracle must NOT flag as vulnerable.

def _nc_xss(payload):
    # Break the tag / event handler so no script context is created.
    return '<img src=x onerr'  # truncated handler — never executes


def _nc_sqli(payload):
    # Unbalanced quote count: valid SQL injection needs balanced quoting.
    return "'''"


def _nc_ssrf(payload):
    # Scheme that cannot resolve / connect out.
    return "zzz://localhost.invalid.nonexistent/"


def _nc_ssti(payload):
    # Literal braces that no template engine evaluates.
    return "{{7*'7'}}zz{{"


def _nc_crlf(payload):
    # Encoded newline that, if decoded, is already neutralised.
    return "%250d%250aX-Test:control"


def _nc_nosql(payload):
    # A plain scalar — not an operator object.
    return "control-not-an-operator"


def _nc_generic(payload):
    return "benign-control-" + str(payload)[:8]


NEGATIVE_CONTROLS = {
    "xss": _nc_xss,
    "dom_xss": _nc_xss,
    "sqli": _nc_sqli,
    "sqli_scan": _nc_sqli,
    "ssrf": _nc_ssrf,
    "ssrf_scan": _nc_ssrf,
    "ssti": _nc_ssti,
    "crlf": _nc_crlf,
    "nosql": _nc_nosql,
}


def negative_control(oracle_name, payload=""):
    """Return the negative-control mutation for an oracle, or None."""
    fn = NEGATIVE_CONTROLS.get(oracle_name)
    if fn is None:
        # Try a family prefix match (e.g. "xss-stored" -> "xss").
        for key, f in NEGATIVE_CONTROLS.items():
            if oracle_name.startswith(key):
                fn = f
                break
    if fn is None:
        fn = _nc_generic
    return fn(payload)


def _is_vulnerable(verdict):
    return (verdict or {}).get("verdict") == "VULNERABLE"


@dataclass
class GateResult:
    status: str                      # CONFIRMED | SUSPICIOUS | SUPPRESSED
    verdict: dict = field(default_factory=dict)
    reason: str = ""
    control_fired: Optional[bool] = None
    rerun_verdict: Optional[str] = None
    stage: str = ""


class OracleGate:
    """Session-scoped confirmation gate with per-oracle unsoundness state."""

    def __init__(self, fact_store=None, sleep=None):
        self.fact_store = fact_store
        self._disabled = {}
        self._sleep = sleep if sleep is not None else time.sleep

    # -- session oracle state --------------------------------------------
    def is_disabled(self, name):
        return name in self._disabled

    def disable_oracle(self, name, reason):
        self._disabled[name] = reason
        if self.fact_store is not None:
            self.fact_store.add(f"oracle_unsound:{name}", reason,
                                source="live_confirm", confidence=1.0)

    # -- the gate ---------------------------------------------------------
    def run(self, oracle_name, exploit_probe, verdict, *,
            benign_payload=None, exploit_payload="", confidence=None):
        """Evaluate one VULNERABLE verdict through the gate.

        exploit_probe(payload) -> verdict dict. The same callable is reused
        with benign, negative-control, and re-run payloads so routing is
        identical.
        """
        if self.is_disabled(oracle_name):
            return GateResult(SUPPRESSED, verdict,
                              reason=f"oracle '{oracle_name}' disabled "
                                     f"for session", stage="disabled")
        if not _is_vulnerable(verdict):
            return GateResult(SUSPICIOUS, verdict,
                              reason="initial verdict not VULNERABLE",
                              stage="initial")

        # Stage 1 — benign-args check
        if benign_payload is not None:
            benign = _safe_probe(exploit_probe, benign_payload)
            if _is_vulnerable(benign):
                self.disable_oracle(oracle_name, "fires on benign args")
                v = dict(verdict)
                v["verdict"] = "PASS"
                return GateResult(SUPPRESSED, v,
                                  reason="[tool_unsound: benign args fired]",
                                  control_fired=True, stage="benign")

        # Stage 2 — negative control
        nc_payload = negative_control(oracle_name, exploit_payload)
        control = _safe_probe(exploit_probe, nc_payload)
        control_fired = _is_vulnerable(control)
        if control_fired:
            self.disable_oracle(oracle_name,
                                "negative control fired (over-matching)")
            v = dict(verdict)
            v["verdict"] = "PASS"
            return GateResult(SUPPRESSED, v,
                              reason="[oracle_unsound: negative control "
                                     "fired]",
                              control_fired=True, stage="negative_control")

        # Stage 3 — 1.5s re-run
        self._sleep(RERUN_DELAY_SECONDS)
        rerun = _safe_probe(exploit_probe, exploit_payload)
        rv = (rerun or {}).get("verdict")
        if rv != "VULNERABLE":
            v = dict(verdict)
            v["verdict"] = "SUSPICIOUS"
            return GateResult(SUSPICIOUS, v,
                              reason=f"[unconfirmed: re-run returned {rv}]",
                              control_fired=False, rerun_verdict=rv,
                              stage="rerun")

        return GateResult(CONFIRMED, verdict,
                          reason="negative control passed; re-run confirmed",
                          control_fired=False, rerun_verdict=rv,
                          stage="confirmed")


def _safe_probe(probe, payload):
    try:
        out = probe(payload)
        return out if isinstance(out, dict) else {"verdict": "UNKNOWN"}
    except Exception as e:
        return {"verdict": "UNKNOWN", "reason": f"{type(e).__name__}: {e}"}


@dataclass
class OracleSignal:
    family: str
    confidence: float = 0.0
    negative_control_passed: bool = True


def corroborate(signals):
    """Cross-oracle corroboration.

    signals: iterable of OracleSignal (or dicts with family/confidence/
    negative_control_passed). Returns (status, reason).
    """
    norm = []
    for s in signals or []:
        if isinstance(s, OracleSignal):
            norm.append(s)
        elif isinstance(s, dict):
            norm.append(OracleSignal(
                family=s.get("family", ""),
                confidence=float(s.get("confidence", 0.0) or 0.0),
                negative_control_passed=bool(
                    s.get("negative_control_passed", True))))
    families = {s.family for s in norm if s.family}
    if len(families) >= 2:
        return CONFIRMED, (f"{len(families)} independent oracle families "
                           f"agree: {', '.join(sorted(families))}")
    for s in norm:
        if s.confidence >= HIGH_CONFIDENCE and s.negative_control_passed:
            return CONFIRMED, (f"single family '{s.family}' at confidence "
                               f"{s.confidence:.2f} with passing negative "
                               f"control")
    return SUSPICIOUS, ("insufficient corroboration (need >=2 families or "
                        "one family >=0.95 with passing control)")


__all__ = [
    "NEGATIVE_CONTROLS", "OracleGate", "GateResult", "OracleSignal",
    "corroborate", "negative_control", "CONFIRMED", "SUSPICIOUS",
    "SUPPRESSED", "HIGH_CONFIDENCE", "RERUN_DELAY_SECONDS",
]
