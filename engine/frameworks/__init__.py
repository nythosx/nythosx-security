"""Framework surface probes.

Each module exports PROBES (safe, read-only detection of known-vulnerable
framework surfaces) and scan() that runs them through engine.http.Client.

scan_all() runs the adapter-appropriate module plus the always-on set
(laravel, spring_boot, wordpress) since those are the most common
high-value targets in the wild.
"""
from . import (laravel, spring_boot, wordpress, rails, tomcat, generic_server)

MODULES_BY_ADAPTER = {
    "laravel": laravel,
    "spring_boot": spring_boot,
    "wordpress": wordpress,
    "rails": rails,
    "aspnet": generic_server,
}

ALWAYS_PROBE = [laravel, spring_boot, wordpress]

_MODULE_NAMES = {
    laravel: "laravel",
    spring_boot: "spring_boot",
    wordpress: "wordpress",
    rails: "rails",
    tomcat: "tomcat",
    generic_server: "generic_server",
}


def scan_all(base_url, adapter_id=None, roe_guard=None, timeout=8,
             include_tomcat=False, neg_fp=None):
    chosen = []
    if adapter_id in MODULES_BY_ADAPTER:
        chosen.append(MODULES_BY_ADAPTER[adapter_id])
    for m in ALWAYS_PROBE:
        if m not in chosen:
            chosen.append(m)
    if include_tomcat and tomcat not in chosen:
        chosen.append(tomcat)
    chosen.append(generic_server)

    all_findings = []
    all_probes = []
    errors = []
    for mod in chosen:
        try:
            r = mod.scan(base_url, roe_guard=roe_guard, timeout=timeout,
                          neg_fp=neg_fp)
        except TypeError:
            r = mod.scan(base_url, roe_guard=roe_guard, timeout=timeout)
        except Exception as e:
            errors.append(f"{_MODULE_NAMES.get(mod, '?'): {type(e).__name__}: {e}}")
            continue
        if r.get("error"):
            errors.append(f"{_MODULE_NAMES.get(mod, '?')}: {r['error']}")
        for p in (r.get("probes") or []):
            p["module"] = _MODULE_NAMES.get(mod, "?")
            all_probes.append(p)
        for f in (r.get("findings") or []):
            f["module"] = _MODULE_NAMES.get(mod, "?")
            all_findings.append(f)

    return {
        "modules_run": [_MODULE_NAMES.get(m, "?") for m in chosen],
        "findings": all_findings,
        "probes": all_probes,
        "errors": errors,
    }


__all__ = ["scan_all", "MODULES_BY_ADAPTER", "ALWAYS_PROBE"]
