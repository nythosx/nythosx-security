"""Client-Side Ground Truth Parser.
Extracts hidden routes, feature flags, and client-side auth guards from JS bundles.
This eliminates LLM hallucination by providing hard evidence of the app's structure.
"""
import re

# Patterns for modern SPAs (Next.js, React, Vue, Angular)
ROUTE_PATTERNS = [
    re.compile(r'path\s*:\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'route\s*\(\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'Router\.(?:push|replace)\s*\(\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'href\s*=\s*["\'](/(?:api|admin|internal|dashboard)[^"\']*)["\']', re.I),
]

FEATURE_FLAG_PATTERNS = [
    re.compile(r'featureFlags?\s*\.\s*([a-zA-Z0-9_]+)', re.I),
    re.compile(r'isEnabled\s*\(\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'config\s*\.\s*([a-zA-Z0-9_]*flag[a-zA-Z0-9_]*)', re.I),
]

AUTH_GUARD_PATTERNS = [
    re.compile(r'if\s*\(\s*!user\.isAdmin\s*\)', re.I),
    re.compile(r'role\s*===\s*["\']admin["\']', re.I),
    re.compile(r'permission\s*===\s*["\']([a-zA-Z0-9_]+)["\']', re.I),
]

def _extract_flows(routes):
    from collections import defaultdict
    by_prefix = defaultdict(list)
    for r in routes:
        parts = [p for p in str(r).strip("/").split("/") if p]
        if not parts:
            continue
        prefix = "/" + parts[0]
        by_prefix[prefix].append(r)

    def _step_sort_key(path):
        import re
        m = re.search(r"/(\d+)(?:/|$)", path)
        if m:
            return int(m.group(1))
        m = re.search(r"(?:step|stage|phase)[_\-]?(\d+)", path, re.I)
        if m:
            return int(m.group(1))
        return 0

    flows = {}
    for prefix, members in by_prefix.items():
        if len(members) < 2:
            continue
        prefix_lower = prefix.lower()
        has_sequential = any(_step_sort_key(m) > 0 for m in members)
        has_workflow_kw = any(k in prefix_lower for k in (
            "checkout", "order", "cart", "payment", "account", "onboard",
            "verify", "signup", "register", "reset", "confirm",
        ))
        if not (has_sequential or has_workflow_kw):
            continue
        flows[prefix] = sorted(members, key=_step_sort_key)
    return flows


def parse_bundle(js_text):
    if not js_text:
        return {"routes": [], "flags": [], "guards": [], "hidden_apis": [], "flows": {}}
    
    routes = set()
    for pat in ROUTE_PATTERNS:
        for m in pat.finditer(js_text):
            val = m.group(1)
            if val.startswith("/") and len(val) < 100:
                routes.add(val)
                
    flags = set()
    for pat in FEATURE_FLAG_PATTERNS:
        for m in pat.finditer(js_text):
            flags.add(m.group(1))
            
    guards = set()
    for pat in AUTH_GUARD_PATTERNS:
        for m in pat.finditer(js_text):
            guards.add(m.group(0))
            
    # Look for hidden APIs that might not be in the standard /api paths
    hidden_apis = set()
    api_pat = re.compile(r'["\'](/(?:api|graphql|internal|admin)/[^"\']{2,60})["\']')
    for m in api_pat.finditer(js_text):
        hidden_apis.add(m.group(1))

    flows = _extract_flows(sorted(routes))
    return {
        "routes": sorted(routes),
        "flags": sorted(flags),
        "guards": sorted(guards),
        "hidden_apis": sorted(hidden_apis),
        "flows": flows,
    }
