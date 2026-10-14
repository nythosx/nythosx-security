"""WordPress surface probes.

The xmlrpc probe uses system.listMethods, which is a documented read-only
method. We do not attempt login, brute-force, or state change.
"""
from ._probe import probe_specs


_XMLRPC_LIST = (
    '<?xml version="1.0"?>'
    '<methodCall>'
    '<methodName>system.listMethods</methodName>'
    '<params></params>'
    '</methodCall>'
)


PROBES = [
    {
        "name": "wp_users_enumeration",
        "method": "GET",
        "path": "/wp-json/wp/v2/users",
        "status_in": [200],
        "body_contains_all": ['"slug"', '"name"'],
        "severity": "high",
        "reason": "WordPress REST API exposes user accounts unauthenticated",
    },
    {
        "name": "wp_users_route_alt",
        "method": "GET",
        "path": "/?rest_route=/wp/v2/users",
        "status_in": [200],
        "body_contains_all": ['"slug"', '"name"'],
        "severity": "high",
        "reason": "WordPress user enumeration reachable via rest_route fallback",
    },
    {
        "name": "wp_xmlrpc_reachable",
        "method": "GET",
        "path": "/xmlrpc.php",
        "status_in": [405, 200],
        "body_contains": ["XML-RPC server accepts POST requests only"],
        "severity": "high",
        "reason": ("xmlrpc.php is reachable — enables amplified credential "
                   "brute-forcing via system.multicall"),
    },
    {
        "name": "wp_xmlrpc_listmethods",
        "method": "POST",
        "path": "/xmlrpc.php",
        "content": _XMLRPC_LIST,
        "headers": {"Content-Type": "text/xml"},
        "status_in": [200],
        "body_contains": ["wp.getUsersBlogs", "system.multicall"],
        "severity": "high",
        "reason": ("xmlrpc.php accepts method calls — amplified brute-force "
                   "and pingback SSRF surface"),
    },
    {
        "name": "wp_setup_config",
        "method": "GET",
        "path": "/wp-admin/setup-config.php",
        "status_in": [200],
        "body_contains": ["setup-config", "wp-config.php"],
        "severity": "critical",
        "reason": "WordPress installer script is reachable — full reinstall possible",
    },
    {
        "name": "wp_debug_log",
        "method": "GET",
        "path": "/wp-content/debug.log",
        "status_in": [200],
        "body_contains_all": ["PHP", "Stack trace"],
        "severity": "high",
        "reason": "WordPress debug log is served as a static file",
    },
    {
        "name": "wp_cron",
        "method": "GET",
        "path": "/wp-cron.php",
        "status_in": [200],
        "severity": "low",
        "reason": "wp-cron.php reachable — can be used for DoS amplification",
    },
]


def scan(base_url, roe_guard=None, timeout=8, neg_fp=None):
    return probe_specs(base_url, PROBES, roe_guard=roe_guard, timeout=timeout,
                       neg_fp=neg_fp)


__all__ = ["scan", "PROBES"]
