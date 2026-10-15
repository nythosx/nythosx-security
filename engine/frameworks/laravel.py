"""Laravel / PHP framework surface probes.

Non-destructive. Each probe checks whether a known-exposed endpoint is
reachable and returns its expected marker. We do NOT execute commands or
post exploit payloads; presence is enough to flag the finding.
"""
from ._probe import probe_specs


PROBES = [
    {
        "name": "laravel_ignition_health_check",
        "method": "GET",
        "path": "/_ignition/health-check",
        "status_in": [200],
        "body_contains": ["can_execute_commands"],
        "severity": "critical",
        "cve": "CVE-2021-3129",
        "reason": ("Laravel Ignition reachable and reports it can execute "
                   "commands (CVE-2021-3129 pre-auth RCE surface)"),
    },
    {
        "name": "laravel_telescope",
        "method": "GET",
        "path": "/telescope",
        "allow_html": True,
        "status_in": [200],
        "body_contains_all": ["<title>Telescope", "telescope-app"],
        "severity": "high",
        "reason": ("Laravel Telescope debug dashboard is exposed — "
                   "request/response/query history readable"),
    },
    {
        "name": "laravel_telescope_requests",
        "method": "GET",
        "path": "/telescope/requests",
        "allow_html": True,
        "status_in": [200],
        "body_contains_all": ["<title>Telescope", "telescope-app"],
        "severity": "high",
        "reason": "Telescope request history endpoint is reachable",
    },
    {
        "name": "laravel_debugbar_open",
        "method": "GET",
        "path": "/_debugbar/open",
        "status_in": [200],
        "body_contains": ["__meta"],
        "severity": "medium",
        "reason": "Laravel Debugbar open endpoint is exposed",
    },
    {
        "name": "laravel_log_exposure",
        "method": "GET",
        "path": "/storage/logs/laravel.log",
        "status_in": [200],
        "body_contains": ["production.ERROR", "local.ERROR"],
        "severity": "high",
        "reason": "Laravel application log is served as a static file",
    },
    {
        "name": "laravel_horizon",
        "method": "GET",
        "path": "/horizon",
        "allow_html": True,
        "status_in": [200],
        "body_contains_all": ["<title>Horizon", "horizon-app"],
        "severity": "high",
        "reason": "Laravel Horizon queue dashboard is exposed",
    },
    {
        "name": "laravel_env_backup",
        "method": "GET",
        "path": "/.env.backup",
        "status_in": [200],
        "body_contains": ["APP_KEY=", "DB_PASSWORD="],
        "severity": "critical",
        "reason": "Laravel .env backup is served as a static file",
    },
]


def scan(base_url, roe_guard=None, timeout=8, neg_fp=None):
    return probe_specs(base_url, PROBES, roe_guard=roe_guard, timeout=timeout,
                       neg_fp=neg_fp)


__all__ = ["scan", "PROBES"]
