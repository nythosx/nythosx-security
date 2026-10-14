"""Generic server misconfiguration probes.

Applies to every target: nginx/apache status pages, static-file leaks
(.git, .svn, .DS_Store, WEB-INF), and source-map exposure.
"""
from ._probe import probe_specs


PROBES = [
    {
        "name": "apache_server_status",
        "method": "GET",
        "path": "/server-status",
        "status_in": [200],
        "body_contains": ["Apache Server Status", "Current Time"],
        "severity": "high",
        "reason": "Apache /server-status is exposed — active requests, vhosts, client IPs",
    },
    {
        "name": "apache_server_info",
        "method": "GET",
        "path": "/server-info",
        "status_in": [200],
        "body_contains": ["Apache Server Information", "Server Settings"],
        "severity": "high",
        "reason": "Apache /server-info is exposed — loaded modules and config",
    },
    {
        "name": "nginx_status",
        "method": "GET",
        "path": "/nginx_status",
        "status_in": [200],
        "body_contains": ["Active connections", "server accepts"],
        "severity": "medium",
        "reason": "Nginx stub_status is exposed",
    },
    {
        "name": "nginx_stub_status",
        "method": "GET",
        "path": "/stub_status",
        "status_in": [200],
        "body_contains": ["Active connections", "server accepts"],
        "severity": "medium",
        "reason": "Nginx stub_status is exposed at /stub_status",
    },
    {
        "name": "git_config_exposure",
        "method": "GET",
        "path": "/.git/config",
        "status_in": [200],
        "body_contains": ["[core]", "repositoryformatversion"],
        "severity": "critical",
        "reason": ".git/config is served — full source and history recoverable",
    },
    {
        "name": "git_head_exposure",
        "method": "GET",
        "path": "/.git/HEAD",
        "status_in": [200],
        "body_contains": ["ref: refs/heads/"],
        "severity": "high",
        "reason": ".git/HEAD is served — git directory is world-readable",
    },
    {
        "name": "svn_entries_exposure",
        "method": "GET",
        "path": "/.svn/entries",
        "status_in": [200],
        "severity": "high",
        "reason": ".svn/entries is served — SVN metadata leak",
    },
    {
        "name": "ds_store_exposure",
        "method": "GET",
        "path": "/.DS_Store",
        "status_in": [200],
        "severity": "low",
        "reason": ".DS_Store is served — reveals directory listing",
    },
    {
        "name": "web_inf_web_xml",
        "method": "GET",
        "path": "/WEB-INF/web.xml",
        "status_in": [200],
        "body_contains": ["<web-app", "<servlet"],
        "severity": "critical",
        "reason": "WEB-INF/web.xml is served — servlet mappings and init params disclosed",
    },
    {
        "name": "manifest_mf",
        "method": "GET",
        "path": "/META-INF/MANIFEST.MF",
        "status_in": [200],
        "severity": "medium",
        "reason": "JAR manifest is served — Java dependencies and versions disclosed",
    },
    {
        "name": "dockerfile_exposure",
        "method": "GET",
        "path": "/Dockerfile",
        "status_in": [200],
        "body_contains": ["FROM "],
        "severity": "high",
        "reason": "Dockerfile is served — build instructions and base image",
    },
    {
        "name": "docker_compose_exposure",
        "method": "GET",
        "path": "/docker-compose.yml",
        "status_in": [200],
        "body_contains": ["services:", "version:"],
        "severity": "critical",
        "reason": "docker-compose.yml is served — service topology and secrets",
    },
    {
        "name": "js_sourcemap_exposure",
        "method": "GET",
        "path": "/static/js/main.js.map",
        "status_in": [200],
        "body_contains": ["sourcesContent", "version"],
        "severity": "medium",
        "reason": ("Webpack source map is exposed — original source code "
                   "recoverable from build artifact"),
    },
]


def scan(base_url, roe_guard=None, timeout=8, neg_fp=None):
    return probe_specs(base_url, PROBES, roe_guard=roe_guard, timeout=timeout,
                       neg_fp=neg_fp)


__all__ = ["scan", "PROBES"]
