"""Apache Tomcat surface probes.

Read-only. We check for the presence of manager and sample apps, and the
status endpoint. We do not attempt login or deploy.
"""
from ._probe import probe_specs


PROBES = [
    {
        "name": "tomcat_manager",
        "method": "GET",
        "path": "/manager/html",
        "status_in": [200, 401, 403],
        "severity": "high",
        "reason": "Tomcat Manager webapp is reachable — WAR deployment surface",
    },
    {
        "name": "tomcat_host_manager",
        "method": "GET",
        "path": "/host-manager/html",
        "status_in": [200, 401, 403],
        "severity": "high",
        "reason": "Tomcat Host Manager is reachable",
    },
    {
        "name": "tomcat_examples",
        "method": "GET",
        "path": "/examples/",
        "status_in": [200],
        "body_contains_all": ["Example", "Servlets"],
        "severity": "high",
        "reason": ("Tomcat sample webapps are deployed — includes "
                   "CGI/Servlet examples that can be abused"),
    },
    {
        "name": "tomcat_docs",
        "method": "GET",
        "path": "/docs/",
        "status_in": [200],
        "body_contains_all": ["Apache Tomcat", "Documentation"],
        "severity": "medium",
        "reason": "Tomcat documentation is served — confirms default deploy",
    },
    {
        "name": "tomcat_manager_status",
        "method": "GET",
        "path": "/manager/status",
        "status_in": [200],
        "body_contains_all": ["JVM", "Free memory"],
        "severity": "high",
        "reason": "Tomcat Manager status page is publicly reachable",
    },
]


def scan(base_url, roe_guard=None, timeout=8):
    return probe_specs(base_url, PROBES, roe_guard=roe_guard, timeout=timeout)


__all__ = ["scan", "PROBES"]
