"""Spring Boot Actuator surface probes.

Read-only. Actuator endpoints are exposed by misconfiguration; some carry
credentials, environment variables, heap dumps, or the prerequisite for
CVE-2022-22947 (Spring Cloud Gateway RCE). We never POST to refresh or
mutate any actuator endpoint.
"""
from ._probe import probe_specs


PROBES = [
    {
        "name": "actuator_root",
        "method": "GET",
        "path": "/actuator",
        "status_in": [200],
        "body_contains": ["_links"],
        "severity": "medium",
        "reason": "Spring Boot Actuator index is exposed",
    },
    {
        "name": "actuator_env",
        "method": "GET",
        "path": "/actuator/env",
        "status_in": [200],
        "body_contains": ["propertySources"],
        "severity": "critical",
        "reason": ("Actuator /env readable — environment variables, "
                   "connection strings, and secrets may be disclosed"),
    },
    {
        "name": "actuator_env_legacy",
        "method": "GET",
        "path": "/env",
        "status_in": [200],
        "body_contains": ["propertySources"],
        "severity": "critical",
        "reason": "Spring Boot 1.x /env path is exposed",
    },
    {
        "name": "actuator_heapdump",
        "method": "GET",
        "path": "/actuator/heapdump",
        "status_in": [200],
        "body_contains": ["JAVA PROFILE"],
        "severity": "critical",
        "reason": ("Actuator /heapdump reachable — full JVM heap is "
                   "downloadable, including in-memory credentials"),
    },
    {
        "name": "actuator_gateway_routes",
        "method": "GET",
        "path": "/actuator/gateway/routes",
        "status_in": [200],
        "body_contains": ["route_id", "predicate"],
        "severity": "critical",
        "cve": "CVE-2022-22947",
        "reason": ("Spring Cloud Gateway /actuator/gateway/routes exposed — "
                   "prerequisite for CVE-2022-22947 RCE"),
    },
    {
        "name": "actuator_loggers",
        "method": "GET",
        "path": "/actuator/loggers",
        "status_in": [200],
        "body_contains": ["loggers"],
        "severity": "high",
        "reason": "Actuator /loggers exposed — runtime log-level control",
    },
    {
        "name": "actuator_mappings",
        "method": "GET",
        "path": "/actuator/mappings",
        "status_in": [200],
        "body_contains": ["contexts", "dispatcherServlets", "handlerMethods"],
        "severity": "high",
        "reason": "Actuator /mappings exposes every registered route",
    },
    {
        "name": "jolokia_list",
        "method": "GET",
        "path": "/jolokia/list",
        "status_in": [200],
        "body_contains_all": ["\"request\"", "\"type\":\"list\""],
        "severity": "critical",
        "reason": "Jolokia JMX-over-HTTP bridge is exposed",
    },
    {
        "name": "actuator_trace",
        "method": "GET",
        "path": "/actuator/httptrace",
        "status_in": [200],
        "body_contains": ["traces"],
        "severity": "high",
        "reason": "Actuator /httptrace exposes recent request history",
    },
]


def scan(base_url, roe_guard=None, timeout=8, neg_fp=None):
    return probe_specs(base_url, PROBES, roe_guard=roe_guard, timeout=timeout,
                       neg_fp=neg_fp)


__all__ = ["scan", "PROBES"]
