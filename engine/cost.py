from __future__ import annotations

DEFAULT_WEIGHT = 1.0

_TOOL_COSTS = {
    "browser_capture": 20.0,
    "domxss_scan": 25.0,
    "dom_xss": 25.0,
    "llm_scan": 5.0,
    "llm_security": 5.0,
    "sca_scan": 3.0,
    "sca": 3.0,
    "cve_correlation": 3.0,
    "cve_lookup": 3.0,
    "ct_subdomain": 2.0,
    "ct_logs": 2.0,
    "wayback_mining": 2.0,
    "wayback": 2.0,
    "cloud_storage": 2.0,
    "subdomain_takeover": 2.0,
    "framework_probe": 2.0,
    "race_scan": 30.0,
    "race_advanced": 30.0,
    "blind_extract": 50.0,
    "bola_scan": 20.0,
    "bola_harvest": 20.0,
    "graphql_scan": 3.0,
    "graphql_schema": 3.0,
    "graphql_schema_walk": 3.0,
    "jwt_attack": 5.0,
    "jwt_attacks": 5.0,
    "smuggle_scan": 8.0,
    "smuggle": 8.0,
    "upload_scan": 5.0,
    "websocket_scan": 5.0,
    "http2_scan": 5.0,
    "http2_desync_scan": 5.0,
    "weak_password_scan": 15.0,
    "weak_credential_enum": 30.0,
    "lockout_probe": 15.0,
    "timing_injection": 15.0,
    "timing_robust": 15.0,
    "second_order_check": 5.0,
    "blind_ssrf": 5.0,
    "blind_xss": 5.0,
    "deserialization": 5.0,
    "deserialization_scan": 5.0,
    "crlf_scan": 1.0,
    "open_redirect_scan": 1.0,
    "host_header_scan": 1.0,
    "ssti_scan": 1.0,
    "nosql_scan": 3.0,
    "xxe_scan": 3.0,
    "hpp_scan": 1.0,
    "upload_probe": 5.0,
}


def estimate_cost(tool_name, args=None):
    if not tool_name:
        return DEFAULT_WEIGHT
    base = _TOOL_COSTS.get(tool_name)
    if base is not None:
        return base
    cap_name = _alias_to_capability(tool_name)
    if cap_name:
        return _TOOL_COSTS.get(cap_name, DEFAULT_WEIGHT)
    return DEFAULT_WEIGHT


_ALIASES = {
    "cloud_storage": "cloud_storage",
    "hpp": "hpp_scan",
    "deserialization": "deserialization_scan",
    "graphql_schema": "graphql_schema_walk",
    "differential": "differential_scan",
    "wayback": "wayback_mining",
    "access_bypass": "access_bypass_scan",
    "cache_deception": "cache_deception_scan",
    "ssrf_cloud": "ssrf_cloud_scan",
    "blind_ssrf": "ssrf_scan",
    "blind_xss": "xss_scan",
    "bizlogic_price": "bizlogic_scan",
    "bizlogic_coupon": "bizlogic_scan",
    "race_coupon": "bizlogic_scan",
    "skip_workflow_step": "bizlogic_scan",
    "timing_robust": "timing_robust",
    "timing_injection": "timing_sqli",
    "cve_correlation": "cve_correlation",
    "framework_probe": "framework_surface",
    "ct_subdomain": "ct_subdomain",
    "sourcemap_mine": "sourcemap_mining",
}


def _alias_to_capability(tool_name):
    return _ALIASES.get(tool_name)


__all__ = ["estimate_cost", "DEFAULT_WEIGHT"]
