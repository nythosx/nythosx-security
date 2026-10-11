
def get_all_chains():
    return [
        {
            "id": "jwt-chain",
            "name": "JWT Attack Chain",
            "priority": 100,
            "trigger": {
                "mode": "any",
                "conditions": [
                    {"fact": "has_jwt_token"},
                    {"fact": "has_jwt_hint"},
                    {"fact": "has_login"},
                ],
            },
            "steps": [
                {
                    "id": "alg_none",
                    "tool": "jwt_attack",
                    "args": {
                        "target": "{{ api_base }}",
                        "token": "{{ jwt_token }}",
                        "vector": "alg:none",
                    },
                    "precondition": {
                        "mode": "all",
                        "conditions": [{"fact": "has_jwt_token"}],
                    },
                    "on_fail": "next",
                },
                {
                    "id": "algorithm_confusion",
                    "tool": "jwt_attack",
                    "args": {
                        "target": "{{ api_base }}",
                        "token": "{{ jwt_token }}",
                        "vector": "algorithm-confusion",
                    },
                    "precondition": {
                        "mode": "all",
                        "conditions": [{"fact": "has_jwt_token"}],
                    },
                    "on_fail": "next",
                },
                {
                    "id": "kid_injection",
                    "tool": "jwt_attack",
                    "args": {
                        "target": "{{ api_base }}",
                        "token": "{{ jwt_token }}",
                        "vector": "kid",
                    },
                    "precondition": {
                        "mode": "all",
                        "conditions": [{"fact": "has_jwt_token"}],
                    },
                    "on_fail": "next",
                },
                {
                    "id": "weak_secret",
                    "tool": "jwt_attack",
                    "args": {
                        "target": "{{ api_base }}",
                        "token": "{{ jwt_token }}",
                        "vector": "weak-secret",
                    },
                    "precondition": {
                        "mode": "all",
                        "conditions": [{"fact": "has_jwt_token"}],
                    },
                    "exports": {"jwt_cracked_secret": "evidence.secret"},
                    "on_fail": "abort",
                },
            ],
        },
        {
            "id": "graphql-chain",
            "name": "GraphQL Attack Chain",
            "priority": 95,
            "trigger": {
                "mode": "any",
                "conditions": [
                    {"fact": "has_graphql"},
                    {"fact": "has_graphql_hint"},
                ],
            },
            "steps": [
                {
                    "id": "graphql_full_scan",
                    "tool": "graphql_scan",
                    "args": {"target": "{{ graphql_url }}"},
                    "on_fail": "abort",
                },
            ],
        },
        {
            "id": "ssrf-chain",
            "name": "SSRF Cloud Metadata Chain",
            "priority": 90,
            "trigger": {
                "mode": "any",
                "conditions": [
                    {"fact": "has_ssrf_hint"},
                ],
            },
            "steps": [
                {
                    "id": "cloud_metadata",
                    "tool": "ssrf_cloud",
                    "args": {"base_url": "{{ api_base }}"},
                    "on_fail": "abort",
                },
            ],
        },
        {
            "id": "bizlogic-chain",
            "name": "Business Logic Chain",
            "priority": 85,
            "trigger": {
                "mode": "any",
                "conditions": [
                    {"fact": "has_ecommerce"},
                    {"fact": "has_coupon"},
                    {"fact": "has_financial"},
                    {"fact": "has_workflow"},
                ],
            },
            "steps": [
                {
                    "id": "coupon_abuse",
                    "tool": "bizlogic_coupon",
                    "args": {"code": "WELCOME50"},
                    "precondition": {
                        "mode": "any",
                        "conditions": [
                            {"fact": "has_coupon"},
                            {"fact": "has_coupon_endpoint"},
                        ],
                    },
                    "on_fail": "next",
                },
                {
                    "id": "coupon_race",
                    "tool": "race_coupon",
                    "args": {"code": "WELCOME50"},
                    "precondition": {
                        "mode": "any",
                        "conditions": [
                            {"fact": "has_coupon"},
                            {"fact": "has_coupon_endpoint"},
                        ],
                    },
                    "on_fail": "next",
                },
                {
                    "id": "workflow_skip",
                    "tool": "skip_workflow_step",
                    "args": {
                        "final_path": "/api/order/confirm",
                        "method": "POST",
                    },
                    "precondition": {
                        "mode": "any",
                        "conditions": [{"fact": "has_workflow"}],
                    },
                    "on_fail": "abort",
                },
            ],
        },
        {
            "id": "race-chain",
            "name": "Race Condition Chain",
            "priority": 75,
            "trigger": {
                "mode": "any",
                "conditions": [
                    {"fact": "has_cart"},
                    {"fact": "has_financial"},
                    {"fact": "has_coupon_endpoint"},
                ],
            },
            "steps": [
                {
                    "id": "race_barrier",
                    "tool": "race_scan",
                    "args": {
                        "url": "{{ cart_url }}",
                        "method": "POST",
                        "modes": ["barrier"],
                    },
                    "on_fail": "next",
                },
                {
                    "id": "race_single_packet",
                    "tool": "race_scan",
                    "args": {
                        "url": "{{ cart_url }}",
                        "method": "POST",
                        "modes": ["single_packet"],
                    },
                    "on_fail": "abort",
                },
            ],
        },
        {
            "id": "llm-chain",
            "name": "LLM Security Chain",
            "priority": 70,
            "trigger": {
                "mode": "any",
                "conditions": [
                    {"fact": "has_llm_hint"},
                ],
            },
            "steps": [
                {
                    "id": "llm_injection",
                    "tool": "llm_scan",
                    "args": {
                        "url": "{{ api_base }}",
                        "model": "gpt-3.5-turbo",
                    },
                    "on_fail": "abort",
                },
            ],
        },
        {
            "id": "xss-chain",
            "name": "DOM XSS Chain",
            "priority": 60,
            "trigger": {
                "mode": "any",
                "conditions": [
                    {"fact": "has_search"},
                    {"fact": "framework", "value": "nuxt"},
                    {"fact": "framework", "value": "nextjs"},
                    {"fact": "framework", "value": "express"},
                ],
            },
            "steps": [
                {
                    "id": "dom_xss",
                    "tool": "domxss_scan",
                    "args": {"url": "{{ target }}"},
                    "on_fail": "abort",
                },
            ],
        },
        {
            "id": "openapi-chain",
            "name": "OpenAPI Spec Chain",
            "priority": 55,
            "trigger": {
                "mode": "any",
                "conditions": [
                    {"fact": "has_openapi"},
                ],
            },
            "steps": [
                {
                    "id": "openapi_discover",
                    "tool": "openapi_scan",
                    "args": {"url": "{{ api_base }}"},
                    "on_fail": "abort",
                },
            ],
        },
        {
            "id": "sca-chain",
            "name": "Supply Chain Chain",
            "priority": 50,
            "trigger": {
                "mode": "all",
                "conditions": [
                    {"fact": "sca_requested"},
                ],
            },
            "steps": [
                {
                    "id": "sca_scan",
                    "tool": "sca_scan",
                    "args": {"path": "{{ sca_path }}"},
                    "on_fail": "abort",
                },
            ],
        },
        {
            "id": "oauth-chain",
            "name": "OAuth/OIDC Chain",
            "priority": 48,
            "trigger": {
                "mode": "any",
                "conditions": [{"fact": "has_oauth_hint"}],
            },
            "steps": [
                {
                    "id": "oauth_discover",
                    "tool": "oauth_discovery",
                    "args": {"base_url": "{{ api_base }}"},
                    "on_fail": "next",
                },
                {
                    "id": "oauth_redirect",
                    "tool": "oauth_redirect",
                    "args": {"auth_endpoint": "{{ oauth_auth_endpoint }}"},
                    "on_fail": "next",
                },
                {
                    "id": "oauth_state",
                    "tool": "oauth_state",
                    "args": {"auth_endpoint": "{{ oauth_auth_endpoint }}"},
                    "on_fail": "next",
                },
                {
                    "id": "oauth_pkce",
                    "tool": "oauth_pkce",
                    "args": {"auth_endpoint": "{{ oauth_auth_endpoint }}"},
                    "on_fail": "abort",
                },
            ],
        },
        {
            "id": "websocket-chain",
            "name": "WebSocket CSWSH Chain",
            "priority": 44,
            "trigger": {
                "mode": "any",
                "conditions": [{"fact": "has_websocket_hint"}],
            },
            "steps": [
                {
                    "id": "ws_cswsh",
                    "tool": "websocket_scan",
                    "args": {"target_url": "{{ websocket_url }}"},
                    "on_fail": "abort",
                },
            ],
        },
        {
            "id": "upload-chain",
            "name": "File Upload Chain",
            "priority": 42,
            "trigger": {
                "mode": "any",
                "conditions": [{"fact": "has_upload"}],
            },
            "steps": [
                {
                    "id": "upload_probe",
                    "tool": "upload_scan",
                    "args": {"upload_url": "{{ upload_url }}"},
                    "on_fail": "abort",
                },
            ],
        },
        {
            "id": "weak-password-chain",
            "name": "Weak Password Chain",
            "priority": 40,
            "trigger": {
                "mode": "any",
                "conditions": [{"fact": "has_login"}],
            },
            "steps": [
                {
                    "id": "weak_password",
                    "tool": "weak_password_scan",
                    "args": {"target_url": "{{ api_base }}"},
                    "on_fail": "next",
                },
                {
                    "id": "lockout",
                    "tool": "lockout_scan",
                    "args": {
                        "login_url": "{{ login_url }}",
                        "username": "probe@example.com",
                    },
                    "on_fail": "abort",
                },
            ],
        },
        {
            "id": "http2-chain",
            "name": "HTTP/2 Desync Chain",
            "priority": 38,
            "trigger": {
                "mode": "any",
                "conditions": [{"fact": "has_http2_hint"}],
            },
            "steps": [
                {
                    "id": "h2_desync",
                    "tool": "http2_scan",
                    "args": {"target_url": "{{ target }}"},
                    "on_fail": "abort",
                },
            ],
        },
        {
            "id": "crlf-chain",
            "name": "CRLF Injection Chain",
            "priority": 36,
            "trigger": {
                "mode": "any",
                "conditions": [{"fact": "has_redirect_hint"}],
            },
            "steps": [
                {
                    "id": "crlf_probe",
                    "tool": "crlf_scan",
                    "args": {"target_url": "{{ target }}"},
                    "on_fail": "abort",
                },
            ],
        },
        {
            "id": "open-redirect-chain",
            "name": "Open Redirect Chain",
            "priority": 34,
            "trigger": {
                "mode": "any",
                "conditions": [{"fact": "has_redirect_hint"}],
            },
            "steps": [
                {
                    "id": "open_redirect",
                    "tool": "open_redirect_scan",
                    "args": {"target_url": "{{ target }}"},
                    "on_fail": "abort",
                },
            ],
        },
        {
            "id": "host-header-chain",
            "name": "Host Header Injection Chain",
            "priority": 32,
            "trigger": {
                "mode": "any",
                "conditions": [{"fact": "has_workflow"}],
            },
            "steps": [
                {
                    "id": "host_header",
                    "tool": "host_header_scan",
                    "args": {"target_url": "{{ target }}"},
                    "on_fail": "abort",
                },
            ],
        },
        {
            "id": "injection-family-chain",
            "name": "Injection Family Chain (SSTI/NoSQL/XXE)",
            "priority": 30,
            "trigger": {
                "mode": "any",
                "conditions": [
                    {"fact": "has_search"},
                    {"fact": "has_ssti_hint"},
                    {"fact": "has_xml_hint"},
                ],
            },
            "steps": [
                {
                    "id": "ssti",
                    "tool": "ssti_scan",
                    "args": {"target_url": "{{ target }}"},
                    "on_fail": "next",
                },
                {
                    "id": "nosql",
                    "tool": "nosql_scan",
                    "args": {"login_url": "{{ login_url }}"},
                    "on_fail": "next",
                },
                {
                    "id": "xxe",
                    "tool": "xxe_scan",
                    "args": {"target_url": "{{ target }}"},
                    "on_fail": "abort",
                },
            ],
        },
        {
            "id": "second-order-chain",
            "name": "Second-Order Injection Chain",
            "priority": 28,
            "trigger": {
                "mode": "any",
                "conditions": [
                    {"fact": "has_workflow"},
                    {"fact": "has_search"},
                ],
            },
            "steps": [
                {
                    "id": "second_order",
                    "tool": "second_order_check",
                    "args": {
                        "target": "{{ target }}",
                        "marker": "SEC_MARKER_2O",
                    },
                    "on_fail": "abort",
                },
            ],
        },
    ]



_RAW_GET_ALL_CHAINS = get_all_chains


def get_all_chains():
    from . import schema
    chains = _RAW_GET_ALL_CHAINS()
    for c in chains:
        schema.validate_chain(c, where=f"chain:{c.get('id')}")
    return chains
