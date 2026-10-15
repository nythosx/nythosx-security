
import threading


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
        {
            "id": "cve-chain",
            "name": "Known CVE Correlation Chain",
            "priority": 26,
            "trigger": {
                "mode": "any",
                "conditions": [
                    {"fact": "powered_by"},
                    {"fact": "server"},
                ],
            },
            "steps": [
                {
                    "id": "cve_corr",
                    "tool": "cve_correlation",
                    "args": {},
                    "on_fail": "abort",
                },
            ],
        },
        {
            "id": "access-bypass-chain",
            "name": "Access Control Bypass Chain",
            "priority": 24,
            "trigger": {
                "mode": "any",
                "conditions": [
                    {"fact": "has_admin"},
                    {"fact": "has_admin_paths"},
                ],
            },
            "steps": [
                {
                    "id": "access_bypass",
                    "tool": "access_bypass",
                    "args": {"url": "{{ admin_url }}"},
                    "on_fail": "abort",
                },
            ],
        },
        {
            "id": "deserialization-chain",
            "name": "Deserialization Chain",
            "priority": 17,
            "trigger": {
                "mode": "any",
                "conditions": [
                    {"fact": "has_login"},
                    {"fact": "has_workflow"},
                    {"fact": "has_cart"},
                ],
            },
            "steps": [
                {
                    "id": "deserialization",
                    "tool": "deserialization",
                    "args": {"url": "{{ target }}", "method": "POST"},
                    "on_fail": "abort",
                },
            ],
        },
        {
            "id": "graphql-schema-chain",
            "name": "GraphQL Schema Reconstruction Chain",
            "priority": 16,
            "trigger": {
                "mode": "any",
                "conditions": [
                    {"fact": "has_graphql"},
                    {"fact": "has_graphql_hint"},
                ],
            },
            "steps": [
                {
                    "id": "graphql_schema",
                    "tool": "graphql_schema",
                    "args": {"url": "{{ graphql_url }}"},
                    "on_fail": "abort",
                },
            ],
        },
        {
            "id": "sourcemap-chain",
            "name": "JS Source Map Mining Chain",
            "priority": 15,
            "trigger": {
                "mode": "all",
                "conditions": [
                    {"fact": "js_bundle_count"},
                ],
            },
            "steps": [
                {
                    "id": "sourcemap_mine",
                    "tool": "sourcemap_mine",
                    "args": {},
                    "on_fail": "abort",
                },
            ],
        },
        {
            "id": "subdomain-chain",
            "name": "CT Log Subdomain Chain",
            "priority": 14,
            "trigger": {
                "mode": "all",
                "conditions": [
                    {"fact": "framework"},
                ],
            },
            "steps": [
                {
                    "id": "ct_subdomain",
                    "tool": "ct_subdomain",
                    "args": {"domain": "{{ target }}"},
                    "on_fail": "abort",
                },
            ],
        },
        {
            "id": "subdomain-takeover-chain",
            "name": "Subdomain Takeover Chain",
            "priority": 13,
            "trigger": {
                "mode": "all",
                "conditions": [{"fact": "live_subdomains"}],
            },
            "steps": [
                {
                    "id": "subdomain_takeover",
                    "tool": "subdomain_takeover",
                    "args": {},
                    "on_fail": "abort",
                },
            ],
        },
        {
            "id": "cloud-storage-chain",
            "name": "Cloud Storage Enumeration Chain",
            "priority": 12,
            "trigger": {
                "mode": "all",
                "conditions": [{"fact": "framework"}],
            },
            "steps": [
                {
                    "id": "cloud_storage",
                    "tool": "cloud_storage",
                    "args": {"domain": "{{ target }}"},
                    "on_fail": "abort",
                },
            ],
        },
        {
            "id": "hpp-chain",
            "name": "HTTP Parameter Pollution Chain",
            "priority": 11,
            "trigger": {
                "mode": "any",
                "conditions": [
                    {"fact": "has_search"},
                    {"fact": "has_cart"},
                    {"fact": "has_workflow"},
                ],
            },
            "steps": [
                {
                    "id": "hpp",
                    "tool": "hpp",
                    "args": {"url": "{{ target }}"},
                    "on_fail": "abort",
                },
            ],
        },
        {
            "id": "framework-exploit-chain",
            "name": "Framework Surface Chain",
            "priority": 19,
            "trigger": {
                "mode": "any",
                "conditions": [
                    {"fact": "framework"},
                    {"fact": "powered_by"},
                    {"fact": "server"},
                ],
            },
            "steps": [
                {
                    "id": "framework_probe",
                    "tool": "framework_probe",
                    "args": {"base_url": "{{ target }}"},
                    "on_fail": "abort",
                },
            ],
        },
        {
            "id": "timing-robust-chain",
            "name": "Robust Timing Oracle Chain",
            "priority": 18,
            "trigger": {
                "mode": "any",
                "conditions": [
                    {"fact": "has_search"},
                    {"fact": "has_login"},
                    {"fact": "has_workflow"},
                ],
            },
            "steps": [
                {
                    "id": "timing_robust",
                    "tool": "timing_robust",
                    "args": {
                        "url": "{{ target }}",
                        "param": "q",
                        "kind": "sqli",
                        "baseline_samples": 10,
                        "payload_samples": 10,
                    },
                    "on_fail": "abort",
                },
            ],
        },
        {
            "id": "differential-chain",
            "name": "Differential Auth Chain",
            "priority": 21,
            "trigger": {
                "mode": "any",
                "conditions": [
                    {"fact": "has_login"},
                    {"fact": "has_jwt_token"},
                    {"fact": "has_workflow"},
                ],
            },
            "steps": [
                {
                    "id": "differential",
                    "tool": "differential",
                    "args": {"base_url": "{{ api_base }}"},
                    "on_fail": "abort",
                },
            ],
        },
        {
            "id": "wayback-chain",
            "name": "Historic URL Harvest Chain",
            "priority": 20,
            "trigger": {
                "mode": "all",
                "conditions": [
                    {"fact": "has_historic_paths"},
                ],
            },
            "steps": [
                {
                    "id": "wayback_harvest",
                    "tool": "wayback",
                    "args": {"base_url": "{{ target }}"},
                    "on_fail": "abort",
                },
            ],
        },
        {
            "id": "cache-deception-chain",
            "name": "Cache Deception Chain",
            "priority": 22,
            "trigger": {
                "mode": "any",
                "conditions": [
                    {"fact": "has_login"},
                    {"fact": "has_ecommerce"},
                ],
            },
            "steps": [
                {
                    "id": "cache_deception",
                    "tool": "cache_deception",
                    "args": {"url": "{{ target }}/api/me"},
                    "on_fail": "abort",
                },
            ],
        },
        {
            "id": "bola-chain",
            "name": "BOLA / BFLA Data Exposure Chain",
            "priority": 98,
            "trigger": {
                "mode": "all",
                "conditions": [{"fact": "banking_requested"}],
            },
            "steps": [
                {
                    "id": "bola_probe",
                    "tool": "bola_scan",
                    "args": {"base_url": "{{ api_base }}"},
                    "on_fail": "next",
                },
            ],
        },
        {
            "id": "unauth-exposure-chain",
            "name": "Unauthenticated Data Exposure Chain",
            "priority": 97,
            "trigger": {
                "mode": "all",
                "conditions": [{"fact": "banking_requested"}],
            },
            "steps": [
                {
                    "id": "unauth_probe",
                    "tool": "unauth_exposure",
                    "args": {"max_paths": 40, "max_rows": 5},
                    "on_fail": "next",
                },
            ],
        },
        {
            "id": "data-extraction-chain",
            "name": "Authenticated Data Extraction Chain",
            "priority": 96,
            "trigger": {
                "mode": "all",
                "conditions": [{"fact": "banking_requested"}],
            },
            "steps": [
                {
                    "id": "extract_me",
                    "tool": "data_extract",
                    "args": {"path": "/api/v1/me", "max_rows": 5},
                    "on_fail": "next",
                },
                {
                    "id": "extract_accounts",
                    "tool": "data_extract",
                    "args": {"path": "/api/v1/accounts/1", "max_rows": 5},
                    "on_fail": "next",
                },
            ],
        },
        {
            "id": "rate-limit-bypass-chain",
            "name": "Rate Limit Bypass Chain",
            "priority": 94,
            "trigger": {
                "mode": "all",
                "conditions": [{"fact": "banking_requested"}],
            },
            "steps": [
                {
                    "id": "rl_bypass",
                    "tool": "rate_limit_bypass",
                    "args": {"path": "/api/v1/accounts", "count": 20},
                    "on_fail": "next",
                },
            ],
        },
        {
            "id": "mcp-security-chain",
            "name": "MCP Security Chain",
            "priority": 99,
            "trigger": {
                "mode": "any",
                "conditions": [
                    {"fact": "has_llm_hint"},
                    {"fact": "framework"},
                ],
            },
            "steps": [
                {
                    "id": "mcp_poison",
                    "tool": "mcp_security",
                    "args": {"config_path": ".mcp.json",
                             "check": "poisoning"},
                    "on_fail": "next",
                },
                {
                    "id": "mcp_creds",
                    "tool": "mcp_security",
                    "args": {"config_path": ".mcp.json",
                             "check": "credentials"},
                    "on_fail": "abort",
                },
            ],
        },
        {
            "id": "blind-sqli-chain",
            "name": "Blind SQLi Extraction Chain",
            "priority": 93,
            "trigger": {
                "mode": "any",
                "conditions": [
                    {"fact": "has_login"},
                    {"fact": "has_search"},
                ],
            },
            "steps": [
                {
                    "id": "blind_extract_users",
                    "tool": "blind_extract",
                    "args": {"url": "{{ target }}",
                             "param": "q",
                             "table": "users",
                             "column": "password"},
                    "on_fail": "abort",
                },
            ],
        },
        {
            "id": "blind-xxe-chain",
            "name": "XXE File Read Extraction Chain",
            "priority": 92,
            "trigger": {
                "mode": "any",
                "conditions": [
                    {"fact": "has_xml_hint"},
                    {"fact": "has_upload"},
                ],
            },
            "steps": [
                {
                    "id": "xxe_file_read",
                    "tool": "xxe_harvest",
                    "args": {"url": "{{ target }}"},
                    "on_fail": "abort",
                },
            ],
        },
        {
            "id": "pagination-dump-chain",
            "name": "Unauthenticated Pagination Dump Chain",
            "priority": 91,
            "trigger": {
                "mode": "any",
                "conditions": [
                    {"fact": "has_search"},
                    {"fact": "framework"},
                    {"fact": "has_login"},
                ],
            },
            "steps": [
                {
                    "id": "pag_dump",
                    "tool": "unauth_pagination",
                    "args": {"url": "{{ api_base }}", "max_pages": 50},
                    "on_fail": "next",
                },
            ],
        },
        {
            "id": "graphql-dump-chain",
            "name": "GraphQL Full Data Dump Chain",
            "priority": 89,
            "trigger": {
                "mode": "any",
                "conditions": [
                    {"fact": "has_graphql"},
                    {"fact": "has_graphql_hint"},
                ],
            },
            "steps": [
                {
                    "id": "gql_dump",
                    "tool": "graphql_dump",
                    "args": {"url": "{{ graphql_url }}"},
                    "on_fail": "abort",
                },
            ],
        },
        {
            "id": "llm-prompt-dump-chain",
            "name": "LLM System Prompt Extraction Chain",
            "priority": 88,
            "trigger": {
                "mode": "any",
                "conditions": [{"fact": "has_llm_hint"}],
            },
            "steps": [
                {
                    "id": "llm_prompt_dump",
                    "tool": "llm_prompt_dump",
                    "args": {"url": "{{ api_base }}"},
                    "on_fail": "next",
                },
            ],
        },
        {
            "id": "llm-cred-tool-chain",
            "name": "LLM Credential + Tool List Extraction Chain",
            "priority": 87,
            "trigger": {
                "mode": "any",
                "conditions": [{"fact": "has_llm_hint"}],
            },
            "steps": [
                {
                    "id": "llm_creds",
                    "tool": "llm_cred_extract",
                    "args": {"url": "{{ api_base }}"},
                    "on_fail": "next",
                },
                {
                    "id": "llm_tools",
                    "tool": "llm_tool_list",
                    "args": {"url": "{{ api_base }}"},
                    "on_fail": "abort",
                },
            ],
        },
        {
            "id": "session-fixation-chain",
            "name": "Session Fixation Chain",
            "priority": 86,
            "trigger": {
                "mode": "any",
                "conditions": [
                    {"fact": "has_login"},
                    {"fact": "has_jwt_token"},
                ],
            },
            "steps": [
                {
                    "id": "session_fixation",
                    "tool": "session_fixation",
                    "args": {"url": "{{ api_base }}"},
                    "on_fail": "abort",
                },
            ],
        },
        {
            "id": "ci-cd-exposure-chain",
            "name": "CI/CD Configuration Exposure Chain",
            "priority": 84,
            "trigger": {
                "mode": "any",
                "conditions": [
                    {"fact": "framework"},
                    {"fact": "server"},
                ],
            },
            "steps": [
                {
                    "id": "ci_cd_probe",
                    "tool": "ci_cd_probe",
                    "args": {"url": "{{ target }}"},
                    "on_fail": "abort",
                },
            ],
        },
        {
            "id": "npmrc-chain",
            "name": "Package Manager Config Exposure Chain",
            "priority": 83,
            "trigger": {
                "mode": "any",
                "conditions": [
                    {"fact": "framework"},
                    {"fact": "server"},
                ],
            },
            "steps": [
                {
                    "id": "npmrc_probe",
                    "tool": "npmrc_probe",
                    "args": {"url": "{{ target }}"},
                    "on_fail": "abort",
                },
            ],
        },
    ]



_RAW_GET_ALL_CHAINS = get_all_chains

_CACHE_LOCK = threading.Lock()
_VALIDATED_CHAINS = None


def get_all_chains():
    global _VALIDATED_CHAINS
    if _VALIDATED_CHAINS is not None:
        return _VALIDATED_CHAINS
    with _CACHE_LOCK:
        if _VALIDATED_CHAINS is not None:
            return _VALIDATED_CHAINS
        from . import schema
        chains = _RAW_GET_ALL_CHAINS()
        for c in chains:
            schema.validate_chain(c, where=f"chain:{c.get('id')}")
        _VALIDATED_CHAINS = chains
        return _VALIDATED_CHAINS


def reload():
    global _VALIDATED_CHAINS
    with _CACHE_LOCK:
        _VALIDATED_CHAINS = None
    return get_all_chains()
