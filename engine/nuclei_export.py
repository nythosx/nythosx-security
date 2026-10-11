"""Convert SEC-CHECKER chains to Nuclei template YAML."""
from pathlib import Path

import yaml


def _tool_to_request(tool, args):
    """Best-effort translation of common tools to a Nuclei HTTP request."""
    if tool == "skip_workflow_step":
        path = args.get("final_path") or "/"
        method = (args.get("method") or "POST").upper()
        return {
            "method": method,
            "path": ["{{BaseURL}}" + path],
            "matchers": [{"type": "status",
                          "status": [200, 201, 202, 204]}],
        }
    if tool == "bizlogic_coupon":
        return {
            "method": "POST",
            "path": ["{{BaseURL}}/api/cart/apply-coupon"],
            "headers": {"Content-Type": "application/json"},
            "body": '{"code":"' + str(args.get("code", "")) + '"}',
            "matchers": [{"type": "status", "status": [200, 201]}],
        }
    if tool == "graphql_scan":
        return {
            "method": "POST",
            "path": ["{{BaseURL}}/graphql"],
            "headers": {"Content-Type": "application/json"},
            "body": '{"query":"{ __typename }"}',
            "matchers": [{"type": "word", "part": "body",
                          "words": ["data"]}],
        }
    if tool == "openapi_scan":
        return {
            "method": "GET",
            "path": ["{{BaseURL}}/openapi.json",
                     "{{BaseURL}}/swagger.json",
                     "{{BaseURL}}/v3/api-docs"],
            "matchers": [{"type": "word", "part": "body",
                          "words": ['"openapi"', '"swagger"']}],
        }
    if tool == "jwt_attack":
        return {
            "method": "GET",
            "path": ["{{BaseURL}}"],
            "headers": {"Authorization": "Bearer "
                        + str(args.get("token", ""))},
            "matchers": [{"type": "status", "status": [200]}],
        }
    return None


def chain_to_nuclei(chain):
    """Return a Nuclei template dict for a SEC-CHECKER chain."""
    cid = chain.get("id") or "sec-checker-chain"
    name = chain.get("name") or cid
    severity = (chain.get("severity") or "info").lower()
    if severity not in ("info", "low", "medium", "high", "critical"):
        severity = "info"
    requests, unmatched = [], []
    for s in chain.get("steps") or []:
        tool = s.get("tool")
        args = s.get("args") or {}
        req = _tool_to_request(tool, args)
        if req is None:
            unmatched.append({"step": s.get("id"), "tool": tool})
            continue
        requests.append(req)
    template = {
        "id": cid,
        "info": {
            "name": name,
            "author": "sec-checker",
            "severity": severity,
            "description": (
                "Exported from SEC-CHECKER chain '" + str(cid) + "'. "
                + ("Some steps could not be translated to plain HTTP and "
                   "are documented in metadata." if unmatched else "")
            ),
            "tags": "sec-checker,chain",
        },
    }
    if unmatched:
        template["info"]["metadata"] = {"untranslated_steps": unmatched}
    template["http"] = requests or [{
        "method": "GET",
        "path": ["{{BaseURL}}/"],
        "matchers": [{"type": "status", "status": [200]}],
    }]
    return template


def save_nuclei(chain, out_path=None):
    tpl = chain_to_nuclei(chain)
    text = yaml.safe_dump(tpl, sort_keys=False, allow_unicode=True)
    if out_path is None:
        out_path = "reports/" + str(tpl["id"]) + ".nuclei.yaml"
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return str(p)


__all__ = ["chain_to_nuclei", "save_nuclei"]
