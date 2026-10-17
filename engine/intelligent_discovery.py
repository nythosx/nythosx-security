"""Intelligent Endpoint Discovery.
Enhances standard discovery with LLM-guided inference and strict soft-404 filtering.
"""
import hashlib
import json
import random
import string
import re
from urllib.parse import urljoin, urlparse

from . import http as _http
from .config import load_engine
from .roe_guard import ROEGuard, ROEViolation

def _verify_tls():
    try:
        cfg = load_engine() or {}
        return bool(cfg.get("http", {}).get("verify_tls", True))
    except Exception:
        return True

def _roe_block(guard, url, method="GET"):
    if guard is None:
        try:
            guard = ROEGuard(engine_cfg=load_engine())
        except Exception:
            return None
    try:
        guard.check_url(url, method)
        return None
    except ROEViolation as e:
        return str(e)

def _soft_404_fingerprint(base_url, timeout=8, verify=None, roe_guard=None):
    """Generate a soft-404 baseline for the target to filter catch-all pages."""
    if verify is None:
        verify = _verify_tls()
    rand = "/zzz-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=20)) + "/does-not-exist"
    url = urljoin(base_url.rstrip("/") + "/", rand.lstrip("/"))
    
    viol = _roe_block(roe_guard, url, "GET")
    if viol:
        return None
        
    try:
        with _http.Client(timeout=timeout, verify=verify, follow_redirects=False) as c:
            r = c.get(url)
            body = r.text or ""
            return {
                "status": r.status_code,
                "is_html": "text/html" in r.headers.get("Content-Type", "").lower(),
                "size": len(body),
                "body_hash": hashlib.sha256(body.encode("utf-8", "ignore")).hexdigest()[:16],
                "catch_all": r.status_code == 200 and "text/html" in r.headers.get("Content-Type", "").lower()
            }
    except Exception:
        return None

def _matches_soft404(status, body, neg):
    if not neg:
        return False
    if neg.get("status") and status != neg["status"]:
        return False
    nsize = neg.get("size") or 0
    if not nsize:
        return True
    return abs(len(body or "") - nsize) <= max(80, int(nsize * 0.15))

def _llm_generate_endpoints(llm_client, target_domain, framework, valid_paths, failed_paths, max_suggestions=15):
    """Ask the LLM to generate probable hidden API endpoints based on context."""
    if not llm_client:
        return []
    
    prompt = f"""You are an expert API security researcher.
Target Domain: {target_domain}
Detected Framework: {framework or 'unknown'}

Known VALID Endpoints (use these to understand the app's structure and naming conventions):
{json.dumps(valid_paths[:15])}

Known FAILED/404 Endpoints (DO NOT suggest these or slight variations of them):
{json.dumps(failed_paths[:15])}

Goal: Generate up to {max_suggestions} highly probable, hidden API endpoint paths.
Focus on: AI/LLM chat interfaces, admin panels, authentication, or common framework defaults.

Rules:
1. Strictly follow the naming convention and versioning of the known VALID endpoints.
2. Do not hallucinate random strings. Use known framework defaults or logical extensions.
3. Return ONLY a valid JSON array of strings. Example: ["/api/v1/chat/completions", "/api/v2/admin/logs"]
"""
    try:
        raw = llm_client(prompt)
        match = re.search(r'\[.*\]', raw, re.DOTALL)
        if match:
            return json.loads(match.group(0))
    except Exception:
        pass
    return []

def intelligent_endpoint_discovery(base_url, valid_paths, failed_paths, llm_client=None, timeout=8, roe_guard=None):
    """
    Orchestrates the 4-phase intelligent discovery:
    1. Passive Harvesting (assumed done, passed as valid_paths)
    2. Context-Aware Wordlisting (assumed done, passed as valid_paths)
    3. LLM-Guided Inference
    4. Strict Soft-404 Filtering
    """
    verify = _verify_tls()
    neg_fp = _soft_404_fingerprint(base_url, timeout=timeout, verify=verify, roe_guard=roe_guard)
    
    parsed = urlparse(base_url)
    domain = parsed.hostname or base_url
    framework = "generic" # Could be passed in from recon
    
    # Phase 3: LLM-Guided Inference
    llm_suggestions = _llm_generate_endpoints(
        llm_client, domain, framework, valid_paths, failed_paths, max_suggestions=15
    )
    
    # Phase 4: Strict Soft-404 Filtering & Probing
    confirmed_paths = []
    for path in llm_suggestions:
        if not isinstance(path, str) or not path.startswith("/"):
            continue
            
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        viol = _roe_block(roe_guard, url, "GET")
        if viol:
            continue
            
        try:
            with _http.Client(timeout=timeout, verify=verify, follow_redirects=False) as c:
                r = c.get(url)
                body = r.text or ""
                
                # Check if it's a soft-404 (catch-all page)
                if neg_fp and _matches_soft404(r.status_code, body, neg_fp):
                    continue 
                
                # If it's a real 200, 401, 403, or JSON response, it's a valid find
                if r.status_code in (200, 201, 401, 403, 405) or "application/json" in r.headers.get("Content-Type", "").lower():
                    confirmed_paths.append({
                        "path": path,
                        "status": r.status_code,
                        "content_type": r.headers.get("Content-Type", ""),
                        "size": len(body)
                    })
        except Exception:
            continue
            
    return confirmed_paths
