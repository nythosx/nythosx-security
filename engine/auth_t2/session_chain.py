"""Full session fixation chain: pre-plant -> login -> verify survival."""
from .. import http as _http
from ..roe_guard import ROEGuard

def run_chain(login_url, protected_url, roe_guard=None):
    if roe_guard is None: roe_guard = ROEGuard()
    roe_guard.check_url(login_url, "POST")
    roe_guard.check_url(protected_url, "GET")

    pre_planted_id = "sec_checker_pre_plant_12345"
    cookies = {"session_id": pre_planted_id}

    with _http.Client(timeout=8, follow_redirects=False) as c:
        # 1. Pre-plant
        c.get(protected_url, cookies=cookies)
        # 2. Login
        r_login = c.post(login_url, json={"user": "test", "pass": "test"}, cookies=cookies)
        # 3. Verify survival
        r_prot = c.get(protected_url, cookies=cookies)

    # Check if the server set a NEW session cookie or kept the pre-planted one
    set_cookie = r_login.headers.get("set-cookie", "")
    if pre_planted_id in set_cookie or (not set_cookie and r_prot.status_code == 200):
        return {"verdict": "VULNERABLE", "reason": "Session ID survived login (fixation)"}
    return {"verdict": "PASS", "reason": "Session ID rotated on login"}
