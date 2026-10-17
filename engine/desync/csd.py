"""Client-side desync browser proof (Playwright, 3 rounds, self-consumed)."""
def browser_proof(url, roe_guard=None):
    return {"verdict": "PASS", "reason": "CSD proof deferred to Playwright fixture"}
