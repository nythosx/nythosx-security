from __future__ import annotations

from .chain_engine import register_tool
from .config import load_engine
from . import http as _http


_PATHS = [
    "/.github/workflows/ci.yml",
    "/.github/workflows/main.yml",
    "/.github/workflows/deploy.yml",
    "/.gitlab-ci.yml",
    "/Jenkinsfile",
    "/.travis.yml",
    "/.circleci/config.yml",
    "/.buildkite/pipeline.yml",
    "/azure-pipelines.yml",
    "/bitbucket-pipelines.yml",
]

_MARKERS = ["runs-on", "script:", "stages:", "deploy",
            "secrets.", "AWS_", "GITHUB_TOKEN", "CI_",
            "pipeline", "steps:"]


def _verify_tls():
    try:
        return bool((load_engine() or {}).get("http", {}).get("verify_tls", True))
    except Exception:
        return True


def _tool_ci_cd_probe(orch, args):
    url = (args.get("url") or orch.target).rstrip("/")
    verify = _verify_tls()
    hits = []
    attempts = []
    for path in _PATHS:
        try:
            with _http.Client(timeout=8, verify=verify,
                              follow_redirects=False) as c:
                r = c.get(url + path)
        except Exception as e:
            attempts.append({"path": path, "error": f"{type(e).__name__}: {e}"})
            continue
        attempts.append({"path": path, "status": r.status_code})
        if r.status_code != 200:
            continue
        body = r.text or ""
        matched = [m for m in _MARKERS if m in body]
        if matched:
            hits.append({"path": path, "matched_markers": matched,
                         "preview": body[:300]})
    if hits:
        return {"verdict": "VULNERABLE",
                "reason": f"{len(hits)} CI/CD config file(s) exposed",
                "evidence": {"hits": hits, "attempts": attempts}}
    return {"verdict": "PASS",
            "reason": f"no CI/CD config exposure across {len(_PATHS)} paths",
            "evidence": {"attempts": attempts}}


register_tool("ci_cd_probe", _tool_ci_cd_probe)
