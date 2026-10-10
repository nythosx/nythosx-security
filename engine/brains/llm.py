import json
import os

from ..state import Hypothesis, ScanState, TriageDecision
from .rule_based import RuleBasedBrain

_API_KEY_ENVS = ("SECCHECKER_LLM_API_KEY", "LLM_API_KEY", "ANTHROPIC_API_KEY",
                 "OPENAI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY",
                 "GROQ_API_KEY", "OPENROUTER_API_KEY")


def _read_api_key(explicit=None, env_name=None):
    if explicit:
        return explicit
    if env_name and os.environ.get(env_name):
        return os.environ[env_name]
    for name in _API_KEY_ENVS:
        if os.environ.get(name):
            return os.environ[name]
    return None


def make_llm_client(provider="openai", model="gpt-4o-mini", base_url=None,
                    api_key=None, env_name=None, timeout=30):
    """Return a callable client(prompt:str) -> str for any AI API.

    provider: openai (any OpenAI-compatible /chat/completions), anthropic, or gemini.
    The API key is read from `api_key`, then `env_name`, then common env vars.
    The raw .env file is never read here; the key must be in the environment.
    """
    import httpx

    key = _read_api_key(api_key, env_name)
    provider = (provider or "openai").lower()

    def _openai(prompt):
        url = (base_url or "https://api.openai.com/v1").rstrip("/") + "/chat/completions"
        headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
        body = {"model": model, "temperature": 0,
                "messages": [{"role": "user", "content": prompt}]}
        with httpx.Client(timeout=timeout) as c:
            r = c.post(url, headers=headers, json=body)
            r.raise_for_status()
            data = r.json()
        return (data.get("choices") or [{}])[0].get("message", {}).get("content", "")

    def _anthropic(prompt):
        url = (base_url or "https://api.anthropic.com").rstrip("/") + "/v1/messages"
        headers = {"x-api-key": key, "anthropic-version": "2023-06-01",
                   "Content-Type": "application/json"}
        body = {"model": model, "max_tokens": 1024, "temperature": 0,
                "messages": [{"role": "user", "content": prompt}]}
        with httpx.Client(timeout=timeout) as c:
            r = c.post(url, headers=headers, json=body)
            r.raise_for_status()
            data = r.json()
        parts = data.get("content") or []
        return "".join(p.get("text", "") for p in parts if isinstance(p, dict))

    def _gemini(prompt):
        base = (base_url or "https://generativelanguage.googleapis.com").rstrip("/")
        url = f"{base}/v1beta/models/{model}:generateContent"
        headers = {"Content-Type": "application/json", "x-goog-api-key": key}
        body = {"contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"temperature": 0}}
        with httpx.Client(timeout=timeout) as c:
            r = c.post(url, headers=headers, json=body)
            r.raise_for_status()
            data = r.json()
        cands = data.get("candidates") or []
        if not cands:
            return ""
        parts = (cands[0].get("content") or {}).get("parts") or []
        return "".join(p.get("text", "") for p in parts if isinstance(p, dict))

    impl = {"openai": _openai, "anthropic": _anthropic, "gemini": _gemini,
            "google": _gemini}.get(provider, _openai)

    def client(prompt):
        if not key:
            raise RuntimeError("no LLM API key in environment")
        return impl(prompt)

    return client


def make_brain_from_config(cfg=None, max_per_iter=20):
    if cfg is None:
        try:
            from ..config import load_engine
            cfg = (load_engine() or {}).get("brain") or {}
        except Exception:
            cfg = {}
    provider = cfg.get("provider") or "openai"
    if provider in ("rule_based", "rule", "none", ""):
        return RuleBasedBrain(max_per_iter=max_per_iter)
    client = make_llm_client(
        provider=provider,
        model=cfg.get("model") or "gpt-4o-mini",
        base_url=cfg.get("base_url"),
        env_name=cfg.get("api_key_env"),
    )
    return LLMBrain(client=client, model=cfg.get("model") or "gpt-4o-mini",
                    max_per_iter=max_per_iter)


_PROMPT = (
    "You are a security scanning brain. Given the current scan state, propose\n"
    "the next batch of capabilities to run. Respond ONLY with JSON in this\n"
    "shape:\n\n"
    '{{"capabilities": ["cap1", "cap2", "cap3"]}}\n\n'
    "State:\n"
    "- target: {target}\n"
    "- framework: {framework}\n"
    "- endpoints: {endpoints}\n"
    "- findings so far: {findings}\n"
    "- already executed: {executed}\n"
)


def _strip_fences(text):
    text = (text or "").strip()
    if not text.startswith("```"):
        return text
    lines = text.splitlines()
    keep = [l for l in lines if not l.strip().startswith("```")]
    return "\n".join(keep).strip()


class LLMBrain:
    def __init__(self, client=None, model="gpt-4", max_per_iter=20,
                 fallback=None):
        self.client = client
        self.model = model
        self.max_per_iter = max_per_iter
        self.fallback = fallback or RuleBasedBrain()

    def _build_prompt(self, state):
        fw = ((state.framework or {}).get("adapter") or {}).get("id") or ""
        findings = []
        for f in state.findings or []:
            cap = getattr(f, "capability", None)
            v = getattr(f, "verdict", None)
            if hasattr(v, "value"):
                v = v.value
            if cap:
                findings.append(f"{cap}:{v}")
        return _PROMPT.format(
            target=state.target,
            framework=fw,
            endpoints=list(state.discovered_endpoints or [])[:30],
            findings=findings[:30],
            executed=sorted(state.executed_capabilities or [])[:30],
        )

    def _parse(self, text):
        text = _strip_fences(text)
        if not text:
            return []
        try:
            data = json.loads(text)
        except Exception:
            return []
        caps = []
        if isinstance(data, dict):
            for c in data.get("capabilities") or []:
                if isinstance(c, str):
                    caps.append(c)
            for h in data.get("hypotheses") or []:
                if isinstance(h, str):
                    caps.append(h)
                elif isinstance(h, dict) and h.get("capability"):
                    caps.append(h["capability"])
        elif isinstance(data, list):
            for c in data:
                if isinstance(c, str):
                    caps.append(c)
                elif isinstance(c, dict) and c.get("capability"):
                    caps.append(c["capability"])
        return caps

    def propose(self, state):
        if self.client is None:
            return self.fallback.propose(state)
        try:
            prompt = self._build_prompt(state)
            raw = self.client(prompt)
            caps = self._parse(raw)
        except Exception:
            return self.fallback.propose(state)
        if not caps:
            return self.fallback.propose(state)
        caps = [c for c in caps if c not in state.executed_capabilities]
        hypotheses = [
            Hypothesis(
                capability=c,
                target=state.target,
                source="llm",
                priority=20,
                reason="llm proposal",
            )
            for c in sorted(set(caps))
        ]
        return hypotheses[:self.max_per_iter]

    def triage(self, finding):
        return TriageDecision(keep=True)

    def should_stop(self, state):
        return False

    def can_author_payload(self, capability):
        return False

    def propose_payload(self, state, capability):
        return None


__all__ = ["LLMBrain"]
