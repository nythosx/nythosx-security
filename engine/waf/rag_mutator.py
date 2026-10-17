"""LLM-backed WAF mutation fallback.

Called only when static encoders in waf/encoder.py have exhausted and the
target is still returning 403. Proposes 5 structurally novel variants.
"""
from __future__ import annotations

import json as _json
import re as _re


_MAX_VARIANTS = 5


def llm_mutate(client, payload, waf_vendor, block_response):
    if client is None or not payload:
        return []
    prompt = (
        f"WAF '{waf_vendor or 'unknown'}' blocked this payload. "
        f"Response snippet: {str(block_response)[:500]!r}. "
        f"Generate up to {_MAX_VARIANTS} structurally novel bypass variants "
        "(encoding, token splitting, Unicode confusables, case flipping, "
        "comment injection, null-byte insertion). "
        "Return ONLY a JSON array of strings."
    )
    try:
        raw = client(prompt)
    except Exception:
        return []
    txt = (raw or "").strip()
    m = _re.search(r"\[.*\]", txt, _re.S)
    if m:
        txt = m.group(0)
    try:
        data = _json.loads(txt)
    except Exception:
        return []
    if not isinstance(data, list):
        return []
    out = []
    seen = set()
    for item in data:
        if not isinstance(item, str):
            continue
        if not item or item in seen or item == payload:
            continue
        if len(item) > 2000:
            continue
        seen.add(item)
        out.append(item)
        if len(out) >= _MAX_VARIANTS:
            break
    return out
