import os
import tempfile
from pathlib import Path


def safe_name(s, maxlen=80):
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in s)[:maxlen]


def atomic_write_text(path, text, encoding="utf-8"):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding=encoding) as f:
            f.write(text)
        os.replace(tmp, path)
    except Exception:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def atomic_write_json(path, obj, indent=2):
    import json
    atomic_write_text(path, json.dumps(obj, indent=indent, default=str))


def strict_yaml_load(text):
    """yaml.safe_load with duplicate-key detection.

    Raises yaml.constructor.ConstructorError on duplicate mapping keys.
    """
    import yaml

    class _StrictLoader(yaml.SafeLoader):
        pass

    def _no_dupes(loader, node, deep=False):
        mapping = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key in mapping:
                raise yaml.constructor.ConstructorError(
                    None, None,
                    f"found duplicate key: {key!r}",
                    key_node.start_mark,
                )
            value = loader.construct_object(value_node, deep=deep)
            mapping[key] = value
        return mapping

    _StrictLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _no_dupes,
    )
    return yaml.load(text, Loader=_StrictLoader)


def strict_yaml_load_file(path):
    from pathlib import Path as _P
    return strict_yaml_load(_P(path).read_text(encoding="utf-8"))


def summarize_failures(items, error_key="error", limit=3):
    """Collapse a list of failed request attempts into a short, generic
    "why" string, e.g. "2x ROE_BLOCK: METHOD NOT ALLOWED: POST; 1x timeout".

    Every pattern/oracle that reports "all requests failed" was discarding
    the real per-attempt error (ROE block, timeout, connect error, rate
    limit) that the HTTP layer already captured, leaving no way to tell a
    scope restriction apart from a dead target or a bug — on ANY target,
    not a specific one. This makes that reason visible without hardcoding
    any target- or pattern-specific text.
    """
    from collections import Counter

    errors = [str(i.get(error_key)) for i in items if i.get(error_key)]
    if not errors:
        return None
    counts = Counter(errors)
    parts = [f"{n}x {msg}" for msg, n in counts.most_common(limit)]
    extra = len(counts) - limit
    if extra > 0:
        parts.append(f"+{extra} more")
    return "; ".join(parts)

def mask_value(s, keep=1, cipher="rot13"):
    if s is None:
        return None
    text = str(s)
    if len(text) <= keep:
        return text
    head = text[:keep]
    tail = text[keep:]
    if cipher == "none":
        return text
    if cipher == "mask":
        return head + ("*" * len(tail))
    out = []
    for c in tail:
        if "a" <= c <= "z":
            out.append(chr((ord(c) - ord("a") + 13) % 26 + ord("a")))
        elif "A" <= c <= "Z":
            out.append(chr((ord(c) - ord("A") + 13) % 26 + ord("A")))
        elif "0" <= c <= "9":
            out.append(chr((ord(c) - ord("0") + 5) % 10 + ord("0")))
        else:
            out.append(c)
    return head + "".join(out)


SENSITIVE_HINTS = (
    "account", "balance", "amount", "transaction", "card", "pan",
    "ssn", "email", "phone", "name", "address", "iban", "sort",
    "cvv", "expiry", "dob", "kyc", "credit", "loan", "token",
    "secret", "id", "username", "customer", "user",
)


def mask_row(row, keep=1, cipher="rot13", hints=None, mask_emails=True):
    if not isinstance(row, dict):
        return row
    hints = hints or SENSITIVE_HINTS
    out = {}
    for k, v in row.items():
        kl = str(k).lower()
        if isinstance(v, bool):
            out[k] = v
            continue
        if mask_emails and isinstance(v, str) and "@" in v and "." in v \
                and " " not in v and len(v) < 254:
            local, _, dom = v.partition("@")
            head = local[:1] if local else ""
            out[k] = head + "***@" + dom
            continue
        if isinstance(v, (list, dict)):
            out[k] = v
            continue
        if any(h in kl for h in hints) and isinstance(v, (str, int, float)):
            out[k] = mask_value(v, keep=keep, cipher=cipher)
        else:
            out[k] = v
    return out


def extract_json_path(data, path):
    cur = data
    for part in str(path).split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list) and part.isdigit():
            idx = int(part)
            cur = cur[idx] if idx < len(cur) else None
        else:
            return None
        if cur is None:
            return None
    return cur


def unwrap_rows(parsed, envelope_keys=None):
    keys = envelope_keys or (
        "data", "items", "results", "records", "content",
        "accounts", "transactions", "customers", "users",
    )
    if isinstance(parsed, list):
        return [d for d in parsed if isinstance(d, dict)]
    if isinstance(parsed, dict):
        for k in keys:
            v = parsed.get(k)
            if isinstance(v, list):
                return [d for d in v if isinstance(d, dict)]
        return [parsed]
    return []

def join_smart(base_url, path):
    from urllib.parse import urlparse
    if not path:
        return base_url or ""
    if not base_url:
        return path
    if path.startswith(("http://", "https://")):
        return path
    base = base_url.rstrip("/")
    p = path if path.startswith("/") else "/" + path
    base_path = (urlparse(base).path or "").rstrip("/")
    if base_path and (p == base_path or p.startswith(base_path + "/")):
        return base + p[len(base_path):]
    return base + p
