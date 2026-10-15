import enum
import os
import re
import tempfile
from pathlib import Path
from urllib.parse import urlparse


class ProbeOutcome(str, enum.Enum):
    HANDLER_REACHED = "handler_reached"
    METHOD_REJECTED = "method_rejected"
    NOT_FOUND = "not_found"
    SERVER_ERROR = "server_error"
    UNREACHABLE = "unreachable"


_NOT_FOUND = frozenset((404, 410))
_METHOD_REJECTED = frozenset((405, 501))


def classify_probe_outcome(status, error=None):
    if error:
        return ProbeOutcome.UNREACHABLE
    if status is None:
        return ProbeOutcome.UNREACHABLE
    if status in _NOT_FOUND:
        return ProbeOutcome.NOT_FOUND
    if status in _METHOD_REJECTED:
        return ProbeOutcome.METHOD_REJECTED
    if 500 <= status < 600:
        return ProbeOutcome.SERVER_ERROR
    if 200 <= status < 400:
        return ProbeOutcome.HANDLER_REACHED
    if 400 <= status < 500:
        return ProbeOutcome.HANDLER_REACHED
    return ProbeOutcome.UNREACHABLE


def any_handler_reached(attempts, status_key="status", error_key="error"):
    for a in attempts or []:
        outcome = classify_probe_outcome(a.get(status_key), a.get(error_key))
        if outcome is ProbeOutcome.HANDLER_REACHED:
            return True
    return False


def unreached_reason(attempts, status_key="status"):
    if not attempts:
        return "no probes were sent"
    statuses = sorted({a.get(status_key) for a in attempts
                       if a.get(status_key) is not None})
    if not statuses:
        return f"all {len(attempts)} probes failed to reach the target"
    return (f"all {len(attempts)} probes returned {statuses} — "
            f"endpoint not found or method not accepted")


_UNREACHABLE_STRINGS = (
    "404", "410", "not found", "no such", "connection refused",
    "name or service not known", "invalidstatus", "unexpected status",
)


def error_looks_like_unreachable(err):
    if not err:
        return False
    low = str(err).lower()
    return any(sig in low for sig in _UNREACHABLE_STRINGS)


def _hostname_of(value):
    if not value:
        return ""
    v = str(value).strip().lower()
    if not v:
        return ""
    if "://" in v:
        try:
            return urlparse(v).hostname or ""
        except Exception:
            return ""
    v = v.split("/", 1)[0]
    v = v.split("?", 1)[0]
    v = v.split("#", 1)[0]
    v = v.split(":", 1)[0]
    return v.strip(".")


def matches_hostname(pattern, value):
    if not pattern or not value:
        return False
    pat = _hostname_of(pattern)
    val = _hostname_of(value)
    if not pat or not val:
        return False
    if pat == val:
        return True
    return val.endswith("." + pat)


def is_reflection(body, sent_payload):
    if not body or not sent_payload:
        return False
    return sent_payload in body


_ERROR_KEYS = frozenset(("error", "errors", "err", "failure", "fail"))
_FALSEY_KEYS = frozenset(("success", "ok"))
_ERROR_STATUS_STRINGS = frozenset(("error", "failed", "failure"))


def response_is_success(body, max_depth=6):
    if not body:
        return False
    import json as _json
    try:
        data = _json.loads(body)
    except Exception:
        return False
    return _walk_success(data, 0, max_depth)


def _walk_success(node, depth, max_depth):
    if depth > max_depth:
        return True
    if isinstance(node, dict):
        for k, v in node.items():
            kl = str(k).lower()
            if kl in _ERROR_KEYS and v:
                return False
            if kl in _FALSEY_KEYS and v is False:
                return False
            if kl == "status":
                if isinstance(v, str) and v.lower() in _ERROR_STATUS_STRINGS:
                    return False
                if isinstance(v, int) and not isinstance(v, bool) and v >= 400:
                    return False
            if not _walk_success(v, depth + 1, max_depth):
                return False
        return True
    if isinstance(node, list):
        for item in node:
            if not _walk_success(item, depth + 1, max_depth):
                return False
        return True
    return True


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
    return strict_yaml_load(Path(path).read_text(encoding="utf-8"))


def summarize_failures(items, error_key="error", limit=3):
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
