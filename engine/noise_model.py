"""Per-endpoint noise model.
Learns what varies run-to-run on a specific endpoint (CSRF tokens, timestamps,
trace IDs) and strips that noise before structural diffing.
"""
import re
import json

NOISE_KEYS = {
    "csrf_token", "_token", "csrf", "token", "timestamp", "created_at",
    "updated_at", "trace_id", "request_id", "nonce", "cache_key", "etag",
    "server_time", "fetched_at", "retrieved_at", "date", "time",
    "csrfmiddlewaretoken", "authenticity_token", "_csrf", "_csrf_token",
    "csrf-token", "xsrf-token", "x-xsrf-token", "x-csrf-token",
    "trace", "span", "span_id", "parent_span_id", "traceparent",
    "tracestate", "correlation_id", "x-correlation-id",
    "x-request-id", "x-trace-id", "request-id", "x-amzn-trace-id",
}

def strip_noise(body_text):
    if not body_text:
        return ""
    try:
        data = json.loads(body_text)
        stripped = _strip_json_noise(data)
        return json.dumps(stripped, sort_keys=True)
    except Exception:
        pass
    
    stripped = body_text
    stripped = re.sub(r'\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b', '"<TS>"', stripped)
    stripped = re.sub(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', '"<UUID>"', stripped, flags=re.I)
    return stripped

def _strip_json_noise(obj):
    if isinstance(obj, dict):
        return {k: _strip_json_noise(v) for k, v in obj.items() 
                if not _is_noise_key(k)}
    if isinstance(obj, list):
        return [_strip_json_noise(i) for i in obj]
    if isinstance(obj, str):
        if re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', obj):
            return "<TS>"
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', obj, re.I):
            return "<UUID>"
    return obj

def _is_noise_key(k):
    return str(k).lower() in NOISE_KEYS
