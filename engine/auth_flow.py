import re
import base64
import json
from .http_client import HttpClient


def _extract_json_path(data, path):
    cur = data
    for part in path.split("."):
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


def _try_parse_json(text):
    try:
        return json.loads(text)
    except Exception:
        return None


def _decode_jwt_payload(token):
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload_b64 = parts[1]
        pad = "=" * (-len(payload_b64) % 4)
        decoded = base64.urlsafe_b64decode(payload_b64 + pad)
        return json.loads(decoded)
    except Exception:
        return None


def _detect_mfa_response(parsed):
    if not isinstance(parsed, dict):
        return None
    for flag in ("mfa_required", "mfaRequired", "requires_mfa",
                  "requiresMfa", "totp_required", "totpRequired",
                  "otp_required", "otpRequired", "two_factor_required",
                  "twoFactorRequired", "needs_mfa", "needsMfa",
                  "challenge_required", "challengeRequired"):
        v = parsed.get(flag)
        if v is True or (isinstance(v, str)
                         and v.lower() in ("true", "required")):
            return _extract_mfa_context(parsed)
    for key in ("data", "result"):
        inner = parsed.get(key)
        if isinstance(inner, dict):
            found = _detect_mfa_response(inner)
            if found:
                return found
    return None


def _extract_mfa_context(parsed):
    ctx = {}
    for k in ("challenge_token", "challengeToken", "mfa_token",
              "mfaToken", "session_id", "sessionId", "temp_token",
              "tempToken", "challenge", "verification_id",
              "verificationId"):
        v = parsed.get(k)
        if isinstance(v, str) and v:
            ctx[k] = v[:200]
    for key in ("data", "result"):
        inner = parsed.get(key)
        if isinstance(inner, dict):
            for k in ("challenge_token", "challengeToken", "mfa_token",
                      "mfaToken", "session_id", "sessionId",
                      "temp_token", "tempToken"):
                v = inner.get(k)
                if isinstance(v, str) and v:
                    ctx[k] = v[:200]
    return ctx


def perform_login(login_url, username, password, login_type="json",
                  username_field="email", password_field="password",
                  extra_fields=None, headers=None, token_path=None,
                  token_header="Authorization", token_prefix="Bearer ",
                  verify=True):
    client = HttpClient(default_headers=headers or {}, verify=verify)
    payload = {username_field: username, password_field: password}
    if extra_fields:
        payload.update(extra_fields)

    if login_type == "form":
        r = client.request("POST", login_url, data=payload)
    else:
        r = client.request("POST", login_url, json=payload)

    result = {
        "login_url": login_url,
        "login_type": login_type,
        "status": r.get("status"),
        "error": r.get("error"),
        "token_path": token_path,
        "token_header": token_header,
        "token_prefix": token_prefix,
        "auth_headers": {},
        "cookies": {},
        "raw_body_preview": (r.get("body") or "")[:500],
        "jwt_payload": None,
    }

    cookies = {}
    for k, v in (r.get("headers") or {}).items():
        if k.lower() == "set-cookie":
            for chunk in v.split(","):
                if "=" in chunk:
                    name, _, rest = chunk.partition("=")
                    val = rest.split(";")[0].strip()
                    cookies[name.strip()] = val

    result["cookies"] = cookies

    body = r.get("body") or ""
    parsed = _try_parse_json(body)

    if parsed is not None:
        mfa_info = _detect_mfa_response(parsed)
        if mfa_info:
            result["mfa_required"] = True
            result["mfa_challenge"] = mfa_info
            client.close()
            return result

    token = None
    if parsed is not None and token_path:
        token = _extract_json_path(parsed, token_path)

    if token:
        result["auth_headers"] = {token_header: f"{token_prefix}{token}"}
        result["token"] = token
        jwt = _decode_jwt_payload(token)
        if jwt:
            result["jwt_payload"] = jwt

    client.close()
    return result


def build_headers_from_session(session):
    if not session:
        return {}
    headers = dict(session.get("auth_headers") or {})
    return headers


def build_cookies_from_session(session):
    if not session:
        return {}
    return dict(session.get("cookies") or {})
