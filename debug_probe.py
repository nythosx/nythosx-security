import argparse
import json
import sys

import httpx

AUTH_PATHS = [
    "/api/v1/me",
    "/api/v1/profile",
    "/api/v1/user",
    "/api/v1/accounts",
    "/api/v1/accounts/1",
    "/api/v1/accounts/2",
    "/api/v1/transactions",
    "/api/v1/transactions/1",
    "/api/v1/customers",
    "/api/v1/customers/1",
    "/api/v1/balance",
    "/api/v1/cards",
    "/api/v1/statements",
]

UNAUTH_PATHS = [
    "/api/v1/accounts",
    "/api/v1/accounts/1",
    "/api/v1/transactions",
    "/api/v1/customers",
    "/api/v1/balance",
    "/api/v1/statements",
    "/api/v1/cards",
    "/check_balance/1",
]

TOKEN_PATHS = [
    "token",
    "access_token",
    "accessToken",
    "data.token",
    "data.access_token",
    "jwt",
]


def _lookup(obj, path):
    cur = obj
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


def _rows(body):
    try:
        data = json.loads(body)
    except Exception:
        return 0
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        for k in ("data", "items", "results", "records", "content",
                  "accounts", "transactions", "customers", "users"):
            v = data.get(k)
            if isinstance(v, list):
                return len(v)
        return 1
    return 0


def _login(client, target, user, pw, login_path):
    url = target.rstrip("/") + login_path
    print("=" * 64)
    print("LOGIN " + url)
    print("=" * 64)
    try:
        r = client.post(url, json={
            "email": user,
            "username": user,
            "password": pw,
        })
    except Exception as e:
        print("ERROR " + type(e).__name__ + ": " + str(e))
        return None
    print("HTTP " + str(r.status_code))
    print("BODY " + r.text[:400])
    try:
        data = r.json()
    except Exception:
        return None
    for path in TOKEN_PATHS:
        tok = _lookup(data, path)
        if isinstance(tok, str) and len(tok) > 15:
            print("TOKEN path=" + path + " len=" + str(len(tok)))
            return tok
    return None


def _probe(client, target, path, headers):
    url = target.rstrip("/") + path
    try:
        r = client.get(url, headers=headers)
    except Exception as e:
        print("  " + path.ljust(36) + " ERROR " + type(e).__name__)
        return
    ct = r.headers.get("content-type", "")
    rows = _rows(r.text) if "json" in ct else 0
    tail = ""
    if rows:
        tail = "  ** " + str(rows) + " ROWS **"
    print("  " + path.ljust(36) + " HTTP " + str(r.status_code).ljust(4) + " " + ct[:28] + tail)
    if rows:
        print("     " + r.text[:220])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--user")
    ap.add_argument("--password", dest="pw")
    ap.add_argument("--login-path", default="/api/v1/auth/login")
    ap.add_argument("--unauth", action="store_true")
    ap.add_argument("--timeout", type=float, default=15.0)
    args = ap.parse_args()

    client = httpx.Client(
        timeout=args.timeout,
        verify=False,
        follow_redirects=False,
    )

    token = None
    if not args.unauth and args.user and args.pw:
        token = _login(client, args.target, args.user, args.pw, args.login_path)

    if not args.unauth:
        print("")
        print("=" * 64)
        print("AUTHENTICATED REQUESTS")
        print("=" * 64)
        headers = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        for path in AUTH_PATHS:
            _probe(client, args.target, path, headers)

    print("")
    print("=" * 64)
    print("UNAUTHENTICATED REQUESTS")
    print("=" * 64)
    headers = {"Accept": "application/json"}
    for path in UNAUTH_PATHS:
        _probe(client, args.target, path, headers)

    client.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
