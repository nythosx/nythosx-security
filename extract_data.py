import argparse
import json
import re
import sys
from datetime import datetime, timezone

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
    "/api/v1/beneficiaries",
    "/api/v1/payments",
]

UNAUTH_PATHS = [
    "/api/v1/accounts",
    "/api/v1/accounts/1",
    "/api/v1/transactions",
    "/api/v1/customers",
    "/api/v1/balance",
    "/check_balance/1",
    "/api/v1/statements",
    "/api/v1/cards",
]

SENSITIVE_HINTS = (
    "account", "balance", "amount", "transaction", "card", "pan",
    "ssn", "email", "phone", "name", "address", "iban", "sort",
    "cvv", "expiry", "dob", "kyc", "credit", "loan", "token",
    "secret", "id", "username", "customer", "user",
)

BOGUS_ID = "987654321987654321"

WRITE_PROBE_BODY = {"__nythosx_authz_probe__": "non-destructive-test"}

TOKEN_PATHS = [
    "token",
    "access_token",
    "accessToken",
    "data.token",
    "data.access_token",
    "jwt",
]


def _rotate(s):
    out = []
    for c in s:
        if "a" <= c <= "z":
            out.append(chr((ord(c) - ord("a") + 13) % 26 + ord("a")))
        elif "A" <= c <= "Z":
            out.append(chr((ord(c) - ord("A") + 13) % 26 + ord("A")))
        elif "0" <= c <= "9":
            out.append(chr((ord(c) - ord("0") + 5) % 10 + ord("0")))
        else:
            out.append(c)
    return "".join(out)


def _mask(value, keep=1):
    if value is None:
        return None
    s = str(value)
    if len(s) <= keep:
        return s
    return s[:keep] + _rotate(s[keep:])


def _mask_row(row, keep=1):
    out = {}
    for k, v in row.items():
        kl = str(k).lower()
        if any(h in kl for h in SENSITIVE_HINTS) and isinstance(v, (str, int, float)) \
                and not isinstance(v, bool):
            out[k] = _mask(v, keep=keep)
        else:
            out[k] = v
    return out


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


def _unwrap(data):
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    if isinstance(data, dict):
        for k in ("data", "items", "results", "records", "content",
                  "accounts", "transactions", "customers", "users"):
            v = data.get(k)
            if isinstance(v, list):
                return [d for d in v if isinstance(d, dict)]
        return [data]
    return []


def _resolve_placeholders(path, sample="1"):
    path = re.sub(r"\{[^}]+\}", sample, path)
    path = re.sub(r":[A-Za-z_][A-Za-z0-9_]*", sample, path)
    return path


def _discover_paths(target, sample="1"):
    try:
        from engine.recon.js_endpoints import discover
    except Exception as e:
        print("DISCOVERY unavailable: " + type(e).__name__ + ": " + str(e))
        return []
    print("=" * 64)
    print("ENDPOINT DISCOVERY " + target)
    print("=" * 64)
    res = discover(target)
    for b in res.get("bundles", []):
        print("  bundle " + b)
    s = res.get("soft_404") or {}
    print("  soft_404 baseline status=" + str(s.get("status"))
          + " len=" + str(s.get("len")))
    out = []
    seen = set()
    for p in res.get("paths", []):
        if not p.startswith("/"):
            continue
        if p.lower().endswith((".js", ".mjs", ".css", ".jpg", ".png", ".svg")):
            continue
        rp = _resolve_placeholders(p, sample)
        if rp not in seen:
            seen.add(rp)
            out.append(rp)
    for e in res.get("errors", []):
        print("  error " + e)
    print("  discovered " + str(len(out)) + " candidate path(s)")
    return out


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


def _extract(client, target, path, headers, max_rows, keep):
    url = target.rstrip("/") + path
    try:
        r = client.get(url, headers=headers)
    except Exception as e:
        print("  " + path.ljust(36) + " ERROR " + type(e).__name__)
        return None
    ct = r.headers.get("content-type", "")
    if r.status_code != 200 or "json" not in ct:
        print("  " + path.ljust(36) + " HTTP " + str(r.status_code).ljust(4) + " " + ct[:28])
        return None
    try:
        parsed = r.json()
    except Exception:
        return None
    rows = _unwrap(parsed)
    if not rows:
        print("  " + path.ljust(36) + " HTTP 200  no rows")
        return None
    masked = [_mask_row(r, keep=keep) for r in rows[:max_rows]]
    print("  " + path.ljust(36) + " HTTP 200  ** " + str(len(rows)) + " ROWS, "
          + str(len(masked)) + " extracted **")
    return {
        "endpoint": path,
        "url": url,
        "method": "GET",
        "status": 200,
        "total_rows": len(rows),
        "extracted": len(masked),
        "rows": masked,
        "raw_rows": rows[:max_rows],
    }


def _classify_write(path, sample_keys=None, reflected=None):
    try:
        from engine.triage import classify_write
        return classify_write(path, sample_keys=sample_keys, reflected=reflected)
    except Exception:
        return {"category": "unknown", "severity": "MEDIUM",
                "recommendation": "manual review", "accepts_unknown_fields": True,
                "confidence": "low", "basis": "none", "reflected": reflected}


def _keys_and_reflection(client, target, base, marker):
    url = target.rstrip("/") + base
    try:
        r = client.get(url, headers={"Accept": "application/json"})
    except Exception:
        return None, None
    ct = r.headers.get("content-type", "")
    if r.status_code != 200 or "json" not in ct:
        return None, None
    reflected = marker in (r.text or "")
    try:
        rows = _unwrap(r.json())
    except Exception:
        return None, reflected
    keys = set()
    for row in rows[:5]:
        if isinstance(row, dict):
            keys.update(row.keys())
    return sorted(keys), reflected


def _interpret_write(status):
    if status in (401, 403):
        return "PROTECTED", "auth enforced"
    if status == 405:
        return "N/A", "method not allowed"
    if status in (200, 201, 204):
        return "WRITABLE", "unauth write accepted (confirm if endpoint is meant to be public)"
    if status in (400, 422):
        return "INCONCLUSIVE", "handler reached but validation/parse may run before authz"
    if status == 404:
        return "INCONCLUSIVE", "resource lookup may precede authz; not proof of missing auth"
    return "UNKNOWN", "status " + str(status)


def _write_base(path):
    return re.sub(r"/\d+(?=/|$)", "", path).rstrip("/")


def _write_probe(client, target, path, headers):
    base = _write_base(path)
    item_url = target.rstrip("/") + base + "/" + BOGUS_ID
    coll_url = target.rstrip("/") + base
    attempts = [
        ("POST", coll_url),
        ("PUT", item_url),
        ("PATCH", item_url),
        ("DELETE", item_url),
    ]
    results = []
    for method, url in attempts:
        try:
            kwargs = {"headers": headers}
            if method in ("POST", "PUT", "PATCH"):
                kwargs["json"] = WRITE_PROBE_BODY
            r = client.request(method, url, **kwargs)
        except Exception as e:
            print("  " + (method + " " + base).ljust(44) + " ERROR " + type(e).__name__)
            continue
        verdict, note = _interpret_write(r.status_code)
        flag = "**" if verdict == "WRITABLE" else "  "
        print("  " + flag + " " + (method + " " + base).ljust(42)
              + " HTTP " + str(r.status_code).ljust(4) + " " + verdict + " - " + note)
        results.append({
            "method": method,
            "url": url,
            "status": r.status_code,
            "verdict": verdict,
            "note": note,
        })
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--user")
    ap.add_argument("--password", dest="pw")
    ap.add_argument("--login-path", default="/api/v1/auth/login")
    ap.add_argument("--unauth", action="store_true")
    ap.add_argument("--rows", type=int, default=5)
    ap.add_argument("--keep", type=int, default=1)
    ap.add_argument("--out", default="extracted.json")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--discover", action="store_true")
    ap.add_argument("--sample-id", default="1")
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    auth_paths = AUTH_PATHS
    unauth_paths = UNAUTH_PATHS
    if args.discover:
        discovered = _discover_paths(args.target, sample=args.sample_id)
        if discovered:
            auth_paths = discovered
            unauth_paths = discovered
        print("")

    client = httpx.Client(
        timeout=args.timeout,
        verify=False,
        follow_redirects=False,
    )

    report = {
        "target": args.target,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "authenticated": [],
        "unauthenticated": [],
        "write_probes": [],
    }

    if not args.unauth and args.user and args.pw:
        token = _login(client, args.target, args.user, args.pw, args.login_path)
        print("")
        print("=" * 64)
        print("AUTHENTICATED EXTRACTION")
        print("=" * 64)
        headers = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        for path in auth_paths:
            row = _extract(client, args.target, path, headers, args.rows, args.keep)
            if row:
                report["authenticated"].append(row)

    print("")
    print("=" * 64)
    print("UNAUTHENTICATED EXTRACTION")
    print("=" * 64)
    headers = {"Accept": "application/json"}
    for path in unauth_paths:
        row = _extract(client, args.target, path, headers, args.rows, args.keep)
        if row:
            report["unauthenticated"].append(row)

    if args.write:
        print("")
        print("=" * 64)
        print("WRITE / AUTHZ PROBE (non-destructive: bogus ids + invalid body)")
        print("=" * 64)
        write_headers = {"Accept": "application/json", "Content-Type": "application/json"}
        probed = set()
        for path in unauth_paths:
            base = _write_base(path)
            if base in probed:
                continue
            probed.add(base)
            results = _write_probe(client, args.target, path, write_headers)
            if results:
                entry = {"endpoint": base, "attempts": results}
                if any(a["verdict"] == "WRITABLE" for a in results):
                    keys, reflected = _keys_and_reflection(
                        client, args.target, base, "__nythosx_authz_probe__")
                    entry["classification"] = _classify_write(
                        base, sample_keys=keys, reflected=reflected)
                report["write_probes"].append(entry)

    client.close()

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)

    auth_rows = sum(len(e["rows"]) for e in report["authenticated"])
    unauth_rows = sum(len(e["rows"]) for e in report["unauthenticated"])
    print("")
    print("=" * 64)
    print("AUTH rows extracted:   " + str(auth_rows)
          + " across " + str(len(report["authenticated"])) + " endpoint(s)")
    print("UNAUTH rows extracted: " + str(unauth_rows)
          + " across " + str(len(report["unauthenticated"])) + " endpoint(s)")
    if args.write:
        writable = [p for p in report["write_probes"] if "classification" in p]
        inconclusive = sorted({p["endpoint"] for p in report["write_probes"]
                               for a in p["attempts"] if a["verdict"] == "INCONCLUSIVE"})
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        writable.sort(key=lambda p: order.get(p["classification"]["severity"], 9))
        real = [p for p in writable
                if p["classification"]["severity"] in ("CRITICAL", "HIGH", "MEDIUM")]
        bydesign = [p for p in writable
                    if p["classification"]["severity"] == "LOW"]
        print("WRITE probe: " + str(len(real)) + " real finding(s), "
              + str(len(bydesign)) + " public-by-design, "
              + str(len(inconclusive)) + " inconclusive")
        for p in writable:
            c = p["classification"]
            tag = "FINDING" if c["severity"] in ("CRITICAL", "HIGH", "MEDIUM") else "by-design"
            refl = c.get("reflected")
            rtag = " reflected" if refl is True else ""
            print("  [" + c["severity"].ljust(8) + "] " + tag.ljust(9)
                  + " " + c["category"].ljust(10)
                  + " conf=" + str(c.get("confidence", "?")).ljust(6)
                  + " " + p["endpoint"] + rtag)
    print("Saved: " + args.out)
    print("=" * 64)
    return 0


if __name__ == "__main__":
    sys.exit(main())
