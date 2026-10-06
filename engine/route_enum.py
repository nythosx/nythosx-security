import time
from pathlib import Path
from urllib.parse import urljoin
from .http_client import HttpClient

ROOT = Path(__file__).parent.parent.absolute()
WORDLIST_DIR = ROOT / "wordlists"

INTERESTING_STATUS = {200, 201, 204, 301, 302, 303, 307, 308, 401, 403, 405, 500, 501}


def _load_wordlist(name):
    p = WORDLIST_DIR / f"{name}.txt"
    if not p.exists():
        return []
    return [l.strip() for l in p.read_text(encoding="utf-8").splitlines()
            if l.strip() and not l.startswith("#")]


def enumerate_routes(base_url, wordlist="common_paths", headers=None, cookies=None,
                     delay_ms=50, max_paths=500):
    paths = _load_wordlist(wordlist)[:max_paths]
    client = HttpClient(default_headers=headers or {}, cookies=cookies or {})
    results = []
    try:
        for i, path in enumerate(paths):
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            r = client.request("GET", url)
            status = r.get("status")
            entry = {
                "path": path,
                "url": url,
                "status": status,
                "time_ms": r.get("time_ms"),
                "content_length": len(r.get("body") or ""),
                "content_type": (r.get("headers") or {}).get("Content-Type", ""),
                "location": (r.get("headers") or {}).get("Location", ""),
                "error": r.get("error"),
                "interesting": status in INTERESTING_STATUS if status else False,
            }
            results.append(entry)
            if delay_ms:
                time.sleep(delay_ms / 1000.0)
    finally:
        client.close()
    return results


def summarize(results):
    counts = {}
    for r in results:
        s = r.get("status")
        key = str(s) if s is not None else "ERR"
        counts[key] = counts.get(key, 0) + 1
    return counts
