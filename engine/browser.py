import threading
import time
from pathlib import Path
from datetime import datetime, timezone

from .roe_guard import ROEGuard, ROEViolation
from .config import load_engine
from .util import safe_name

ROOT = Path(__file__).parent.parent.absolute()
BROWSER_EVIDENCE_DIR = ROOT / "evidence" / "browser"


class BrowserUnavailable(RuntimeError):
    pass


_CONTEXTS = {}
_CONTEXTS_LOCK = threading.Lock()


def _context_key(url, headers, cookies, verify_tls):
    from urllib.parse import urlparse as _urlparse
    import hashlib as _hashlib
    import json as _json
    parsed = _urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    fp = _hashlib.sha256(
        _json.dumps(
            {"headers": headers or {}, "cookies": cookies or {},
             "verify_tls": bool(verify_tls)},
            sort_keys=True, default=str,
        ).encode()
    ).hexdigest()[:16]
    return (origin, fp)


def get_context(url, headers=None, cookies=None, verify_tls=True):
    key = _context_key(url, headers, cookies, verify_tls)
    with _CONTEXTS_LOCK:
        entry = _CONTEXTS.get(key)
        if entry is not None:
            return entry
        sync_playwright = _import_playwright()
        pw = sync_playwright().start()
        try:
            browser = pw.chromium.launch(headless=True)
            ctx = browser.new_context(
                ignore_https_errors=not verify_tls,
                extra_http_headers=headers or {},
            )
            if cookies:
                _apply_cookies(ctx, url, cookies)
        except Exception:
            try:
                pw.stop()
            except Exception:
                pass
            raise
        _CONTEXTS[key] = (pw, browser, ctx)
        return _CONTEXTS[key]


def close_all_contexts():
    with _CONTEXTS_LOCK:
        for _key, (pw, browser, ctx) in list(_CONTEXTS.items()):
            for closer in (ctx.close, browser.close, pw.stop):
                try:
                    closer()
                except Exception:
                    pass
        _CONTEXTS.clear()


def _import_playwright():
    try:
        from playwright.sync_api import sync_playwright
        return sync_playwright
    except ImportError as e:
        raise BrowserUnavailable(
            "playwright not installed. Run: pip install -r requirements.txt "
            "&& python -m playwright install chromium"
        ) from e


def _get_shared_browser(sync_playwright):
    import threading
    if not hasattr(_import_playwright, "_shared_lock"):
        _import_playwright._shared_lock = threading.Lock()
        _import_playwright._shared_pw = None
        _import_playwright._shared_browser = None
    with _import_playwright._shared_lock:
        if _import_playwright._shared_browser is None:
            _import_playwright._shared_pw = sync_playwright().start()
            _import_playwright._shared_browser = (
                _import_playwright._shared_pw.chromium.launch(headless=True)
            )
    return _import_playwright._shared_browser


def capture(url, headers=None, cookies=None, timeout_ms=15000,
            screenshot=True, wait_until="load", roe_guard=None,
            engine_cfg=None):
    engine_cfg = engine_cfg if engine_cfg is not None else load_engine()
    guard = roe_guard or ROEGuard(engine_cfg=engine_cfg)
    try:
        guard.check_url(url, "GET")
    except ROEViolation as e:
        return {"url": url, "error": f"ROE_BLOCK: {e}", "console": [],
                "page_errors": [], "failed_requests": [], "screenshot": None,
                "status": None, "title": None, "final_url": None,
                "duration_ms": 0.0}

    sync_playwright = _import_playwright()
    result = {
        "url": url, "error": None, "console": [], "page_errors": [],
        "failed_requests": [], "screenshot": None, "status": None,
        "title": None, "final_url": None, "duration_ms": 0.0,
    }
    t0 = time.perf_counter()
    page = None
    try:
        _verify = bool(engine_cfg.get("http", {}).get("verify_tls", True))
        _pw, _browser, context = get_context(
            url, headers=headers, cookies=cookies, verify_tls=_verify,
        )
        page = context.new_page()
        page.on("console", lambda m: result["console"].append(
            {"type": m.type, "text": m.text[:500]}))
        page.on("pageerror", lambda e: result["page_errors"].append(
            str(e)[:500]))
        page.on("requestfailed", lambda r: result["failed_requests"].append(
            {"url": r.url[:300], "failure": (r.failure or "")[:200]}))
        response = page.goto(url, timeout=timeout_ms, wait_until=wait_until)
        if response is not None:
            result["status"] = response.status
        result["title"] = page.title()
        result["final_url"] = page.url
        if screenshot:
            BROWSER_EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
            shot = BROWSER_EVIDENCE_DIR / f"{stamp}_{safe_name(url)}.png"
            page.screenshot(path=str(shot), full_page=True)
            result["screenshot"] = str(shot)
    except BrowserUnavailable:
        raise
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
    finally:
        if page is not None:
            try:
                page.close()
            except Exception:
                pass
    result["duration_ms"] = round((time.perf_counter() - t0) * 1000.0, 3)
    return result


def _apply_cookies(context, url, cookies):
    from urllib.parse import urlparse
    host = urlparse(url).hostname or ""
    jar = []
    for k, v in cookies.items():
        jar.append({"name": k, "value": str(v), "domain": host, "path": "/"})
    try:
        context.add_cookies(jar)
    except Exception:
        pass


def console_errors(result):
    return [m for m in result.get("console", [])
            if m.get("type") in ("error", "warning")]
