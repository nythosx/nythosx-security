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


def _import_playwright():
    try:
        from playwright.sync_api import sync_playwright
        return sync_playwright
    except ImportError as e:
        raise BrowserUnavailable(
            "playwright not installed. Run: pip install -r requirements.txt "
            "&& python -m playwright install chromium"
        ) from e


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
                "status": None, "title": None, "final_url": None}

    sync_playwright = _import_playwright()
    result = {
        "url": url, "error": None, "console": [], "page_errors": [],
        "failed_requests": [], "screenshot": None, "status": None,
        "title": None, "final_url": None, "duration_ms": 0.0,
    }
    t0 = time.perf_counter()
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            try:
                context = browser.new_context(
                    ignore_https_errors=not engine_cfg.get("http", {}).get("verify_tls", True),
                    extra_http_headers=headers or {},
                )
                if cookies:
                    _apply_cookies(context, url, cookies)
                page = context.new_page()
                page.on("console", lambda m: result["console"].append(
                    {"type": m.type, "text": m.text[:500]}))
                page.on("pageerror", lambda e: result["page_errors"].append(str(e)[:500]))
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
            finally:
                browser.close()
    except BrowserUnavailable:
        raise
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
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
    return [m for m in result.get("console", []) if m.get("type") in ("error", "warning")]
