import re
import py_compile
from pathlib import Path

ROOT = Path(__file__).parent.absolute()
TARGET = ROOT / "engine" / "auto.py"

OLD_BLOCK = '''    if auth_headers or auth_cookies:
        save_session("auto_" + _safe_name(url), {
            "login_url": (login_info or {}).get("url", ""),
            "auth_headers": auth_headers,
            "cookies": auth_cookies,
            "token": (login_info or {}).get("token", {}).get("token", "") if login_info else "",
        })'''

NEW_BLOCK = '''    if auth_headers or auth_cookies:
        save_session("auto_" + _safe_name(url), {
            "login_url": _get_login_url(login_info),
            "auth_headers": auth_headers,
            "cookies": auth_cookies,
            "token": _get_token_string(login_info),
        })'''

HELPER = '''

def _get_login_url(login_info):
    if not isinstance(login_info, dict):
        return ""
    return login_info.get("url") or login_info.get("login_url") or ""


def _get_token_string(login_info):
    if not isinstance(login_info, dict):
        return ""
    t = login_info.get("token")
    if isinstance(t, str):
        return t
    if isinstance(t, dict):
        return t.get("token", "") or ""
    return ""
'''

MARKER = "def _safe_name(url):"


def patch():
    if not TARGET.exists():
        print(f"  [FAIL]  {TARGET} not found")
        return False

    text = TARGET.read_text(encoding="utf-8")

    if "_get_token_string" in text:
        print("  [SKIP]  Already patched")
        return True

    if OLD_BLOCK not in text:
        print("  [FAIL]  Old block not found — file may be different version")
        print()
        print("  Looking for:")
        print(f"  {OLD_BLOCK[:200]}")
        return False

    text = text.replace(OLD_BLOCK, NEW_BLOCK, 1)

    if MARKER not in text:
        print(f"  [FAIL]  Marker '{MARKER}' not found")
        return False

    text = text.replace(MARKER, HELPER.strip() + "\n\n\n" + MARKER, 1)

    TARGET.write_text(text, encoding="utf-8")
    print(f"  [ OK ]  Patched: {TARGET.relative_to(ROOT)}")
    return True


def verify():
    try:
        py_compile.compile(str(TARGET), doraise=True)
        print("  [ OK ]  Syntax OK")
        return True
    except py_compile.PyCompileError as e:
        print(f"  [FAIL]  Syntax error: {e}")
        return False


def main():
    print()
    print("=" * 62)
    print("  HOTFIX 1  ::  token format inconsistency")
    print("=" * 62)
    print()
    ok = patch()
    if ok:
        verify()
    print()
    if ok:
        print("  Run: python run.py auto http://localhost:3000")
    print()


if __name__ == "__main__":
    main()