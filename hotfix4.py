import py_compile
from pathlib import Path

ROOT = Path(__file__).parent.absolute()
AUTO_FILE = ROOT / "engine" / "auto.py"

OLD_IMPORT = "from . import (discovery, api_discovery, loader, executor, oracle,\n               evidence, ledger, report, auth_flow)"

NEW_IMPORT = "import httpx\nfrom . import (discovery, api_discovery, loader, executor, oracle,\n               evidence, ledger, report, auth_flow)"

PREFLIGHT_FUNC = '''

def _preflight_check(url, timeout=5):
    try:
        with httpx.Client(timeout=timeout, follow_redirects=False, verify=False) as c:
            r = c.get(url)
            return True, r.status_code, None
    except httpx.ConnectError as e:
        return False, None, f"ConnectError: {e}"
    except httpx.TimeoutException:
        return False, None, "Timeout"
    except Exception as e:
        return False, None, f"{type(e).__name__}: {e}"

'''

PREFLIGHT_CALL = '''    url = url.rstrip("/")
    console.rule("[bold cyan]AUTO-DISCOVERY[/bold cyan]")
    console.print(f"[cyan]Target:[/cyan] {url}")
    console.print()

    console.print("[bold]Preflight check...[/bold]")
    ok, status, err = _preflight_check(url)
    if ok:
        console.print(f"  [green]Reachable[/green]  HTTP {status}")
    else:
        console.print(f"  [red]UNREACHABLE[/red]  {err}")
        console.print()
        console.print("[yellow]Target is not responding. Aborting scan.[/yellow]")
        console.print()
        console.print("[bold]Common causes:[/bold]")
        console.print("  - Dev server not running (php artisan serve / npm run dev)")
        console.print("  - Wrong URL or port")
        console.print("  - Firewall blocking the connection")
        console.print("  - Server crashed")
        console.print()
        console.print("[bold]Verify manually:[/bold]")
        console.print(f"  curl {url}")
        console.print()
        return
    console.print()

'''

OLD_BLOCK = '''    url = url.rstrip("/")
    console.rule("[bold cyan]AUTO-DISCOVERY[/bold cyan]")
    console.print(f"[cyan]Target:[/cyan] {url}")
    console.print()

    if adapter_override:'''

NEW_BLOCK = PREFLIGHT_CALL + '''    if adapter_override:'''


def patch():
    if not AUTO_FILE.exists():
        print(f"  [FAIL]  {AUTO_FILE.relative_to(ROOT)} not found")
        return False
    text = AUTO_FILE.read_text(encoding="utf-8")

    if "_preflight_check" in text:
        print(f"  [SKIP]  Already patched")
        return True

    if OLD_IMPORT not in text:
        print(f"  [FAIL]  Import block not found")
        return False
    text = text.replace(OLD_IMPORT, NEW_IMPORT, 1)

    if "def _safe_name(url):" not in text:
        print(f"  [FAIL]  Marker _safe_name not found")
        return False
    text = text.replace("def _safe_name(url):", PREFLIGHT_FUNC.strip() + "\n\n\ndef _safe_name(url):", 1)

    if OLD_BLOCK not in text:
        print(f"  [FAIL]  URL block not found")
        return False
    text = text.replace(OLD_BLOCK, NEW_BLOCK, 1)

    AUTO_FILE.write_text(text, encoding="utf-8")
    print(f"  [ OK ]  Patched: {AUTO_FILE.relative_to(ROOT)}")
    return True


def verify():
    try:
        py_compile.compile(str(AUTO_FILE), doraise=True)
        print("  [ OK ]  Syntax OK")
        return True
    except py_compile.PyCompileError as e:
        print(f"  [FAIL]  {e}")
        return False


def main():
    print()
    print("=" * 62)
    print("  HOTFIX 4  ::  Preflight reachability check")
    print("=" * 62)
    print()
    ok = patch()
    if ok:
        verify()
    print()
    if ok:
        print("  Behavior change:")
        print("    Offline target  -> abort sa 5 segundos (hindi 13 minutes)")
        print("    Live target     -> tuloy tulad ng dati")
        print()
        print("  Test:")
        print("    python run.py auto http://localhost:3000")
    print()


if __name__ == "__main__":
    main()