import sys
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).parent.absolute()
PY = sys.executable
RUN = str(ROOT / "run.py")
TARGET = "http://localhost:3000"


def section(title):
    print()
    print("=" * 70)
    print(f"  {title}")
    print("=" * 70)
    print()


def run_cmd(args, timeout=300):
    t0 = time.perf_counter()
    try:
        r = subprocess.run(
            [PY, RUN] + args,
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
        elapsed = (time.perf_counter() - t0) * 1000.0
        return {
            "code": r.returncode,
            "stdout": r.stdout or "",
            "stderr": r.stderr or "",
            "elapsed_ms": round(elapsed, 3),
        }
    except subprocess.TimeoutExpired:
        return {"code": -1, "stdout": "", "stderr": "TIMEOUT", "elapsed_ms": timeout * 1000}
    except Exception as e:
        return {"code": -1, "stdout": "", "stderr": str(e), "elapsed_ms": 0}


def check_server(url):
    try:
        import httpx
        r = httpx.get(url, timeout=5.0)
        return True, r.status_code
    except Exception as e:
        return False, str(e)


def show(result, label):
    print(f"[{label}] exit={result['code']}  time={result['elapsed_ms']:.0f}ms")
    print("-" * 70)
    if result["stdout"]:
        print(result["stdout"].rstrip())
    if result["stderr"]:
        print("[STDERR]")
        print(result["stderr"].rstrip())
    print("-" * 70)
    print()


def main():
    print()
    print("=" * 70)
    print("  SEC-CHECKER  ::  FULL TEST SUITE")
    print("=" * 70)
    print(f"  Root   : {ROOT}")
    print(f"  Target : {TARGET}")
    print()

    summary = []

    section("TEST 1 / 5  ::  Validate Patterns")
    r1 = run_cmd(["validate"])
    show(r1, "validate")
    summary.append(("validate", r1["code"]))

    section("TEST 2 / 5  ::  List Patterns")
    r2 = run_cmd(["list"])
    show(r2, "list")
    summary.append(("list", r2["code"]))

    section("TEST 3 / 5  ::  Server Reachability")
    ok, info = check_server(TARGET)
    if ok:
        print(f"  [ OK ]  {TARGET}  ->  HTTP {info}")
    else:
        print(f"  [FAIL]  {TARGET}  ->  {info}")
        print()
        print("  Dev server not running. Start your React/Node app first.")
        print("  Skipping scan tests.")
        print()
        _print_summary(summary, skipped=True)
        return
    print()
    summary.append(("reachability", 0))

    section("TEST 4 / 5  ::  Single Scan (security-headers-missing)")
    r4 = run_cmd(["scan", "security-headers-missing", TARGET], timeout=120)
    show(r4, "scan-single")
    summary.append(("scan-single", r4["code"]))

    section("TEST 5 / 5  ::  Full Scan (scan-all, min-severity medium)")
    r5 = run_cmd(["scan-all", TARGET, "--min-severity", "medium"], timeout=600)
    show(r5, "scan-all")
    summary.append(("scan-all", r5["code"]))

    section("GENERATE REPORT")
    r6 = run_cmd(["report", TARGET], timeout=60)
    show(r6, "report")
    summary.append(("report", r6["code"]))

    _print_summary(summary)


def _print_summary(summary, skipped=False):
    section("SUMMARY")
    print(f"  {'Test':<20}  {'Status':<10}")
    print(f"  {'-'*20}  {'-'*10}")
    for name, code in summary:
        status = "OK" if code == 0 else f"FAIL({code})"
        print(f"  {name:<20}  {status:<10}")
    print()
    if skipped:
        print("  Scan tests skipped — dev server not reachable.")
    else:
        failed = [n for n, c in summary if c != 0]
        if not failed:
            print("  ALL TESTS PASSED")
        else:
            print(f"  FAILED: {', '.join(failed)}")
    print()
    print("  Files to inspect:")
    print(f"    evidence/   - raw request/response per finding")
    print(f"    findings/   - ledger.db (SQLite)")
    print(f"    reports/    - HTML + Markdown reports")
    print()


if __name__ == "__main__":
    main()