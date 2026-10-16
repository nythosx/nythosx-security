import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).parent.resolve()


def patch(rel, old, new):
    f = ROOT / rel
    if not f.exists():
        raise AssertionError(f"file not found: {rel}")
    t = f.read_text(encoding="utf-8")
    if old in t:
        f.write_text(t.replace(old, new, 1), encoding="utf-8")
        print(f"  patch  {rel}")
        return True
    if new in t:
        print(f"  skip   {rel}")
        return False
    raise AssertionError(f"anchor not found in {rel}:\n  {old[:200]!r}")


print("fix pass: hunt tests")

# ---------------------------------------------------------------------------
# 1. test_hunt.py — add permissive ROE fixture + fix dedupe test
# ---------------------------------------------------------------------------

patch(
    "tests/test_hunt.py",
    '''import pytest


def test_severity_default_mapping():''',
    '''import pytest

from engine import roe_guard as roe_mod


@pytest.fixture(autouse=True)
def permissive_roe(monkeypatch):
    monkeypatch.setattr(roe_mod, "load_roe", lambda: {
        "enabled": True,
        "scope": {"in_scope": ["test.local", "127.0.0.1", "localhost"],
                  "out_of_scope": [],
                  "allowed_methods": ["GET", "POST", "PUT", "PATCH",
                                       "DELETE", "OPTIONS", "HEAD"],
                  "forbidden_paths": []},
    })


def test_severity_default_mapping():''',
)

patch(
    "tests/test_hunt.py",
    '''def test_collect_from_report_dedupes():
    from engine.hunt import _collect_from_report
    report = {"findings": [
        {"chain": "a", "step": "s1", "tool": "t1", "verdict": "VULNERABLE",
         "reason": "same reason", "evidence": {"severity": "critical"}},
        {"chain": "b", "step": "s2", "tool": "t2", "verdict": "SUSPICIOUS",
         "reason": "other reason", "evidence": {}},
        {"chain": "a", "step": "s1", "tool": "t1", "verdict": "VULNERABLE",
         "reason": "same reason", "evidence": {"severity": "critical"}},
    ]}
    out = _collect_from_report(report)
    assert len(out) == 2
    assert out[0]["severity"] == "critical"
    assert out[1]["severity"] == "medium"''',
    '''def test_collect_from_report_dedupes():
    from engine.hunt import _collect_from_report, _dedupe_and_sort
    report = {"findings": [
        {"chain": "a", "step": "s1", "tool": "t1", "verdict": "VULNERABLE",
         "reason": "same reason", "evidence": {"severity": "critical"}},
        {"chain": "b", "step": "s2", "tool": "t2", "verdict": "SUSPICIOUS",
         "reason": "other reason", "evidence": {}},
        {"chain": "a", "step": "s1", "tool": "t1", "verdict": "VULNERABLE",
         "reason": "same reason", "evidence": {"severity": "critical"}},
    ]}
    raw = _collect_from_report(report)
    assert len(raw) == 3
    unique = _dedupe_and_sort(raw)
    assert len(unique) == 2
    assert unique[0]["severity"] == "critical"
    assert unique[1]["severity"] == "medium"''',
)

# ---------------------------------------------------------------------------
# 2. Run only the affected test file
# ---------------------------------------------------------------------------

print("\nrunning affected tests only:")
rc = subprocess.call([
    sys.executable, "-m", "pytest", "-q", "--no-header",
    str(ROOT / "tests" / "test_hunt.py"),
])
if rc != 0:
    print(f"\n  pytest exited with code {rc}")
    sys.exit(rc)

print("\nfixed")