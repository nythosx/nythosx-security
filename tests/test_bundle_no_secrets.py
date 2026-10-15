import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).parent.parent


def _make_fixture_tree(tmp_path):
    tree = tmp_path / "proj"
    (tree / "configs").mkdir(parents=True)
    (tree / "configs" / "credentials.yaml").write_text(
        "credentials:\n  localhost:\n    password: sec-xyz-should-not-leak\n",
        encoding="utf-8")
    (tree / "configs" / "engine.example.yaml").write_text(
        "http:\n  timeout_seconds: 30\n", encoding="utf-8")
    (tree / "src").mkdir(parents=True)
    (tree / "src" / "main.py").write_text(
        "def main():\n    print('hello world')\n", encoding="utf-8")
    (tree / "src" / "leaked.py").write_text(
        'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")
    (tree / "node_modules").mkdir()
    (tree / "node_modules" / "big.js").write_text("x" * 5000, encoding="utf-8")
    (tree / "findings").mkdir()
    (tree / "findings" / "audit.jsonl").write_text(
        '{"ts":"2026"}\n', encoding="utf-8")
    return tree


def test_bundle_excludes_credentials(tmp_path):
    tree = _make_fixture_tree(tmp_path)
    out = tmp_path / "bundle.txt"
    r = subprocess.run(
        [sys.executable, str(ROOT / "build_bundle.py"),
         "--root", str(tree), "--out", str(out), "--strict"],
        cwd=str(ROOT), capture_output=True, text=True, timeout=60,
    )
    text = out.read_text(encoding="utf-8")
    assert "sec-xyz-should-not-leak" not in text
    assert r.returncode != 0, (
        "strict mode must exit non-zero when a secret file would be "
        "included")


def _bundle_body(text):
    _, marker, body = text.partition("# FILE ")
    return "# FILE " + body if marker else ""


def test_bundle_excludes_build_dirs(tmp_path):
    tree = _make_fixture_tree(tmp_path)
    out = tmp_path / "bundle.txt"
    subprocess.run(
        [sys.executable, str(ROOT / "build_bundle.py"),
         "--root", str(tree), "--out", str(out)],
        cwd=str(ROOT), capture_output=True, text=True, timeout=60,
    )
    text = out.read_text(encoding="utf-8")
    body = _bundle_body(text)
    assert "big.js" not in body, (
        "excluded file content leaked into bundle body")
    assert "audit.jsonl" not in body, (
        "excluded file content leaked into bundle body")
    assert "node_modules" in text, (
        "bundle header should name excluded files for auditability")


def test_bundle_refuses_files_with_token_patterns(tmp_path):
    tree = _make_fixture_tree(tmp_path)
    out = tmp_path / "bundle.txt"
    subprocess.run(
        [sys.executable, str(ROOT / "build_bundle.py"),
         "--root", str(tree), "--out", str(out), "--strict"],
        cwd=str(ROOT), capture_output=True, text=True, timeout=60,
    )
    text = out.read_text(encoding="utf-8")
    assert "AKIAIOSFODNN7EXAMPLE" not in text, (
        "bundle must not contain AWS-key-shaped strings")


def test_bundle_includes_safe_files(tmp_path):
    tree = _make_fixture_tree(tmp_path)
    out = tmp_path / "bundle.txt"
    subprocess.run(
        [sys.executable, str(ROOT / "build_bundle.py"),
         "--root", str(tree), "--out", str(out)],
        cwd=str(ROOT), capture_output=True, text=True, timeout=60,
    )
    text = out.read_text(encoding="utf-8")
    assert "hello world" in text


def test_bundle_header_names_excluded_files(tmp_path):
    tree = _make_fixture_tree(tmp_path)
    out = tmp_path / "bundle.txt"
    subprocess.run(
        [sys.executable, str(ROOT / "build_bundle.py"),
         "--root", str(tree), "--out", str(out)],
        cwd=str(ROOT), capture_output=True, text=True, timeout=60,
    )
    text = out.read_text(encoding="utf-8")
    assert "EXCLUDED FILES" in text
    assert "credentials.yaml" in text
