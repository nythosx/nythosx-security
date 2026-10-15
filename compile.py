import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT_NAME = "sec-checker_code.txt"
OUT_NAME_SECRETS = "sec-checker_code_WITH_SECRETS.txt"

CODE_SUFFIXES = {
    ".py", ".yaml", ".yml", ".txt", ".bat", ".sh",
    ".json", ".cfg", ".ini", ".toml", ".html", ".css", ".js",
}

SKIP_DIRS = {
    ".git", ".github", "__pycache__", ".pytest_cache",
    ".venv", "venv", "env", ".env", "node_modules", "site-packages",
    ".mypy_cache", ".ruff_cache", ".idea", ".vscode", ".claude", ".claude1",
    "evidence", "findings", "reports", "logs", "sessions",
}

SKIP_FILES = {
    "a.py", "a2.py", "compile.py", "domxss_test.html",
    "credentials.yaml", "targets.yaml", "roe.yaml",
}

SECRET_GLOBS = (
    "configs/credentials.yaml",
    "configs/targets.yaml",
    "configs/roe.yaml",
    "configs/sessions/*",
    "configs/sessions/**/*",
)

SKIP_PREFIXES = ("build", "diag", "scratch", "tmp")

WITH_SECRETS = False


def is_scratch(name: str) -> bool:
    stem = name.rsplit(".", 1)[0].lower()
    return any(stem.startswith(p) for p in SKIP_PREFIXES)


def _skipped_dir(path: Path) -> bool:
    for part in path.relative_to(ROOT).parts[:-1]:
        if part in SKIP_DIRS or part.endswith(".bak"):
            return True
    return False


def _collect_secrets():
    found = []
    for pattern in SECRET_GLOBS:
        for p in ROOT.glob(pattern):
            if p.is_file():
                found.append(p.resolve())
    return sorted(set(found))


def included(path: Path) -> bool:
    name = path.name
    if name in SKIP_FILES:
        return False
    if name.lower().endswith(".md"):
        return False
    if name.lower().endswith((".log", ".pyc", ".pyo", ".pyd")):
        return False
    if is_scratch(name):
        return False
    if path.suffix.lower() not in CODE_SUFFIXES:
        return False
    return True


def _git_tracked():
    try:
        out = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
            cwd=str(ROOT), capture_output=True, text=True, timeout=30,
        )
    except Exception:
        return None
    if out.returncode != 0 or not out.stdout.strip():
        return None
    files = []
    for rel in out.stdout.splitlines():
        rel = rel.strip()
        if not rel:
            continue
        p = (ROOT / rel).resolve()
        if p.is_file() and not _skipped_dir(p) and included(p):
            files.append(p)
    return sorted(set(files))


def _walk():
    files = []
    for path in sorted(ROOT.rglob("*")):
        if path.is_dir():
            continue
        if _skipped_dir(path):
            continue
        if any(part in SKIP_DIRS or part.endswith(".bak") for part in path.parts):
            continue
        if included(path):
            files.append(path)
    return files


def collect():
    files = _git_tracked() or _walk()
    if WITH_SECRETS:
        existing = set(files)
        for p in _collect_secrets():
            if p not in existing:
                files.append(p)
                existing.add(p)
    return files


def main():
    global WITH_SECRETS
    WITH_SECRETS = "--with-secrets" in sys.argv[1:]

    out_dir = Path.home() / "Downloads"
    if not out_dir.is_dir():
        out_dir = ROOT
    out_path = out_dir / (OUT_NAME_SECRETS if WITH_SECRETS else OUT_NAME)

    files = collect()
    if not files:
        print("No code files found.")
        return 1

    secret_set = set(_collect_secrets()) if WITH_SECRETS else set()
    total_bytes = 0

    with out_path.open("w", encoding="utf-8") as out:
        out.write("SEC-CHECKER source bundle\n")
        out.write(f"Generated: {datetime.now().isoformat(timespec='seconds')}\n")
        out.write(f"Root: {ROOT}\n")
        out.write(f"Files: {len(files)}\n")
        if WITH_SECRETS:
            out.write("!! WARNING: THIS BUNDLE CONTAINS SECRET FILES "
                      "(credentials.yaml, targets.yaml, roe.yaml, sessions). "
                      "KEEP LOCAL ONLY — never paste, upload, push, or share it. !!\n")

        for i, path in enumerate(files, 1):
            rel = path.relative_to(ROOT).as_posix()
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                text = path.read_text(encoding="utf-8", errors="replace")
            total_bytes += len(text.encode("utf-8"))
            tag = "  [SECRET]" if path.resolve() in secret_set else ""
            out.write("\n")
            out.write(f"# FILE {i}/{len(files)}: {rel}{tag}\n")
            out.write("\n")
            out.write(text)
            if not text.endswith("\n"):
                out.write("\n")

    print(f"Wrote {len(files)} files -> {out_path}")
    print(f"Size: {total_bytes / 1024:.1f} KiB")
    if WITH_SECRETS:
        print("!! INCLUDED SECRET FILES — keep this bundle LOCAL ONLY, never share:")
        for p in sorted(secret_set):
            print("  [SECRET] " + p.relative_to(ROOT).as_posix())
    else:
        print("Secrets NOT included. Run with --with-secrets to include them.")
    return 0


if __name__ == "__main__":
    sys.exit(main())