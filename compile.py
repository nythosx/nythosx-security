import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT_NAME = "sec-checker_code.txt"

CODE_SUFFIXES = {
    ".py", ".yaml", ".yml", ".txt", ".bat", ".sh",
    ".json", ".cfg", ".ini", ".toml", ".html", ".css", ".js",
}

SKIP_DIRS = {
    ".git", ".github", "__pycache__", ".pytest_cache",
    ".venv", "venv", "env", ".env", "node_modules", "site-packages",
    ".mypy_cache", ".ruff_cache", ".idea", ".vscode",
    "evidence", "findings", "reports", "logs", "sessions",
}

SKIP_FILES = {
    "a.py", "compile.py",
    "credentials.yaml", "targets.yaml", "roe.yaml",
}

SKIP_PREFIXES = ("build", "diag", "scratch", "tmp")


def is_scratch(name: str) -> bool:
    stem = name.rsplit(".", 1)[0].lower()
    return any(stem.startswith(p) for p in SKIP_PREFIXES)


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


def collect():
    files = []
    for path in sorted(ROOT.rglob("*")):
        if path.is_dir():
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(ROOT).parts[:-1]):
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if included(path):
            files.append(path)
    return files


def main():
    out_dir = Path.home() / "Downloads"
    if not out_dir.is_dir():
        out_dir = ROOT
    out_path = out_dir / OUT_NAME

    files = collect()
    if not files:
        print("No code files found.")
        return 1

    total_bytes = 0
    skipped_secret = ["credentials.yaml", "targets.yaml", "roe.yaml", "configs/sessions/"]

    with out_path.open("w", encoding="utf-8") as out:
        out.write("=" * 70 + "\n")
        out.write("SEC-CHECKER source bundle\n")
        out.write(f"Generated: {datetime.now().isoformat(timespec='seconds')}\n")
        out.write(f"Root: {ROOT}\n")
        out.write(f"Files: {len(files)}\n")
        out.write("Excluded: packages, .github, __pycache__, scratch, *.md, "
                  "scan artifacts, and secret configs\n")
        out.write("=" * 70 + "\n\n")

        for i, path in enumerate(files, 1):
            rel = path.relative_to(ROOT).as_posix()
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                text = path.read_text(encoding="utf-8", errors="replace")
            total_bytes += len(text.encode("utf-8"))
            out.write("\n")
            out.write("#" * 70 + "\n")
            out.write(f"# FILE {i}/{len(files)}: {rel}\n")
            out.write("#" * 70 + "\n\n")
            out.write(text)
            if not text.endswith("\n"):
                out.write("\n")

    print(f"Wrote {len(files)} files -> {out_path}")
    print(f"Size: {total_bytes / 1024:.1f} KiB")
    print("Skipped secret files (not included): " + ", ".join(skipped_secret))
    for path in files:
        print("  + " + path.relative_to(ROOT).as_posix())
    return 0


if __name__ == "__main__":
    sys.exit(main())
