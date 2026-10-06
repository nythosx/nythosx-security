import sys
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).parent.absolute()
DOWNLOADS = Path.home() / "Downloads"
OUTPUT = DOWNLOADS / f"sec-checker-full-export-{datetime.now().strftime('%Y%m%dT%H%M%S')}.md"

EXCLUDE_DIRS = {
    "__pycache__", ".git", ".venv", "venv", "node_modules",
    "site-packages", "evidence", "findings", "reports", "logs",
    "sandbox", ".pytest_cache", ".mypy_cache", ".idea", ".vscode",
    "dist", "build",
}

EXCLUDE_ROOT_FILES = {
    "export_all.py", "inventory.py", "test_all.py",
    "fix_creds.py", "fix_adapters.py",
    "build.py", "build3.py", "build4.py", "build5.py",
    "build6.py", "build7.py",
    "hotfix1.py", "hotfix2.py", "hotfix3.py", "hotfix4.py",
    "diag_api.py", "diag_api2.py", "diag_debug.py",
    "diagnose.py", "diag9.py", "MANIFEST.md",
}

EXCLUDE_PATTERNS = {
    "*.pyc", "*.pyo", "*.log", "*.tmp", "*.swp", "*.bak",
    ".setup_complete", ".deps_installed", ".playwright_installed",
}

INCLUDE_ROOT_PY = {"run.py"}

INCLUDE_DIRS = {
    "engine": [".py"],
    "adapters": [".yaml", ".yml"],
    "patterns": [".yaml", ".yml"],
    "configs": [".yaml", ".yml"],
    "wordlists": [".txt"],
}

EXCLUDE_CONFIG_FILES = {"credentials.yaml", "targets.yaml", "roe.yaml"}


def should_exclude_dir(name):
    if name in EXCLUDE_DIRS:
        return True
    if name.startswith(".") and name not in (".",):
        return True
    return False


def matches_exclude_pattern(name):
    for pat in EXCLUDE_PATTERNS:
        if pat.startswith("*."):
            if name.endswith(pat[1:]):
                return True
        elif name == pat:
            return True
    return False


def collect_files():
    files = []

    for name in INCLUDE_ROOT_PY:
        p = ROOT / name
        if p.exists():
            files.append(p)

    for dir_name, extensions in INCLUDE_DIRS.items():
        d = ROOT / dir_name
        if not d.exists():
            continue
        for p in sorted(d.rglob("*")):
            if not p.is_file():
                continue
            if any(should_exclude_dir(part) for part in p.parts):
                continue
            if p.suffix.lower() not in extensions:
                continue
            if matches_exclude_pattern(p.name):
                continue
            if dir_name == "configs" and p.name in EXCLUDE_CONFIG_FILES:
                continue
            files.append(p)

    files.sort(key=lambda x: str(x.relative_to(ROOT)).lower())
    return files


def read_file(path):
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        try:
            return path.read_text(encoding="latin-1")
        except Exception:
            return f"<<< binary or unreadable: {path} >>>"
    except Exception as e:
        return f"<<< error: {e} >>>"


def get_language(path):
    ext = path.suffix.lower()
    if ext == ".py":
        return "python"
    if ext in (".yaml", ".yml"):
        return "yaml"
    if ext == ".json":
        return "json"
    if ext == ".md":
        return "markdown"
    if ext == ".txt":
        return "text"
    return ""


def get_category(path):
    rel = path.relative_to(ROOT)
    parts = rel.parts
    if len(parts) == 1:
        return "ROOT"
    if parts[0] == "engine":
        return "ENGINE"
    if parts[0] == "adapters":
        return "ADAPTERS"
    if parts[0] == "patterns":
        return "PATTERNS"
    if parts[0] == "configs":
        return "CONFIGS"
    if parts[0] == "wordlists":
        return "WORDLISTS"
    return "OTHER"


def build_export(files):
    lines = []
    lines.append("# SEC-CHECKER :: FULL CODE EXPORT")
    lines.append("")
    lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"**Project root:** `{ROOT}`")
    lines.append(f"**Total files:** {len(files)}")
    lines.append("")
    lines.append("## Overview")
    lines.append("")
    lines.append("Black-box security testing platform.")
    lines.append("- Pattern-driven (YAML)")
    lines.append("- Framework-agnostic (11 adapters)")
    lines.append("- One-command auto-discovery")
    lines.append("")
    lines.append("## File Index")
    lines.append("")

    by_cat = {}
    for f in files:
        cat = get_category(f)
        by_cat.setdefault(cat, []).append(f)

    cat_order = ["ROOT", "ENGINE", "ADAPTERS", "PATTERNS", "CONFIGS", "WORDLISTS", "OTHER"]
    for cat in cat_order:
        if cat not in by_cat:
            continue
        lines.append(f"### {cat} ({len(by_cat[cat])})")
        lines.append("")
        for f in by_cat[cat]:
            rel = str(f.relative_to(ROOT)).replace("\\", "/")
            lines.append(f"- `{rel}`")
        lines.append("")

    lines.append("---")
    lines.append("")

    current_cat = None
    for f in files:
        cat = get_category(f)
        rel = str(f.relative_to(ROOT)).replace("\\", "/")
        if cat != current_cat:
            lines.append(f"# ============================================")
            lines.append(f"# CATEGORY: {cat}")
            lines.append(f"# ============================================")
            lines.append("")
            current_cat = cat

        lines.append(f"## `{rel}`")
        lines.append("")
        lang = get_language(f)
        content = read_file(f)
        lines.append(f"```{lang}")
        lines.append(content.rstrip())
        lines.append("```")
        lines.append("")

    return "\n".join(lines)


def main():
    print()
    print("=" * 62)
    print("  SEC-CHECKER  ::  FULL CODE EXPORT")
    print("=" * 62)
    print(f"  Root     : {ROOT}")
    print(f"  Output   : {OUTPUT}")
    print()

    if not DOWNLOADS.exists():
        print(f"  [FAIL]  Downloads folder not found: {DOWNLOADS}")
        return

    files = collect_files()
    if not files:
        print("  [FAIL]  No files collected.")
        return

    print(f"  Collected: {len(files)} files")
    for f in files:
        rel = str(f.relative_to(ROOT)).replace("\\", "/")
        size = f.stat().st_size
        print(f"    {size:>8}b  {rel}")
    print()

    print("  Building export...")
    content = build_export(files)
    OUTPUT.write_text(content, encoding="utf-8")

    size_kb = OUTPUT.stat().st_size / 1024
    print(f"  [ OK ]  Written: {OUTPUT}")
    print(f"          Size: {size_kb:.1f} KB")
    print()
    print("=" * 62)
    print("  DONE")
    print("=" * 62)
    print()
    print("  Share this single file with any AI.")
    print()


if __name__ == "__main__":
    main()