import os
import sys
import hashlib
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).parent.absolute()

EXCLUDE_DIRS = {
    "__pycache__", ".git", ".venv", "venv", "env", "node_modules",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", ".idea", ".vscode",
    "dist", "build", ".next", ".nuxt", ".cache", "coverage",
    "site-packages", "Lib", "Scripts", "include",
}

EXCLUDE_EXT = {
    ".pyc", ".pyo", ".pyd", ".so", ".dll", ".exe", ".bin",
    ".lock", ".log", ".tmp", ".swp", ".bak",
}

EXCLUDE_FILE_PATTERNS = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
}

MAX_DEPTH = 6
MAX_FILE_PREVIEW = 200


def should_skip_dir(name):
    if name in EXCLUDE_DIRS:
        return True
    if name.startswith(".") and name not in (".setup_complete", ".deps_installed",
                                              ".playwright_installed"):
        return True
    return False


def should_skip_file(name):
    if name in EXCLUDE_FILE_PATTERNS:
        return True
    ext = Path(name).suffix.lower()
    if ext in EXCLUDE_EXT:
        return True
    return False


def human_size(n):
    for unit in ["B", "KB", "MB", "GB"]:
        if n < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


def file_hash(path, max_bytes=1024 * 1024):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            read = 0
            while read < max_bytes:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
                read += len(chunk)
        return h.hexdigest()[:12]
    except Exception:
        return ""


def walk_tree(root, max_depth):
    results = []
    root = Path(root)
    base_depth = len(root.parts)

    for current, dirs, files in os.walk(root):
        cur_path = Path(current)
        depth = len(cur_path.parts) - base_depth
        if depth > max_depth:
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if not should_skip_dir(d)]
        for f in files:
            if should_skip_file(f):
                continue
            p = cur_path / f
            try:
                stat = p.stat()
                results.append({
                    "path": p,
                    "rel": str(p.relative_to(root)),
                    "size": stat.st_size,
                    "mtime": stat.st_mtime,
                    "depth": depth,
                    "ext": p.suffix.lower(),
                })
            except Exception:
                continue
    return results


def group_by_category(files):
    groups = {
        "ENGINE": [],
        "PATTERNS": [],
        "CONFIGS": [],
        "SESSIONS": [],
        "EVIDENCE": [],
        "FINDINGS": [],
        "REPORTS": [],
        "LOGS": [],
        "WORDLISTS": [],
        "SCRIPTS": [],
        "SANDBOX": [],
        "OTHER": [],
    }
    for f in files:
        rel = f["rel"].replace("\\", "/")
        if rel.startswith("engine/"):
            groups["ENGINE"].append(f)
        elif rel.startswith("patterns/"):
            groups["PATTERNS"].append(f)
        elif rel.startswith("configs/sessions/"):
            groups["SESSIONS"].append(f)
        elif rel.startswith("configs/"):
            groups["CONFIGS"].append(f)
        elif rel.startswith("evidence/"):
            groups["EVIDENCE"].append(f)
        elif rel.startswith("findings/"):
            groups["FINDINGS"].append(f)
        elif rel.startswith("reports/"):
            groups["REPORTS"].append(f)
        elif rel.startswith("logs/"):
            groups["LOGS"].append(f)
        elif rel.startswith("wordlists/"):
            groups["WORDLISTS"].append(f)
        elif rel.startswith("sandbox/"):
            groups["SANDBOX"].append(f)
        elif f["ext"] == ".py":
            groups["SCRIPTS"].append(f)
        else:
            groups["OTHER"].append(f)
    return groups


def print_header():
    print()
    print("=" * 78)
    print("  SEC-CHECKER  ::  FILE INVENTORY")
    print("=" * 78)
    print(f"  Root     : {ROOT}")
    print(f"  Scanned  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Max depth: {MAX_DEPTH}")
    print()


def print_summary(groups, total_files, total_size):
    print("-" * 78)
    print(f"  {'CATEGORY':<15} {'FILES':>8}  {'SIZE':>12}  {'PATH'}")
    print("-" * 78)
    for name, items in groups.items():
        if not items:
            continue
        size = sum(i["size"] for i in items)
        sample = items[0]["rel"].split("\\")[0].split("/")[0]
        print(f"  {name:<15} {len(items):>8}  {human_size(size):>12}  {sample}/")
    print("-" * 78)
    print(f"  {'TOTAL':<15} {total_files:>8}  {human_size(total_size):>12}")
    print()


def print_category(name, items):
    if not items:
        return
    print()
    print("=" * 78)
    print(f"  {name}  ({len(items)} files)")
    print("=" * 78)
    print()
    items_sorted = sorted(items, key=lambda x: x["rel"])
    for f in items_sorted:
        rel = f["rel"].replace("\\", "/")
        size = human_size(f["size"])
        mtime = datetime.fromtimestamp(f["mtime"]).strftime("%Y-%m-%d %H:%M")
        print(f"  {rel}")
        print(f"    size={size:<10}  modified={mtime}")
    print()


def print_extensions(files):
    print("=" * 78)
    print("  FILE TYPES")
    print("=" * 78)
    print()
    ext_counts = {}
    for f in files:
        ext = f["ext"] or "(no ext)"
        ext_counts[ext] = ext_counts.get(ext, 0) + 1
    sorted_ext = sorted(ext_counts.items(), key=lambda x: -x[1])
    print(f"  {'EXTENSION':<15} {'COUNT':>8}")
    print("  " + "-" * 26)
    for ext, count in sorted_ext:
        print(f"  {ext:<15} {count:>8}")
    print()


def print_top_files(files, limit=20):
    print("=" * 78)
    print(f"  TOP {limit} LARGEST FILES")
    print("=" * 78)
    print()
    sorted_files = sorted(files, key=lambda x: -x["size"])[:limit]
    print(f"  {'SIZE':>10}  {'PATH'}")
    print("  " + "-" * 74)
    for f in sorted_files:
        rel = f["rel"].replace("\\", "/")
        print(f"  {human_size(f['size']):>10}  {rel}")
    print()


def print_recent_files(files, limit=15):
    print("=" * 78)
    print(f"  RECENTLY MODIFIED ({limit})")
    print("=" * 78)
    print()
    sorted_files = sorted(files, key=lambda x: -x["mtime"])[:limit]
    for f in sorted_files:
        rel = f["rel"].replace("\\", "/")
        mtime = datetime.fromtimestamp(f["mtime"]).strftime("%Y-%m-%d %H:%M:%S")
        print(f"  {mtime}  {human_size(f['size']):>10}  {rel}")
    print()


def write_manifest(files, groups, out_path):
    lines = []
    lines.append("# SEC-CHECKER FILE MANIFEST")
    lines.append("")
    lines.append(f"Generated: {datetime.now().isoformat()}")
    lines.append(f"Root: {ROOT}")
    lines.append(f"Total files: {len(files)}")
    lines.append("")
    lines.append("## By category")
    lines.append("")
    for name, items in groups.items():
        if not items:
            continue
        lines.append(f"### {name} ({len(items)})")
        lines.append("")
        for f in sorted(items, key=lambda x: x["rel"]):
            rel = f["rel"].replace("\\", "/")
            lines.append(f"- `{rel}`  ({human_size(f['size'])})")
        lines.append("")
    out_path.write_text("\n".join(lines), encoding="utf-8")


def main():
    print_header()
    files = walk_tree(ROOT, MAX_DEPTH)
    if not files:
        print("  [ERROR] No files found.")
        return
    groups = group_by_category(files)
    total_size = sum(f["size"] for f in files)

    print_summary(groups, len(files), total_size)

    for name in ["ENGINE", "PATTERNS", "CONFIGS", "SESSIONS", "WORDLISTS",
                 "SCRIPTS", "FINDINGS", "EVIDENCE", "REPORTS", "LOGS",
                 "SANDBOX", "OTHER"]:
        print_category(name, groups.get(name, []))

    print_extensions(files)
    print_top_files(files)
    print_recent_files(files)

    manifest_path = ROOT / "MANIFEST.md"
    write_manifest(files, groups, manifest_path)

    print("=" * 78)
    print("  MANIFEST SAVED")
    print("=" * 78)
    print(f"  {manifest_path}")
    print()
    print("  Use this file to:")
    print("    - See all generated files at a glance")
    print("    - Track what changed between builds")
    print("    - Share project structure without sharing code")
    print()


if __name__ == "__main__":
    main()