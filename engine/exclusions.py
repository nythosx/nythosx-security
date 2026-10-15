"""Shared exclusion list for bundle generation and pre-commit hooks.

Single source of truth so the two lists cannot drift.
"""

SECRET_FILES = (
    "configs/credentials.yaml",
    "configs/credentials.yml",
    "configs/roe.yaml",
    "configs/roe.yml",
    "configs/targets.yaml",
    "configs/targets.yml",
)

SECRET_DIRS = (
    "configs/sessions",
    "findings",
    "evidence",
    "reports",
    "workflows",
)

BUILD_DIRS = (
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".venv",
    "venv",
    ".git",
    "dist",
    "build",
)

DEV_FILES = (
    "a.py",
    "b.py",
    "debug_probe.py",
    "extract_data.py",
    "mockup_ui.html",
    "newui.html",
    "new_ui.html",
)

ENV_FILES = (
    ".env",
    ".env.local",
    ".env.production",
    ".env.backup",
)


def is_excluded(rel_path):
    path = str(rel_path).replace("\\", "/")
    parts = path.split("/")
    for s in SECRET_FILES:
        if path == s or path.endswith("/" + s):
            return True, "secret"
    for d in SECRET_DIRS:
        if d in parts:
            return True, "secret-dir"
    for d in BUILD_DIRS:
        if d in parts:
            return True, "build"
    for f in DEV_FILES:
        if path == f or parts[-1] == f:
            return True, "dev"
    for f in ENV_FILES:
        if path == f or parts[-1] == f:
            return True, "env"
    return False, None


SCAN_ALLOWLIST = frozenset((
    "engine/redact.py",
    "wordlists/sensitive_keys.txt",
    "wordlists/jwt_secrets.txt",
    "wordlists/weak_passwords_top100.txt",
    "wordlists/llm_payloads.txt",
    "wordlists/jailbreak_templates.txt",
    "wordlists/blind_extract_queries.txt",
    "wordlists/user_agents.txt",
))

SCAN_SKIP_PREFIXES = ("tests/",)

SCANNABLE_SUFFIXES = (
    ".yaml", ".yml", ".json", ".txt", ".cfg", ".ini", ".conf",
    ".py", ".js", ".ts", ".tsx", ".jsx", ".sh", ".bash", ".ps1",
    ".env", ".toml", ".properties",
)


def should_scan(rel_path):
    path = str(rel_path).replace("\\", "/")
    if path in SCAN_ALLOWLIST:
        return False
    for prefix in SCAN_SKIP_PREFIXES:
        if path.startswith(prefix):
            return False
    return path.endswith(SCANNABLE_SUFFIXES) or "." not in path.split("/")[-1]
