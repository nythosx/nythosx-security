import sys
from pathlib import Path

ROOT = Path(__file__).parent.absolute()
sys.path.insert(0, str(ROOT))
try:
    from engine.version import __version__  # noqa: E402
except Exception:
    __version__ = "unknown"


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("--version", "-V"):
        print(f"sec-checker {__version__}")
        return 0
    
    # Vault enforcement check
    try:
        import os
        cred_path = ROOT / "configs" / "credentials.yaml"
        if cred_path.exists():
            text = cred_path.read_text(encoding="utf-8", errors="ignore")
            # If it's not the example file and not encrypted
            if "CHANGE_ME" not in text and "change-me" not in text and not text.startswith("SECVAULT1:"):
                if not os.environ.get("SEC_CHECKER_VAULT_KEY"):
                    print("[FATAL] configs/credentials.yaml contains real secrets but SEC_CHECKER_VAULT_KEY is not set.")
                    print("[FATAL] Set the env var or encrypt the file: python -c 'from engine import secrets_vault; secrets_vault.encrypt_file()'")
                    return 4
    except Exception:
        pass
    if not (ROOT / "engine" / "__init__.py").exists():
        print("[ERROR] engine/ not found. Project is incomplete.")
        return 2
    from engine.cli import main as cli_main
    return cli_main(sys.argv[1:]) or 0


if __name__ == "__main__":
    raise SystemExit(main())
