import sys
from pathlib import Path

ROOT = Path(__file__).parent.absolute()
__version__ = "1.2.0"


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("--version", "-V"):
        print(f"sec-checker {__version__}")
        return 0
    if not (ROOT / "engine" / "__init__.py").exists():
        print("[ERROR] engine/ not found. Project is incomplete.")
        return 2
    from engine.cli import main as cli_main
    return cli_main(sys.argv[1:]) or 0


if __name__ == "__main__":
    raise SystemExit(main())
