#!/usr/bin/env python3
import sys
import yaml
import fnmatch
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).parent.absolute()
ROE_PATH = ROOT / "configs" / "roe.yaml"

DEFAULT_TEMPLATE = {
    "enabled": True,
    "scope": {
        "in_scope": ["localhost", "127.0.0.1", "::1", "*.local", "*.test"],
        "out_of_scope": ["*.gov", "*.mil"],
        "allowed_methods": ["GET", "POST", "PUT", "PATCH", "DELETE",
                            "OPTIONS", "HEAD"],
        "forbidden_paths": [],
    },
}

DANGEROUS_PATTERNS = {"*", "*.*", "0.0.0.0/0"}


def load():
    if not ROE_PATH.exists():
        ROE_PATH.parent.mkdir(parents=True, exist_ok=True)
        ROE_PATH.write_text(yaml.safe_dump(DEFAULT_TEMPLATE, sort_keys=False),
                            encoding="utf-8")
        return dict(DEFAULT_TEMPLATE)
    try:
        roe = yaml.safe_load(ROE_PATH.read_text(encoding="utf-8")) or {}
    except Exception as e:
        print(f"[ERROR] cannot parse {ROE_PATH}: {e}")
        sys.exit(1)
    roe.setdefault("scope", {}).setdefault("in_scope", [])
    return roe


def save(roe):
    ROE_PATH.write_text(yaml.safe_dump(roe, sort_keys=False,
                                        default_flow_style=False,
                                        allow_unicode=True),
                        encoding="utf-8")


def get_scope(roe):
    return roe.get("scope", {}).get("in_scope") or []


def confirm_dangerous(host):
    if host not in DANGEROUS_PATTERNS:
        return True
    print(f"  [WARN] '{host}' matches EVERY host — this disables ROE scope.")
    print(f"  [WARN] You will be able to scan anything, including systems you")
    print(f"  [WARN] do not own. This is illegal in most jurisdictions.")
    try:
        ans = input(f"  Type YES to confirm: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return ans == "YES"


def cmd_list(args):
    roe = load()
    scope = get_scope(roe)
    enabled = roe.get("enabled", True)
    print(f"configs/roe.yaml  (enabled={enabled})")
    print(f"scope.in_scope  ({len(scope)} entries):")
    for h in scope:
        print(f"  - {h}")
    oos = (roe.get("scope") or {}).get("out_of_scope") or []
    if oos:
        print(f"\nscope.out_of_scope  ({len(oos)} entries):")
        for h in oos:
            print(f"  - {h}")
    return 0


def cmd_add(args):
    if not args:
        print("usage: scope.py add <host> [<host> ...]")
        return 1
    roe = load()
    scope = roe["scope"]["in_scope"]
    added = 0
    for h in args:
        h = h.strip()
        if not h:
            continue
        if h in scope:
            print(f"  [skip] {h} already present")
            continue
        if not confirm_dangerous(h):
            print(f"  [skip] {h} not added")
            continue
        scope.append(h)
        added += 1
        print(f"  [add]  {h}")
    if added:
        save(roe)
        print(f"\nsaved. now {len(scope)} entries in scope.in_scope")
        print("hint: restart the web UI (`python run.py web`) if it is running")
    return 0


def cmd_remove(args):
    if not args:
        print("usage: scope.py remove <host> [<host> ...]")
        return 1
    roe = load()
    scope = roe["scope"]["in_scope"]
    removed = 0
    for h in args:
        if h in scope:
            scope.remove(h)
            removed += 1
            print(f"  [rm]   {h}")
        else:
            print(f"  [skip] {h} not in scope")
    if removed:
        save(roe)
        print(f"\nsaved. now {len(scope)} entries in scope.in_scope")
    return 0


def cmd_set(args):
    if not args:
        print("usage: scope.py set <host> [<host> ...]")
        return 1
    roe = load()
    new_scope = [h.strip() for h in args if h.strip()]
    for h in new_scope:
        if not confirm_dangerous(h):
            print("aborted.")
            return 1
    roe["scope"]["in_scope"] = new_scope
    save(roe)
    print(f"replaced. now {len(new_scope)} entries in scope.in_scope")
    return 0


def cmd_test(args):
    if not args:
        print("usage: scope.py test <url>")
        return 1
    roe = load()
    url = args[0]
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    host = urlparse(url).hostname or ""

    if roe.get("enabled") is False:
        print(f"ALLOWED (roe.enabled = false — scope checks OFF): {host}")
        return 0

    oos = (roe.get("scope") or {}).get("out_of_scope") or []
    for pat in oos:
        if fnmatch.fnmatch(host, pat):
            print(f"BLOCKED (out_of_scope): {host} matches {pat}")
            return 1

    scope = get_scope(roe)
    if not scope:
        print(f"BLOCKED (in_scope is empty — fail-closed): {host}")
        print(f"hint: python scope.py add {host}")
        return 1

    for pat in scope:
        if fnmatch.fnmatch(host, pat):
            print(f"ALLOWED: {host} matches {pat}")
            return 0

    print(f"BLOCKED (not in scope): {host}")
    print(f"hint: python scope.py add {host}")
    return 1


def cmd_ui(args):
    roe = load()
    print("interactive scope editor — type 'help' for commands")
    while True:
        scope = get_scope(roe)
        print(f"\ncurrent in_scope ({len(scope)}):")
        for i, h in enumerate(scope, 1):
            print(f"  {i:3}. {h}")
        try:
            line = input("\nscope> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        parts = line.split(None, 1)
        cmd = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""

        if cmd in ("quit", "exit", "q"):
            break
        elif cmd == "help":
            print("  add <host> [<host> ...]      append")
            print("  remove <host> [<host> ...]   remove")
            print("  del <n> [<n> ...]            delete by index")
            print("  set <host> [<host> ...]      replace all")
            print("  save                         write to disk")
            print("  quit                         save and exit")
        elif cmd == "add":
            for h in arg.replace(",", " ").split():
                if h and h not in scope:
                    if confirm_dangerous(h):
                        scope.append(h)
        elif cmd == "remove":
            for h in arg.replace(",", " ").split():
                if h in scope:
                    scope.remove(h)
        elif cmd == "del":
            try:
                idxs = sorted((int(x) - 1 for x in arg.split()), reverse=True)
                for idx in idxs:
                    if 0 <= idx < len(scope):
                        scope.pop(idx)
            except ValueError:
                print("  invalid index")
        elif cmd == "set":
            new_scope = [h for h in arg.replace(",", " ").split() if h]
            if all(confirm_dangerous(h) for h in new_scope):
                scope[:] = new_scope
        elif cmd == "save":
            roe["scope"]["in_scope"] = scope
            save(roe)
            print("  saved.")
        else:
            print(f"  unknown: {cmd}")
        roe["scope"]["in_scope"] = scope
    roe["scope"]["in_scope"] = scope
    save(roe)
    print("done.")
    return 0


def cmd_help(args):
    print("scope.py — manage configs/roe.yaml scope.in_scope")
    print()
    print("  list                        show current scope")
    print("  add <host> [<host> ...]     append host(s)")
    print("  remove <host> [<host> ...]  remove host(s)")
    print("  set <host> [<host> ...]     replace the whole list")
    print("  test <url>                  check whether a URL would be allowed")
    print("  ui                          interactive editor")
    print("  help                        this message")
    print()
    print("wildcards (fnmatch): * ? [seq]")
    print("  '*.example.com'   matches api.example.com, www.example.com")
    print("  '192.168.1.*'     matches 192.168.1.0/24")
    print("  '*'               matches EVERYTHING — prompt requires YES to confirm")
    print()
    print("examples:")
    print("  python scope.py add scanme.nmap.org")
    print("  python scope.py add '*.staging.example.com'")
    print("  python scope.py test https://scanme.nmap.org/")
    print("  python scope.py ui")
    return 0


COMMANDS = {
    "list": cmd_list, "ls": cmd_list, "show": cmd_list,
    "add": cmd_add,
    "remove": cmd_remove, "rm": cmd_remove,
    "set": cmd_set,
    "test": cmd_test, "check": cmd_test,
    "ui": cmd_ui, "edit": cmd_ui,
    "help": cmd_help, "-h": cmd_help, "--help": cmd_help,
}


def main(argv):
    if not argv:
        return cmd_list([])
    handler = COMMANDS.get(argv[0])
    if not handler:
        print(f"unknown command: {argv[0]}")
        cmd_help([])
        return 1
    return handler(argv[1:]) or 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))