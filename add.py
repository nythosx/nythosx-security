import sys
import yaml
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).parent.absolute()
ROE_PATH = ROOT / "configs" / "roe.yaml"

def load_roe():
    if not ROE_PATH.exists():
        return {
            "enabled": True,
            "scope": {
                "in_scope": ["localhost", "127.0.0.1", "::1", "*.local", "*.test"],
                "out_of_scope": ["*.gov", "*.mil"],
                "allowed_methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
                "forbidden_paths": []
            }
        }
    try:
        return yaml.safe_load(ROE_PATH.read_text(encoding="utf-8")) or {}
    except Exception as e:
        print(f"[ERROR] Cannot parse {ROE_PATH}: {e}")
        sys.exit(1)

def save_roe(roe):
    ROE_PATH.parent.mkdir(parents=True, exist_ok=True)
    ROE_PATH.write_text(
        yaml.safe_dump(roe, sort_keys=False, default_flow_style=False, allow_unicode=True),
        encoding="utf-8"
    )

def normalize_domain(domain):
    """Extract and normalize the base domain from a URL or raw domain string."""
    domain = domain.strip().lower()
    if domain.startswith("http://") or domain.startswith("https://"):
        parsed = urlparse(domain)
        domain = parsed.hostname or domain
    
    # Remove leading/trailing dots and wildcards to get the clean base domain
    domain = domain.strip(".*")
    return domain

def add_client(domain):
    base_domain = normalize_domain(domain)
    if not base_domain:
        print("[ERROR] Invalid domain provided.")
        sys.exit(1)
        
    wildcard_domain = f"*.{base_domain}"
    
    roe = load_roe()
    scope = roe.setdefault("scope", {})
    in_scope = scope.setdefault("in_scope", [])
    
    added = False
    if base_domain not in in_scope:
        in_scope.append(base_domain)
        added = True
        
    if wildcard_domain not in in_scope:
        in_scope.append(wildcard_domain)
        added = True
        
    if added:
        save_roe(roe)
        print(f"[SUCCESS] Added to scope:")
        print(f"  - {base_domain}")
        print(f"  - {wildcard_domain}")
        print("\nHint: Restart the web UI (`python run.py web`) if it is running.")
    else:
        print(f"[INFO] {base_domain} and {wildcard_domain} are already in scope.")

def remove_client(domain):
    base_domain = normalize_domain(domain)
    if not base_domain:
        print("[ERROR] Invalid domain provided.")
        sys.exit(1)
        
    wildcard_domain = f"*.{base_domain}"
    
    roe = load_roe()
    scope = roe.setdefault("scope", {})
    in_scope = scope.setdefault("in_scope", [])
    
    removed = False
    if base_domain in in_scope:
        in_scope.remove(base_domain)
        removed = True
    if wildcard_domain in in_scope:
        in_scope.remove(wildcard_domain)
        removed = True
        
    if removed:
        save_roe(roe)
        print(f"[SUCCESS] Removed from scope:")
        print(f"  - {base_domain}")
        print(f"  - {wildcard_domain}")
    else:
        print(f"[INFO] {base_domain} was not in scope.")

def list_clients():
    roe = load_roe()
    scope = roe.get("scope", {})
    in_scope = scope.get("in_scope", [])
    
    print(f"Configs/ROE Scope (enabled={roe.get('enabled', True)}):")
    print(f"  in_scope ({len(in_scope)} entries):")
    for h in in_scope:
        print(f"    - {h}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Universal Scope Manager")
        print("Usage:")
        print("  python a.py add <domain>     # Add a domain and its wildcard to scope")
        print("  python a.py remove <domain>  # Remove a domain and its wildcard from scope")
        print("  python a.py list             # List all currently scoped domains")
        print("\nExamples:")
        print("  python a.py add example.com")
        print("  python a.py add https://api.example.com")
        print("  python a.py remove example.com")
        sys.exit(0)
        
    action = sys.argv[1].lower()
    
    if action == "add":
        if len(sys.argv) < 3:
            print("[ERROR] Please provide a domain. Usage: python a.py add <domain>")
            sys.exit(1)
        add_client(sys.argv[2])
    elif action == "remove":
        if len(sys.argv) < 3:
            print("[ERROR] Please provide a domain. Usage: python a.py remove <domain>")
            sys.exit(1)
        remove_client(sys.argv[2])
    elif action == "list":
        list_clients()
    else:
        print(f"[ERROR] Unknown action: {action}")
        print("Use 'add', 'remove', or 'list'")
        sys.exit(1)