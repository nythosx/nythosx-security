import sys
from pathlib import Path
import yaml

ROOT = Path(__file__).parent.absolute()

USERNAME = "evt.admin@tamid.test"
PASSWORD = "43c6b5b043c6393b"
LOGIN_URL = "http://127.0.0.1:8000/api/login"
TARGET_URL = "http://localhost:3000"

TARGETS_FILE = ROOT / "configs" / "targets.yaml"
CREDS_FILE = ROOT / "configs" / "credentials.yaml"

TARGETS_DATA = {
    "targets": {
        "local-dev": {
            "url": TARGET_URL,
            "auth": {
                "type": "login",
                "login_url": LOGIN_URL,
                "login_type": "json",
                "username": USERNAME,
                "password": PASSWORD,
                "username_field": "email",
                "password_field": "password",
                "token_path": "token",
                "token_header": "Authorization",
                "token_prefix": "Bearer ",
            },
            "notes": "TAMID local dev - Nuxt frontend + Laravel API",
        },
        "local-api": {
            "url": LOGIN_URL.rsplit("/", 1)[0],
            "auth": {
                "type": "login",
                "login_url": LOGIN_URL,
                "login_type": "json",
                "username": USERNAME,
                "password": PASSWORD,
                "username_field": "email",
                "password_field": "password",
                "token_path": "token",
                "token_header": "Authorization",
                "token_prefix": "Bearer ",
            },
            "notes": "Direct API endpoint",
        },
    }
}

CREDS_DATA = {
    "credentials": {
        "localhost": {
            "username": USERNAME,
            "password": PASSWORD,
            "login_url": LOGIN_URL,
            "login_type": "json",
            "username_field": "email",
            "password_field": "password",
            "token_path": "token",
        },
        "127.0.0.1": {
            "username": USERNAME,
            "password": PASSWORD,
            "login_url": LOGIN_URL,
            "login_type": "json",
            "username_field": "email",
            "password_field": "password",
            "token_path": "token",
        },
    }
}


def write_yaml(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    text = yaml.safe_dump(data, default_flow_style=False, sort_keys=False,
                           allow_unicode=True)
    path.write_text(text, encoding="utf-8")


def show_file(path):
    print()
    print("-" * 60)
    print(f"  {path.relative_to(ROOT)}")
    print("-" * 60)
    print(path.read_text(encoding="utf-8"))


def test_login():
    try:
        import httpx
    except ImportError:
        print("[SKIP] httpx not installed")
        return
    print()
    print("=" * 60)
    print("  TESTING LOGIN")
    print("=" * 60)
    print(f"  URL: {LOGIN_URL}")
    print(f"  User: {USERNAME}")
    print()
    try:
        r = httpx.post(LOGIN_URL, json={"email": USERNAME, "password": PASSWORD},
                        timeout=10.0, follow_redirects=False)
    except Exception as e:
        print(f"  [FAIL] Connection error: {e}")
        return
    print(f"  Status: {r.status_code}")
    print(f"  Content-Type: {r.headers.get('Content-Type', '')}")
    body = r.text or ""
    print(f"  Body preview: {body[:400]}")
    print()
    if r.status_code == 200:
        try:
            data = r.json()
            print("  [ OK ] Login SUCCESS")
            print(f"  Response keys: {list(data.keys())}")
            if "token" in data:
                print(f"  Token (first 60): {str(data['token'])[:60]}")
            elif "access_token" in data:
                print(f"  access_token (first 60): {str(data['access_token'])[:60]}")
            elif "data" in data and isinstance(data["data"], dict):
                print(f"  data.* keys: {list(data['data'].keys())}")
        except Exception:
            print("  [WARN] 200 but not JSON")
    elif r.status_code == 401:
        print("  [FAIL] 401 Invalid credentials")
        print("  Check the PASSWORD value in fix_creds.py")
    elif r.status_code == 422:
        print("  [FAIL] 422 Field mismatch")
        try:
            print(f"  Errors: {r.json()}")
        except Exception:
            pass
    else:
        print(f"  [WARN] Unexpected status: {r.status_code}")


def main():
    print()
    print("=" * 60)
    print("  FIX CREDENTIALS")
    print("=" * 60)
    print(f"  Root     : {ROOT}")
    print(f"  Username : {USERNAME}")
    print(f"  Password : {'*' * len(PASSWORD)}")
    print(f"  Login URL: {LOGIN_URL}")
    print()
    print("  Writing config files...")
    write_yaml(TARGETS_FILE, TARGETS_DATA)
    print(f"  [ OK ] {TARGETS_FILE.relative_to(ROOT)}")
    write_yaml(CREDS_FILE, CREDS_DATA)
    print(f"  [ OK ] {CREDS_FILE.relative_to(ROOT)}")

    show_file(TARGETS_FILE)

    test_login()

    print()
    print("=" * 60)
    print("  DONE")
    print("=" * 60)
    print()
    print("  Next:")
    print("    python run.py login local-dev")
    print()


if __name__ == "__main__":
    main()