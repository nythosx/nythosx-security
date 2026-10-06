import yaml
from pathlib import Path

ROOT = Path(__file__).parent.absolute()
ADAPTERS_DIR = ROOT / "adapters"

ADAPTERS = {}

ADAPTERS["laravel.yaml"] = r'''id: laravel
name: Laravel / PHP
priority: 100

detect:
  headers_any:
    X-Powered-By:
      - "PHP"
      - "Laravel"
    Server:
      - "PHP"
  cookies_any:
    - "laravel_session"
    - "XSRF-TOKEN"
    - "sanctum"
  html_contains:
    - "csrf-token"
    - "bootstrap/app.php"
  meta_generator: "Laravel"

runtime_config:
  html_patterns:
    - 'apiBase\s*[:=]\s*[\x22\x27]([^\x22\x27]+)[\x22\x27]'
    - 'api_url\s*[:=]\s*[\x22\x27]([^\x22\x27]+)[\x22\x27]'
    - 'API_URL\s*[:=]\s*[\x22\x27]([^\x22\x27]+)[\x22\x27]'
    - 'NUXT_PUBLIC_[A-Z_]*API[A-Z_]*\s*[:=]\s*[\x22\x27]([^\x22\x27]+)[\x22\x27]'
  json_scripts:
    - "__NUXT_DATA__"
    - "__NEXT_DATA__"

auth:
  login_paths:
    - /api/login
    - /api/auth/login
    - /sanctum/csrf-cookie
    - /login
  login_fields:
    - email
    - username
    - identifier
  token_paths:
    - token
    - access_token
    - data.token
  default_header: "Authorization"
  default_prefix: "Bearer "

endpoints:
  auth_probe:
    - /api/me
    - /api/user
    - /api/auth/me
  health:
    - /api/health
    - /up

ports:
  - 8000
  - 8001
  - 8080

api_hints:
  - api
  - auth
  - login
  - logout
  - register
  - token
  - session
  - user
  - account
  - me
  - roster
  - roles
  - permissions
'''

ADAPTERS["nuxt.yaml"] = r'''id: nuxt
name: Nuxt (Vue)
priority: 90

detect:
  headers_any:
    X-Powered-By:
      - "Nuxt"
  cookies_any:
    - "nuxt"
  html_contains:
    - "__NUXT__"
    - "/_nuxt/"
    - "nuxt-link"
  meta_generator: "Nuxt"

runtime_config:
  html_patterns:
    - 'apiBase\s*[:=]\s*[\x22\x27]([^\x22\x27]+)[\x22\x27]'
    - 'NUXT_PUBLIC_[A-Z_]*API[A-Z_]*\s*[:=]\s*[\x22\x27]([^\x22\x27]+)[\x22\x27]'
  json_scripts:
    - "__NUXT_DATA__"

auth:
  login_paths:
    - /api/login
    - /api/auth/login
    - /login
  login_fields:
    - email
    - username
  token_paths:
    - token
    - access_token
    - data.token
  default_header: "Authorization"
  default_prefix: "Bearer "

endpoints:
  auth_probe:
    - /api/me
    - /api/user
  health:
    - /api/health

ports:
  - 3000
  - 3001

api_hints:
  - api
  - auth
  - login
  - me
  - user
'''

ADAPTERS["nextjs.yaml"] = r'''id: nextjs
name: Next.js (React)
priority: 90

detect:
  headers_any:
    X-Powered-By:
      - "Next.js"
  cookies_any:
    - "next-auth"
    - "__Secure-next-auth"
  html_contains:
    - "__NEXT_DATA__"
    - "/_next/"
    - "next/head"
  meta_generator: "Next.js"

runtime_config:
  html_patterns:
    - 'NEXT_PUBLIC_[A-Z_]+_URL\s*[:=]\s*[\x22\x27]([^\x22\x27]+)[\x22\x27]'
    - 'NEXT_PUBLIC_API[A-Z_]*\s*[:=]\s*[\x22\x27]([^\x22\x27]+)[\x22\x27]'
  json_scripts:
    - "__NEXT_DATA__"

auth:
  login_paths:
    - /api/auth/login
    - /api/auth/callback/credentials
    - /api/login
    - /login
  login_fields:
    - email
    - username
  token_paths:
    - token
    - access_token
    - data.token
  default_header: "Authorization"
  default_prefix: "Bearer "

endpoints:
  auth_probe:
    - /api/auth/session
    - /api/me
    - /api/user
  health:
    - /api/health

ports:
  - 3000
  - 3001

api_hints:
  - api
  - auth
  - session
  - me
  - user
'''

ADAPTERS["django.yaml"] = r'''id: django
name: Django (Python)
priority: 80

detect:
  headers_any:
    Server:
      - "WSGIServer"
      - "gunicorn"
    X-Frame-Options:
      - "DENY"
      - "SAMEORIGIN"
  cookies_any:
    - "csrftoken"
    - "sessionid"
    - "django_language"
  html_contains:
    - "csrfmiddlewaretoken"
    - "django"
  meta_generator: ""

runtime_config:
  html_patterns:
    - 'window\.__DJANGO__\s*=\s*(\{[^}]+\})'
    - 'API_BASE\s*=\s*[\x22\x27]([^\x22\x27]+)[\x22\x27]'
  json_scripts: []

auth:
  login_paths:
    - /api-auth/login/
    - /accounts/login/
    - /api/login/
    - /login/
    - /admin/login/
  login_fields:
    - username
    - email
  token_paths:
    - token
    - access
    - data.token
  default_header: "Authorization"
  default_prefix: "Bearer "

endpoints:
  auth_probe:
    - /api/me/
    - /api/user/
    - /api/users/me/
  health:
    - /health/
    - /api/health/

ports:
  - 8000
  - 8080
  - 8888

api_hints:
  - api
  - auth
  - accounts
  - login
  - me
  - user
'''

ADAPTERS["rails.yaml"] = r'''id: rails
name: Ruby on Rails
priority: 80

detect:
  headers_any:
    X-Powered-By:
      - "Phusion Passenger"
    Server:
      - "WEBrick"
      - "Puma"
  cookies_any:
    - "_rails_session"
    - "_session_id"
  html_contains:
    - "csrf-token"
    - "data-turbo"
    - "rails-ujs"
  meta_generator: ""

runtime_config:
  html_patterns:
    - 'window\.apiUrl\s*=\s*[\x22\x27]([^\x22\x27]+)[\x22\x27]'
  json_scripts: []

auth:
  login_paths:
    - /api/v1/login
    - /users/sign_in
    - /api/login
    - /login
  login_fields:
    - email
    - username
  token_paths:
    - token
    - access_token
    - auth_token
  default_header: "Authorization"
  default_prefix: "Bearer "

endpoints:
  auth_probe:
    - /api/v1/me
    - /api/me
    - /api/users/me
  health:
    - /up
    - /health

ports:
  - 3000
  - 3001

api_hints:
  - api
  - auth
  - users
  - me
  - session
'''

ADAPTERS["express.yaml"] = r'''id: express
name: Express / Node.js
priority: 70

detect:
  headers_any:
    X-Powered-By:
      - "Express"
  cookies_any:
    - "connect.sid"
    - "express-session"
  html_contains: []
  meta_generator: ""

runtime_config:
  html_patterns:
    - 'window\.__API[A-Z_]*__\s*=\s*[\x22\x27]([^\x22\x27]+)[\x22\x27]'
    - 'API_URL\s*[:=]\s*[\x22\x27]([^\x22\x27]+)[\x22\x27]'
  json_scripts: []

auth:
  login_paths:
    - /api/auth/login
    - /api/login
    - /auth/login
    - /login
  login_fields:
    - email
    - username
  token_paths:
    - token
    - accessToken
    - access_token
    - data.token
  default_header: "Authorization"
  default_prefix: "Bearer "

endpoints:
  auth_probe:
    - /api/me
    - /api/user
    - /api/users/me
  health:
    - /health
    - /api/health

ports:
  - 3000
  - 3001
  - 5000
  - 8080

api_hints:
  - api
  - auth
  - login
  - me
  - user
'''

ADAPTERS["aspnet.yaml"] = r'''id: aspnet
name: ASP.NET (.NET)
priority: 85

detect:
  headers_any:
    X-AspNet-Version:
      - ".+"
    X-AspNetMvc-Version:
      - ".+"
    Server:
      - "Kestrel"
      - "IIS"
  cookies_any:
    - "ASP.NET_SessionId"
    - ".AspNetCore.Session"
    - ".AspNetCore.Identity.Application"
  html_contains:
    - "__RequestVerificationToken"
    - "aspnet"
  meta_generator: ""

runtime_config:
  html_patterns:
    - 'window\.__API__\s*=\s*[\x22\x27]([^\x22\x27]+)[\x22\x27]'
  json_scripts: []

auth:
  login_paths:
    - /api/auth/login
    - /Account/Login
    - /api/login
    - /login
  login_fields:
    - Email
    - UserName
    - username
    - email
  token_paths:
    - token
    - access_token
    - data.token
  default_header: "Authorization"
  default_prefix: "Bearer "

endpoints:
  auth_probe:
    - /api/me
    - /api/user
    - /api/users/me
  health:
    - /health
    - /healthz

ports:
  - 5000
  - 5001
  - 8080
  - 44300

api_hints:
  - api
  - auth
  - account
  - me
  - user
'''

ADAPTERS["generic.yaml"] = r'''id: generic
name: Generic (Fallback)
priority: 1

detect:
  headers_any: {}
  cookies_any: []
  html_contains: []
  meta_generator: ""

runtime_config:
  html_patterns:
    - 'apiBase\s*[:=]\s*[\x22\x27]([^\x22\x27]+)[\x22\x27]'
    - 'baseURL\s*[:=]\s*[\x22\x27]([^\x22\x27]+)[\x22\x27]'
    - 'apiUrl\s*[:=]\s*[\x22\x27]([^\x22\x27]+)[\x22\x27]'
    - 'API_URL\s*[:=]\s*[\x22\x27]([^\x22\x27]+)[\x22\x27]'
    - 'API_BASE\s*[:=]\s*[\x22\x27]([^\x22\x27]+)[\x22\x27]'
    - 'window\.__API[A-Z_]*__\s*=\s*[\x22\x27]([^\x22\x27]+)[\x22\x27]'
  json_scripts:
    - "__NUXT_DATA__"
    - "__NEXT_DATA__"

auth:
  login_paths:
    - /api/login
    - /api/auth/login
    - /api/v1/login
    - /auth/login
    - /login
    - /signin
  login_fields:
    - email
    - username
    - identifier
    - user
  token_paths:
    - token
    - access_token
    - accessToken
    - data.token
    - jwt
  default_header: "Authorization"
  default_prefix: "Bearer "

endpoints:
  auth_probe:
    - /api/me
    - /api/user
    - /api/users/me
  health:
    - /api/health
    - /health

ports:
  - 3000
  - 3001
  - 4000
  - 5000
  - 8000
  - 8080
  - 9000

api_hints:
  - api
  - auth
  - login
  - me
  - user
  - account
  - session
  - token
'''


def write_all():
    ADAPTERS_DIR.mkdir(parents=True, exist_ok=True)
    for name, content in sorted(ADAPTERS.items()):
        p = ADAPTERS_DIR / name
        p.write_text(content, encoding="utf-8")
        print(f"  [ OK ]  adapters/{name}")


def validate_all():
    errors = []
    valid = 0
    for name in sorted(ADAPTERS):
        p = ADAPTERS_DIR / name
        try:
            data = yaml.safe_load(p.read_text(encoding="utf-8"))
            if not data or "id" not in data:
                errors.append((name, "missing id"))
                continue
            valid += 1
        except Exception as e:
            errors.append((name, str(e)[:200]))
    return valid, errors


def main():
    print()
    print("=" * 62)
    print("  FIX ADAPTERS  ::  YAML escaping repair")
    print("=" * 62)
    print()
    print("  Rewriting adapters with hex-escaped regex...")
    print()
    write_all()
    print()
    print("  Validating YAML...")
    valid, errors = validate_all()
    print()
    if errors:
        for name, err in errors:
            print(f"  [FAIL]  {name}")
            print(f"          {err}")
        print()
        print(f"  {valid} valid, {len(errors)} invalid")
        return
    print(f"  [ OK ]  All {valid} adapters valid")
    print()
    print("=" * 62)
    print("  DONE")
    print("=" * 62)
    print()
    print("  Test:")
    print("    python run.py adapters")
    print("    python run.py auto http://localhost:3000")
    print()


if __name__ == "__main__":
    main()