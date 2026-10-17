import secrets
import threading
import time
from dataclasses import dataclass, field

from . import auth_flow
from .config import load_engine
from .roe_guard import ROEGuard, ROEViolation
from . import http as _http


def _redact(value):
    try:
        from . import redact as _r
        return _r.redact_text(str(value))
    except Exception:
        return str(value)


def _rand_email(prefix="sec"):
    return f"{prefix}-{secrets.token_hex(4)}@test.local"


def _rand_password():
    return "Sc!" + secrets.token_urlsafe(12)


def _bearer_from_headers(headers):
    if not headers:
        return ""
    for k, v in headers.items():
        if k.lower() == "authorization" and isinstance(v, str):
            if v.lower().startswith("bearer "):
                return v[7:]
            return v
    return ""


_SIGNUP_PATHS = [
    "/api/register", "/api/signup", "/api/auth/register",
    "/api/v1/register", "/api/v1/signup", "/api/v1/auth/register",
    "/api/v1/users", "/register", "/signup", "/auth/register",
    "/users/register", "/user/register",
]

_LOGIN_PATHS = [
    "/api/login", "/api/auth/login", "/api/v1/login",
    "/api/v1/auth/login", "/login", "/signin", "/auth/login",
]

_LIVENESS_PATHS = ["/api/me", "/api/v1/me", "/api/user", "/api/v1/user"]


@dataclass
class IdentityContext:
    name: str
    headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)
    known_ids: list = field(default_factory=list)
    username: str = ""
    password: str = ""
    token: str = ""
    login_url: str = ""
    signup_url: str = ""
    created: bool = False
    created_at: float = 0.0
    last_refresh: float = 0.0
    refresh_failures: int = 0

    def get_headers(self):
        h = dict(self.headers)
        if self.cookies and not any(k.lower() == "cookie" for k in h):
            h["Cookie"] = "; ".join(
                f"{k}={v}" for k, v in self.cookies.items())
        return h

    def to_safe_dict(self):
        return {
            "name": self.name,
            "username": self.username,
            "known_ids": list(self.known_ids),
            "has_token": bool(self.token),
            "has_cookies": bool(self.cookies),
            "login_url": self.login_url,
            "signup_url": self.signup_url,
            "created": self.created,
        }


class IdentityBrokerError(RuntimeError):
    pass


class IdentityBroker:
    def __init__(self, target, roe_guard=None, engine_cfg=None,
                 fact_store=None, diag=None, warn=None):
        self.base_url = (target or "").rstrip("/")
        self.roe_guard = roe_guard
        self.engine_cfg = (engine_cfg if engine_cfg is not None
                            else load_engine())
        self.fact_store = fact_store
        self._diag = diag or (lambda *a, **k: None)
        self._warn = warn or (lambda *a, **k: None)
        self.identities = {"anon": IdentityContext(name="anon")}
        self._lock = threading.RLock()
        self._initialized = False
        self.discovered = {"signup_url": None, "login_url": None}
        self.cleanup_endpoint = None

    def _emit_diag(self, category, severity, detail, **extra):
        try:
            self._diag(category, severity, _redact(detail), **extra)
        except Exception:
            pass

    def _emit_warn(self, code, detail, **extra):
        try:
            self._warn(code, _redact(detail), **extra)
        except Exception:
            pass

    def _roe_ok(self, url, method):
        if self.roe_guard is None:
            return True
        try:
            self.roe_guard.check_url(url, method)
            return True
        except ROEViolation:
            return False

    def initialize(self, adapter=None, paths=None):
        if self._initialized:
            return
        self._initialized = True
        if self.fact_store is not None:
            self._consume_recon_facts()
        self._discover_endpoints(adapter or {}, paths or {})
        self._try_auto_signup()
        try:
            self._seed_admin_from_config()
        except Exception:
            pass
        self._publish_facts()

    def _consume_recon_facts(self):
        fs = self.fact_store
        for key, slot in (("signup_url", "signup_url"),
                          ("login_url", "login_url")):
            if fs.has(key):
                val = fs.get(key)
                if isinstance(val, str) and val:
                    self.discovered[slot] = val

    def _discover_endpoints(self, adapter, paths):
        auth_cfg = adapter.get("auth") or {}
        login_candidates = []
        if isinstance(self.discovered.get("login_url"), str):
            login_candidates.append(self.discovered["login_url"])
        login_candidates.extend(auth_cfg.get("login_paths") or [])
        login_candidates.extend(_LOGIN_PATHS)
        for p in (paths or {}).get("login") or []:
            login_candidates.insert(0, p)
        for p in (paths or {}).get("signup") or []:
            if not self.discovered.get("signup_url"):
                self.discovered["signup_url"] = p
        for cand in login_candidates:
            if cand:
                self.discovered["login_url"] = cand
                break
        self._emit_diag(
            "identity_broker", "info",
            f"login={self.discovered.get('login_url') or ''} "
            f"signup={self.discovered.get('signup_url') or ''}",
        )

    def _try_auto_signup(self):
        signup_paths = []
        if self.discovered.get("signup_url"):
            signup_paths.append(self.discovered["signup_url"])
        signup_paths.extend(_SIGNUP_PATHS)
        seen = set()
        ordered = []
        for p in signup_paths:
            if p and p not in seen:
                seen.add(p)
                ordered.append(p)

        for path in ordered:
            url = (path if path.startswith("http")
                    else self.base_url + path)
            if not self._roe_ok(url, "POST"):
                continue
            pw = _rand_password()
            if not self._try_signup(url, _rand_email("sec-a"), pw, "user_a"):
                continue
            if self._try_signup(url, _rand_email("sec-b"), pw, "user_b"):
                self.cleanup_endpoint = url
                return

    def _try_signup(self, url, email, password, name):
        payload = {
            "email": email,
            "username": email,
            "password": password,
            "password_confirmation": password,
        }
        try:
            with _http.Client(timeout=10, verify=True,
                              follow_redirects=False) as c:
                r = c.post(url, json=payload)
        except _http.ROEBlock as e:
            self._emit_warn("identity_broker_roe_block", str(e))
            return False
        except _http.TimeoutException:
            self._emit_diag("identity_broker", "warning",
                            f"signup timeout at {url}")
            return False
        except Exception as e:
            self._emit_diag(
                "identity_broker", "warning",
                f"signup error at {url}: {type(e).__name__}: {e}",
            )
            return False
        if r.status_code not in (200, 201, 202):
            return False
        session = self._extract_session(r)
        if not session:
            session = self._try_login(
                self.discovered.get("login_url"), email, password)
        if not session:
            return False
        ctx_headers = session.get("auth_headers") or {}
        ctx_cookies = session.get("cookies") or {}
        ctx_token = session.get("token") or ""
        self.add_identity(
            name, ctx_headers, ctx_cookies,
            username=email, password=password, token=ctx_token,
            login_url=self.discovered.get("login_url") or "",
            signup_url=url, created=True,
        )
        self._emit_diag("identity_broker", "info",
                        f"created identity {name} via {url}")
        return True

    def _try_login(self, login_path, email, password):
        if not login_path:
            return None
        url = (login_path if login_path.startswith("http")
               else self.base_url + login_path)
        if not self._roe_ok(url, "POST"):
            return None
        for attempt in range(3):
            try:
                r = auth_flow.perform_login(
                    url, email, password,
                    login_type="json",
                    username_field="email",
                    password_field="password",
                    token_path="token",
                )
            except Exception as e:
                self._emit_diag(
                    "identity_broker", "warning",
                    f"login error at {url}: {type(e).__name__}",
                )
                return None
            status = r.get("status")
            if status == 429:
                time.sleep(2 ** attempt)
                continue
            if r.get("token"):
                return {
                    "auth_headers": {
                        "Authorization": f"Bearer {r['token']}"
                    },
                    "cookies": r.get("cookies") or {},
                    "token": r["token"],
                }
            return None
        return None

    def _extract_session(self, response):
        session = {"auth_headers": {}, "cookies": {}, "token": ""}
        try:
            data = response.json()
        except Exception:
            data = {}
        for path in (("token",), ("access_token",), ("data", "token"),
                     ("data", "access_token"), ("jwt",)):
            cur = data
            ok = True
            for p in path:
                if isinstance(cur, dict):
                    cur = cur.get(p)
                else:
                    ok = False
                    break
                if cur is None:
                    ok = False
                    break
            if ok and isinstance(cur, str) and len(cur) > 15:
                session["auth_headers"]["Authorization"] = f"Bearer {cur}"
                session["token"] = cur
                break
        try:
            session["cookies"] = dict(response.cookies)
        except Exception:
            pass
        if not (session["auth_headers"] or session["cookies"]):
            return None
        return session

    def add_identity(self, name, headers=None, cookies=None,
                     known_ids=None, username="", password="",
                     token="", login_url="", signup_url="",
                     created=False):
        with self._lock:
            ctx = IdentityContext(
                name=name,
                headers=dict(headers or {}),
                cookies=dict(cookies or {}),
                known_ids=list(known_ids or []),
                username=username,
                password=password,
                token=token,
                login_url=login_url,
                signup_url=signup_url,
                created=created,
                created_at=time.time(),
            )
            self.identities[name] = ctx

    def get_identity(self, name):
        return self.identities.get(name)

    def get_all_authenticated(self):
        return {k: v for k, v in self.identities.items() if k != "anon"}

    def has_two_identities(self):
        return all(n in self.identities for n in ("user_a", "user_b"))

    def identity_token(self, name):
        ctx = self.identities.get(name)
        if not ctx:
            return ""
        return ctx.token or _bearer_from_headers(ctx.headers)

    def refresh_identity(self, name):
        ctx = self.identities.get(name)
        if not ctx or not ctx.username or not ctx.password:
            return False
        if not ctx.login_url:
            return False
        if time.time() - ctx.last_refresh < 30:
            return True
        session = self._try_login(ctx.login_url, ctx.username, ctx.password)
        if not session:
            ctx.refresh_failures += 1
            return False
        ctx.headers = session.get("auth_headers") or {}
        ctx.cookies = session.get("cookies") or {}
        ctx.token = session.get("token") or ""
        ctx.last_refresh = time.time()
        ctx.refresh_failures = 0
        return True

    def seed_admin(self, creds):
        if not creds:
            return False
        username = creds.get("username") or ""
        password = creds.get("password") or ""
        if not (username and password):
            return False
        login_url = creds.get("login_url") or self.discovered.get("login_url") or ""
        if not login_url:
            return False
        session = self._try_login(login_url, username, password)
        if not session:
            self._emit_diag("identity_broker", "warning",
                            f"seed_admin: login failed at {login_url}")
            return False
        known = list(creds.get("known_ids") or [1, 2, 3])
        self.add_identity(
            "admin",
            headers=session.get("auth_headers") or {},
            cookies=session.get("cookies") or {},
            token=session.get("token") or "",
            username=username,
            password=password,
            login_url=login_url,
            known_ids=known,
            created=True,
        )
        self._emit_diag("identity_broker", "info",
                        f"seeded admin identity via {login_url}")
        return True

    def refresh_on_auth_error(self, name, status):
        if status not in (401, 403):
            return False
        return self.refresh_identity(name)

    def learn_ids_from_response(self, name, body):
        if not body or not name:
            return []
        ctx = self.identities.get(name)
        if ctx is None:
            return []
        import json as _json
        try:
            data = _json.loads(body)
        except Exception:
            return []
        found = []
        _ID_KEYS = frozenset({
            "id", "user_id", "userid", "account_id", "accountid",
            "uid", "customer_id", "customerid", "profile_id", "profileid",
        })

        def walk(o, depth=0):
            if depth > 8 or len(found) >= 200:
                return
            if isinstance(o, dict):
                for k, v in o.items():
                    kl = str(k).lower()
                    if kl in _ID_KEYS and isinstance(v, (int, str)) \
                            and not isinstance(v, bool):
                        found.append(v)
                    walk(v, depth + 1)
            elif isinstance(o, list):
                for item in o[:50]:
                    walk(item, depth + 1)

        walk(data)
        added = []
        for fid in found:
            if fid not in ctx.known_ids:
                ctx.known_ids.append(fid)
                added.append(fid)
        return added

    def _seed_admin_from_config(self):
        try:
            from .config import load_targets
            targets = load_targets().get("targets") or {}
        except Exception:
            return False
        for _name, spec in targets.items():
            if not isinstance(spec, dict):
                continue
            url = str(spec.get("url") or "").rstrip("/")
            if not url:
                continue
            if url != self.base_url:
                continue
            auth = spec.get("auth") or {}
            if not isinstance(auth, dict):
                continue
            admin = auth.get("admin")
            if not isinstance(admin, dict):
                continue
            if not (admin.get("username") and admin.get("password")):
                continue
            return self.seed_admin({
                "username": admin["username"],
                "password": admin["password"],
                "login_url": (admin.get("login_url")
                              or auth.get("login_url") or ""),
                "known_ids": admin.get("known_ids") or [1, 2, 3],
            })
        return False

    def probe_liveness(self, name):
        ctx = self.identities.get(name)
        if not ctx:
            return False
        for path in _LIVENESS_PATHS:
            url = self.base_url + path
            if not self._roe_ok(url, "GET"):
                continue
            try:
                with _http.Client(timeout=6, verify=True,
                                  follow_redirects=False) as c:
                    r = c.get(url, headers=ctx.get_headers())
            except Exception:
                continue
            if r.status_code == 200:
                return True
        return False

    def ensure_healthy(self):
        for name in ("user_a", "user_b"):
            if name not in self.identities:
                continue
            if not self.probe_liveness(name):
                self.refresh_identity(name)

    def cleanup(self):
        if not self.cleanup_endpoint:
            self._emit_diag(
                "identity_broker", "info",
                "no cleanup endpoint declared, test accounts left in place",
            )
            return
        for name in ("user_a", "user_b"):
            ctx = self.identities.get(name)
            if not ctx or not ctx.created:
                continue
            url = self.cleanup_endpoint
            if not self._roe_ok(url, "DELETE"):
                continue
            try:
                with _http.Client(timeout=8, verify=True,
                                  follow_redirects=False) as c:
                    c.request("DELETE", url, headers=ctx.get_headers())
            except Exception:
                continue

    def _publish_facts(self):
        fs = self.fact_store
        if fs is None:
            return
        for name, letter in (("user_a", "a"), ("user_b", "b")):
            if name in self.identities:
                fs.add(f"has_identity_{letter}", True,
                       source="identity_broker", confidence=0.95)
                ids = self.identities[name].known_ids
                if ids:
                    fs.add(f"identity_{letter}_uid", ids[0],
                           source="identity_broker", confidence=0.9)
        fs.add("identity_broker_available", self.has_two_identities(),
               source="identity_broker", confidence=0.95)


__all__ = ["IdentityBroker", "IdentityContext", "IdentityBrokerError"]
