"""SCA — Software Composition Analysis via OSV.dev.

Fixes (2026-10-10, Claude Code handoff):
- Real lockfile parsers (poetry.lock, Cargo.lock, Gemfile.lock)
- build.gradle parsed via regex, not XML
- TLS verification from engine config (http.verify_tls)
- Degraded markers instead of silent 0-dep returns

NOTE: OSV.dev is an external vulnerability database, NOT a scan target.
Per SEC-CHECKER ROE policy, outbound calls to vuln DBs are an allowed
exception and are NOT routed through ROEGuard.
"""
import json
import os
import re
from pathlib import Path
from urllib.parse import quote

import httpx

try:
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib  # type: ignore
    except ImportError:
        tomllib = None


OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
OSV_MAX_BATCH = 1000

ECOSYSTEMS = {
    "package.json": "npm", "package-lock.json": "npm",
    "requirements.txt": "PyPI", "requirements-dev.txt": "PyPI",
    "pyproject.toml": "PyPI", "Pipfile": "PyPI", "poetry.lock": "PyPI",
    "composer.json": "Packagist", "composer.lock": "Packagist",
    "pom.xml": "Maven", "build.gradle": "Maven",
    "go.mod": "Go",
    "Cargo.toml": "crates.io", "Cargo.lock": "crates.io",
    "Gemfile": "RubyGems", "Gemfile.lock": "RubyGems",
    "nuget.config": "NuGet", "packages.config": "NuGet",
}
SKIP_DIRS = {".git", "node_modules", "vendor", "__pycache__", ".venv",
             "venv", "dist", "build", ".next", ".nuxt", "target"}
from .contract import SEVERITY_ORDER as SEVERITY_RANK  # noqa: E402


def _verify_tls():
    try:
        from .config import load_engine
        return bool(load_engine().get("http", {}).get("verify_tls", True))
    except Exception:
        return True


def _client(timeout=30):
    return httpx.Client(timeout=timeout, verify=_verify_tls())


def discover_dependency_files(root):
    root = Path(root)
    if not root.exists():
        return []
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if fn in ECOSYSTEMS:
                found.append(Path(dirpath) / fn)
    return found


def read_text(path):
    try:
        return Path(path).read_text(encoding="utf-8")
    except Exception:
        try:
            return Path(path).read_text(encoding="latin-1")
        except Exception:
            return ""


def _clean_semver(spec):
    if not spec:
        return ""
    spec = str(spec).strip()
    spec = re.sub(r"^[\^~>=<v\s]+", "", spec)
    spec = spec.split(" ")[0].split("||")[0].strip()
    m = re.match(r"^[\d]+\.[\d]+(?:\.[\d]+)?", spec)
    return m.group(0) if m else ""


def _degraded(reason):
    return {"_degraded": True, "reason": reason}


# ---------- parsers ----------
def _parse_package_json(path):
    try:
        data = json.loads(read_text(path))
    except Exception:
        return []
    deps = []
    for section in ("dependencies", "devDependencies", "peerDependencies",
                    "optionalDependencies"):
        for name, spec in (data.get(section) or {}).items():
            v = _clean_semver(spec)
            if v:
                deps.append({"name": name, "version": v,
                             "ecosystem": "npm", "scope": section})
    return deps


def _parse_package_lock(path):
    try:
        data = json.loads(read_text(path))
    except Exception:
        return []
    deps = []
    for pkg_path, info in (data.get("packages") or {}).items():
        if not pkg_path:
            continue
        name = info.get("name") or pkg_path.replace("node_modules/", "")
        version = info.get("version")
        if name and version:
            deps.append({"name": name, "version": version,
                         "ecosystem": "npm", "scope": "lock"})
    return deps


def _parse_requirements(path):
    deps = []
    for line in read_text(path).splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        line = line.split(";")[0].strip()
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(?:[=<>!~]+)\s*([\w.\-+]+)", line)
        if m:
            deps.append({"name": m.group(1), "version": m.group(2),
                         "ecosystem": "PyPI", "scope": "direct"})
    return deps


def _parse_pyproject(path):
    deps = []
    m = re.search(r"dependencies\s*=\s*\[([^\]]+)\]", read_text(path), re.DOTALL)
    if m:
        for item in re.findall(r'"([^"]+)"', m.group(1)):
            mm = re.match(r"^([A-Za-z0-9_.\-]+)\s*[=<>!~]+\s*([\w.\-+]+)", item)
            if mm:
                deps.append({"name": mm.group(1), "version": mm.group(2),
                             "ecosystem": "PyPI", "scope": "direct"})
    return deps


def _parse_poetry_lock(path):
    if tomllib is None:
        return [_degraded("poetry.lock requires tomli (pip install tomli)")]
    try:
        data = tomllib.loads(read_text(path))
    except Exception as e:
        return [_degraded(f"poetry.lock parse error: {e}")]
    deps = []
    for pkg in (data.get("package") or []):
        n, v = pkg.get("name"), pkg.get("version")
        if n and v:
            deps.append({"name": n, "version": v,
                         "ecosystem": "PyPI", "scope": "lock"})
    return deps


def _parse_composer(path):
    try:
        data = json.loads(read_text(path))
    except Exception:
        return []
    deps = []
    for section in ("require", "require-dev"):
        for name, spec in (data.get(section) or {}).items():
            if name.startswith("php") or name.startswith("ext-"):
                continue
            v = _clean_semver(spec)
            if v:
                deps.append({"name": name, "version": v,
                             "ecosystem": "Packagist", "scope": section})
    return deps


def _parse_composer_lock(path):
    try:
        data = json.loads(read_text(path))
    except Exception:
        return []
    deps = []
    for pkg in (data.get("packages") or []) + (data.get("packages-dev") or []):
        n = pkg.get("name")
        v = _clean_semver(pkg.get("version"))
        if n and v:
            deps.append({"name": n, "version": v,
                         "ecosystem": "Packagist", "scope": "lock"})
    return deps


def _parse_pom(path):
    import xml.etree.ElementTree as ET
    try:
        tree = ET.parse(path)
    except Exception:
        return []
    ns = {"m": "http://maven.apache.org/POM/4.0.0"}
    deps = []
    for dep in tree.getroot().findall(".//m:dependency", ns):
        gid = dep.findtext("m:groupId", default="", namespaces=ns)
        aid = dep.findtext("m:artifactId", default="", namespaces=ns)
        ver = dep.findtext("m:version", default="", namespaces=ns)
        if gid and aid and ver and "${" not in ver:
            deps.append({"name": f"{gid}:{aid}", "version": ver,
                         "ecosystem": "Maven", "scope": "compile"})
    return deps


def _parse_build_gradle(path):
    """Groovy/Kotlin DSL — regex out implementation/api/etc lines."""
    pat = re.compile(
        r"""(?:implementation|api|compileOnly|runtimeOnly|testImplementation|"""
        r"""testCompile|debugImplementation)\s*[\(]?\s*['"]"""
        r"""([^:'"]+):([^:'"]+):([^'"\)\s]+)"""
    )
    deps = []
    for line in read_text(path).splitlines():
        s = line.strip()
        if s.startswith("//"):
            continue
        m = pat.search(s)
        if m:
            gid, aid, ver = m.groups()
            if "$" in ver:
                continue
            deps.append({"name": f"{gid}:{aid}", "version": ver,
                         "ecosystem": "Maven", "scope": "compile"})
    if not deps:
        return [_degraded("build.gradle: no static version pins found")]
    return deps


def _parse_go_mod(path):
    deps = []
    for line in read_text(path).splitlines():
        s = line.strip()
        if s.startswith("//") or not s:
            continue
        if s.startswith("require ") or s.startswith("require(") or s == "require":
            continue
        m = re.match(r"^([\w./\-]+)\s+v([\w.\-+]+)", s)
        if m:
            deps.append({"name": m.group(1), "version": m.group(2),
                         "ecosystem": "Go", "scope": "direct"})
    return deps


def _parse_cargo_toml(path):
    deps = []
    in_deps = False
    for line in read_text(path).splitlines():
        s = line.strip()
        if s.startswith("[") and "dependencies" in s:
            in_deps = True
            continue
        if s.startswith("[") and in_deps:
            in_deps = False
        if not in_deps or not s or s.startswith("#"):
            continue
        m = re.match(r'^([\w\-]+)\s*=\s*"([^"]+)"', s)
        if not m:
            m = re.match(r'^([\w\-]+)\s*=\s*\{[^}]*version\s*=\s*"([^"]+)"', s)
        if m:
            deps.append({"name": m.group(1),
                         "version": _clean_semver(m.group(2)),
                         "ecosystem": "crates.io", "scope": "direct"})
    return deps


def _parse_cargo_lock(path):
    if tomllib is None:
        return [_degraded("Cargo.lock requires tomli (pip install tomli)")]
    try:
        data = tomllib.loads(read_text(path))
    except Exception as e:
        return [_degraded(f"Cargo.lock parse error: {e}")]
    deps = []
    for pkg in (data.get("package") or []):
        n, v = pkg.get("name"), pkg.get("version")
        if n and v:
            deps.append({"name": n, "version": v,
                         "ecosystem": "crates.io", "scope": "lock"})
    return deps


def _parse_gemfile(path):
    deps = []
    for line in read_text(path).splitlines():
        m = re.match(r"^\s*gem\s+['\"]([^'\"]+)['\"]\s*,?\s*(?:['\"]([^'\"]+)['\"])?", line)
        if m:
            deps.append({"name": m.group(1),
                         "version": _clean_semver(m.group(2) or ""),
                         "ecosystem": "RubyGems", "scope": "direct"})
    return deps


def _parse_gemfile_lock(path):
    """Parse Bundler lockfile GEM -> specs: tree."""
    deps = []
    in_specs = False
    for line in read_text(path).splitlines():
        s = line.rstrip()
        stripped = s.strip()
        if stripped == "specs:":
            in_specs = True
            continue
        if in_specs:
            # Section boundary: non-indented non-empty line
            if s and not s.startswith(" "):
                in_specs = False
                continue
            m = re.match(r"^\s{4}([A-Za-z0-9_.\-]+) \(([^)]+)\)", s)
            if m:
                deps.append({"name": m.group(1), "version": m.group(2),
                             "ecosystem": "RubyGems", "scope": "lock"})
    return deps


PARSERS = {
    "package.json": _parse_package_json,
    "package-lock.json": _parse_package_lock,
    "requirements.txt": _parse_requirements,
    "requirements-dev.txt": _parse_requirements,
    "pyproject.toml": _parse_pyproject,
    "Pipfile": _parse_requirements,
    "poetry.lock": _parse_poetry_lock,
    "composer.json": _parse_composer,
    "composer.lock": _parse_composer_lock,
    "pom.xml": _parse_pom,
    "build.gradle": _parse_build_gradle,
    "go.mod": _parse_go_mod,
    "Cargo.toml": _parse_cargo_toml,
    "Cargo.lock": _parse_cargo_lock,
    "Gemfile": _parse_gemfile,
    "Gemfile.lock": _parse_gemfile_lock,
}


def parse_dependency_file(path):
    path = Path(path)
    parser = PARSERS.get(path.name)
    if parser is None:
        return []
    try:
        return parser(path)
    except Exception as e:
        return [_degraded(f"{path.name}: parser raised {type(e).__name__}: {e}")]


def collect_all_dependencies(root):
    files = discover_dependency_files(root)
    all_deps = []
    seen = set()
    degraded = []
    root = Path(root)
    for f in files:
        deps = parse_dependency_file(f)
        for d in deps:
            if d.get("_degraded"):
                try:
                    rel = str(f.relative_to(root))
                except Exception:
                    rel = str(f)
                degraded.append({"file": rel, "reason": d.get("reason", "")})
                continue
            key = (d["ecosystem"], d["name"], d["version"])
            if key in seen:
                continue
            seen.add(key)
            try:
                d["source_file"] = str(f.relative_to(root))
            except Exception:
                d["source_file"] = str(f)
            all_deps.append(d)
    return all_deps, degraded


def query_osv_batch(deps, timeout=30):
    if not deps:
        return []
    results = []
    for i in range(0, len(deps), OSV_MAX_BATCH):
        chunk = deps[i:i + OSV_MAX_BATCH]
        queries = []
        for d in chunk:
            q = {"package": {"name": d["name"], "ecosystem": d["ecosystem"]}}
            if d.get("version"):
                q["version"] = d["version"]
            queries.append(q)
        try:
            with _client(timeout) as c:
                r = c.post(OSV_BATCH_URL, json={"queries": queries},
                           headers={"Content-Type": "application/json"})
            if r.status_code != 200:
                continue
            for dep, res in zip(chunk, (r.json() or {}).get("results") or []):
                vulns = res.get("vulns") or []
                if vulns:
                    results.append({"dependency": dep,
                                    "vuln_ids": [v.get("id") for v in vulns]})
        except Exception:
            continue
    return results


def fetch_vuln_details(vuln_ids, timeout=15):
    details = []
    for vid in vuln_ids:
        try:
            with _client(timeout) as c:
                r = c.get(f"{OSV_VULN_URL}{quote(vid)}")
            if r.status_code == 200:
                details.append(r.json())
        except Exception:
            continue
    return details


def _severity_from_vuln(vuln):
    for entry in (vuln.get("severity") or []):
        m = re.search(r"(\d+\.\d+)", str(entry.get("score") or ""))
        if m:
            val = float(m.group(1))
            if val >= 9.0: return "critical"
            if val >= 7.0: return "high"
            if val >= 4.0: return "medium"
            if val > 0:    return "low"
    s = ((vuln.get("database_specific") or {}).get("severity") or "").lower()
    return s if s in SEVERITY_RANK else "medium"


def _scan_dependencies_impl(root, timeout=30):
    deps, degraded = collect_all_dependencies(root)
    if not deps:
        return {"root": str(root), "files": [], "dependencies": [],
                "vulnerabilities": [], "summary": {}, "degraded": degraded}
    hits = query_osv_batch(deps, timeout=timeout)
    all_ids = []
    for h in hits:
        all_ids.extend(h["vuln_ids"])
    details = fetch_vuln_details(list(set(all_ids)), timeout=timeout)
    by_id = {v.get("id"): v for v in details}
    findings = []
    for h in hits:
        for vid in h["vuln_ids"]:
            v = by_id.get(vid)
            if not v or v.get("withdrawn"):
                continue
            aliases = v.get("aliases") or []
            cve = next((a for a in aliases if a.startswith("CVE-")), "")
            findings.append({
                "dependency": h["dependency"],
                "vuln_id": vid,
                "cve": cve,
                "summary": (v.get("summary") or "")[:300],
                "severity": _severity_from_vuln(v),
                "aliases": aliases[:5],
                "references": [r.get("url") for r in (v.get("references") or [])[:3]],
                "source_file": h["dependency"].get("source_file", ""),
            })
    findings.sort(key=lambda f: -SEVERITY_RANK.get(f["severity"], 0))
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return {
        "root": str(root),
        "files": sorted(set(d.get("source_file", "") for d in deps)),
        "dependencies": deps,
        "vulnerabilities": findings,
        "summary": counts,
        "degraded": degraded,
    }


# --- ROE guard setter (no-op for SCA; osv.dev is not a target) ---
_ROE_GUARD = None

def scan_dependencies(*args, **kwargs):
    from .contract import make_result
    raw = _scan_dependencies_impl(*args, **kwargs)
    return make_result(raw, capability="sca", args=args, kwargs=kwargs)
