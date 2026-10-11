"""SBOM generation — CycloneDX 1.6 & SPDX 2.3."""
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

try:
    from engine import sca
except ImportError:
    from . import sca
from .version import __version__ as SEC_CHECKER_VERSION



PURL_TYPES = {
    "npm": "npm", "PyPI": "pypi", "Packagist": "composer",
    "Maven": "maven", "Go": "golang", "crates.io": "cargo",
    "RubyGems": "gem", "NuGet": "nuget",
}


def _purl(dep):
    etype = PURL_TYPES.get(dep["ecosystem"], dep["ecosystem"].lower())
    name = dep["name"]
    version = dep.get("version", "")
    if etype in ("maven", "golang"):
        return f"pkg:{etype}/{quote(name, safe='/')}@{version}"
    return f"pkg:{etype}/{quote(name, safe='')}@{version}"


def _completeness_marker():
    return {
        "sec-checker:completeness": "no-hashes,no-graph",
        "sec-checker:note": (
            "CycloneDX components omit hashes[] and dependencies[] graph. "
            "Downstream tools MUST NOT assume completeness."
        ),
    }


def build_cyclonedx(root, scan_result=None):
    if scan_result is None:
        scan_result = sca.scan_dependencies(root)
    deps = scan_result.get("dependencies") or []
    findings = scan_result.get("vulnerabilities") or []
    serial = f"urn:uuid:{uuid.uuid4()}"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    vuln_map = {}
    for f in findings:
        key = (f["dependency"]["ecosystem"], f["dependency"]["name"],
               f["dependency"].get("version", ""))
        vuln_map.setdefault(key, []).append(f)

    components = []
    for d in deps:
        purl = _purl(d)
        key = (d["ecosystem"], d["name"], d.get("version", ""))
        comp = {"type": "library", "bom-ref": purl,
                "name": d["name"], "version": d.get("version", ""),
                "purl": purl}
        vlist = vuln_map.get(key) or []
        if vlist:
            comp["properties"] = [
                {"name": "sec-checker:vulnerabilities",
                 "value": ",".join(v["vuln_id"] for v in vlist)},
                {"name": "sec-checker:max-severity",
                 "value": max(vlist, key=lambda x: sca.SEVERITY_RANK.get(x["severity"], 0))["severity"]},
            ]
        components.append(comp)

    vulnerabilities = []
    for f in findings:
        purl = _purl(f["dependency"])
        entry = {
            "id": f["vuln_id"],
            "source": {"name": "OSV",
                       "url": f"https://osv.dev/vulnerability/{f['vuln_id']}"},
            "ratings": [{"severity": f["severity"], "method": "other"}],
            "description": f.get("summary", ""),
            "affects": [{"ref": purl}],
        }
        if f.get("cve"):
            entry["references"] = [{
                "type": "advisory",
                "url": f"https://nvd.nist.gov/vuln/detail/{f['cve']}",
            }]
        vulnerabilities.append(entry)

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {"components": [{
                "type": "application", "name": "sec-checker",
                "version": SEC_CHECKER_VERSION,
            }]},
            "component": {
                "type": "application",
                "bom-ref": f"root:{Path(root).name}",
                "name": Path(root).name,
                "properties": [
                    {"name": k, "value": v}
                    for k, v in _completeness_marker().items()
                ],
            },
        },
        "components": components,
    }
    if vulnerabilities:
        bom["vulnerabilities"] = vulnerabilities
    return bom


def save_cyclonedx(root, out_path=None):
    bom = build_cyclonedx(root)
    if out_path is None:
        out_dir = Path("reports")
        out_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        out_path = out_dir / f"{stamp}_{Path(root).name}_sbom.cdx.json"
    Path(out_path).write_text(json.dumps(bom, indent=2), encoding="utf-8")
    return str(out_path)


def build_spdx(root, scan_result=None):
    if scan_result is None:
        scan_result = sca.scan_dependencies(root)
    deps = scan_result.get("dependencies") or []
    findings = scan_result.get("vulnerabilities") or []
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    doc_id = "SPDXRef-DOCUMENT"
    root_id = "SPDXRef-RootPackage"
    packages = [{
        "SPDXID": root_id,
        "name": Path(root).name,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "comment": "SEC-CHECKER completeness: no-hashes,no-graph",
    }]
    relationships = [{
        "spdxElementId": doc_id,
        "relationshipType": "DESCRIBES",
        "relatedSpdxElement": root_id,
    }]
    for i, d in enumerate(deps):
        sid = f"SPDXRef-Package-{i}"
        packages.append({
            "SPDXID": sid,
            "name": d["name"],
            "versionInfo": d.get("version", ""),
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": _purl(d),
            }],
        })
        relationships.append({
            "spdxElementId": root_id,
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": sid,
        })
    spdx = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": doc_id,
        "name": f"SBOM-{Path(root).name}",
        "documentNamespace": f"https://sec-checker.local/spdx/{uuid.uuid4()}",
        "creationInfo": {
            "created": timestamp,
            "creators": [f"Tool: sec-checker-{SEC_CHECKER_VERSION}"],
        },
        "packages": packages,
        "relationships": relationships,
    }
    if findings:
        spdx["annotations"] = [{
            "annotationDate": timestamp,
            "annotationType": "OTHER",
            "annotator": "Tool: sec-checker-1.2.1",
            "comment": f"{len(findings)} vulnerabilities detected via OSV; "
                       f"completeness=no-hashes,no-graph",
        }]
    return spdx


def save_spdx(root, out_path=None):
    spdx = build_spdx(root)
    if out_path is None:
        out_dir = Path("reports")
        out_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        out_path = out_dir / f"{stamp}_{Path(root).name}_sbom.spdx.json"
    Path(out_path).write_text(json.dumps(spdx, indent=2), encoding="utf-8")
    return str(out_path)
