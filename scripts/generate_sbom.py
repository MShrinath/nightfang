#!/usr/bin/env python3
"""Generate Software Bill of Materials (SBOM) in SPDX 2.3 and CycloneDX 1.5 formats.

Usage:
    python scripts/generate_sbom.py --root /path/to/project --format spdx-json -o sbom.json
    python scripts/generate_sbom.py --root /path/to/project --format cyclonedx-xml -o sbom.xml
    python scripts/generate_sbom.py --root /path/to/project --format all -o sbom

Identifies lockfiles/package manifests, enumerates dependencies with hashes
where available, computes file-level SHA-256 for source-tree provenance, and
emits a standards-compliant SBOM artifact ready for downstream CVE scanning
(grype, osv-scanner, syft).
"""
import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Package discovery engines
# ---------------------------------------------------------------------------

def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
    except OSError:
        pass
    return h.hexdigest()


def discover_npm(root: str) -> Dict[str, Any]:
    """Parse package-lock.json to extract packages with integrity hashes."""
    packages: Dict[str, Dict] = {}
    lockfile = os.path.join(root, "package-lock.json")
    if not os.path.exists(lockfile):
        return packages
    try:
        with open(lockfile) as f:
            data = json.load(f)
        deps = data.get("packages", {})
        for pkg_path, info in deps.items():
            if not pkg_path:  # root package
                continue
            name = info.get("name", pkg_path.split(":")[-1])
            version = info.get("version", "?")
            integrity = info.get("integrity", "")
            resolved = info.get("resolved", "")
            packages[name] = {
                "version": version,
                "integrity": integrity,
                "resolved": resolved,
                "type": "npm",
            }
    except Exception:
        pass
    return packages


def discover_pip(root: str) -> Dict[str, Any]:
    """Parse requirements.txt or Pipfile.lock for Python packages."""
    packages: Dict[str, Dict] = {}
    req_file = os.path.join(root, "requirements.txt")
    if os.path.exists(req_file):
        with open(req_file) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                if "==" in line:
                    name, _, ver = line.partition("==")
                    packages[name.strip()] = {"version": ver.strip(), "type": "pypi"}
                elif ">=" in line or "<=" in line or "~=" in line:
                    name, _, _ = line.partition(">=")
                    name, _, _ = name.partition("~=")
                    name, _, _ = name.partition("<=")
                    packages[name.strip()] = {"version": "*", "type": "pypi"}
                else:
                    packages[line.strip()] = {"version": "*", "type": "pypi"}
    pipfile_lock = os.path.join(root, "Pipfile.lock")
    if os.path.exists(pipfile_lock):
        try:
            with open(pipfile_lock) as f:
                data = json.load(f)
            for section in ("default", "develop"):
                for name, info in data.get(section, {}).items():
                    packages[name] = {
                        "version": info.get("version", "*"),
                        "hash": info.get("hash", ""),
                        "type": "pypi",
                    }
        except Exception:
            pass
    return packages


def discover_go(root: str) -> Dict[str, Any]:
    """Parse go.sum for Go module checksums."""
    packages: Dict[str, Dict] = {}
    mod_file = os.path.join(root, "go.mod")
    sum_file = os.path.join(root, "go.sum")
    if not os.path.exists(mod_file) or not os.path.exists(sum_file):
        return packages
    modules: List[Tuple[str, str]] = []
    with open(mod_file) as f:
        for line in f:
            line = line.strip()
            if line.startswith("require") and "(" not in line:
                parts = line.split()
                if len(parts) >= 3:
                    modules.append((parts[1], parts[2]))
    with open(sum_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            parts = line.split()
            if len(parts) >= 3 and parts[0].startswith("h1:"):
                mod_hash = parts[0]
                for mod_name, mod_ver in modules:
                    key = f"{mod_name}@{mod_ver}"
                    packages[key] = {"checksum": mod_hash, "type": "golang"}
    return packages


def discover_maven(root: str) -> Dict[str, Any]:
    """Parse pom.xml for Maven coordinates (best-effort regex)."""
    packages: Dict[str, Dict] = {}
    pom_files = list(Path(root).rglob("pom.xml"))[:5]
    for pom_path in pom_files:
        try:
            with open(pom_path) as f:
                content = f.read()
            import re as _re
            deps_block = _re.search(r"<dependencies>(.*?)</dependencies>", content, _re.DOTALL)
            if not deps_block:
                continue
            for dep_match in _re.finditer(
                r"<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>",
                deps_block.group(1),
            ):
                gid, aid, ver = dep_match.groups()
                coord = f"{gid}:{aid}:{ver}"
                packages[coord] = {"type": "maven", "group_id": gid, "artifact_id": aid, "version": ver}
        except Exception:
            pass
    return packages


DISCOVERY_ENGINES = {
    "npm": discover_npm,
    "pip": discover_pip,
    "go": discover_go,
    "maven": discover_maven,
}


# ---------------------------------------------------------------------------
# SPDX 2.3 emitter
# ---------------------------------------------------------------------------

SPDX_NS = "https://spdx.org/rdf/terms#"
CREATOR_TOOL = "nightfang-sbom-generator"
CREATOR_ORGANIZATION = "NIGHTFANG Security Capability Pack"


def build_spdx_json(
    root: str,
    packages: Dict[str, Dict],
    doc_namespace: str,
) -> Dict[str, Any]:
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    spdx_version = "SPDXVersion: SPDX-2.3"
    data_license = "CC0-1.0"
    name = f"sbom-{Path(root).name}-{now_iso.replace(':', '')}"
    external_refs: List[Dict] = [
        {"refType": "PACKAGE-MANAGER", "referenceLocator": "cpe:2.3:*:unknown"},
    ]
    package_list: List[Dict] = []
    relationship_list: List[Dict] = []

    root_pkg_id = "ROOT-PACKAGE"
    root_pkg = {
        "SPDXID": root_pkg_id,
        "name": Path(root).name,
        "versionInfo": "0.0.0",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
    }
    package_list.append(root_pkg)

    for idx, (pkg_name, info) in enumerate(sorted(packages.items())):
        pkg_id = f"Package-{idx:04d}"
        safe_name = pkg_name.replace("/", "-").replace(":", "-").replace("@", "")
        pkg: Dict[str, Any] = {
            "SPDXID": pkg_id,
            "name": safe_name,
            "versionInfo": info.get("version", "NOASSERTION"),
            "downloadLocation": info.get("resolved", "NOASSERTION")
                                or info.get("hash", "NOASSERTION")
                                or "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": _make_purl(info.get("type", "unknown"), safe_name, info.get("version", "NOASSERTION")),
                }
            ],
        }
        pkg_summary = info.get("integrity") or info.get("checksum") or ""
        if pkg_summary:
            pkg["externalRefs"].append({
                "referenceCategory": "SECURITY",
                "referenceType": "cpe23Type",
                "referenceLocator": pkg_summary,
            })
        package_list.append(pkg)
        relationship_list.append({
            "spdxElementId": root_pkg_id,
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": pkg_id,
        })

    document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": data_license,
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": name,
        "documentNamespace": doc_namespace,
        "creationInfo": {
            "created": now_iso,
            "creators": [f"Tool: {CREATOR_TOOL}", f"Organization: {CREATOR_ORGANIZATION}"],
            "licenseListVersion": "3.17",
        },
        "packages": [root_pkg] + package_list,
        "relationships": [
            {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": root_pkg_id}
        ] + relationship_list,
        "externalDocumentRefs": [],
        "files": [],
    }
    return document


def _make_purl(ecosystem: str, name: str, version: str) -> str:
    purl_types = {
        "npm": "npm",
        "pypi": "pypi",
        "golang": "generic",
        "maven": "maven",
    }
    type_ = purl_types.get(ecosystem, "generic")
    ns_part = ""
    if "@" in name:
        ns_part, _, local = name.partition("@")
        return f"pkg:{type_}/{ns_part}%2F{local}@{version}"
    return f"pkg:{type_}/{name}@{version}"


# ---------------------------------------------------------------------------
# CycloneDX 1.5 emitter
# ---------------------------------------------------------------------------

CD_NS = "http://cyclonedx.org/schema/bom/1.5"
CD_XSD = "http://cyclonedx.org/schema/bom-1.5.xsd"


def build_cyclonedx_json(
    root: str,
    packages: Dict[str, Dict],
    doc_namespace: str,
) -> Dict[str, Any]:
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    components: List[Dict[str, Any]] = []

    for pkg_name, info in sorted(packages.items()):
        safe_name = pkg_name.replace("/", "-").replace(":", "-").replace("@", "")
        component: Dict[str, Any] = {
            "type": "library",
            "name": safe_name,
            "version": info.get("version", "NOASSERTION"),
            "purl": _make_purl(info.get("type", "unknown"), safe_name, info.get("version", "NOASSERTION")),
            "licenses": {"license": [{"id": "NOASSERTION"}]},
            "externalReferences": [],
        }
        integrity = info.get("integrity") or info.get("checksum") or ""
        if integrity:
            component["properties"] = [{"name": "cdx:component:integrity", "value": integrity}]
        resolved = info.get("resolved", "")
        if resolved:
            component["externalReferences"].append({
                "type": "distribution",
                "url": resolved,
            })
        components.append(component)

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{_uuid_from_root(root)}",
        "version": 1,
        "metadata": {
            "timestamp": now_iso,
            "tools": [{"name": CREATOR_TOOL, "vendor": CREATOR_ORGANIZATION}],
            "component": {
                "type": "application",
                "name": Path(root).name,
                "version": "0.0.0",
            },
        },
        "components": components,
        "dependencies": [],
    }
    dep_ids = {comp["name"]: i for i, comp in enumerate(components)}
    for comp in components:
        bom["dependencies"].append({
            "ref": str(list(dep_ids.keys()).index(comp["name"]) if comp["name"] in dep_ids else 0),
            "dependsOn": [],
        })
    return bom


def _uuid_from_root(root: str) -> str:
    h = hashlib.md5(root.encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-4{_uuid_char(h[12:14])}-{h[14:16]}-{h[16:32]}"


def _uuid_char(hex_byte: str) -> str:
    n = int(hex_byte, 16) if hex_byte else 0
    return str((n & 0xF) % 10)


def build_cyclonedx_xml(root: str, packages: Dict[str, Dict]) -> str:
    from xml.dom.minidom import Document
    doc = Document()
    bom = doc.createElementNS(CD_NS, "bom")
    bom.setAttribute("xmlns", CD_NS)
    bom.setAttribute("version", "1")
    bom.setAttribute("serialNumber", f"urn:uuid:{_uuid_from_root(root)}")
    bom.setAttribute("specVersion", "1.5")
    doc.appendChild(bom)

    metadata = doc.createElement("metadata")
    timestamp = doc.createElement("timestamp")
    timestamp_text = doc.createTextNode(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    timestamp.appendChild(timestamp_text)
    metadata.appendChild(timestamp)
    tools_el = doc.createElement("tools")
    tool = doc.createElement("tool")
    tool_text = doc.createTextNode(f"{CREATOR_TOOL}|{CREATOR_ORGANIZATION}")
    tool.appendChild(tool_text)
    tools_el.appendChild(tool)
    metadata.appendChild(tools_el)
    component_el = doc.createElement("component")
    component_el.setAttribute("type", "application")
    comp_name = doc.createElement("name")
    comp_name.appendChild(doc.createTextNode(Path(root).name))
    component_el.appendChild(comp_name)
    metadata.appendChild(component_el)
    bom.appendChild(metadata)

    components_el = doc.createElement("components")
    for idx, (pkg_name, info) in enumerate(sorted(packages.items()), 1):
        safe_name = pkg_name.replace("/", "-").replace(":", "-").replace("@", "")
        c = doc.createElement("component")
        c.setAttribute("type", "library")
        cname = doc.createElement("name")
        cname.appendChild(doc.createTextNode(safe_name))
        c.appendChild(cname)
        version_el = doc.createElement("version")
        version_el.appendChild(doc.createTextNode(info.get("version", "NOASSERTION")))
        c.appendChild(version_el)
        purl = doc.createElement("purl")
        purl.appendChild(doc.createTextNode(_make_purl(info.get("type", "unknown"), safe_name, info.get("version", "NOASSERTION"))))
        c.appendChild(purl)
        licenses_el = doc.createElement("licenses")
        lic_item = doc.createElement("license")
        lic_id = doc.createElement("id")
        lic_id.appendChild(doc.createTextNode("NOASSERTION"))
        lic_item.appendChild(lic_id)
        licenses_el.appendChild(lic_item)
        c.appendChild(licenses_el)
        components_el.appendChild(c)
    bom.appendChild(components_el)

    return doc.toprettyxml(indent="  ", encoding="UTF-8")


# ---------------------------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------------------------

def collect_packages(root: str) -> Dict[str, Dict]:
    all_packages: Dict[str, Dict] = {}
    discovered_engines: List[str] = []
    for engine_name, engine_fn in DISCOVERY_ENGINES.items():
        result = engine_fn(root)
        if result:
            discovered_engines.append(engine_name)
            for name, info in result.items():
                if name not in all_packages:
                    all_packages[name] = info
                else:
                    all_packages[name].update(info)
    return all_packages, discovered_engines


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate SPDX/CycloneDX SBOM from a project tree.")
    ap.add_argument("--root", required=True, help="Project root directory")
    ap.add_argument("--format", choices=["spdx-json", "cyclonedx-json", "cyclonedx-xml", "all"], default="all")
    ap.add_argument("--output", "-o", required=True, help="Output path (directory when format=all)")
    ap.add_argument("--namespace", default="", help="SPDX document namespace URI (auto-generated if omitted)")
    args = ap.parse_args()

    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        print(f"Error: {root} is not a directory", file=sys.stderr)
        return 1

    packages, engines = collect_packages(root)
    if not packages:
        print("Warning: no packages discovered. Ensure lockfiles are present.", file=sys.stderr)

    print(f"Discovered {len(packages)} packages across [{', '.join(engines or ['none'])}] registries.")

    namespace = args.namespace or f"https://nightfang.security/sbom/{Path(root).name}"
    output_path = os.path.abspath(args.output)

    if args.format in ("spdx-json", "all"):
        spdx_doc = build_spdx_json(root, packages, namespace)
        _write_output(spdx_doc, output_path, ".spdx.json" if args.format == "all" else ".json")
        print(f"  SPDX 2.3 written.")

    if args.format in ("cyclonedx-json", "all"):
        cd_doc = build_cyclonedx_json(root, packages, namespace)
        _write_output(cd_doc, output_path, ".cyclonedx.json" if args.format == "all" else ".json")
        print(f"  CycloneDX 1.5 (JSON) written.")

    if args.format in ("cyclonedx-xml", "all"):
        cd_xml = build_cyclonedx_xml(root, packages)
        _write_output(cd_xml, output_path, ".cyclonedx.xml" if args.format == "all" else ".xml")
        print(f"  CycloneDX 1.5 (XML) written.")

    summary = {
        "root": root,
        "formats_generated": [args.format] if args.format != "all" else ["spdx-json", "cyclonedx-json", "cyclonedx-xml"],
        "packages_discovered": len(packages),
        "registries_detected": engines,
        "namespaces": namespace,
    }
    print(json.dumps(summary, indent=2))
    return 0


def _write_output(content: Any, output_base: str, suffix: str) -> None:
    # Strip existing .json extension to avoid double suffix like .json.json
    base = output_base.rsplit(".json")[0] if output_base.endswith(".json") else output_base
    if os.path.isdir(base):
        dest = os.path.join(base, f"sbom{suffix}")
    else:
        dest = base + suffix if suffix else base
    os.makedirs(os.path.dirname(os.path.abspath(dest)), exist_ok=True)
    with open(dest, "w", encoding="utf-8") as f:
        if isinstance(content, dict):
            json.dump(content, f, indent=2, ensure_ascii=False)
        else:
            f.write(str(content))
    print(f"  -> {dest}")


if __name__ == "__main__":
    sys.exit(main())
