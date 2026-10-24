#!/usr/bin/env python3
"""Offline supply-chain evidence inspection for jankhunt42.

Supported inputs:
* SPDX 2.x JSON and tag-value, SPDX 3 JSON-LD
* CycloneDX JSON and XML
* Sigstore / DSSE / in-toto bundles produced by GitHub artifact attestations
* JFrog AppTrust / `jf evd verify --format json` evidence exports

This module never contacts a registry, transparency log, or JFrog instance. It
parses and correlates evidence that is already on disk. Cryptographic
verification is reported only when the exporter (for example JFrog) recorded a
successful verification result; otherwise the file is marked unverified.
Opt-in fetching and native-verifier runs live in jh_verify, which feeds its
files and results back through `inspect(extra_files=...)` and `summarize`.
"""
from __future__ import annotations

import base64
import json
import os
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from jh_core import DEFAULT_SKIP_DIRS

MAX_EVIDENCE_BYTES = 24_000_000
MAX_PACKAGES = 5000
MAX_DISCOVER = 4000

_SBOM_HINTS = ("sbom", "spdx", "cyclonedx", ".cdx", "bom.json", "bom.xml")
_ATTEST_HINTS = ("attestation", "attest", "provenance", "intoto", "in-toto",
                 "sigstore", "dsse", "bundle")
_JFROG_HINTS = ("apptrust", "jfrog", "release-bundle", "release_bundle", "evd")
BUNDLE_KEY_WARNING = ("exporter verified the signature with the key embedded in the Sigstore bundle; "
                      "the signer identity is not established by this result")


def _rel(root: str, path: str) -> str:
    try:
        rel = os.path.relpath(os.path.abspath(path), os.path.abspath(root))
    except ValueError:
        return path.replace(os.sep, "/")
    if rel == ".":
        return os.path.basename(path)
    if rel.startswith(".." + os.sep) or rel == "..":
        return path.replace(os.sep, "/")
    return rel.replace(os.sep, "/")


def _read_text(path: str, limit: int = MAX_EVIDENCE_BYTES) -> Optional[str]:
    try:
        if os.path.getsize(path) > limit:
            return None
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError:
        return None
    if b"\x00" in raw[:8192]:
        return None
    return raw.decode("utf-8", "replace")


def _json(text: str) -> Optional[Any]:
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _scalar(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    if isinstance(value, dict):
        for key in ("name", "id", "uri", "url", "value", "@id", "spdxId"):
            if value.get(key) is not None:
                return str(value[key])
    if isinstance(value, list):
        return ", ".join(x for x in (_scalar(v) for v in value) if x)
    return ""


def _license(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return ", ".join(x for x in (_license(v) for v in value) if x)
    if isinstance(value, dict):
        for key in ("license", "licenseId", "id", "name", "expression"):
            if key in value:
                got = _license(value[key])
                if got:
                    return got
    return ""


def _digest_map(value: Any) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if isinstance(value, dict):
        for key, val in value.items():
            if isinstance(val, (str, int)):
                out[str(key).lower()] = str(val)
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                alg = item.get("algorithm") or item.get("alg")
                val = item.get("value") or item.get("digest")
                if alg and val:
                    out[str(alg).lower()] = str(val)
    return out


def _detect_kind(text: str, name: str) -> Set[str]:
    low_name = os.path.basename(name).lower()
    head = text[:200_000]
    low = head.lower()
    # JSON key detection must tolerate arbitrary whitespace after colons and
    # between tokens; filename hints alone are not enough for generic names.
    compact = re.sub(r"\s+", "", head).lower()
    kinds: Set[str] = set()
    if (any(h in low_name for h in _SBOM_HINTS)
            or '"spdxversion"' in compact
            or "spdxversion:" in low
            or ('"bomformat"' in compact and "cyclonedx" in compact)
            or ("<bom" in low and "cyclonedx" in low)
            or ('"@graph"' in compact and "spdx" in compact)):
        kinds.add("sbom")
    if (any(h in low_name for h in _ATTEST_HINTS)
            or '"dsseenvelope"' in compact
            or '"predicatetype"' in compact
            or '"verificationmaterial"' in compact
            or '"in-toto.io/statement"' in compact
            or ('"payloadtype"' in compact and '"payload"' in compact)):
        kinds.add("attestation")
    if (any(h in low_name for h in _JFROG_HINTS)
            or '"evidenceverifications"' in compact
            or ('"sigstorebundle"' in compact and '"verificationresult"' in compact)
            or ('"evidence"' in compact and ('"jfrog"' in compact or '"apptrust"' in compact))):
        kinds.add("jfrog")
    return kinds


def _walk_candidates(root: str) -> List[str]:
    out: List[str] = []
    base = os.path.abspath(root)
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in DEFAULT_SKIP_DIRS and (not d.startswith(".") or d == ".github")
        )
        for fn in sorted(filenames):
            low = fn.lower()
            if low.endswith((".pyc", ".pyo", ".class", ".jar", ".war", ".zip",
                             ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z",
                             ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".woff",
                             ".woff2", ".ttf", ".ico", ".mp4", ".mov")):
                continue
            path = os.path.join(dirpath, fn)
            if (any(h in low for h in _SBOM_HINTS + _ATTEST_HINTS + _JFROG_HINTS)
                    or low.endswith((".json", ".jsonl", ".spdx", ".cdx",
                                     ".intoto", ".attestation"))):
                out.append(path)
                if len(out) >= MAX_DISCOVER:
                    return out
    return out


def _known(value: Any) -> bool:
    """A value that states something (SPDX writes NOASSERTION/NONE for gaps)."""
    text = _scalar(value).strip()
    return bool(text) and text.upper() not in ("NOASSERTION", "NONE")


# Relationship types that say how components depend on each other (a link to
# a manifest file is not one). SPDX 3 scopes build/test dependencies through
# LifecycleScopedRelationship rather than separate types.
_SPDX2_DEPENDENCY_TYPES = {"DEPENDS_ON", "DEPENDENCY_OF", "CONTAINS", "CONTAINED_BY", "DYNAMIC_LINK", "STATIC_LINK",
                           "BUILD_DEPENDENCY_OF", "DEV_DEPENDENCY_OF", "OPTIONAL_DEPENDENCY_OF",
                           "PROVIDED_DEPENDENCY_OF", "RUNTIME_DEPENDENCY_OF", "TEST_DEPENDENCY_OF",
                           "PREREQUISITE_FOR", "HAS_PREREQUISITE"}
_SPDX3_DEPENDENCY_TYPES = {"dependsOn", "contains", "hasDynamicLink", "hasStaticLink", "hasProvidedDependency",
                           "hasOptionalDependency", "hasOptionalComponent", "hasPrerequisite"}


def _split_creators(creators: Sequence[str]) -> Tuple[List[str], List[str]]:
    """SPDX 2 creators as (authors, tools): Person:/Organization: vs Tool:."""
    return ([c for c in creators if c.startswith(("Person:", "Organization:"))],
            [c for c in creators if c.startswith("Tool:")])


def _prefer_known(*values: str) -> str:
    """The first value that states something, else the first non-empty one."""
    return next((v for v in values if _known(v)), next((v for v in values if v), ""))


def _spdx2_packages(data: Dict[str, Any]) -> List[Dict[str, str]]:
    packages: List[Dict[str, str]] = []
    for p in _as_list(data.get("packages")):
        if not isinstance(p, dict):
            continue
        purl, cpe = "", ""
        for ref in _as_list(p.get("externalRefs")):
            if not isinstance(ref, dict):
                continue
            kind = str(ref.get("referenceType", "")).lower()
            if "purl" in kind:
                purl = str(ref.get("referenceLocator", ""))
            elif kind.startswith("cpe") and not cpe:
                cpe = str(ref.get("referenceLocator", ""))
        packages.append({
            "name": _scalar(p.get("name")),
            "version": _scalar(p.get("versionInfo")),
            "supplier": _scalar(p.get("supplier")),
            "license": _prefer_known(_license(p.get("licenseConcluded")), _license(p.get("licenseDeclared"))),
            "purl": purl,
            "cpe": cpe,
            "hashes": sorted({_scalar(c.get("algorithm")) for c in _as_list(p.get("checksums"))
                              if isinstance(c, dict) and c.get("algorithm")}),
            "id": _scalar(p.get("SPDXID")),
        })
    return packages


def _spdx2_doc(data: Dict[str, Any]) -> Dict[str, Any]:
    ci = data.get("creationInfo") if isinstance(data.get("creationInfo"), dict) else {}
    authors, tools = _split_creators([str(c) for c in _as_list(ci.get("creators"))])
    rels = [r for r in _as_list(data.get("relationships")) if isinstance(r, dict)]
    return {
        "timestamp": _scalar(ci.get("created")),
        "authors": authors,
        "tools": tools,
        "dependencies": sum(1 for r in rels if str(r.get("relationshipType", "")).upper() in _SPDX2_DEPENDENCY_TYPES),
        "primary": bool(_as_list(data.get("documentDescribes"))) or any(
            str(r.get("relationshipType", "")).upper() == "DESCRIBES" for r in rels),
        "context": [],
    }


def _spdx3_graph(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [n for n in (_as_list(data.get("@graph")) or _as_list(data.get("graph"))) if isinstance(n, dict)]


def _spdx3_type(node: Dict[str, Any]) -> str:
    return str(node.get("type") or node.get("@type") or "")


def _spdx3_id(node: Dict[str, Any]) -> str:
    return _scalar(node.get("spdxId") or node.get("@id"))


def _spdx3_names(by_id: Dict[str, Dict[str, Any]], refs: Any) -> List[str]:
    """Agent or tool references resolved to their names where the graph has them."""
    out = []
    for ref in _as_list(refs):
        node = by_id.get(ref) if isinstance(ref, str) else (ref if isinstance(ref, dict) else None)
        out.append(_scalar(node.get("name")) if node and node.get("name") else _scalar(ref))
    return [o for o in out if o]


def _spdx3_packages(data: Dict[str, Any]) -> List[Dict[str, str]]:
    graph = _spdx3_graph(data)
    by_id = {_spdx3_id(n): n for n in graph}
    licenses: Dict[str, str] = {}
    for rel in graph:
        if "Relationship" in _spdx3_type(rel) and rel.get("relationshipType") in ("hasConcludedLicense",
                                                                                   "hasDeclaredLicense"):
            target = by_id.get(_scalar(next(iter(_as_list(rel.get("to"))), "")), {})
            expr = _scalar(target.get("simplelicensing_licenseExpression") or target.get("licenseExpression")
                           or target.get("name"))
            # a stated concluded licence wins over a declared one, NOASSERTION never does
            if _known(expr) and (rel["relationshipType"] == "hasConcludedLicense"
                                 or _scalar(rel.get("from")) not in licenses):
                licenses[_scalar(rel.get("from"))] = expr
    packages: List[Dict[str, str]] = []
    for node in graph:
        typ = _spdx3_type(node)
        if "Package" not in typ and "package" not in typ:
            continue
        ids = [i for i in _as_list(node.get("externalIdentifier")) if isinstance(i, dict)]
        purl = _scalar(node.get("software_packageUrl") or node.get("packageUrl") or node.get("purl")) or next(
            (_scalar(i.get("identifier")) for i in ids if str(i.get("externalIdentifierType")) == "packageUrl"), "")
        cpe = next((_scalar(i.get("identifier")) for i in ids
                    if str(i.get("externalIdentifierType")) in ("cpe22", "cpe23")), "")
        supplier = _spdx3_names(by_id, node.get("suppliedBy") or node.get("supplier") or node.get("originatedBy"))
        packages.append({
            "name": _scalar(node.get("name")),
            "version": _scalar(node.get("software_packageVersion") or node.get("packageVersion") or node.get("version")),
            "supplier": ", ".join(supplier),
            "license": licenses.get(_spdx3_id(node), "") or _prefer_known(
                _license(node.get("licenseConcluded")), _license(node.get("licenseDeclared"))),
            "purl": purl,
            "cpe": cpe,
            "hashes": sorted({_scalar(h.get("algorithm")) for h in _as_list(node.get("verifiedUsing"))
                              if isinstance(h, dict) and _spdx3_type(h) == "Hash" and h.get("algorithm")}),
            "id": _spdx3_id(node),
        })
    return packages


def _spdx3_doc(data: Dict[str, Any]) -> Dict[str, Any]:
    graph = _spdx3_graph(data)
    by_id = {_spdx3_id(n): n for n in graph}
    infos = [n for n in graph if _spdx3_type(n) == "CreationInfo"]
    infos += [n.get("creationInfo") for n in graph if isinstance(n.get("creationInfo"), dict)]
    info = infos[0] if infos else {}
    rels = [n for n in graph if "Relationship" in _spdx3_type(n)]
    roots = [n for n in graph if _spdx3_type(n) in ("SpdxDocument", "software_Sbom") and _as_list(n.get("rootElement"))]
    return {
        "timestamp": _scalar(info.get("created")),
        "spec_version": _scalar(info.get("specVersion")),
        "authors": _spdx3_names(by_id, info.get("createdBy")),
        "tools": _spdx3_names(by_id, info.get("createdUsing")),
        "dependencies": sum(1 for r in rels if str(r.get("relationshipType", "")) in _SPDX3_DEPENDENCY_TYPES),
        "primary": bool(roots) or any(r.get("relationshipType") == "describes" for r in rels),
        "context": sorted({_scalar(t) for n in graph if _spdx3_type(n) == "software_Sbom"
                           for t in _as_list(n.get("software_sbomType"))}),
    }


def _cyclonedx_components(data: Dict[str, Any]) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []

    def walk(component: Any) -> None:
        if not isinstance(component, dict):
            return
        name = _scalar(component.get("name"))
        if name:
            swid = component.get("swid") if isinstance(component.get("swid"), dict) else {}
            out.append({
                "name": name,
                "version": _scalar(component.get("version")),
                # group is a namespace, not who supplies the component
                "supplier": _scalar(component.get("supplier") or component.get("manufacturer")
                                    or component.get("publisher") or component.get("author")),
                "license": _license(component.get("licenses")),
                "purl": _scalar(component.get("purl")),
                "cpe": _scalar(component.get("cpe")) or _scalar(swid.get("tagId")),
                "hashes": sorted({_scalar(h.get("alg")) for h in _as_list(component.get("hashes"))
                                  if isinstance(h, dict) and h.get("alg")}),
                "id": _scalar(component.get("bom-ref")),
            })
        for child in _as_list(component.get("components")):
            walk(child)

    md = data.get("metadata")
    if isinstance(md, dict):
        walk(md.get("component"))
    for component in _as_list(data.get("components")):
        walk(component)
    return out


def _cyclonedx_doc(data: Dict[str, Any]) -> Dict[str, Any]:
    md = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    tools = md.get("tools")
    if isinstance(tools, dict):                          # 1.5+: {"components": [...], "services": [...]}
        tools = _as_list(tools.get("components")) + _as_list(tools.get("services"))
    authors = [_scalar(a) for a in _as_list(md.get("authors"))]
    for key in ("manufacturer", "manufacture", "supplier"):
        if md.get(key):
            authors.append(_scalar(md.get(key)))
    return {
        "timestamp": _scalar(md.get("timestamp")),
        "authors": [a for a in authors if a],
        "tools": [t for t in (_scalar(t) for t in _as_list(tools)) if t],
        "dependencies": sum(1 for d in _as_list(data.get("dependencies"))
                            if isinstance(d, dict) and _as_list(d.get("dependsOn"))),
        "primary": isinstance(md.get("component"), dict) and bool(md["component"].get("name")),
        "context": sorted({_scalar(l.get("phase") or l.get("name")) for l in _as_list(md.get("lifecycles"))
                           if isinstance(l, dict) and (l.get("phase") or l.get("name"))}),
    }


def _spdx_tag_value(text: str) -> Dict[str, Any]:
    meta: Dict[str, Any] = {"creators": [], "dependencies": 0, "describes": False}
    packages: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None

    def flush() -> None:
        nonlocal current
        if current and current.get("name"):
            packages.append(current)
        current = None

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key, value = key.strip(), value.strip()
        if key == "Relationship":
            parts = value.split()
            if len(parts) >= 3:
                if parts[1].upper() in _SPDX2_DEPENDENCY_TYPES:
                    meta["dependencies"] += 1
                elif parts[1].upper() == "DESCRIBES":
                    meta["describes"] = True
            continue
        if key == "Creator":
            meta["creators"].append(value)
            continue
        if key == "PackageName":
            flush()
            current = {"name": value, "version": "", "supplier": "", "license": "", "purl": "", "cpe": "",
                       "hashes": [], "id": ""}
            continue
        if current is not None:
            if key == "PackageVersion":
                current["version"] = value
            elif key == "PackageSupplier":
                current["supplier"] = value
            elif key in ("PackageLicenseConcluded", "PackageLicenseDeclared") and not _known(current["license"]):
                current["license"] = value
            elif key == "PackageChecksum" and ":" in value:
                current["hashes"] = sorted(set(current["hashes"]) | {value.split(":", 1)[0].strip()})
            elif key == "ExternalRef":
                parts = value.split()
                if len(parts) >= 3 and parts[1].lower() == "purl":
                    current["purl"] = parts[2]
                elif len(parts) >= 3 and parts[1].lower().startswith("cpe") and not current["cpe"]:
                    current["cpe"] = parts[2]
            elif key == "SPDXID" and not current.get("id"):
                current["id"] = value
            continue
        if key in ("SPDXVersion", "DocumentName", "DocumentNamespace", "Created"):
            meta[key] = value
    flush()
    return {"meta": meta, "packages": packages}


def _xml_tag(node: Any) -> str:
    return node.tag.rsplit("}", 1)[-1].lower() if isinstance(node.tag, str) else ""


def _xml_find(node: Any, *path: str) -> Optional[Any]:
    for step in path:
        node = next((c for c in node if _xml_tag(c) == step), None)
        if node is None:
            return None
    return node


def _cyclonedx_xml(text: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    doc: Dict[str, Any] = {"timestamp": "", "authors": [], "tools": [], "dependencies": 0, "primary": False,
                           "context": []}
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return out, doc

    def text_of(node: Any, *path: str) -> str:
        found = _xml_find(node, *path) if node is not None else None
        return (found.text or "").strip() if found is not None else ""

    md = _xml_find(root, "metadata")
    if md is not None:
        doc["timestamp"] = text_of(md, "timestamp")
        authors = _xml_find(md, "authors")
        doc["authors"] = [text_of(a, "name") or (a.text or "").strip() for a in (authors if authors is not None else [])
                          if _xml_tag(a) == "author"]
        if text_of(md, "manufacturer", "name") or text_of(md, "supplier", "name"):
            doc["authors"].append(text_of(md, "manufacturer", "name") or text_of(md, "supplier", "name"))
        tools = _xml_find(md, "tools")
        doc["tools"] = [text_of(t, "name") for t in (tools.iter() if tools is not None else [])
                        if _xml_tag(t) in ("tool", "component", "service") and text_of(t, "name")]
        doc["primary"] = bool(text_of(md, "component", "name"))
        lifecycles = _xml_find(md, "lifecycles")
        doc["context"] = sorted({(p.text or "").strip() for p in (lifecycles.iter() if lifecycles is not None else [])
                                 if _xml_tag(p) in ("phase", "name") and (p.text or "").strip()})
        doc["authors"] = [a for a in doc["authors"] if a]
    deps = _xml_find(root, "dependencies")
    if deps is not None:
        doc["dependencies"] = sum(1 for d in deps.iter() if _xml_tag(d) == "dependency" and len(list(d)))
    # Like the JSON walker: the primary component, then the listed components,
    # each followed by its own nested <components>. Pedigree ancestors,
    # descendants and variants are history, and tool components under
    # metadata are not packages, so neither is walked.
    def walk(component: Any) -> List[Any]:
        out_nodes = [component]
        nested = _xml_find(component, "components")
        for child in (nested if nested is not None else []):
            if _xml_tag(child) == "component":
                out_nodes += walk(child)
        return out_nodes

    nodes: List[Any] = []
    primary = _xml_find(md, "component") if md is not None else None
    if primary is not None:
        nodes += walk(primary)
    for child in (_xml_find(root, "components") if _xml_find(root, "components") is not None else []):
        if _xml_tag(child) == "component":
            nodes += walk(child)
    for node in nodes:
        if not text_of(node, "name"):
            continue
        licenses = _xml_find(node, "licenses")
        licence = ""
        for entry in (licenses if licenses is not None else []):
            licence = (text_of(entry, "id") or text_of(entry, "name")) if _xml_tag(entry) == "license" \
                else (entry.text or "").strip()
            if licence:
                break
        hashes = _xml_find(node, "hashes")
        out.append({
            "name": text_of(node, "name"),
            "version": text_of(node, "version"),
            "supplier": text_of(node, "supplier", "name") or text_of(node, "manufacturer", "name")
            or text_of(node, "publisher") or text_of(node, "author"),
            "license": licence,
            "purl": text_of(node, "purl"),
            "cpe": text_of(node, "cpe"),
            "hashes": sorted({h.get("alg", "") for h in (hashes if hashes is not None else [])
                              if _xml_tag(h) == "hash" and h.get("alg")}),
            "id": node.get("bom-ref", ""),
        })
    return out, doc


QUALITY_BASIS = ("NTIA minimum elements (2021); the CISA 2025 draft additions are reported separately and are "
                 "not a requirement")
QUALITY_RANK = {"met": 3, "partial": 2, "not-met": 1, "none": 0}


def sbom_quality(packages: Sequence[Dict[str, Any]], doc: Dict[str, Any]) -> Dict[str, Any]:
    """How completely one SBOM covers the minimum elements. Counting, not
    judgement: a field is present or it is not."""
    total = len(packages)

    def count(pred: Any) -> int:
        return sum(1 for p in packages if pred(p))

    comps = {"total": total,
             "with_version": count(lambda p: _known(p.get("version"))),
             "with_supplier": count(lambda p: _known(p.get("supplier"))),
             "with_identifier": count(lambda p: _known(p.get("purl")) or _known(p.get("cpe"))),
             "with_hash": count(lambda p: bool(p.get("hashes"))),
             "with_license": count(lambda p: _known(p.get("license")))}
    document = {"timestamp": bool(doc.get("timestamp")), "author": bool(doc.get("authors") or doc.get("tools")),
                "tool": bool(doc.get("tools")), "dependency_relationships": bool(doc.get("dependencies")),
                "primary_component": bool(doc.get("primary")), "generation_context": bool(doc.get("context"))}
    missing: List[str] = []
    for key, label in (("with_supplier", "supplier"), ("with_version", "version"),
                       ("with_identifier", "a unique identifier (purl or CPE)")):
        if comps[key] < total:
            missing.append("%s for %d of %d components" % (label, total - comps[key], total))
    if not document["dependency_relationships"]:
        missing.append("dependency relationships")
    if not document["author"]:
        missing.append("author of the SBOM data")
    if not document["timestamp"]:
        missing.append("timestamp")
    draft: List[str] = []
    if comps["with_hash"] < total:
        draft.append("component hash for %d of %d components" % (total - comps["with_hash"], total))
    if comps["with_license"] < total:
        draft.append("license for %d of %d components" % (total - comps["with_license"], total))
    if not document["tool"]:
        draft.append("tool name")
    if not document["generation_context"]:
        draft.append("generation context")
    status = "not-met" if not total else ("met" if not missing else "partial")
    return {"basis": QUALITY_BASIS, "minimum_elements": status, "missing": missing,
            "cisa_2025_draft_missing": draft, "components": comps, "document": document}


def _finalize_sbom(path: str, rel: str, fmt: str, data: Optional[Dict[str, Any]],
                   packages: List[Dict[str, str]], source: Dict[str, Any],
                   doc: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    packages = [p for p in packages if p.get("name")][:MAX_PACKAGES]
    licenses: Dict[str, int] = {}
    for p in packages:
        lic = (p.get("license") or "").strip()
        if lic:
            licenses[lic] = licenses.get(lic, 0) + 1
    return {
        "path": rel,
        "format": fmt,
        "name": _scalar(source.get("name")),
        "spec_version": _scalar(source.get("spec_version")),
        "namespace": _scalar(source.get("namespace")),
        "created": _scalar(source.get("created")),
        "package_count": len(packages),
        "unique_components": len({(p.get("name"), p.get("version")) for p in packages}),
        "licenses": dict(sorted(licenses.items(), key=lambda kv: (-kv[1], kv[0]))[:12]),
        "packages": packages,
        "quality": sbom_quality(packages, doc or {}),
        "warnings": [],
    }


def parse_sbom(path: str, rel: str, text: str) -> Optional[Dict[str, Any]]:
    stripped = text.lstrip()
    if stripped.startswith("{"):
        data = _json(text)
        if not isinstance(data, dict):
            return None
        if data.get("spdxVersion"):
            packages = _spdx2_packages(data)
            return _finalize_sbom(path, rel, "spdx-json", data, packages, {
                "name": data.get("name"),
                "spec_version": data.get("spdxVersion"),
                "namespace": data.get("documentNamespace"),
                "created": (data.get("creationInfo") or {}).get("created")
                if isinstance(data.get("creationInfo"), dict) else "",
            }, _spdx2_doc(data))
        if data.get("bomFormat") == "CycloneDX":
            packages = _cyclonedx_components(data)
            md = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
            return _finalize_sbom(path, rel, "cyclonedx-json", data, packages, {
                "name": (md.get("component") or {}).get("name")
                if isinstance(md.get("component"), dict) else data.get("name"),
                "spec_version": data.get("specVersion"),
                "namespace": data.get("serialNumber"),
                "created": md.get("timestamp"),
            }, _cyclonedx_doc(data))
        if data.get("@graph") or data.get("graph"):
            packages = _spdx3_packages(data)
            doc = _spdx3_doc(data)
            return _finalize_sbom(path, rel, "spdx-jsonld", data, packages, {
                "name": data.get("name") or next((_scalar(n.get("name")) for n in _spdx3_graph(data)
                                                  if _spdx3_type(n) in ("SpdxDocument", "software_Sbom")), ""),
                "spec_version": data.get("spdxVersion") or (("SPDX-" + doc["spec_version"]) if doc["spec_version"]
                                                            else "SPDX-3"),
                "namespace": data.get("@id"),
                "created": doc["timestamp"],
            }, doc)
        return None
    low = text.lower()
    if "spdxversion:" in low or "packagename:" in low:
        parsed = _spdx_tag_value(text)
        meta = parsed["meta"]
        return _finalize_sbom(path, rel, "spdx-tag-value", None, parsed["packages"], {
            "name": meta.get("DocumentName"),
            "spec_version": meta.get("SPDXVersion"),
            "namespace": meta.get("DocumentNamespace"),
            "created": meta.get("Created"),
        }, {"timestamp": meta.get("Created", ""),
            "authors": _split_creators(meta["creators"])[0], "tools": _split_creators(meta["creators"])[1],
            "dependencies": meta["dependencies"], "primary": meta["describes"], "context": []})
    if "<bom" in low and "cyclonedx" in low:
        packages, doc = _cyclonedx_xml(text)
        return _finalize_sbom(path, rel, "cyclonedx-xml", None, packages, {
            "name": "", "spec_version": "", "namespace": "", "created": doc["timestamp"],
        }, doc)
    return None


def _decode_payload(payload: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(payload, str) or not payload:
        return None
    raw: Optional[bytes] = None
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            candidate = decoder(payload + "===", validate=False)
            if candidate:
                raw = candidate
                break
        except Exception:
            continue
    if raw is None:
        return None
    try:
        value = json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def _find_envelope(obj: Any, depth: int = 0) -> Optional[Dict[str, Any]]:
    if depth > 6 or not isinstance(obj, dict):
        return None
    if isinstance(obj.get("dsseEnvelope"), dict):
        return obj["dsseEnvelope"]
    if "payload" in obj and "payloadType" in obj:
        return obj
    for key in ("bundle", "attestation", "sigstoreBundle", "envelope"):
        found = _find_envelope(obj.get(key), depth + 1)
        if found:
            return found
    return None


def _find_statement(obj: Any, depth: int = 0) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]], Optional[str]]:
    if depth > 7:
        return None, None, "nesting limit"
    if isinstance(obj, list):
        for item in obj:
            st, env, err = _find_statement(item, depth + 1)
            if st:
                return st, env, None
        return None, None, "no statement"
    if not isinstance(obj, dict):
        return None, None, "not an object"
    if isinstance(obj.get("statement"), dict):
        return obj["statement"], _find_envelope(obj), None
    if obj.get("_type") and (obj.get("predicateType") or obj.get("subject")):
        return obj, _find_envelope(obj), None
    if obj.get("predicateType") and isinstance(obj.get("subject"), (list, dict)):
        return obj, _find_envelope(obj), None
    envelope = _find_envelope(obj)
    if envelope:
        statement = _decode_payload(envelope.get("payload"))
        if statement:
            return statement, envelope, None
        return None, envelope, "DSSE payload is not base64-encoded JSON"
    for key in ("bundle", "attestation", "sigstoreBundle", "evidence"):
        if key in obj:
            st, env, err = _find_statement(obj[key], depth + 1)
            if st:
                return st, env, None
    return None, None, "no in-toto statement or DSSE envelope"


def _verification_from_result(result: Any) -> Tuple[str, str]:
    if not isinstance(result, dict):
        return "", ""
    values: List[str] = []
    for key, value in result.items():
        if key.endswith("VerificationStatus") and isinstance(value, str):
            values.append(value.lower())
            if value.lower() in ("failed", "failure", "invalid", "error"):
                return "failed", "%s=%s" % (key, value)
    if values and all(v in ("success", "verified", "passed", "ok") for v in values):
        return "provider-verified", ", ".join("%s=%s" % (k, v) for k, v in result.items()
                                              if k.endswith("VerificationStatus"))
    if result.get("verified") is True:
        return "provider-verified", "verified=true"
    return "", ""


def _subject_list(value: Any) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for item in _as_list(value):
        if isinstance(item, dict):
            digest = _digest_map(item.get("digest"))
            if not digest:
                digest = _digest_map({k: v for k, v in item.items()
                                      if k.lower() in ("sha256", "sha1", "sha512", "md5", "gitcommit")})
            out.append({"name": _scalar(item.get("name")), "digest": digest})
        elif isinstance(item, str):
            out.append({"name": item, "digest": {}})
    return out


def _statement_summary(statement: Dict[str, Any], path: str, rel: str,
                       source: str, verification: str, verification_detail: str,
                       created_by: str = "", created_at: str = "",
                       media_type: str = "", download_path: str = "",
                       signature_material: bool = False, key_source: str = "") -> Dict[str, Any]:
    predicate = statement.get("predicate") if isinstance(statement.get("predicate"), dict) else {}
    predicate_type = _scalar(statement.get("predicateType"))
    kind = "unknown"
    if "slsa.dev/provenance/v1" in predicate_type:
        kind = "slsa-provenance-v1"
    elif "slsa.dev/provenance/v0.2" in predicate_type:
        kind = "slsa-provenance-v0.2"
    elif "spdx" in predicate_type.lower() or predicate.get("spdxVersion"):
        kind = "spdx-sbom"
    elif "cyclonedx" in predicate_type.lower() or predicate.get("bomFormat") == "CycloneDX":
        kind = "cyclonedx-sbom"
    elif predicate_type:
        kind = predicate_type.rsplit("/", 1)[-1] or predicate_type

    builder = ""
    source_repo = ""
    source_revision = ""
    workflow = ""
    build_type = ""
    created = created_at
    materials = 0
    if isinstance(predicate.get("runDetails"), dict):
        run = predicate["runDetails"]
        if isinstance(run.get("builder"), dict):
            builder = _scalar(run["builder"].get("id"))
        md = run.get("metadata") if isinstance(run.get("metadata"), dict) else {}
        created = created or _scalar(md.get("finishedOn") or md.get("buildFinishedOn"))
    if isinstance(predicate.get("builder"), dict):
        builder = builder or _scalar(predicate["builder"].get("id"))
    bd = predicate.get("buildDefinition") if isinstance(predicate.get("buildDefinition"), dict) else {}
    if bd:
        build_type = _scalar(bd.get("buildType"))
        ext = bd.get("externalParameters") if isinstance(bd.get("externalParameters"), dict) else {}
        wf = ext.get("workflow") if isinstance(ext.get("workflow"), dict) else {}
        source_repo = _scalar(wf.get("repository"))
        workflow = " ".join(x for x in (_scalar(wf.get("path")), _scalar(wf.get("ref"))) if x)
        deps = _as_list(bd.get("resolvedDependencies"))
        materials = len(deps)
        for dep in deps:
            if not isinstance(dep, dict):
                continue
            digest = _digest_map(dep.get("digest"))
            source_revision = source_revision or digest.get("gitcommit") or digest.get("sha1") or ""
    else:
        build_type = _scalar(predicate.get("buildType"))
        inv = predicate.get("invocation") if isinstance(predicate.get("invocation"), dict) else {}
        cfg = inv.get("configSource") if isinstance(inv.get("configSource"), dict) else {}
        source_repo = _scalar(cfg.get("uri"))
        source_revision = _digest_map(cfg.get("digest")).get("sha1", "")
        workflow = _scalar(cfg.get("entryPoint"))
        mats = _as_list(predicate.get("materials"))
        materials = len(mats)
        if not source_revision:
            for mat in mats:
                if isinstance(mat, dict):
                    source_revision = _digest_map(mat.get("digest")).get("sha1", "")
                    if source_revision:
                        break
    if not source_repo:
        source_repo = _scalar((predicate.get("invocation") or {}).get("configSource", {}).get("uri")) \
            if isinstance(predicate.get("invocation"), dict) else ""
    if source != "jfrog" and ("github.com" in builder.lower() or "github.com" in source_repo.lower()):
        source = "github"
    warnings: List[str] = []
    if not statement.get("subject"):
        warnings.append("statement has no subject digest")
    if kind == "slsa-provenance-v1" and not source_revision:
        warnings.append("SLSA provenance has no git revision in resolvedDependencies")
    if verification in ("unverified", "unsigned") and signature_material:
        warnings.append("signature material present but not cryptographically verified")
    if verification == "provider-verified" and _bundle_key(key_source):
        warnings.append(BUNDLE_KEY_WARNING)
    out = {
        "path": rel,
        "source": source,
        "format": "sigstore-bundle" if signature_material else "in-toto-statement",
        "predicate_type": predicate_type,
        "predicate_kind": kind,
        "subjects": _subject_list(statement.get("subject")),
        "builder": builder,
        "source_repo": source_repo,
        "source_revision": source_revision,
        "workflow": workflow,
        "build_type": build_type,
        "created": created,
        "created_by": created_by,
        "materials": materials,
        "signature_material": signature_material,
        "verification": verification or ("unverified" if signature_material else "unsigned"),
        "verification_detail": verification_detail,
        "verify_hint": _verify_hint(source, rel),
        "media_type": media_type,
        "download_path": download_path,
        "warnings": warnings,
        "embedded_sbom": kind in ("spdx-sbom", "cyclonedx-sbom"),
    }
    if key_source:
        out["key_source"] = key_source
    return out


def _bundle_key(key_source: str) -> bool:
    return key_source.strip().lower().startswith("sigstore bundle")


def _key_source(result: Any) -> str:
    return _scalar(result.get("keySource")) if isinstance(result, dict) else ""


def _verify_hint(source: str, rel: str) -> str:
    if source == "github":
        return "gh attestation verify <artifact> --repo <owner/repo>  # or use the downloaded bundle"
    if source == "jfrog":
        return "jf evd verify --format json <subject>"
    return "cosign verify-attestation --type slsaprovenance <artifact>"


def _parse_jfrog_bundle(path: str, rel: str, data: Dict[str, Any]) -> Tuple[
        List[Dict[str, Any]], Dict[str, Any], List[Dict[str, Any]]]:
    attestations: List[Dict[str, Any]] = []
    sboms: List[Dict[str, Any]] = []
    items = _as_list(data.get("evidenceVerifications"))
    if not items:
        items = _as_list(data.get("evidence"))
    if not items and any(k in data for k in ("sigstoreBundle", "dsseEnvelope", "predicate")):
        items = [data]
    app = data.get("application")
    app_name = _scalar(app.get("name") if isinstance(app, dict) else app)
    version = _scalar(data.get("applicationVersion") or data.get("version"))
    bundle_raw = data.get("releaseBundle")
    bundle_name = _scalar(bundle_raw.get("name") if isinstance(bundle_raw, dict) else bundle_raw)
    if not bundle_name:
        bundle_name = _scalar(data.get("releaseBundleName"))
    bundle_version = _scalar(data.get("releaseBundleVersion")
                             or (bundle_raw.get("version") if isinstance(bundle_raw, dict) else ""))
    subject = data.get("subject")
    verified = failed = 0
    for item in items:
        if not isinstance(item, dict):
            continue
        vr = item.get("verificationResult")
        status, detail = _verification_from_result(vr)
        if status == "provider-verified":
            verified += 1
        elif status == "failed":
            failed += 1
        bundle = item.get("sigstoreBundle")
        target: Any = bundle if bundle is not None else item
        statement, envelope, err = _find_statement(target)
        if statement is None and item.get("dsseEnvelope"):
            statement, envelope, err = _find_statement(item)
        pred = item.get("predicate")
        if statement is None and isinstance(pred, dict):
            if pred.get("_type") and pred.get("predicateType"):
                statement = pred
            elif pred.get("spdxVersion") or pred.get("bomFormat") == "CycloneDX":
                statement = {
                    "_type": "https://in-toto.io/Statement/v1",
                    "subject": _subject_list(subject) if subject else [],
                    "predicateType": ("https://spdx.dev/Document" if pred.get("spdxVersion")
                                      else "https://cyclonedx.org/bom"),
                    "predicate": pred,
                }
        download_path = _scalar(item.get("downloadPath"))
        if statement is None and download_path and not re.match(r"^[a-z][a-z0-9+.-]*://", download_path):
            candidates = [download_path] if os.path.isabs(download_path) else [
                os.path.join(os.path.dirname(path), download_path),
                os.path.join(os.getcwd(), download_path),
            ]
            for candidate in candidates:
                downloaded = _read_text(candidate)
                if not downloaded:
                    continue
                downloaded_data = _json(downloaded)
                if downloaded_data is None:
                    for line in downloaded.splitlines():
                        if line.strip():
                            downloaded_data = _json(line.strip())
                            if downloaded_data is not None:
                                break
                if downloaded_data is not None:
                    st, env, down_err = _find_statement(downloaded_data)
                    if st is not None:
                        statement, envelope, err = st, env, None
                        break
        if statement is None:
            attestations.append({
                "path": rel,
                "source": "jfrog",
                "format": "jfrog-evidence",
                "predicate_type": _scalar(item.get("predicateType")),
                "predicate_kind": "unknown",
                "subjects": _subject_list(subject) if subject else [],
                "builder": "", "source_repo": "", "source_revision": "",
                "workflow": "", "build_type": "", "created": _scalar(item.get("createdAt")),
                "created_by": _scalar(item.get("createdBy")),
                "materials": 0, "signature_material": bool(item.get("sigstoreBundle") or item.get("dsseEnvelope")),
                "verification": status or "unverified",
                "verification_detail": detail or (err or ""),
                "verify_hint": _verify_hint("jfrog", rel),
                "media_type": _scalar(item.get("mediaType")),
                "download_path": _scalar(item.get("downloadPath")),
                "warnings": [err or "no in-toto statement found"]
                + ([BUNDLE_KEY_WARNING] if status == "provider-verified" and _bundle_key(_key_source(vr)) else []),
                "embedded_sbom": False,
            })
            if _key_source(vr):
                attestations[-1]["key_source"] = _key_source(vr)
            continue
        sig = bool(envelope and envelope.get("signatures")) or bool(item.get("sigstoreBundle"))
        summary = _statement_summary(
            statement, path, rel, "jfrog", status or ("unverified" if sig else "unsigned"),
            detail, _scalar(item.get("createdBy")), _scalar(item.get("createdAt")),
            _scalar(item.get("mediaType")), _scalar(item.get("downloadPath")), sig, _key_source(vr),
        )
        if subject:
            summary["subjects"] = summary["subjects"] or _subject_list(subject)
        attestations.append(summary)
        predicate = statement.get("predicate") if isinstance(statement.get("predicate"), dict) else {}
        if isinstance(predicate, dict) and (predicate.get("spdxVersion")
                                            or predicate.get("bomFormat") == "CycloneDX"):
            embedded = parse_sbom(path, rel + "#predicate", json.dumps(predicate))
            if embedded:
                embedded["source"] = "attestation-predicate"
                sboms.append(embedded)
    first = next((x for x in items if isinstance(x, dict)), {})
    bundle_info = {
        "path": rel,
        "schema_version": _scalar(data.get("schemaVersion")),
        "application": app_name,
        "version": version,
        "release_bundle": bundle_name,
        "release_bundle_version": bundle_version,
        "subject": _subject_list(subject) if subject else [],
        "evidence_count": len(items),
        "verified": verified,
        "failed": failed,
        "created_by": _scalar(data.get("createdBy") or first.get("createdBy")),
        "created_at": _scalar(data.get("createdAt") or data.get("updatedAt")
                              or first.get("createdAt")),
        "evidence_types": sorted({_scalar(x.get("mediaType") or x.get("predicateType"))
                                  for x in items if isinstance(x, dict)
                                  and (x.get("mediaType") or x.get("predicateType"))}),
    }
    return attestations, bundle_info, sboms


def parse_evidence_file(path: str, rel: str, text: str, forced: str = "") -> Dict[str, Any]:
    result: Dict[str, Any] = {"sboms": [], "attestations": [], "jfrog": [], "warnings": []}
    kind_set = _detect_kind(text, path)
    if forced:
        kind_set.add(forced)
    data: Any = _json(text)
    jfrog_parsed = False
    if "sbom" in kind_set:
        sbom = parse_sbom(path, rel, text)
        if sbom:
            result["sboms"].append(sbom)
        elif data is not None and "jfrog" not in kind_set:
            result["warnings"].append("%s: recognized as SBOM but no supported package list" % rel)
    if "jfrog" in kind_set and isinstance(data, dict):
        atts, bundle, embedded_sboms = _parse_jfrog_bundle(path, rel, data)
        if (bundle.get("evidence_count") or bundle.get("application")
                or bundle.get("release_bundle") or bundle.get("subject")):
            result["attestations"].extend(atts)
            result["sboms"].extend(embedded_sboms)
            result["jfrog"].append(bundle)
            jfrog_parsed = True
    if "attestation" in kind_set and not jfrog_parsed:
        docs: List[Any] = []
        if isinstance(data, list):
            docs = data
        elif isinstance(data, dict) and isinstance(data.get("attestations"), list):
            docs = data["attestations"]
        elif isinstance(data, dict) and isinstance(data.get("evidenceVerifications"), list):
            docs = data["evidenceVerifications"]
        elif isinstance(data, dict) and isinstance(data.get("evidence"), list):
            docs = data["evidence"]
        elif data is not None:
            docs = [data]
        else:
            # JSONL: one bundle per line.
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                doc = _json(line)
                if doc is not None:
                    docs.append(doc)
        for doc in docs:
            statement, envelope, err = _find_statement(doc)
            if statement is None:
                result["warnings"].append("%s: %s" % (rel, err or "no attestation statement"))
                continue
            vr = doc.get("verificationResult") if isinstance(doc, dict) else None
            status, detail = _verification_from_result(vr)
            sig = bool(envelope and envelope.get("signatures"))
            if not status:
                status = "unverified" if sig else "unsigned"
            source = "github" if "github" in rel.lower() else "sigstore"
            summary = _statement_summary(
                statement, path, rel, source, status, detail,
                _scalar(doc.get("createdBy")) if isinstance(doc, dict) else "",
                _scalar(doc.get("createdAt")) if isinstance(doc, dict) else "",
                _scalar(doc.get("mediaType")) if isinstance(doc, dict) else "",
                _scalar(doc.get("downloadPath")) if isinstance(doc, dict) else "",
                sig or bool(isinstance(doc, dict) and doc.get("verificationMaterial")),
                _key_source(vr),
            )
            result["attestations"].append(summary)
            predicate = statement.get("predicate") if isinstance(statement.get("predicate"), dict) else {}
            if isinstance(predicate, dict) and (predicate.get("spdxVersion")
                                                or predicate.get("bomFormat") == "CycloneDX"):
                embedded = parse_sbom(path, rel + "#predicate", json.dumps(predicate))
                if embedded:
                    embedded["source"] = "attestation-predicate"
                    result["sboms"].append(embedded)
    return result


def inspect(root: str, sbom_paths: Sequence[str] = (), attestation_paths: Sequence[str] = (),
            jfrog_paths: Sequence[str] = (), requirements: Optional[Dict[str, bool]] = None,
            discover: bool = True,
            extra_files: Sequence[Tuple[str, str, str, str]] = ()) -> Dict[str, Any]:
    """`extra_files` are (path, display name, forced kind, origin) tuples for
    evidence obtained outside the repository (see jh_verify); each parsed
    record keeps its origin."""
    root = os.path.abspath(root)
    explicit_jobs: List[Tuple[str, str]] = []
    for paths, forced in ((sbom_paths, "sbom"), (attestation_paths, "attestation"),
                          (jfrog_paths, "jfrog")):
        for raw in paths:
            explicit_jobs.append((os.path.abspath(raw), forced))
    explicit_set = {path for path, _ in explicit_jobs}
    jobs = list(explicit_jobs)
    if discover:
        for path in _walk_candidates(root):
            if path not in explicit_set:
                jobs.append((path, ""))
    sboms: List[Dict[str, Any]] = []
    attestations: List[Dict[str, Any]] = []
    jfrog: List[Dict[str, Any]] = []
    warnings: List[str] = []
    seen_files: Set[str] = set()
    labels: Dict[str, Tuple[str, str]] = {}
    for path, rel, forced, origin in extra_files:
        path = os.path.abspath(path)
        labels[path] = (rel, origin)
        jobs.append((path, forced))
    for path, forced in jobs:
        if path in seen_files:
            continue
        rel, origin = labels.get(path, (_rel(root, path), ""))
        if not os.path.isfile(path):
            warnings.append("%s: evidence file not found" % rel)
            continue
        seen_files.add(path)
        text = _read_text(path)
        if text is None:
            warnings.append("%s: skipped (binary or larger than %d bytes)" % (rel, MAX_EVIDENCE_BYTES))
            continue
        parsed = parse_evidence_file(path, rel, text, forced=forced)
        if origin:
            for record in parsed["sboms"] + parsed["attestations"] + parsed["jfrog"]:
                record["origin"] = origin
            if origin == "github-actions-artifact":
                for record in parsed["sboms"]:
                    record.setdefault("warnings", []).append(
                        "fetched from a GitHub Actions artifact: unsigned; integrity rests on the "
                        "digest GitHub recorded for the artifact")
        sboms.extend(parsed["sboms"])
        attestations.extend(parsed["attestations"])
        jfrog.extend(parsed["jfrog"])
        warnings.extend(parsed["warnings"])

    # A file can be discovered by both content and filename; keep the richest
    # record for each semantic object.
    def dedupe(items: List[Dict[str, Any]], keys: Tuple[str, ...]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        seen: Set[Tuple[Any, ...]] = set()
        for item in items:
            key = tuple(item.get(k) for k in keys)
            if key in seen:
                continue
            seen.add(key)
            out.append(item)
        return out

    sboms = dedupe(sboms, ("path", "format", "name", "package_count"))
    for att in attestations:
        att["_subject_digest"] = ",".join(
            "%s:%s" % (alg, val)
            for sub in att.get("subjects", [])
            for alg, val in (sub.get("digest") or {}).items()
        )
    # A JFrog evidence item may reference a locally downloaded payload that is
    # also discovered as a standalone bundle. Keep one semantic attestation,
    # preferring the exporter's verified record over a loose bundle.
    attestation_keys = ("predicate_type", "source_revision", "builder", "_subject_digest")
    rank = {"provider-verified": 0, "unverified": 1, "unsigned": 2, "failed": 3}
    order: List[Tuple[Any, ...]] = []
    best: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
    for item in attestations:
        key = tuple(item.get(k) for k in attestation_keys)
        if key not in best:
            order.append(key)
            best[key] = item
        elif rank.get(item.get("verification", ""), 9) < rank.get(best[key].get("verification", ""), 9):
            best[key] = item
    attestations = [best[key] for key in order]
    jfrog = dedupe(jfrog, ("path", "application", "version", "release_bundle"))
    for item in attestations:
        item.pop("_subject_digest", None)

    if not sboms:
        warnings.append("no SBOM found (SPDX or CycloneDX)")
    if not attestations:
        warnings.append("no in-toto/Sigstore/GitHub attestation found")
    if jfrog and not attestations:
        warnings.append("JFrog evidence bundle found but no parseable in-toto statement")
    report = {
        "root": root,
        "summary": {},
        "sboms": sboms,
        "attestations": attestations,
        "jfrog": jfrog,
        "requirements": dict(requirements or {}),
        "gate": {},
        "warnings": list(dict.fromkeys(warnings)),
    }
    return summarize(report)


VERIFIED_STATES = ("provider-verified", "tool-verified")


def best_sbom_quality(sboms: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """The most complete SBOM's quality (ties: fewest missing elements)."""
    if not sboms:
        return {"minimum_elements": "none", "missing": ["an SBOM"], "cisa_2025_draft_missing": [], "path": ""}
    ranked = sorted(sboms, key=lambda s: (-QUALITY_RANK[s.get("quality", {}).get("minimum_elements", "not-met")],
                                          len(s.get("quality", {}).get("missing", [])), s.get("path", "")))
    q = ranked[0].get("quality") or {"minimum_elements": "not-met", "missing": [], "cisa_2025_draft_missing": []}
    return {"minimum_elements": q["minimum_elements"], "missing": list(q.get("missing", [])),
            "cisa_2025_draft_missing": list(q.get("cisa_2025_draft_missing", [])), "path": ranked[0].get("path", "")}


def summarize(report: Dict[str, Any]) -> Dict[str, Any]:
    """(Re)compute summary counts and the requirement gate. Called again by
    jh_verify after tool results have been attached."""
    sboms, attestations = report["sboms"], report["attestations"]
    req = report.get("requirements") or {}
    verification = report.get("verification") or {}
    results = verification.get("results", [])
    tool_verified = any(r.get("outcome") == "tool-verified" for r in results)
    reasons: List[str] = []
    if req.get("sbom") and not sboms:
        reasons.append("no SBOM found")
    best = best_sbom_quality(sboms)
    if req.get("sbom_minimum") and best["minimum_elements"] != "met":
        reasons.append("no SBOM meets the NTIA minimum elements (best: %s%s)" % (
            best["minimum_elements"], "; missing " + ", ".join(best["missing"][:3]) if best["missing"] else ""))
    if req.get("attestation") and not attestations:
        reasons.append("no attestation found")
    if req.get("verified_attestation") and not tool_verified and not any(
            a.get("verification") in VERIFIED_STATES for a in attestations):
        reasons.append("no provider-verified or tool-verified attestation found")
    for r in results:
        if r.get("outcome") == "failed":
            reasons.append("verification failed: %s (%s): %s" % (r["subject"], r["verifier"], r["reason"]))
        elif r.get("outcome") in ("not-run", "error", "signature-only"):
            reasons.append("verification not completed: %s (%s): %s" % (r["subject"], r["verifier"], r["reason"]))
    unique_components = set()
    for s in sboms:
        for p in s.get("packages", []):
            unique_components.add((p.get("name"), p.get("version")))

    def count(state: str) -> int:
        return sum(1 for a in attestations if a.get("verification") == state)

    report["summary"] = {
        "sboms": len(sboms),
        "attestations": len(attestations),
        "jfrog_bundles": len(report["jfrog"]),
        "packages": sum(s.get("package_count", 0) for s in sboms),
        "unique_components": len(unique_components),
        "sbom_minimum_elements": best["minimum_elements"],
        "verified_attestations": sum(1 for a in attestations if a.get("verification") in VERIFIED_STATES),
        "unverified_attestations": count("unverified"),
        "unsigned_attestations": count("unsigned"),
        "failed_attestations": count("failed"),
        "warnings": len(report["warnings"]),
    }
    if verification:
        report["summary"].update({
            "tool_verified_attestations": count("tool-verified"),
            "signature_only_attestations": count("signature-only"),
            "verifications": len(results),
            "verifications_passed": sum(1 for r in results if r.get("outcome") == "tool-verified"),
        })
    report["gate"] = {"result": "fail" if reasons else "pass", "reasons": reasons}
    return report


def summary_line(report: Dict[str, Any]) -> str:
    s = report.get("summary", {})
    bits = [
        "SBOM %d" % s.get("sboms", 0),
        "attestations %d" % s.get("attestations", 0),
        "JFrog %d" % s.get("jfrog_bundles", 0),
        "packages %d" % s.get("packages", 0),
        "verified %d" % s.get("verified_attestations", 0),
    ]
    if "verifications" in s:
        bits.append("checks %d/%d passed" % (s.get("verifications_passed", 0), s.get("verifications", 0)))
    return " · ".join(bits)


def markdown(report: Dict[str, Any], heading: str = "## Supply chain evidence") -> str:
    s = report.get("summary", {})
    out: List[str] = [heading, ""]
    out.append("**%s**" % summary_line(report))
    out.append("")
    if report.get("gate", {}).get("result") == "fail":
        out.append("> Supply-chain requirement failed: %s"
                   % "; ".join(report["gate"].get("reasons", [])))
    if report.get("sboms"):
        out.append("")
        out.append("### SBOMs")
        out.append("")
        out.append("| File | Format | Spec | Packages | Licenses | Minimum elements |")
        out.append("|---|---|---|---:|---|---|")
        for sbom in report["sboms"]:
            licenses = ", ".join("%s ×%d" % (k, v) for k, v in list(sbom.get("licenses", {}).items())[:4]) or "—"
            out.append("| `%s` | %s | %s | %d | %s | %s |"
                       % (sbom.get("path"), sbom.get("format"), sbom.get("spec_version") or "—",
                          sbom.get("package_count", 0), licenses,
                          (sbom.get("quality") or {}).get("minimum_elements", "—")))
        for sbom in report["sboms"]:
            q = sbom.get("quality") or {}
            draft = ("; the CISA 2025 draft also lists %s" % "; ".join(q["cisa_2025_draft_missing"])
                     if q.get("cisa_2025_draft_missing") else "")
            if q.get("missing"):
                out.append("")
                out.append("- `%s` is missing %s%s" % (sbom.get("path"), "; ".join(q["missing"]), draft))
            elif draft:
                out.append("")
                out.append("- `%s` covers the NTIA minimum elements%s" % (sbom.get("path"), draft))
        out.append("")
        out.append("_Minimum elements: %s._" % QUALITY_BASIS)
        for sbom in report["sboms"]:
            if sbom.get("source") == "attestation-predicate":
                out.append("")
                out.append("_`%s` was embedded in an attestation predicate._" % sbom.get("path"))
    if report.get("attestations"):
        out.append("")
        out.append("### Attestations")
        out.append("")
        out.append("| File | Kind | Subject | Builder / source | Verification |")
        out.append("|---|---|---|---|---|")
        for att in report["attestations"]:
            subject = ", ".join(
                "%s%s" % (sub.get("name", ""), (" " + next(iter(sub.get("digest", {}).values()))) if sub.get("digest") else "")
                for sub in att.get("subjects", [])[:2]
            ) or "—"
            provenance = att.get("builder") or att.get("source_repo") or "—"
            state = att.get("verification", "unknown")
            if att.get("verified_by"):
                state += " (%s)" % att["verified_by"]
            elif state == "provider-verified" and _bundle_key(att.get("key_source", "")):
                state += " (bundle key)"
            out.append("| `%s` | %s | %s | %s | %s |"
                       % (att.get("path"), att.get("predicate_kind", "unknown"), subject,
                          provenance, state))
        for att in report["attestations"]:
            details = []
            if att.get("source_revision"):
                details.append("revision `%s`" % att["source_revision"])
            if att.get("verification_detail"):
                details.append(att["verification_detail"])
            if att.get("warnings"):
                details.append("; ".join(att["warnings"]))
            if details:
                out.append("")
                out.append("- `%s` · %s" % (att.get("path"), " · ".join(details)))
            if att.get("verification") in ("unverified", "unsigned"):
                out.append("  - verify: `%s`" % att.get("verify_hint", ""))
    if report.get("jfrog"):
        out.append("")
        out.append("### JFrog AppTrust evidence")
        out.append("")
        out.append("| File | Application | Version | Evidence | Verified | Failed |")
        out.append("|---|---|---|---:|---:|---:|")
        for bundle in report["jfrog"]:
            out.append("| `%s` | %s | %s | %d | %d | %d |"
                       % (bundle.get("path"), bundle.get("application") or "—",
                          bundle.get("version") or bundle.get("release_bundle_version") or "—",
                          bundle.get("evidence_count", 0), bundle.get("verified", 0),
                          bundle.get("failed", 0)))
    ver = report.get("verification")
    if ver:
        out.append("")
        out.append("### Verification (%s, plan `%s`)" % (ver.get("mode"), ver.get("plan")))
        out.append("")
        out.append("| Subject | Verifier | Outcome | Reason |")
        out.append("|---|---|---|---|")
        for r in ver.get("results", []):
            tool = ("%s %s" % (r.get("verifier"), r.get("tool_version") or "")).strip()
            out.append("| `%s` | %s | **%s** | %s |"
                       % (r.get("subject"), tool, r.get("outcome"), str(r.get("reason", "")).replace("|", "/")))
        for f in ver.get("fetched", []):
            what = f.get("name") or f.get("subject") or ""
            got = f.get("error") or ("%d bundle(s)" % f["count"] if "count" in f
                                     else "%d file(s)" % len(f.get("files", [])))
            out.append("")
            out.append("- fetched %s `%s`: %s" % (f.get("kind"), what, got))
        if ver.get("network_requests"):
            out.append("- network requests made by jankhunt42: %d" % ver["network_requests"])
    out.append("")
    if ver:
        out.append("> jankhunt42 performs no cryptographic verification itself. `tool-verified` means the named "
                   "verifier (`gh`, `cosign`, or `jf`) checked the signature and signer identity; "
                   "`signature-only` means the signature was checked but not who signed it; "
                   "`provider-verified` means an exporter recorded a successful result.")
    else:
        out.append("> jankhunt42 parses evidence but does not perform cryptographic verification itself. "
                   "`provider-verified` means the exporter recorded a successful verification result; "
                   "otherwise run the listed verification command with `gh`, `cosign`, or `jf`, "
                   "or use `supply-chain --verify PLAN`.")
    if report.get("warnings"):
        out.append("")
        out.append("**Evidence gaps:**")
        out.append("")
        for warning in report["warnings"]:
            out.append("- %s" % warning)
    return "\n".join(out)
