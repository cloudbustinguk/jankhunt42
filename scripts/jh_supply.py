#!/usr/bin/env python3
"""Offline supply-chain evidence inspection for jankhunt.

Supported inputs:
* SPDX 2.x JSON and tag-value, SPDX 3 JSON-LD
* CycloneDX JSON and XML
* Sigstore / DSSE / in-toto bundles produced by GitHub artifact attestations
* JFrog AppTrust / `jf evd verify --format json` evidence exports

This module never contacts a registry, transparency log, or JFrog instance. It
parses and correlates evidence that is already on disk. Cryptographic
verification is reported only when the exporter (for example JFrog) recorded a
successful verification result; otherwise the file is marked unverified.
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


def _spdx2_packages(data: Dict[str, Any]) -> List[Dict[str, str]]:
    packages: List[Dict[str, str]] = []
    for p in _as_list(data.get("packages")):
        if not isinstance(p, dict):
            continue
        purl = ""
        for ref in _as_list(p.get("externalRefs")):
            if isinstance(ref, dict) and "purl" in str(ref.get("referenceType", "")).lower():
                purl = str(ref.get("referenceLocator", ""))
        packages.append({
            "name": _scalar(p.get("name")),
            "version": _scalar(p.get("versionInfo")),
            "supplier": _scalar(p.get("supplier")),
            "license": _license(p.get("licenseConcluded") or p.get("licenseDeclared")),
            "purl": purl,
            "id": _scalar(p.get("SPDXID")),
        })
    return packages


def _spdx3_packages(data: Dict[str, Any]) -> List[Dict[str, str]]:
    graph = _as_list(data.get("@graph")) or _as_list(data.get("graph"))
    packages: List[Dict[str, str]] = []
    for node in graph:
        if not isinstance(node, dict):
            continue
        typ = str(node.get("type") or node.get("@type") or "")
        if "Package" not in typ and "package" not in typ:
            continue
        packages.append({
            "name": _scalar(node.get("name")),
            "version": _scalar(node.get("packageVersion") or node.get("version")),
            "supplier": _scalar(node.get("supplier") or node.get("originatedBy")),
            "license": _license(node.get("licenseConcluded") or node.get("licenseDeclared")),
            "purl": _scalar(node.get("purl") or node.get("packageUrl")),
            "id": _scalar(node.get("spdxId") or node.get("@id")),
        })
    return packages


def _cyclonedx_components(data: Dict[str, Any]) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []

    def walk(component: Any) -> None:
        if not isinstance(component, dict):
            return
        name = _scalar(component.get("name"))
        if name:
            out.append({
                "name": name,
                "version": _scalar(component.get("version")),
                "supplier": _scalar(component.get("supplier") or component.get("group")),
                "license": _license(component.get("licenses")),
                "purl": _scalar(component.get("purl")),
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


def _spdx_tag_value(text: str) -> Dict[str, Any]:
    meta: Dict[str, str] = {}
    packages: List[Dict[str, str]] = []
    current: Optional[Dict[str, str]] = None

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
        if key == "PackageName":
            flush()
            current = {"name": value, "version": "", "supplier": "", "license": "", "purl": "", "id": ""}
            continue
        if current is not None:
            if key == "PackageVersion":
                current["version"] = value
            elif key == "PackageSupplier":
                current["supplier"] = value
            elif key in ("PackageLicenseConcluded", "PackageLicenseDeclared"):
                current["license"] = value
            elif key == "PackageDownloadLocation":
                current["purl"] = value
            elif key == "SPDXID" and not current.get("id"):
                current["id"] = value
            continue
        if key in ("SPDXVersion", "DocumentName", "DocumentNamespace", "Created", "Creator"):
            meta[key] = value
    flush()
    return {"meta": meta, "packages": packages}


def _cyclonedx_xml(text: str) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return out
    for node in root.iter():
        tag = node.tag.rsplit("}", 1)[-1].lower()
        if tag != "component":
            continue
        vals: Dict[str, str] = {}
        for child in node:
            ctag = child.tag.rsplit("}", 1)[-1].lower()
            if ctag in ("name", "version", "purl", "bom-ref"):
                vals[ctag] = (child.text or "").strip()
        if vals.get("name"):
            out.append({
                "name": vals.get("name", ""),
                "version": vals.get("version", ""),
                "supplier": "",
                "license": "",
                "purl": vals.get("purl", ""),
                "id": vals.get("bom-ref", ""),
            })
    return out


def _finalize_sbom(path: str, rel: str, fmt: str, data: Optional[Dict[str, Any]],
                   packages: List[Dict[str, str]], source: Dict[str, Any]) -> Dict[str, Any]:
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
            })
        if data.get("bomFormat") == "CycloneDX":
            packages = _cyclonedx_components(data)
            md = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
            return _finalize_sbom(path, rel, "cyclonedx-json", data, packages, {
                "name": (md.get("component") or {}).get("name")
                if isinstance(md.get("component"), dict) else data.get("name"),
                "spec_version": data.get("specVersion"),
                "namespace": data.get("serialNumber"),
                "created": md.get("timestamp"),
            })
        if data.get("@graph") or data.get("graph"):
            packages = _spdx3_packages(data)
            return _finalize_sbom(path, rel, "spdx-jsonld", data, packages, {
                "name": data.get("name"),
                "spec_version": data.get("spdxVersion") or "SPDX-3",
                "namespace": data.get("@id"),
                "created": _scalar((data.get("creationInfo") or {}).get("created"))
                if isinstance(data.get("creationInfo"), dict) else "",
            })
        return None
    low = text.lower()
    if "spdxversion:" in low or "packagename:" in low:
        parsed = _spdx_tag_value(text)
        return _finalize_sbom(path, rel, "spdx-tag-value", None, parsed["packages"], {
            "name": parsed["meta"].get("DocumentName"),
            "spec_version": parsed["meta"].get("SPDXVersion"),
            "namespace": parsed["meta"].get("DocumentNamespace"),
            "created": parsed["meta"].get("Created"),
        })
    if "<bom" in low and "cyclonedx" in low:
        packages = _cyclonedx_xml(text)
        return _finalize_sbom(path, rel, "cyclonedx-xml", None, packages, {
            "name": "", "spec_version": "", "namespace": "", "created": "",
        })
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
                       signature_material: bool = False) -> Dict[str, Any]:
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
    return {
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
                "warnings": [err or "no in-toto statement found"],
                "embedded_sbom": False,
            })
            continue
        sig = bool(envelope and envelope.get("signatures")) or bool(item.get("sigstoreBundle"))
        summary = _statement_summary(
            statement, path, rel, "jfrog", status or ("unverified" if sig else "unsigned"),
            detail, _scalar(item.get("createdBy")), _scalar(item.get("createdAt")),
            _scalar(item.get("mediaType")), _scalar(item.get("downloadPath")), sig,
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
            discover: bool = True) -> Dict[str, Any]:
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
    for path, forced in jobs:
        if path in seen_files:
            continue
        if not os.path.isfile(path):
            warnings.append("%s: evidence file not found" % _rel(root, path))
            continue
        seen_files.add(path)
        text = _read_text(path)
        if text is None:
            warnings.append("%s: skipped (binary or larger than %d bytes)"
                            % (_rel(root, path), MAX_EVIDENCE_BYTES))
            continue
        rel = _rel(root, path)
        parsed = parse_evidence_file(path, rel, text, forced=forced)
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

    req = dict(requirements or {})
    reasons: List[str] = []
    if req.get("sbom") and not sboms:
        reasons.append("no SBOM found")
    if req.get("attestation") and not attestations:
        reasons.append("no attestation found")
    if req.get("verified_attestation") and not any(
            a.get("verification") == "provider-verified" for a in attestations):
        reasons.append("no provider-verified attestation found")
    packages = sum(s.get("package_count", 0) for s in sboms)
    unique_components = set()
    for s in sboms:
        for p in s.get("packages", []):
            unique_components.add((p.get("name"), p.get("version")))
    verified = sum(1 for a in attestations if a.get("verification") == "provider-verified")
    unverified = sum(1 for a in attestations if a.get("verification") == "unverified")
    unsigned = sum(1 for a in attestations if a.get("verification") == "unsigned")
    failed = sum(1 for a in attestations if a.get("verification") == "failed")
    if not sboms:
        warnings.append("no SBOM found (SPDX or CycloneDX)")
    if not attestations:
        warnings.append("no in-toto/Sigstore/GitHub attestation found")
    if jfrog and not attestations:
        warnings.append("JFrog evidence bundle found but no parseable in-toto statement")
    warnings = list(dict.fromkeys(warnings))
    report = {
        "root": root,
        "summary": {
            "sboms": len(sboms),
            "attestations": len(attestations),
            "jfrog_bundles": len(jfrog),
            "packages": packages,
            "unique_components": len(unique_components),
            "verified_attestations": verified,
            "unverified_attestations": unverified,
            "unsigned_attestations": unsigned,
            "failed_attestations": failed,
            "warnings": len(warnings),
        },
        "sboms": sboms,
        "attestations": attestations,
        "jfrog": jfrog,
        "requirements": req,
        "gate": {"result": "fail" if reasons else "pass", "reasons": reasons},
        "warnings": warnings,
    }
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
        out.append("| File | Format | Spec | Packages | Licenses |")
        out.append("|---|---|---|---:|---|")
        for sbom in report["sboms"]:
            licenses = ", ".join("%s ×%d" % (k, v) for k, v in list(sbom.get("licenses", {}).items())[:4]) or "—"
            out.append("| `%s` | %s | %s | %d | %s |"
                       % (sbom.get("path"), sbom.get("format"), sbom.get("spec_version") or "—",
                          sbom.get("package_count", 0), licenses))
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
            out.append("| `%s` | %s | %s | %s | %s |"
                       % (att.get("path"), att.get("predicate_kind", "unknown"), subject,
                          provenance, att.get("verification", "unknown")))
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
    out.append("")
    out.append("> JankHunt42 parses evidence but does not perform cryptographic verification itself. "
               "`provider-verified` means the exporter recorded a successful verification result; "
               "otherwise run the listed verification command with `gh`, `cosign`, or `jf`.")
    if report.get("warnings"):
        out.append("")
        out.append("**Evidence gaps:**")
        out.append("")
        for warning in report["warnings"]:
            out.append("- %s" % warning)
    return "\n".join(out)
