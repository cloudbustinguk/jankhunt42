#!/usr/bin/env python3
"""Dependency CVE awareness via the OSV.dev batch API (opt-in)."""
from __future__ import annotations

import concurrent.futures
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from jh_core import Finding, Rule, SEV_RANK, TOOL, VERSION

OSV_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
MAX_BATCH = 500
_VULN_CACHE: Dict[str, dict] = {}


@dataclass
class Dependency:
    ecosystem: str
    name: str
    version: str
    path: str
    line: int = 1


@dataclass
class CveResult:
    findings: List[Finding] = field(default_factory=list)
    packages: int = 0
    queried: int = 0
    warnings: List[str] = field(default_factory=list)


def _line_of(text: str, needle: str) -> int:
    idx = text.find(needle)
    if idx < 0:
        return 1
    return text.count("\n", 0, idx) + 1


def _clean_version(v: str) -> Optional[str]:
    v = v.strip().strip("'\"")
    v = v.lstrip("=<>~^! ")
    v = v.split(",")[0].strip()
    if not v or v in ("*", "latest", "x", "X"):
        return None
    if any(ch in v for ch in (" ", "|", "<", ">", "~", "^", "*", "{")):
        return None
    if v.startswith(("git", "http", "file:", "workspace:", "link:", "portal:")):
        return None
    return v


def _walk_npm_lock(deps: Dict[str, object], path: str, out: List[Dependency]) -> None:
    for name, meta in deps.items():
        if not isinstance(meta, dict):
            continue
        version = meta.get("version")
        if isinstance(name, str) and isinstance(version, str):
            clean = _clean_version(version)
            if clean:
                out.append(Dependency("npm", name, clean, path, 1))
        sub = meta.get("dependencies")
        if isinstance(sub, dict):
            _walk_npm_lock(sub, path, out)


def _json_deps(text: str, path: str, kind: str) -> List[Dependency]:
    out: List[Dependency] = []
    try:
        obj = json.loads(text)
    except (ValueError, TypeError, RecursionError):
        return out
    if not isinstance(obj, dict):
        return out
    if kind == "package_json":
        for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            deps = obj.get(section)
            if not isinstance(deps, dict):
                continue
            for name, spec in deps.items():
                if not isinstance(spec, str):
                    continue
                version = _clean_version(spec)
                if version:
                    out.append(Dependency("npm", name, version, path, _line_of(text, '"%s"' % name)))
    elif kind == "package_lock":
        packages = obj.get("packages")
        if isinstance(packages, dict):
            for key, meta in packages.items():
                if not isinstance(meta, dict) or not key:
                    continue
                name = meta.get("name") or key.split("node_modules/")[-1]
                version = meta.get("version")
                if isinstance(name, str) and isinstance(version, str):
                    v = _clean_version(version)
                    if v:
                        out.append(Dependency("npm", name, v, path, 1))
        deps = obj.get("dependencies")
        if not out and isinstance(deps, dict):
            _walk_npm_lock(deps, path, out)
    elif kind == "pipfile_lock":
        for section in ("default", "develop"):
            deps = obj.get(section)
            if not isinstance(deps, dict):
                continue
            for name, meta in deps.items():
                if not isinstance(meta, dict):
                    continue
                v = meta.get("version")
                if not isinstance(v, str):
                    continue
                cv = _clean_version(v)
                if cv:
                    out.append(Dependency("PyPI", name, cv, path, 1))
    elif kind == "composer_lock":
        for section in ("packages", "packages-dev"):
            deps = obj.get(section)
            if not isinstance(deps, list):
                continue
            for meta in deps:
                if not isinstance(meta, dict):
                    continue
                name, v = meta.get("name"), meta.get("version")
                if not isinstance(name, str) or not isinstance(v, str):
                    continue
                cv = _clean_version(v)
                if cv:
                    out.append(Dependency("Packagist", name, cv, path, 1))
    return out


def _requirements(text: str, path: str) -> List[Dependency]:
    out: List[Dependency] = []
    for i, line in enumerate(text.splitlines(), 1):
        raw = line.split("#", 1)[0].strip()
        if not raw or raw.startswith(("-", "git+", "http:", "https:", "file:")):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*==\s*([^\s;]+)", raw)
        if m:
            v = _clean_version(m.group(2))
            if v:
                out.append(Dependency("PyPI", m.group(1), v, path, i))
    return out


def _pyproject(text: str, path: str) -> List[Dependency]:
    out: List[Dependency] = []
    for i, line in enumerate(text.splitlines(), 1):
        m = re.search(r"['\"]([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*==\s*([^'\"\s;,]+)['\"]", line)
        if m:
            v = _clean_version(m.group(2))
            if v:
                out.append(Dependency("PyPI", m.group(1), v, path, i))
    return out


def _toml_lock(text: str, path: str, ecosystem: str) -> List[Dependency]:
    out: List[Dependency] = []
    name = None
    for i, line in enumerate(text.splitlines(), 1):
        m = re.match(r"^\s*name\s*=\s*\"([^\"]+)\"", line)
        if m:
            name = m.group(1)
        m = re.match(r"^\s*version\s*=\s*\"([^\"]+)\"", line)
        if m and name:
            v = _clean_version(m.group(1))
            if v:
                out.append(Dependency(ecosystem, name, v, path, i))
            name = None
    return out


def _poetry_lock(text: str, path: str) -> List[Dependency]:
    return _toml_lock(text, path, "PyPI")


def _cargo_lock(text: str, path: str) -> List[Dependency]:
    return _toml_lock(text, path, "crates.io")


def _go_mod(text: str, path: str) -> List[Dependency]:
    out: List[Dependency] = []
    in_block = False
    for i, line in enumerate(text.splitlines(), 1):
        s = line.split("//", 1)[0].strip()
        if s.startswith("require ("):
            in_block = True
            continue
        if in_block and s == ")":
            in_block = False
            continue
        m = None
        if in_block:
            m = re.match(r"^([^\s]+)\s+(v[^\s]+)$", s)
        elif s.startswith("require "):
            m = re.match(r"^require\s+([^\s]+)\s+(v[^\s]+)$", s)
        if m:
            out.append(Dependency("Go", m.group(1), m.group(2), path, i))
    return out


def _gem_lock(text: str, path: str) -> List[Dependency]:
    out: List[Dependency] = []
    for i, line in enumerate(text.splitlines(), 1):
        m = re.match(r"^    ([A-Za-z0-9_.\-]+) \(([^)]+)\)$", line)
        if m:
            v = _clean_version(m.group(2))
            if v:
                out.append(Dependency("RubyGems", m.group(1), v, path, i))
    return out


def _pom(text: str, path: str) -> List[Dependency]:
    out: List[Dependency] = []
    for m in re.finditer(r"<dependency>(.*?)</dependency>", text, re.DOTALL):
        block = m.group(1)
        g = re.search(r"<groupId>([^<]+)</groupId>", block)
        a = re.search(r"<artifactId>([^<]+)</artifactId>", block)
        v = re.search(r"<version>([^<]+)</version>", block)
        if g and a and v:
            cv = _clean_version(v.group(1))
            if cv:
                line = text.count("\n", 0, m.start()) + 1
                out.append(Dependency("Maven", "%s:%s" % (g.group(1), a.group(1)), cv, path, line))
    return out


def _gradle(text: str, path: str) -> List[Dependency]:
    out: List[Dependency] = []
    pat = re.compile(r"(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s*[('\"]\s*([\w.\-]+):([\w.\-]+):([^'\")]+)")
    for i, line in enumerate(text.splitlines(), 1):
        for m in pat.finditer(line):
            v = _clean_version(m.group(3))
            if v:
                out.append(Dependency("Maven", "%s:%s" % (m.group(1), m.group(2)), v, path, i))
    return out


def _csproj(text: str, path: str) -> List[Dependency]:
    out: List[Dependency] = []
    for m in re.finditer(r"<PackageReference\s+Include=\"([^\"]+)\"\s+Version=\"([^\"]+)\"", text):
        v = _clean_version(m.group(2))
        if v:
            line = text.count("\n", 0, m.start()) + 1
            out.append(Dependency("NuGet", m.group(1), v, path, line))
    return out


def _pubspec_lock(text: str, path: str) -> List[Dependency]:
    out: List[Dependency] = []
    name = None
    in_packages = False
    for i, line in enumerate(text.splitlines(), 1):
        if re.match(r"^packages:\s*$", line):
            in_packages = True
            continue
        if in_packages and re.match(r"^\S", line):
            in_packages = False
        if not in_packages:
            continue
        m = re.match(r"^  ([A-Za-z0-9_]+):\s*$", line)
        if m:
            name = m.group(1)
            continue
        m = re.match(r"^    version:\s*\"?([^\"\s]+)\"?", line)
        if m and name:
            v = _clean_version(m.group(1))
            if v:
                out.append(Dependency("Pub", name, v, path, i))
            name = None
    return out


def parse_manifest(path: str, rel: str) -> List[Dependency]:
    base = os.path.basename(path).lower()
    try:
        with open(path, "rb") as fh:
            text = fh.read().decode("utf-8", "replace")
    except OSError:
        return []
    if base == "package.json":
        return _json_deps(text, rel, "package_json")
    if base in ("package-lock.json", "npm-shrinkwrap.json"):
        return _json_deps(text, rel, "package_lock")
    if base in ("pipfile.lock",):
        return _json_deps(text, rel, "pipfile_lock")
    if base == "composer.lock":
        return _json_deps(text, rel, "composer_lock")
    if base.startswith("requirements") and base.endswith(".txt"):
        return _requirements(text, rel)
    if base == "pyproject.toml":
        return _pyproject(text, rel)
    if base == "poetry.lock":
        return _poetry_lock(text, rel)
    if base == "cargo.lock":
        return _cargo_lock(text, rel)
    if base == "go.mod":
        return _go_mod(text, rel)
    if base == "gemfile.lock":
        return _gem_lock(text, rel)
    if base == "pom.xml":
        return _pom(text, rel)
    if base in ("build.gradle", "build.gradle.kts"):
        return _gradle(text, rel)
    if base.endswith((".csproj", ".fsproj", ".vbproj")):
        return _csproj(text, rel)
    if base == "pubspec.lock":
        return _pubspec_lock(text, rel)
    return []


def collect_dependencies(files: Sequence[Tuple[str, str]]) -> List[Dependency]:
    seen = set()
    out: List[Dependency] = []
    for path, rel in files:
        for dep in parse_manifest(path, rel):
            key = (dep.ecosystem, dep.name, dep.version)
            if key in seen:
                continue
            seen.add(key)
            out.append(dep)
    return out


def _severity(sev: Optional[str]) -> str:
    if not sev:
        return "major"
    s = sev.lower()
    if s in ("critical", "high"):
        return "critical" if s == "critical" else "major"
    if s in ("moderate", "medium"):
        return "minor"
    if s == "low":
        return "info"
    return "major"


def _osv_batch(deps: Sequence[Dependency], timeout: float = 12.0) -> Tuple[List[List[dict]], Optional[str]]:
    queries = [{"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version}
               for d in deps]
    body = json.dumps({"queries": queries}).encode("utf-8")
    req = urllib.request.Request(
        OSV_URL, data=body, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "%s/%s" % (TOOL, VERSION)},
    )
    last_err: Optional[str] = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            results = data.get("results", [])
            if not isinstance(results, list):
                return [], "OSV returned an unexpected response"
            return results, None
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError, OSError,
                RecursionError) as exc:
            last_err = str(exc)
            time.sleep(0.5 + attempt)
    return [], last_err or "network error"


def _vuln_details(vid: str, timeout: float = 10.0) -> Optional[dict]:
    """querybatch returns only id/modified; fetch the full advisory."""
    if vid in _VULN_CACHE:
        return _VULN_CACHE[vid] or None
    url = OSV_VULN_URL + urllib.parse.quote(vid, safe="")
    req = urllib.request.Request(url, headers={"User-Agent": "%s/%s" % (TOOL, VERSION)})
    for attempt in range(2):
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            if isinstance(data, dict):
                _VULN_CACHE[vid] = data
                return data
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError, OSError, RecursionError):
            time.sleep(0.3 + attempt)
    _VULN_CACHE[vid] = {}
    return None


def _needs_details(vuln: object) -> bool:
    return isinstance(vuln, dict) and not (vuln.get("summary") or vuln.get("affected"))


def query_osv(deps: Sequence[Dependency]) -> CveResult:
    result = CveResult(packages=len(deps))
    if not deps:
        return result
    detail_budget = 80
    for start in range(0, len(deps), MAX_BATCH):
        batch = deps[start:start + MAX_BATCH]
        results, err = _osv_batch(batch)
        if err:
            result.warnings.append("OSV query failed: %s" % err)
            continue
        result.queried += len(batch)
        # querybatch returns only id/modified. Fetch full advisories in parallel,
        # capped so a large dependency tree cannot turn into an unbounded crawl.
        wanted: List[str] = []
        for item in results:
            vulns = item.get("vulns") if isinstance(item, dict) else None
            for vuln in vulns or []:
                vid = str(vuln.get("id") or "") if isinstance(vuln, dict) else ""
                if vid and _needs_details(vuln) and vid not in wanted:
                    wanted.append(vid)
        if wanted and detail_budget > 0:
            wanted = wanted[:detail_budget]
            detail_budget -= len(wanted)
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(wanted))) as pool:
                list(pool.map(_vuln_details, wanted))
        for dep, item in zip(batch, results):
            vulns = item.get("vulns") if isinstance(item, dict) else None
            if not vulns:
                continue
            for vuln in vulns:
                if not isinstance(vuln, dict):
                    continue
                vid = str(vuln.get("id") or "")
                if vid and _needs_details(vuln):
                    full = _vuln_details(vid)
                    if full:
                        vuln = full
                result.findings.append(_to_finding(dep, vuln))
    result.findings.sort(key=lambda f: (SEV_RANK.get(f.severity, 9), f.path, f.line))
    return result


def _cvss_severity(vuln: dict) -> Optional[str]:
    db = vuln.get("database_specific") or {}
    sev_raw = db.get("severity") if isinstance(db, dict) else None
    if sev_raw:
        return str(sev_raw)
    for entry in vuln.get("severity") or []:
        if not isinstance(entry, dict):
            continue
        score = str(entry.get("score") or "")
        m = re.search(r"(\d+(?:\.\d+)?)$", score)
        if not m:
            continue
        try:
            num = float(m.group(1))
        except ValueError:  # jankhunt42: ignore JH201
            return None
        if num >= 9.0:
            return "critical"
        if num >= 7.0:
            return "high"
        if num >= 4.0:
            return "medium"
        return "low"
    return None


def _to_finding(dep: Dependency, vuln: dict) -> Finding:
    vid = str(vuln.get("id") or "OSV-?")
    aliases = [str(a) for a in (vuln.get("aliases") or [])]
    cves = [a for a in aliases if a.startswith("CVE-")]
    if vid.startswith("CVE-") and vid not in cves:
        cves.insert(0, vid)
    summary = str(vuln.get("summary") or vuln.get("details") or "Known vulnerability").strip()
    summary = re.sub(r"\s+", " ", summary)[:220]
    sev = _severity(_cvss_severity(vuln))
    fixed: List[str] = []
    for affected in vuln.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        pkg = affected.get("package") or {}
        if isinstance(pkg, dict):
            if pkg.get("name") and pkg.get("name") != dep.name:
                continue
            if pkg.get("ecosystem") and str(pkg.get("ecosystem")).lower() != dep.ecosystem.lower():
                continue
        for rng in affected.get("ranges") or []:
            if not isinstance(rng, dict):
                continue
            for event in rng.get("events") or []:
                if isinstance(event, dict) and event.get("fixed"):
                    fixed.append(str(event["fixed"]))
    fixed = list(dict.fromkeys(fixed))[:3]
    ids = ", ".join(cves[:3] or [vid])
    fixed_txt = ("; fixed in %s" % ", ".join(fixed)) if fixed else ""
    message = "%s %s: %s — %s%s" % (dep.name, dep.version, ids, summary, fixed_txt)
    refs = []
    for ref in (vuln.get("references") or [])[:2]:
        if isinstance(ref, dict) and ref.get("url"):
            refs.append(str(ref["url"]))
    rule = Rule(
        id="JH901", title="Known vulnerable dependency", severity=sev,
        category="security", message=message,
        fix="Upgrade to a fixed version; if none exists, mitigate or replace the dependency.",
        confidence="high", tags=("cve", "supply-chain"),
    )
    return Finding(
        rule=rule.id, title=rule.title, severity=sev, category="security",
        path=dep.path, line=dep.line, evidence="%s %s (%s)" % (dep.name, dep.version, dep.ecosystem),
        message=message, fix=rule.fix, confidence="high", tags=rule.tags,
        extra={"cve": cves, "advisory": vid, "fixed": fixed, "ecosystem": dep.ecosystem,
               "package": dep.name, "version": dep.version, "references": refs},
    )
