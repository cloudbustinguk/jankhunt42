#!/usr/bin/env python3
"""Package sources: which registries a repository's package managers resolve
from, and whether that matches an operator's allowed list.

Declared sources come from committed configuration (.npmrc, .yarnrc.yml,
pip.conf, requirements index options, pyproject and Pipfile sources, Maven
repositories and mirrors, Gradle repositories, nuget.config, Cargo source
replacement). Lockfiles record where packages were actually fetched from,
which is observed evidence. A package manager in use with no committed
configuration is `unknown`: the developer's machine or the CI runner
decides, and the public registry is only the default, not a fact.
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from jh_core import is_test_path

ECOSYSTEMS = ("npm", "pypi", "maven", "nuget", "cargo")
# What each manager uses when nothing is configured.
PUBLIC_DEFAULT = {"npm": "https://registry.npmjs.org/", "pypi": "https://pypi.org/simple/",
                  "maven": "https://repo.maven.apache.org/maven2/", "nuget": "https://api.nuget.org/v3/index.json",
                  "cargo": "https://index.crates.io/"}
_GRADLE_BUILTINS = {"mavenCentral": "https://repo.maven.apache.org/maven2/",
                    "google": "https://dl.google.com/dl/android/maven2/",
                    "gradlePluginPortal": "https://plugins.gradle.org/m2/",
                    "jcenter": "https://jcenter.bintray.com/"}
_LOCKFILES = {"package-lock.json": "npm", "npm-shrinkwrap.json": "npm", "yarn.lock": "npm", "pnpm-lock.yaml": "npm",
              "uv.lock": "pypi", "poetry.lock": "pypi", "pipfile.lock": "pypi"}
_SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", "target", ".venv", "venv", "__pycache__", ".next"}
_URL_RE = re.compile(r"https?://[^\s\"'<>,;)\]}]+", re.I)
MAX_LOCK_BYTES = 8_000_000


def normalize(url: str) -> str:
    """Lowercase scheme and host, credentials removed, one trailing slash on
    the path. A token in a registry URL must never reach a report or a CI log."""
    url = re.sub(r"(?i)^(https?://)[^/@\s]*@", r"\1", url.strip())
    m = re.match(r"(?i)^(https?)://([^/\s]+)(/[^\s?#]*)?", url)
    if not m:
        return url.strip()
    path = (m.group(3) or "/").rstrip("/") + "/"
    return "%s://%s%s" % (m.group(1).lower(), m.group(2).lower(), path)


def _host(url: str) -> str:
    m = re.match(r"(?i)^https?://([^/\s:]+)", url)
    return m.group(1).lower() if m else ""


def _in_use(rel: str) -> Optional[str]:
    base = os.path.basename(rel).lower()
    if base == "package.json":
        return "npm"
    if base.startswith("requirements") and base.endswith(".txt") or base in ("pyproject.toml", "pipfile", "setup.py",
                                                                             "setup.cfg"):
        return "pypi"
    if base in ("pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"):
        return "maven"
    if base.endswith((".csproj", ".fsproj", ".vbproj")) or base == "packages.config":
        return "nuget"
    if base == "cargo.toml":
        return "cargo"
    return None


def _source(url: str, kind: str, rel: str, line: int, scope: str = "") -> Dict[str, Any]:
    return {"url": normalize(url), "kind": kind, "scope": scope, "path": rel, "line": line}


def _declared(rel: str, text: str) -> List[Tuple[str, Dict[str, Any]]]:
    """(ecosystem, source) pairs declared in one committed file."""
    base = os.path.basename(rel).lower()
    low = rel.lower()
    out: List[Tuple[str, Dict[str, Any]]] = []
    lines = text.split("\n")
    if base == ".npmrc":
        for i, ln in enumerate(lines, 1):
            m = re.match(r"^\s*(@[\w.\-]+:)?registry\s*=\s*(\S+)", ln)
            if m and _URL_RE.match(m.group(2)):
                out.append(("npm", _source(m.group(2), "scoped" if m.group(1) else "default", rel, i,
                                           (m.group(1) or "").rstrip(":"))))
    elif base == ".yarnrc.yml":
        scope = ""
        for i, ln in enumerate(lines, 1):
            ms = re.match(r"^\s{2,}[\"']?([\w.\-]+)[\"']?\s*:\s*$", ln)
            if ms:
                scope = "@" + ms.group(1)
            m = re.match(r"^(\s*)npmRegistryServer\s*:\s*[\"']?(https?://[^\s\"']+)", ln)
            if m:
                nested = bool(m.group(1))
                out.append(("npm", _source(m.group(2), "scoped" if nested else "default", rel, i, scope if nested else "")))
    elif base == ".yarnrc":
        for i, ln in enumerate(lines, 1):
            m = re.match(r"^\s*registry\s+[\"']?(https?://[^\s\"']+)", ln)
            if m:
                out.append(("npm", _source(m.group(1), "default", rel, i)))
    elif base == "bunfig.toml":
        for i, ln in enumerate(lines, 1):
            m = re.match(r"^\s*registry\s*=\s*[\"'](https?://[^\"']+)", ln)
            if m:
                out.append(("npm", _source(m.group(1), "default", rel, i)))
    elif base in ("pip.conf", "pip.ini", "uv.toml") or (base.startswith("requirements") and base.endswith(".txt")) \
            or base.endswith(".in") and "requirements" in base:
        for i, ln in enumerate(lines, 1):
            m = re.match(r"^\s*(?:--)?(index-url|extra-index-url|i)\s*[= ]\s*(\S+)", ln) or \
                re.match(r"^\s*-(i)\s*(\S+)", ln)
            if m and _URL_RE.match(m.group(2).strip("\"'")):
                out.append(("pypi", _source(m.group(2).strip("\"'"), "extra" if m.group(1).startswith("extra")
                                            else "default", rel, i)))
    elif base == "pyproject.toml":
        section = ""
        for i, ln in enumerate(lines, 1):
            ms = re.match(r"^\s*\[\[?\s*([\w.\-]+)\s*\]\]?\s*$", ln)
            if ms:
                section = ms.group(1)
                continue
            m = re.match(r"^\s*(url|index-url|extra-index-url)\s*=\s*[\"'](https?://[^\"']+)", ln)
            if m and section in ("tool.poetry.source", "tool.uv.index", "tool.uv", "tool.pdm.source", "tool.hatch.envs"):
                kind = "extra" if m.group(1) == "extra-index-url" else ("default" if section == "tool.uv" else "index")
                out.append(("pypi", _source(m.group(2), kind, rel, i)))
    elif base == "pipfile":
        section = ""
        for i, ln in enumerate(lines, 1):
            ms = re.match(r"^\s*\[\[?\s*([\w.\-]+)\s*\]\]?\s*$", ln)
            if ms:
                section = ms.group(1)
                continue
            m = re.match(r"^\s*url\s*=\s*[\"'](https?://[^\"']+)", ln)
            if m and section == "source":
                out.append(("pypi", _source(m.group(1), "index", rel, i)))
    elif base == "pom.xml" or base == "settings.xml" and (".mvn/" in low or ".m2/" in low or base == low):
        block, publishing = "", False   # distributionManagement holds publish targets, not sources
        for i, ln in enumerate(lines, 1):
            if re.search(r"<distributionManagement\b", ln):
                publishing = True
            mb = re.search(r"<(repository|pluginRepository|mirror|snapshotRepository)\b", ln)
            if mb:
                block = mb.group(1)
            m = re.search(r"<url>\s*(https?://[^<\s]+)\s*</url>", ln)
            if m and not publishing and block in ("repository", "pluginRepository", "mirror"):
                out.append(("maven", _source(m.group(1), "mirror" if block == "mirror" else "repository", rel, i)))
            if re.search(r"</(?:repository|pluginRepository|mirror|snapshotRepository)>", ln):
                block = ""
            if re.search(r"</distributionManagement>", ln):
                publishing = False
    elif base in ("build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"):
        depth, publishing_at = 0, None    # publishing targets are not package sources
        for i, ln in enumerate(lines, 1):
            if publishing_at is None and re.search(r"\bpublishing\s*\{", ln):
                publishing_at = depth
            in_publishing = publishing_at is not None
            depth += ln.count("{") - ln.count("}")
            if publishing_at is not None and depth <= publishing_at:
                publishing_at = None
            for name, url in _GRADLE_BUILTINS.items():
                if re.search(r"\b%s\s*\(\s*\)" % name, ln) and not in_publishing:
                    out.append(("maven", _source(url, "repository", rel, i, name + "()")))
            m = re.search(r"""\burl\s*(?:=\s*)?(?:uri\s*\(\s*)?[\"'](https?://[^\"']+)""", ln) or \
                re.search(r"""\bmaven\s*\(\s*(?:url\s*=\s*)?(?:uri\s*\(\s*)?[\"'](https?://[^\"']+)""", ln)
            if m and not in_publishing:
                out.append(("maven", _source(m.group(1), "repository", rel, i)))
    elif base == "nuget.config":
        for i, ln in enumerate(lines, 1):
            if re.search(r"<\s*disabledPackageSources|<\s*packageSourceMapping", ln, re.I):
                break
            m = re.search(r"""<add\s+key=["'][^"']*["']\s+value=["'](https?://[^"']+)["']""", ln, re.I)
            if m:
                out.append(("nuget", _source(m.group(1), "source", rel, i)))
    elif low.endswith(".cargo/config.toml") or low.endswith(".cargo/config"):
        for i, ln in enumerate(lines, 1):
            m = re.match(r"^\s*(?:registry|index)\s*=\s*[\"']((?:sparse\+)?https?://[^\"']+)", ln)
            if m:
                out.append(("cargo", _source(m.group(1).replace("sparse+", ""), "source", rel, i)))
    return out


def _lockfile_sources(root: str, max_files: int = 40, excludes: Sequence[str] = ()) -> List[Tuple[str, Dict[str, Any]]]:
    """Registries recorded in lockfiles (observed): one entry per registry
    origin and lockfile, with the first line it appears on. Lockfiles in test,
    fixture and example trees, or under an excluded path, are not the
    project's own."""
    import fnmatch
    out: List[Tuple[str, Dict[str, Any]]] = []
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS and not d.startswith("."))
        rel_dir = os.path.relpath(dirpath, root)
        if rel_dir.count(os.sep) > 6:
            dirnames[:] = []
            continue
        for name in sorted(filenames):
            eco = _LOCKFILES.get(name.lower())
            if not eco:
                continue
            path = os.path.join(dirpath, name)
            rel_path = os.path.relpath(path, root).replace(os.sep, "/")
            if os.path.islink(path) or os.path.getsize(path) > MAX_LOCK_BYTES or is_test_path(rel_path) or \
                    re.search(r"(?:^|/)(?:fixtures?|testdata|test-data|examples?|samples?|demos?)/", rel_path) or \
                    any(fnmatch.fnmatch(rel_path, g) or fnmatch.fnmatch(rel_path, g.rstrip("/") + "/*") for g in excludes):
                continue
            seen += 1
            if seen > max_files:
                return out
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            origins: Dict[str, int] = {}
            for i, ln in enumerate(text.split("\n"), 1):
                if not re.search(r"\b(resolved|registry|url|tarball)\b", ln):
                    continue
                for u in _URL_RE.findall(ln):
                    if u.endswith((".git", ".git#")) or "github.com/" in u and "/tarball/" not in u:
                        continue              # git dependencies are not registry sources
                    origin = _registry_origin(eco, u)
                    if origin and origin not in origins:
                        origins[origin] = i
            for origin, line in sorted(origins.items()):
                out.append((eco, _source(origin, "lockfile", rel, line)))
    return out


def _registry_origin(eco: str, url: str) -> str:
    """The registry root a lockfile URL was fetched from."""
    u = normalize(url)
    if eco == "npm":
        # https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz, .../api/npm/repo/pkg/-/...
        m = re.match(r"^(https?://[^/]+/.*?)(?:@[^/]+/)?[^/@]+/-/", u)
        return m.group(1) if m else re.sub(r"^(https?://[^/]+/).*$", r"\1", u)
    if eco == "pypi":
        m = re.match(r"^(https?://[^/]+/(?:.*?/)?simple/)", u)
        if m:
            return m.group(1)
        if "files.pythonhosted.org" in u:
            return PUBLIC_DEFAULT["pypi"]       # PyPI's file host: the same registry as pypi.org/simple
        return re.sub(r"^(https?://[^/]+/).*$", r"\1", u)
    return re.sub(r"^(https?://[^/]+/).*$", r"\1", u)


def collect(items: Iterable[Any], root: Optional[str] = None, excludes: Sequence[str] = ()) -> Dict[str, Any]:
    """Package sources per ecosystem from committed files (`items` with .rel
    and .text) and, when `root` is given, lockfiles under it."""
    eco: Dict[str, Dict[str, Any]] = {e: {"in_use": False, "manifests": [], "sources": []} for e in ECOSYSTEMS}
    for item in items:
        rel = item.rel.replace(os.sep, "/")
        if "/node_modules/" in "/" + rel or "/vendor/" in "/" + rel:
            continue
        used = _in_use(rel)
        if used and len(eco[used]["manifests"]) < 20:
            eco[used]["in_use"] = True
            eco[used]["manifests"].append(rel)
        for e, src in _declared(rel, item.text):
            eco[e]["sources"].append(src)
    for e, src in _lockfile_sources(root, excludes=excludes) if root else []:
        eco[e]["in_use"] = True
        eco[e]["sources"].append(src)
    out: Dict[str, Any] = {}
    for e, d in eco.items():
        if not d["in_use"] and not d["sources"]:
            continue
        kinds = {s["kind"] for s in d["sources"]}
        state = "observed" if "lockfile" in kinds else ("declared" if d["sources"] else "unknown")
        srcs = sorted({(s["url"], s["kind"], s["scope"], s["path"], s["line"]): s for s in d["sources"]}.values(),
                      key=lambda s: (s["path"], s["line"], s["url"]))
        out[e] = {"state": state, "in_use": d["in_use"], "manifests": d["manifests"][:10], "sources": srcs[:50],
                  "default_if_unconfigured": PUBLIC_DEFAULT[e]}
    return {"ecosystems": out,
            "note": "declared and lockfile sources only; a manager with no committed configuration resolves from "
                    "whatever the machine or CI runner configures, which is unknown here"}


def allowed(url: str, permitted: Sequence[str]) -> bool:
    """A source is allowed when it starts with an allowed URL prefix, or its
    host equals an allowed bare host name."""
    u = normalize(url)
    for a in permitted:
        a = a.strip()
        if not a:
            continue
        if "://" in a:
            if u.startswith(normalize(a)):
                return True
        elif _host(u) == a.lower().rstrip("."):
            return True
    return False


def assess(sources: Dict[str, Any], permitted: Sequence[str]) -> Dict[str, Any]:
    """Declared or observed sources outside the allowed list, and ecosystems in use whose
    sources are not configured in the repository."""
    disallowed, unconfigured = [], []
    for e, d in sorted(sources.get("ecosystems", {}).items()):
        if d["in_use"] and not d["sources"]:
            unconfigured.append(e)
        for s in d["sources"]:
            if not allowed(s["url"], permitted):
                disallowed.append(dict(s, ecosystem=e))
    return {"disallowed": disallowed, "unconfigured": unconfigured}
