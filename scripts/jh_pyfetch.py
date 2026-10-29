"""Hash-pinned requirements acquisition. No pip, imports from packages, or archive reads on the host.

Only the deliberately small requirements subset below authorizes downloads; everything else is a coverage gap.
PEP 691 indexes and distributions use jh_acquire's checked, metered HTTPS transport and share its run budget.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
from typing import Any, Dict, Iterator, List, Tuple
from urllib.parse import urljoin

import jh_acquire as A
import jh_ceiling

MAX_INDEX_BYTES = 32 * 1024 * 1024
JSON_ACCEPT = "application/vnd.pypi.simple.v1+json"
_NAME = r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?"
_PIN = re.compile(r"^(" + _NAME + r")\s*==\s*([^\s;]+)(.*)$")
_HASH = re.compile(r"--hash(?:=|\s+)sha256:([0-9a-fA-F]{64})(?=\s|$)")
_VERSION = re.compile(
    r"v?(?:(?P<epoch>[0-9]+)!)?(?P<release>[0-9]+(?:\.[0-9]+)*)"
    r"(?:[-_.]?(?P<pre>alpha|beta|preview|pre|rc|a|b|c)[-_.]?(?P<pre_n>[0-9]+)?)?"
    r"(?:(?:-(?P<post1>[0-9]+))|(?:[-_.]?(?P<post>post|rev|r)[-_.]?(?P<post2>[0-9]+)?))?"
    r"(?:[-_.]?dev[-_.]?(?P<dev>[0-9]*))?(?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?", re.I)


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _version_key(version: str) -> Any:
    """PEP 440 equality for exact pins and distribution filenames, without a packaging dependency."""
    m = _VERSION.fullmatch(version)
    if not m:
        return None
    d = m.groupdict()
    # Keep components as strings: an attacker-controlled huge integer need not be converted by int().
    number = lambda n: (n or "0").lstrip("0") or "0"
    release = [number(n) for n in d["release"].split(".")]
    while len(release) > 1 and release[-1] == "0":
        release.pop()
    pre = (d["pre"] or "").lower()
    pre = {"alpha": "a", "beta": "b", "c": "rc", "pre": "rc", "preview": "rc"}.get(pre, pre)
    post = number(d["post1"] or d["post2"]) if d["post"] or d["post1"] is not None else None
    local = tuple(number(n) if n.isdigit() else n.lower() for n in re.split(r"[-_.]", d["local"])) \
        if d["local"] else None
    return (number(d["epoch"]), tuple(release), (pre, number(d["pre_n"])) if pre else None,
            post, number(d["dev"]) if d["dev"] is not None else None, local)


def _logical_lines(text: str) -> Iterator[Tuple[int, str]]:
    pending, first = [], 1
    # Only physical LF/CRLF lines, not the extra Unicode separators str.splitlines accepts.
    for line, raw in enumerate(text.split("\n"), 1):
        raw = raw.removesuffix("\r")
        if not pending:
            first = line
        if raw.endswith("\\") and not raw.lstrip().startswith("#"):
            pending.append(raw[:-1])
            continue
        pending.append(raw)
        yield first, " ".join(pending)
        pending = []
    if pending:
        yield first, " ".join(pending) + " \\"  # a dangling continuation is refused, never silently dropped


def plan_requirements(root: str) -> Dict[str, Any]:
    plan: Dict[str, Any] = {"lockfile": "requirements.txt", "lockfile_sha256": None,
                            "artifacts": [], "refused": [], "skipped_platform": 0}
    try:
        raw = A._read_lockfile(os.path.join(root, "requirements.txt"), "requirements.txt")
        plan["lockfile_sha256"] = hashlib.sha256(raw).hexdigest()
        text = raw.decode("utf-8-sig")
    except (A.AcquireError, UnicodeError) as exc:
        plan["refused"].append({"package": "requirements.txt", "reason": str(exc)[:200]})
        return plan
    pins: Dict[str, List[Dict[str, Any]]] = {}
    for line, raw_line in _logical_lines(text):
        value = re.sub(r"(^|\s+)#.*$", "", raw_line).strip()
        if not value or value == "--require-hashes":
            continue
        m = _PIN.fullmatch(value)
        package, reason = "requirements.txt:%d" % line, ""
        if not m:
            reason = "requires name==version with sha256 hashes; URLs, paths, includes and pip options are refused"
        else:
            name, version, options = m.groups()
            package = normalize(name)
            hashes = _HASH.findall(options)
            if _version_key(version) is None:
                reason = "not an exact PEP 440 version (wildcards and ranges are refused)"
            elif not hashes or _HASH.sub("", options).strip():
                reason = "each pin needs only --hash=sha256:<64 hex digits>; markers, extras and other options are refused"
            else:
                pins.setdefault(package, []).append({"ecosystem": "python", "package": package,
                                                     "version": version, "hashes": sorted({h.lower() for h in hashes}),
                                                     "line": line})
        if reason:
            plan["refused"].append({"package": package, "line": line, "reason": reason})
    for package, entries in sorted(pins.items()):
        signatures = {(_version_key(p["version"]), tuple(p["hashes"])) for p in entries}
        if len(signatures) != 1:
            plan["refused"].append({"package": package, "reason": "conflicting duplicate requirements or hash sets"})
        else:
            plan["artifacts"].append(entries[0])
    if len(plan["artifacts"]) > A.MAX_ARTIFACTS:
        plan["refused"].append({"package": "requirements.txt", "reason": "too many pinned requirements"})
        plan["artifacts"] = []
    return plan


def _index(url: str, origins: Any, limit: int, stream: Any) -> Tuple[Dict[str, Any], int]:
    """Read bounded JSON with the same wire accounting as artifacts, including every failure path."""
    chunks, body, size, usage = None, [], 0, {"received": 0}
    try:
        if not A.approved(url, origins):
            raise A.AcquireError("the simple API URL is not under an approved origin")
        chunks = stream(url, min(limit, MAX_INDEX_BYTES), usage)
        for chunk in chunks:
            size += len(chunk)
            if size > min(limit, MAX_INDEX_BYTES):
                raise A.AcquireError("the simple API response is larger than the size limit")
            body.append(chunk)
        doc = json.loads(b"".join(body).decode("utf-8"), object_pairs_hook=jh_ceiling._unique)
        meta = doc.get("meta", {}) if isinstance(doc, dict) else {}
        api = meta.get("api-version", "1.0") if isinstance(meta, dict) else None
        if not isinstance(doc, dict) or not isinstance(doc.get("files"), list) or \
                not isinstance(api, str) or not re.fullmatch(r"1\.[0-9]+", api):
            raise A.AcquireError("not a supported PEP 691 JSON project response (API major version 1)")
        return doc, max(size, usage["received"])
    except (A.AcquireError, OSError, http.client.HTTPException, ValueError, UnicodeError, RecursionError) as exc:
        A.close_stream(chunks)
        err = exc if isinstance(exc, A.AcquireError) else A.AcquireError("invalid or unreadable simple API JSON")
        err.received = max(size, usage["received"])
        raise err
    finally:
        A.close_stream(chunks)


def _kind(filename: str, pin: Dict[str, Any]) -> str:
    # pip needs the distribution filename; permit one short ASCII basename, never a repository/index path.
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+!-]{0,239}", filename):
        return ""
    if filename.endswith(".whl"):
        parts = filename[:-4].split("-")
        if len(parts) not in (5, 6) or any(not p for p in parts) or \
                (len(parts) == 6 and not re.fullmatch(r"[0-9][A-Za-z0-9_]*", parts[2])):
            return ""
        name, version, kind = parts[0], parts[1], "wheel"
    else:
        suffix = next((s for s in (".tar.gz", ".zip", ".tar.bz2", ".tar.xz") if filename.endswith(s)), "")
        if not suffix or "-" not in filename[:-len(suffix)]:
            return ""
        name, version = filename[:-len(suffix)].rsplit("-", 1)
        kind = "sdist"
    ours, theirs = _version_key(pin["version"]), _version_key(version)
    # PEP 440 == without a local suffix also matches that release's local builds.
    same = ours is not None and theirs is not None and (ours == theirs or (ours[-1] is None and ours[:-1] == theirs[:-1]))
    return kind if normalize(name) == pin["package"] and same else ""


def _candidates(doc: Dict[str, Any], index_url: str, pin: Dict[str, Any]) -> List[Dict[str, Any]]:
    found = []
    for f in doc["files"]:
        if not isinstance(f, dict) or not isinstance(f.get("filename"), str) or not isinstance(f.get("url"), str):
            continue
        hashes = f.get("hashes")
        digest = hashes.get("sha256") if isinstance(hashes, dict) else None
        if not isinstance(digest, str) or digest.lower() not in pin["hashes"]:
            continue
        kind = _kind(f["filename"], pin)
        if kind:
            try:
                url = urljoin(index_url, f["url"])
            except ValueError:
                continue
            found.append({"ecosystem": "python", "package": pin["package"], "version": pin["version"],
                          "filename": f["filename"], "url": url,
                          "sha256": digest.lower(), "kind": kind})
    unique = {(a["filename"], a["sha256"], a["url"]): a for a in found}
    return [unique[k] for k in sorted(unique)]


def json_stream(url: str, limit: int, usage: Dict[str, int]) -> Iterator[bytes]:
    return A._stream(url, limit, usage, accept=JSON_ACCEPT)


def acquire(plan: Dict[str, Any], origins: Any, wheelhouse: str, budget: int, stream: Any,
            index_stream: Any = json_stream) -> Dict[str, Any]:
    result: Dict[str, Any] = {"fetched": [], "refused": list(plan["refused"]), "bytes": 0,
                              "downloaded": 0, "pinned": len(plan["artifacts"])}
    os.makedirs(wheelhouse)
    selected: List[Dict[str, Any]] = []
    for pin in plan["artifacts"]:
        candidates, errors = [], []
        for origin in origins:
            base = "%s://%s:%d%s" % origin
            if not base.endswith("/simple/"):
                base += "simple/"
            index_url = base + pin["package"] + "/"
            room = budget - result["downloaded"]
            if room <= 0:
                errors.append("the download budget is spent")
                break
            try:
                doc, used = _index(index_url, origins, room, index_stream)
                result["downloaded"] += used
                matches = _candidates(doc, index_url, pin)
            except A.AcquireError as exc:
                result["downloaded"] += getattr(exc, "received", 0)
                errors.append(str(exc))
                continue
            wheels = [a for a in matches if a["kind"] == "wheel"]
            if wheels:
                candidates = wheels                 # never fall back to executing a source build when wheels are pinned
                break
            if matches and not candidates:
                candidates = matches[:1]             # keep a source fallback while looking for a pinned wheel
        if not candidates:
            reason = "no wheel or sdist matches the pinned name, version and sha256"
            if errors:
                reason += "; " + errors[-1]
            result["refused"].append({"package": pin["package"], "reason": reason[:200]})
        # Multiple URLs for one file do not create multiple pins. Prefer an approved mirror of the same bytes.
        unique = {}
        for a in sorted(candidates, key=lambda a: (not A.approved(a["url"], origins), a["url"])):
            unique.setdefault((a["filename"], a["sha256"]), a)
        candidates = list(unique.values())
        result["pinned"] += max(0, len(candidates) - 1)
        selected.extend(candidates)
        if len(selected) > A.MAX_ARTIFACTS:
            result["refused"].append({"package": "requirements.txt", "reason": "too many pinned distribution files"})
            selected = []
            break
    # A hostile index cannot overwrite one verified file with another pin's bytes under the same filename.
    names: Dict[str, set] = {}
    for a in selected:
        names.setdefault(a["filename"], set()).add(a["sha256"])
    seen = set()
    for a in sorted(selected, key=lambda a: (a["package"], a["filename"], a["url"])):
        key = (a["filename"], a["sha256"])
        if key in seen:
            continue
        seen.add(key)
        if len(names[a["filename"]]) != 1:
            result["refused"].append({"package": a["package"], "reason": "one filename is pinned to conflicting hashes"})
            continue
        room = budget - result["downloaded"]
        if room <= 0:
            result["refused"].append({"package": a["package"], "reason": "not fetched: the download budget is spent"})
            continue
        dest = os.path.join(wheelhouse, a["filename"])
        try:
            size, used = A.fetch(a, origins, dest, min(A.MAX_ARTIFACT_BYTES, room), stream)
        except A.AcquireError as exc:
            result["downloaded"] += getattr(exc, "received", 0)
            result["refused"].append({"package": a["package"], "reason": str(exc)[:200]})
            continue
        result["downloaded"] += used
        result["bytes"] += size
        os.chmod(dest, 0o644)
        result["fetched"].append({k: a[k] for k in ("ecosystem", "package", "version", "filename", "sha256", "kind")} |
                                 {"bytes": size, "build_runs_code": a["kind"] == "sdist"})
    return result
