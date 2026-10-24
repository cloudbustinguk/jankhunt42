#!/usr/bin/env python3
"""Opt-in attestation fetching and verification for jankhunt42.

jankhunt42 does not implement signature verification itself: the Python
standard library has no X.509 or ECDSA support, and a release gate should not
rest on home-made cryptography. A verification plan (`jankhunt.verify.v1`)
names the subjects, the signer identity to expect and an optional Sigstore
trusted root. This module runs the native verifiers (`gh attestation verify`,
`cosign verify-blob-attestation`, `jf evd verify`) and records what they
report, next to the evidence `jh_supply` parses.

Network rules:
* Without --online this module opens no connection itself and runs a verifier
  only when its inputs allow offline verification (a bundle plus a trusted
  root). It cannot sandbox a third-party binary; it only withholds the inputs
  that make the binary go online.
* With --online it may fetch attestation bundles from the GitHub attestations
  API and workflow artifacts from the GitHub Actions API, and verifiers may use
  the network. A token is read only from GH_TOKEN/GITHUB_TOKEN and is sent only
  to api.github.com, never to a redirect target.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

import jh_supply
from jh_core import TOOL, VERSION, safe_text

PLAN_SCHEMA = "jankhunt.verify.v1"
API = "https://api.github.com"
API_HOST = "api.github.com"
GITHUB_ISSUER = "https://token.actions.githubusercontent.com"
DEFAULT_PREDICATE = "https://slsa.dev/provenance/v1"
HTTP_TIMEOUT = 30
MAX_RESPONSE = 24_000_000
MAX_ZIP = 50_000_000
MAX_ZIP_MEMBERS = 200
MAX_ZIP_TOTAL = 100_000_000
MAX_TOOL_OUTPUT = 8_000_000
OUTCOMES = ("tool-verified", "signature-only", "failed", "not-run", "error")
GH_SIGNER_FLAGS = (("certificate_identity", "--cert-identity"),
                   ("certificate_identity_regexp", "--cert-identity-regex"),
                   ("signer_workflow", "--signer-workflow"), ("signer_repo", "--signer-repo"))

_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
_OWNER_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_EVIDENCE_EXT = (".json", ".jsonl", ".spdx", ".xml", ".cdx")

_PLAN_KEYS = {"schema_version", "identity", "trusted_root", "subjects", "fetch", "jfrog", "tools",
              "timeout_seconds"}
_IDENTITY_KEYS = {"repo", "owner", "repo_id", "signer_workflow", "signer_repo", "certificate_identity",
                  "certificate_identity_regexp", "oidc_issuer", "source_ref", "deny_self_hosted_runners"}
_SUBJECT_KEYS = {"path", "oci", "bundle", "predicate_type", "verifier"}
_FETCH_KEYS = {"github_attestations", "actions_artifacts"}
_ARTIFACT_KEYS = {"name", "run_id"}
_JFROG_KEYS = {"subject_repo_path", "public_keys", "use_artifactory_keys", "server_id", "project"}
_TOOL_KEYS = {"gh", "cosign", "jf", "cosign_args"}


class PlanError(ValueError):
    pass


class FetchError(RuntimeError):
    pass


def _inside(path: str, root: str) -> bool:
    try:
        rp, rr = os.path.realpath(path), os.path.realpath(root)
        return os.path.commonpath([rp, rr]) == rr
    except ValueError:
        return False


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _strict(obj: Any, allowed: set, where: str) -> Dict[str, Any]:
    if not isinstance(obj, dict):
        raise PlanError("%s must be a JSON object" % where)
    unknown = sorted(set(obj) - allowed)
    if unknown:
        # A misspelt identity constraint must not silently weaken verification.
        raise PlanError("%s: unknown key(s) %s" % (where, ", ".join(unknown)))
    return obj


def _str(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 2048:
        raise PlanError("%s must be a non-empty string" % where)
    return value.strip()


def load_plan(path: str, root: str) -> Dict[str, Any]:
    """Load and validate a verification plan. The plan decides which signer
    identity counts as trustworthy, so a plan inside the scanned repository is
    refused: repository content must not choose its own verifier policy."""
    if _inside(path, root):
        raise PlanError("verification plan %s is inside the scanned repository; it names the signer "
                        "identity to trust, so it must come from outside the repository"
                        % os.path.basename(path))
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        raise PlanError("cannot read verification plan %s: %s" % (os.path.basename(path), exc))
    data = _strict(data, _PLAN_KEYS, "plan")
    if data.get("schema_version") != PLAN_SCHEMA:
        raise PlanError("plan schema_version must be %s" % PLAN_SCHEMA)
    base = os.path.dirname(os.path.realpath(path))

    def resolve(value: Any, where: str) -> str:
        return os.path.normpath(os.path.join(base, os.path.expanduser(_str(value, where))))

    identity = dict(_strict(data.get("identity") or {}, _IDENTITY_KEYS, "identity"))
    for key in ("repo", "owner", "signer_workflow", "signer_repo", "certificate_identity",
                "certificate_identity_regexp", "oidc_issuer", "source_ref"):
        if key in identity:
            identity[key] = _str(identity[key], "identity.%s" % key)
    if "repo" in identity and not _REPO_RE.match(identity["repo"]):
        raise PlanError("identity.repo must be OWNER/NAME")
    if "owner" in identity and not _OWNER_RE.match(identity["owner"]):
        raise PlanError("identity.owner must be a GitHub owner name")
    if "repo_id" in identity:
        if not str(identity["repo_id"]).isdigit():
            raise PlanError("identity.repo_id must be the numeric GitHub repository ID")
        identity["repo_id"] = str(identity["repo_id"])
    if "deny_self_hosted_runners" in identity and not isinstance(identity["deny_self_hosted_runners"], bool):
        raise PlanError("identity.deny_self_hosted_runners must be true or false")

    trusted_root = resolve(data["trusted_root"], "trusted_root") if data.get("trusted_root") else None
    if trusted_root and not os.path.isfile(trusted_root):
        raise PlanError("trusted_root %s not found" % os.path.basename(trusted_root))

    subjects: List[Dict[str, Any]] = []
    raw_subjects = data.get("subjects") or []
    if not isinstance(raw_subjects, list):
        raise PlanError("subjects must be a list")
    for i, raw in enumerate(raw_subjects):
        where = "subjects[%d]" % i
        s = _strict(raw, _SUBJECT_KEYS, where)
        if bool(s.get("path")) == bool(s.get("oci")):
            raise PlanError("%s needs exactly one of path or oci" % where)
        verifier = s.get("verifier", "gh")
        if verifier not in ("gh", "cosign"):
            raise PlanError("%s.verifier must be gh or cosign" % where)
        subj = {
            "path": resolve(s["path"], where + ".path") if s.get("path") else None,
            "oci": _str(s["oci"], where + ".oci") if s.get("oci") else None,
            "bundle": resolve(s["bundle"], where + ".bundle") if s.get("bundle") else None,
            "predicate_type": _str(s.get("predicate_type", DEFAULT_PREDICATE), where + ".predicate_type"),
            "verifier": verifier,
        }
        if subj["oci"] and not subj["oci"].startswith("oci://"):
            raise PlanError("%s.oci must start with oci://" % where)
        if subj["oci"] and verifier != "gh":
            raise PlanError("%s: oci subjects are verified with gh" % where)
        if verifier == "gh" and not (identity.get("repo") or identity.get("owner")):
            raise PlanError("%s: gh verification needs identity.repo or identity.owner" % where)
        if verifier == "cosign":
            if not (identity.get("certificate_identity") or identity.get("certificate_identity_regexp")):
                raise PlanError("%s: cosign verification needs identity.certificate_identity or "
                                "identity.certificate_identity_regexp" % where)
            if not subj["path"]:
                raise PlanError("%s: cosign verification needs a subject path" % where)
        subjects.append(subj)

    fetch = dict(_strict(data.get("fetch") or {}, _FETCH_KEYS, "fetch"))
    if not isinstance(fetch.get("github_attestations", False), bool):
        raise PlanError("fetch.github_attestations must be true or false")
    artifacts: List[Dict[str, Any]] = []
    for i, raw in enumerate(fetch.get("actions_artifacts") or []):
        a = _strict(raw, _ARTIFACT_KEYS, "fetch.actions_artifacts[%d]" % i)
        name = _str(a.get("name"), "fetch.actions_artifacts[%d].name" % i)
        run_id = a.get("run_id")
        if run_id is not None and not str(run_id).isdigit():
            raise PlanError("fetch.actions_artifacts[%d].run_id must be numeric" % i)
        artifacts.append({"name": name, "run_id": int(run_id) if run_id is not None else None})
    if (fetch.get("github_attestations") or artifacts) and not identity.get("repo"):
        raise PlanError("fetching from GitHub needs identity.repo")

    jfrog: List[Dict[str, Any]] = []
    for i, raw in enumerate(data.get("jfrog") or []):
        where = "jfrog[%d]" % i
        j = _strict(raw, _JFROG_KEYS, where)
        keys = [resolve(k, where + ".public_keys") for k in (j.get("public_keys") or [])]
        use_af = bool(j.get("use_artifactory_keys", False))
        if bool(keys) == use_af:
            raise PlanError("%s needs exactly one of public_keys or use_artifactory_keys" % where)
        jfrog.append({
            "subject_repo_path": _str(j.get("subject_repo_path"), where + ".subject_repo_path"),
            "public_keys": keys, "use_artifactory_keys": use_af,
            "server_id": _str(j["server_id"], where + ".server_id") if j.get("server_id") else None,
            "project": _str(j["project"], where + ".project") if j.get("project") else None,
        })

    tools_raw = _strict(data.get("tools") or {}, _TOOL_KEYS, "tools")
    tools: Dict[str, Any] = {}
    for name in ("gh", "cosign", "jf"):
        value = tools_raw.get(name, name)
        value = _str(value, "tools.%s" % name)
        tools[name] = resolve(value, "tools.%s" % name) if (os.sep in value or value.startswith(".")) else value
    cosign_args = tools_raw.get("cosign_args") or []
    if not isinstance(cosign_args, list) or not all(isinstance(a, str) for a in cosign_args):
        raise PlanError("tools.cosign_args must be a list of strings")
    tools["cosign_args"] = list(cosign_args)
    timeout = data.get("timeout_seconds", 120)
    if not isinstance(timeout, int) or not 1 <= timeout <= 600:
        raise PlanError("timeout_seconds must be an integer from 1 to 600")
    if not subjects and not jfrog and not fetch.get("actions_artifacts"):
        raise PlanError("plan has nothing to verify or fetch (no subjects, jfrog or actions_artifacts)")
    return {"label": os.path.basename(path), "identity": identity, "trusted_root": trusted_root,
            "subjects": subjects, "fetch": {"github_attestations": bool(fetch.get("github_attestations")),
                                            "actions_artifacts": artifacts},
            "jfrog": jfrog, "tools": tools, "timeout": timeout}


# --------------------------------------------------------------------- HTTP --

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None  # redirects are followed by _http_get, without credentials


_OPENER = urllib.request.build_opener(_NoRedirect)


def _open(req: urllib.request.Request, timeout: int):
    return _OPENER.open(req, timeout=timeout)


class _Net:
    def __init__(self, online: bool, token: Optional[str]) -> None:
        self.online = online
        self.token = token
        self.requests = 0

    def get(self, url: str, accept: str = "application/vnd.github+json",
            limit: int = MAX_RESPONSE) -> Tuple[int, bytes]:
        if not self.online:
            raise FetchError("network access needs --online")
        for _hop in range(4):
            parts = urllib.parse.urlsplit(url)
            if parts.scheme != "https" or not parts.hostname:
                raise FetchError("refusing non-HTTPS URL")
            headers = {"Accept": accept, "User-Agent": "%s/%s" % (TOOL, VERSION)}
            if parts.hostname == API_HOST:
                headers["X-GitHub-Api-Version"] = "2022-11-28"
                if self.token:
                    headers["Authorization"] = "Bearer " + self.token
            self.requests += 1
            try:
                resp = _open(urllib.request.Request(url, headers=headers), HTTP_TIMEOUT)
            except urllib.error.HTTPError as exc:
                location = exc.headers.get("Location") if exc.headers else None
                if exc.code in (301, 302, 303, 307, 308) and location:
                    url = urllib.parse.urljoin(url, location)
                    continue
                return exc.code, b""
            except (urllib.error.URLError, OSError) as exc:
                raise FetchError("request to %s failed: %s" % (parts.hostname, getattr(exc, "reason", exc)))
            with resp:
                body = resp.read(limit + 1)
                status = getattr(resp, "status", 200)
            if len(body) > limit:
                raise FetchError("response from %s is larger than %d bytes" % (parts.hostname, limit))
            return status, body
        raise FetchError("too many redirects")


def _json_body(body: bytes, what: str) -> Any:
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise FetchError("%s returned invalid JSON" % what)


def fetch_github_attestations(net: _Net, repo: str, sha256: str, workdir: str) -> Dict[str, Any]:
    url = "%s/repos/%s/attestations/sha256:%s?per_page=100" % (API, repo, sha256)
    status, body = net.get(url)
    info: Dict[str, Any] = {"kind": "github-attestations", "repo": repo, "subject": "sha256:" + sha256,
                            "count": 0, "file": None, "warnings": []}
    if status == 404:
        info["warnings"].append("no attestations for sha256:%s in %s" % (sha256[:12], repo))
        return info
    if status in (401, 403):
        raise FetchError("GitHub attestations API refused the request (HTTP %d); private repositories "
                         "need GH_TOKEN with attestations read access" % status)
    if status != 200:
        raise FetchError("GitHub attestations API returned HTTP %d" % status)
    data = _json_body(body, "GitHub attestations API")
    items = data.get("attestations") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise FetchError("GitHub attestations API response has no attestations list")
    lines, skipped, repo_ids = [], 0, set()
    for item in items:
        bundle = item.get("bundle") if isinstance(item, dict) else None
        if isinstance(item, dict) and item.get("repository_id") is not None:
            repo_ids.add(str(item["repository_id"]))
        if isinstance(bundle, dict):
            lines.append(json.dumps(bundle, sort_keys=True))
        else:
            skipped += 1
    if skipped:
        info["warnings"].append("%d attestation(s) only available via bundle_url (compressed); "
                                "use `gh attestation download`" % skipped)
    info["repository_ids"] = sorted(repo_ids)
    if lines:
        name = "sha256-%s.jsonl" % sha256
        with open(os.path.join(workdir, name), "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        info["file"] = name
        info["count"] = len(lines)
    return info


def _safe_member_name(name: str) -> str:
    base = os.path.basename(name.replace("\\", "/"))
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base)[:100]
    return "" if base in ("", ".", "..") else base


def fetch_actions_artifact(net: _Net, repo: str, name: str, run_id: Optional[int],
                           workdir: str, head: Optional[str]) -> Dict[str, Any]:
    query = urllib.parse.urlencode({"name": name, "per_page": 100})
    status, body = net.get("%s/repos/%s/actions/artifacts?%s" % (API, repo, query))
    if status in (401, 403):
        raise FetchError("GitHub Actions API refused the artifact listing (HTTP %d); set GH_TOKEN" % status)
    if status != 200:
        raise FetchError("GitHub Actions API returned HTTP %d for the artifact listing" % status)
    data = _json_body(body, "GitHub Actions API")
    arts = [a for a in (data.get("artifacts") or []) if isinstance(a, dict)
            and a.get("name") == name and not a.get("expired")]
    if run_id is not None:
        arts = [a for a in arts if (a.get("workflow_run") or {}).get("id") == run_id]
    if not arts:
        raise FetchError("no unexpired Actions artifact named %r%s" % (name, " in run %d" % run_id if run_id else ""))
    art = sorted(arts, key=lambda a: (str(a.get("created_at", "")), int(a.get("id", 0))))[-1]
    run = art.get("workflow_run") or {}
    info: Dict[str, Any] = {"kind": "actions-artifact", "repo": repo, "name": name,
                            "artifact_id": art.get("id"), "run_id": run.get("id"),
                            "head_sha": run.get("head_sha"), "created_at": art.get("created_at"),
                            "expires_at": art.get("expires_at"), "files": [], "warnings": [],
                            "signed": False}
    status, blob = net.get("%s/repos/%s/actions/artifacts/%d/zip" % (API, repo, int(art["id"])),
                           limit=MAX_ZIP)
    if status in (401, 403):
        raise FetchError("downloading an Actions artifact needs GH_TOKEN, even for public repositories "
                         "(HTTP %d)" % status)
    if status != 200:
        raise FetchError("artifact download returned HTTP %d" % status)
    recorded = str(art.get("digest") or "")
    actual = "sha256:" + hashlib.sha256(blob).hexdigest()
    info["digest"] = actual
    if recorded:
        info["digest_recorded"] = recorded
        info["digest_match"] = recorded == actual
        if recorded != actual:
            raise FetchError("artifact %r download does not match the digest GitHub recorded" % name)
    else:
        info["digest_match"] = None
        info["warnings"].append("GitHub recorded no digest for artifact %r" % name)
    if head and info["head_sha"] and info["head_sha"] != head:
        info["warnings"].append("artifact %r was built from commit %s; the repository is at %s"
                                % (name, str(info["head_sha"])[:12], head[:12]))
    try:
        zf = zipfile.ZipFile(io.BytesIO(blob))
    except zipfile.BadZipFile:
        raise FetchError("artifact %r is not a valid zip archive" % name)
    total = 0
    with zf:
        members = [m for m in zf.infolist() if not m.is_dir()]
        if len(members) > MAX_ZIP_MEMBERS:
            raise FetchError("artifact %r has more than %d files" % (name, MAX_ZIP_MEMBERS))
        for member in members:
            safe = _safe_member_name(member.filename)
            if not safe or not safe.lower().endswith(_EVIDENCE_EXT):
                continue
            with zf.open(member) as src:
                data_bytes = src.read(jh_supply.MAX_EVIDENCE_BYTES + 1)
            if len(data_bytes) > jh_supply.MAX_EVIDENCE_BYTES:
                info["warnings"].append("%s: larger than %d bytes, skipped" % (safe, jh_supply.MAX_EVIDENCE_BYTES))
                continue
            total += len(data_bytes)
            if total > MAX_ZIP_TOTAL:
                raise FetchError("artifact %r expands beyond %d bytes" % (name, MAX_ZIP_TOTAL))
            out = "artifact-%s-%s" % (art["id"], safe)
            with open(os.path.join(workdir, out), "wb") as fh:
                fh.write(data_bytes)
            info["files"].append(out)
    if not info["files"]:
        info["warnings"].append("artifact %r contains no SBOM or attestation files" % name)
    return info


# -------------------------------------------------------------- verifiers --

class _Tools:
    def __init__(self, plan: Dict[str, Any]) -> None:
        self.spec = plan["tools"]
        self.timeout = plan["timeout"]
        self._versions: Dict[str, str] = {}

    def path(self, name: str) -> Optional[str]:
        value = self.spec[name]
        if os.path.isabs(value):
            return value if os.path.isfile(value) and os.access(value, os.X_OK) else None
        return shutil.which(value)

    def run(self, argv: List[str], timeout: Optional[int] = None) -> Tuple[int, str, str]:
        proc = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=timeout or self.timeout, check=False)
        return (proc.returncode, proc.stdout[:MAX_TOOL_OUTPUT].decode("utf-8", "replace"),
                proc.stderr[:MAX_TOOL_OUTPUT].decode("utf-8", "replace"))

    def version(self, name: str) -> str:
        if name in self._versions:
            return self._versions[name]
        exe = self.path(name)
        out = ""
        if exe:
            try:
                rc, so, se = self.run([exe, "version"] if name == "cosign" else [exe, "--version"], timeout=15)
                text = so or se
                if name == "cosign":
                    m = re.search(r"GitVersion:\s*(\S+)", text)
                    out = m.group(1) if m else (text.strip().splitlines() or [""])[0]
                else:
                    out = (text.strip().splitlines() or [""])[0]
                    out = re.sub(r"^%s\s+version\s+" % re.escape(name), "", out)
            except (OSError, subprocess.SubprocessError):
                out = ""
        self._versions[name] = safe_text(out)[:120]
        return self._versions[name]


class _Scrub:
    """Removes local paths from tool output and recorded commands, so reports
    stay free of home directories and temporary paths."""

    def __init__(self, *roots: Optional[str]) -> None:
        pairs = []
        for label, path in zip(("<repo>", "<workdir>", "<plan>"), roots):
            if path:
                pairs.append((os.path.realpath(path), label))
                pairs.append((path, label))
        home = os.path.expanduser("~")
        if home and home != "/":
            pairs.append((home, "~"))
        self.pairs = sorted(set(pairs), key=lambda p: -len(p[0]))

    def text(self, value: str, limit: int = 400) -> str:
        for path, label in self.pairs:
            value = value.replace(path, label)
        value = " ".join(safe_text(value).split())
        return value[-limit:] if len(value) > limit else value

    def argv(self, argv: Sequence[str]) -> List[str]:
        return [os.path.basename(arg) if os.path.isabs(arg) else self.text(arg, 300) for arg in argv]


def _result(verifier: str, subject: str, outcome: str, reason: str, **extra: Any) -> Dict[str, Any]:
    assert outcome in OUTCOMES
    out = {"verifier": verifier, "subject": subject, "outcome": outcome, "reason": reason}
    out.update(extra)
    return out


def _gh_matches(stdout: str, sha256: Optional[str], repo_id: Optional[str]) -> Tuple[List[Dict[str, Any]], Dict[str, Any], str]:
    try:
        entries = json.loads(stdout)
    except ValueError:
        return [], {}, "gh exited 0 but its JSON output could not be parsed"
    if not isinstance(entries, list) or not entries:
        return [], {}, "gh exited 0 but reported no verified attestation"
    matches: List[Dict[str, Any]] = []
    identity: Dict[str, Any] = {}
    for entry in entries:
        vr = entry.get("verificationResult") if isinstance(entry, dict) else None
        if not isinstance(vr, dict):
            continue
        st = vr.get("statement") if isinstance(vr.get("statement"), dict) else {}
        cert = (vr.get("signature") or {}).get("certificate") if isinstance(vr.get("signature"), dict) else None
        cert = cert if isinstance(cert, dict) else {}
        if repo_id and str(cert.get("sourceRepositoryIdentifier", "")) != repo_id:
            return [], {}, ("signing certificate names repository ID %s, the plan expects %s (renamed or "
                            "re-created repository?)" % (cert.get("sourceRepositoryIdentifier") or "none", repo_id))
        if not identity:
            identity = {k: safe_text(cert[k])[:300] for k in (
                "sourceRepositoryURI", "sourceRepositoryIdentifier", "sourceRepositoryRef",
                "sourceRepositoryDigest", "buildSignerURI", "runInvocationURI", "issuer",
                "runnerEnvironment") if cert.get(k) not in (None, "")}
        for sub in st.get("subject") or []:
            digest = (sub.get("digest") or {}).get("sha256") if isinstance(sub, dict) else None
            if isinstance(digest, str) and _SHA256_RE.match(digest):
                matches.append({"sha256": digest, "predicate_type": str(st.get("predicateType", ""))})
    if sha256 and not any(m["sha256"] == sha256 for m in matches):
        return [], identity, "gh reported success but no verified statement names the subject digest"
    if not matches:
        return [], identity, "gh reported success but no statement subject could be read"
    return matches, identity, ""


def _verify_gh(plan: Dict[str, Any], tools: _Tools, scrub: _Scrub, subj: Dict[str, Any],
               label: str, online: bool) -> Dict[str, Any]:
    ident = plan["identity"]
    tr = plan["trusted_root"]
    bundle = subj.get("bundle")
    mode = "offline" if (bundle and tr) else "online"
    if mode == "online" and not online:
        need = "a bundle and a trusted_root" if not bundle and not tr else ("a bundle" if not bundle else "a trusted_root")
        return _result("gh", label, "not-run", "offline verification needs %s; add them to the plan or pass --online" % need)
    exe = tools.path("gh")
    if not exe:
        return _result("gh", label, "not-run", "gh not found (tools.gh: %s)" % os.path.basename(plan["tools"]["gh"]))
    argv = [exe, "attestation", "verify", subj["path"] or subj["oci"], "--format", "json",
            "--predicate-type", subj["predicate_type"]]
    argv += ["--repo", ident["repo"]] if ident.get("repo") else ["--owner", ident["owner"]]
    # gh accepts only one of these signer constraints; pass the most specific.
    constraint = next(((key, flag) for key, flag in GH_SIGNER_FLAGS if ident.get(key)), None)
    if constraint:
        argv += [constraint[1], ident[constraint[0]]]
    for key, flag in (("oidc_issuer", "--cert-oidc-issuer"), ("source_ref", "--source-ref")):
        if ident.get(key):
            argv += [flag, ident[key]]
    if ident.get("deny_self_hosted_runners"):
        argv.append("--deny-self-hosted-runners")
    if bundle:
        argv += ["--bundle", bundle]
    if tr:
        argv += ["--custom-trusted-root", tr]
    common = {"tool_version": tools.version("gh"), "command": scrub.argv(argv), "mode": mode,
              "predicate_type": subj["predicate_type"], "sha256": subj.get("sha256"),
              "signer_constraint": constraint[1] if constraint else "repository only"}
    try:
        rc, out, err = tools.run(argv)
    except subprocess.TimeoutExpired:
        return _result("gh", label, "error", "gh timed out after %ds" % tools.timeout, **common)
    except OSError as exc:
        return _result("gh", label, "error", "gh could not be started: %s" % scrub.text(str(exc)), **common)
    if rc != 0:
        return _result("gh", label, "failed", "gh rejected the attestation (subject digest, signer identity, or "
                       "trust root did not match): %s" % (scrub.text(err or out) or "exit %d" % rc),
                       exit_code=rc, **common)
    matches, identity, problem = _gh_matches(out, subj.get("sha256"), ident.get("repo_id"))
    if problem:
        outcome = "failed" if "repository ID" in problem or "subject digest" in problem else "error"
        return _result("gh", label, outcome, problem, exit_code=rc, **common)
    return _result("gh", label, "tool-verified", "signature, transparency log and signer identity verified by gh",
                   exit_code=rc, identity_checked=True, signer=identity, matches=matches, **common)


def _verify_cosign(plan: Dict[str, Any], tools: _Tools, scrub: _Scrub, label: str, online: bool,
                   bundle: Optional[str], predicate_type: str, path: Optional[str] = None,
                   sha256: Optional[str] = None) -> Dict[str, Any]:
    ident = plan["identity"]
    tr = plan["trusted_root"]
    if not bundle:
        return _result("cosign", label, "not-run", "cosign verification needs a bundle (subjects[].bundle or fetch)")
    mode = "offline" if tr else "online"
    if mode == "online" and not online:
        return _result("cosign", label, "not-run",
                       "offline verification needs a trusted_root in the plan; or pass --online")
    exe = tools.path("cosign")
    if not exe:
        return _result("cosign", label, "not-run",
                       "cosign not found (tools.cosign: %s)" % os.path.basename(plan["tools"]["cosign"]))
    argv = [exe, "verify-blob-attestation", "--bundle", bundle, "--type", predicate_type]
    if ident.get("certificate_identity"):
        argv += ["--certificate-identity", ident["certificate_identity"]]
    else:
        argv += ["--certificate-identity-regexp", ident["certificate_identity_regexp"]]
    argv += ["--certificate-oidc-issuer", ident.get("oidc_issuer") or GITHUB_ISSUER]
    if ident.get("repo"):
        argv += ["--certificate-github-workflow-repository", ident["repo"]]
    if tr:
        argv += ["--trusted-root", tr]
    argv += plan["tools"]["cosign_args"]
    argv += [path] if path else ["--digest", sha256 or "", "--digestAlg", "sha256"]
    common = {"tool_version": tools.version("cosign"), "command": scrub.argv(argv), "mode": mode,
              "predicate_type": predicate_type, "sha256": sha256}
    try:
        rc, out, err = tools.run(argv)
    except subprocess.TimeoutExpired:
        return _result("cosign", label, "error", "cosign timed out after %ds" % tools.timeout, **common)
    except OSError as exc:
        return _result("cosign", label, "error", "cosign could not be started: %s" % scrub.text(str(exc)), **common)
    if rc != 0:
        return _result("cosign", label, "failed", scrub.text(err or out) or "cosign exited %d" % rc,
                       exit_code=rc, **common)
    matches = [{"sha256": sha256, "predicate_type": predicate_type}] if sha256 else []
    return _result("cosign", label, "tool-verified",
                   "signature, transparency log and certificate identity verified by cosign",
                   exit_code=rc, identity_checked=True, matches=matches, **common)


def _jf_items(data: Any) -> List[Dict[str, Any]]:
    items = data.get("evidenceVerifications") if isinstance(data, dict) else None
    return [i for i in items if isinstance(i, dict)] if isinstance(items, list) else []


def _verify_jfrog(plan: Dict[str, Any], tools: _Tools, scrub: _Scrub, spec: Dict[str, Any], index: int,
                  online: bool, workdir: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    label = spec["subject_repo_path"]
    if not online:
        return [_result("jf", label, "not-run", "jf evd verify reads evidence from the JFrog Platform; pass --online")], None
    exe = tools.path("jf")
    if not exe:
        return [_result("jf", label, "not-run", "jf not found (tools.jf: %s)" % os.path.basename(plan["tools"]["jf"]))], None
    argv = [exe, "evd", "verify", "--subject-repo-path", spec["subject_repo_path"], "--format", "json"]
    argv += ["--use-artifactory-keys"] if spec["use_artifactory_keys"] else ["--public-keys", ";".join(spec["public_keys"])]
    if spec.get("server_id"):
        argv += ["--server-id", spec["server_id"]]
    if spec.get("project"):
        argv += ["--project", spec["project"]]
    common = {"tool_version": tools.version("jf"), "command": scrub.argv(argv), "mode": "online"}
    try:
        rc, out, err = tools.run(argv)
    except subprocess.TimeoutExpired:
        return [_result("jf", label, "error", "jf timed out after %ds" % tools.timeout, **common)], None
    except OSError as exc:
        return [_result("jf", label, "error", "jf could not be started: %s" % scrub.text(str(exc)), **common)], None
    try:
        data = json.loads(out)
    except ValueError:
        data = None
    items = _jf_items(data)
    if not items:
        outcome = "failed" if rc != 0 else "error"
        return [_result("jf", label, outcome, scrub.text(err or out) or "jf returned no evidence verifications",
                        exit_code=rc, **common)], None
    saved = "jfrog-evd-%d.json" % (index + 1)
    with open(os.path.join(workdir, saved), "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    subject_sha = str((data.get("subject") or {}).get("sha256", "")) if isinstance(data.get("subject"), dict) else ""
    results = []
    for n, item in enumerate(items):
        status, detail = jh_supply._verification_from_result(item.get("verificationResult"))
        vr = item.get("verificationResult") if isinstance(item.get("verificationResult"), dict) else {}
        key_source = str(vr.get("keySource", ""))
        sha = str(item.get("evidenceSubjectSha256") or subject_sha)
        statement, _env, _err = jh_supply._find_statement(item.get("sigstoreBundle") or item)
        ptype = str((statement or {}).get("predicateType") or item.get("predicateType") or "")
        item_label = "%s#%d" % (label, n + 1)
        extra = dict(common, exit_code=rc, key_source=key_source, predicate_type=ptype,
                     sha256=sha if _SHA256_RE.match(sha) else None)
        matches = [{"sha256": sha, "predicate_type": ptype}] if _SHA256_RE.match(sha) else []
        if status == "failed":
            results.append(_result("jf", item_label, "failed", detail, **extra))
        elif status != "provider-verified":
            results.append(_result("jf", item_label, "error", "jf reported no clear verification status", **extra))
        elif key_source.lower().startswith("sigstore bundle"):
            res = _result("jf", item_label, "signature-only",
                          "jf verified the signature with the key embedded in the Sigstore bundle; the signer "
                          "identity was not checked", identity_checked=False, matches=matches, **extra)
            ident = plan["identity"]
            if ident.get("certificate_identity") or ident.get("certificate_identity_regexp"):
                bundle_path = os.path.join(workdir, "jfrog-bundle-%d-%d.json" % (index + 1, n + 1))
                with open(bundle_path, "w", encoding="utf-8") as fh:
                    json.dump(item.get("sigstoreBundle"), fh)
                recheck = _verify_cosign(plan, tools, scrub, item_label, online, bundle_path,
                                         ptype or "custom", sha256=extra["sha256"])
                res["identity_recheck"] = {k: recheck.get(k) for k in ("outcome", "reason", "tool_version", "command")}
                if recheck["outcome"] == "tool-verified" and matches:
                    res.update(outcome="tool-verified", identity_checked=True,
                               reason="jf verified the signature; cosign verified the signer identity")
                elif recheck["outcome"] == "failed":
                    res.update(outcome="failed", reason="cosign identity re-check failed: %s" % recheck["reason"])
            results.append(res)
        else:
            source = key_source or "unspecified key"
            results.append(_result("jf", item_label, "tool-verified",
                                   "jf verified the evidence with %s" % source,
                                   identity_checked=key_source.lower() in ("user provided key", "artifactory key"),
                                   matches=matches, **extra))
    return results, saved


def _git_head(root: str) -> Optional[str]:
    try:
        proc = subprocess.run(["git", "-C", root, "rev-parse", "HEAD"], stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    head = proc.stdout.decode("ascii", "replace").strip()
    return head if proc.returncode == 0 and re.match(r"^[0-9a-f]{40,64}$", head) else None


# ------------------------------------------------------------- orchestration --

def apply(report: Dict[str, Any], verification: Dict[str, Any]) -> Dict[str, Any]:
    """Attach verification results to the parsed evidence and recompute the
    summary and gate. A tool result upgrades an attestation only when the tool
    verified a statement for the same subject digest and predicate type."""
    rank = {"tool-verified": 2, "signature-only": 1}
    for att in report.get("attestations", []):
        digests = {str((sub.get("digest") or {}).get("sha256", "")) for sub in att.get("subjects", [])}
        best: Optional[Dict[str, Any]] = None
        for res in verification.get("results", []):
            if res["outcome"] not in rank:
                continue
            for m in res.get("matches", []):
                if m.get("sha256") in digests and (not m.get("predicate_type")
                                                   or m["predicate_type"] == att.get("predicate_type")):
                    if best is None or rank[res["outcome"]] > rank[best["outcome"]]:
                        best = res
        if best is not None:
            att["exporter_verification"] = att.get("verification")
            att["verification"] = best["outcome"]
            att["verified_by"] = ("%s %s" % (best["verifier"], best.get("tool_version") or "")).strip()
            att["warnings"] = [w for w in att.get("warnings", []) if "not cryptographically verified" not in w]
            if best["outcome"] == "signature-only":
                att["warnings"].append("signature verified by %s; signer identity not checked" % best["verifier"])
    report["verification"] = verification
    jh_supply.summarize(report)
    return report


def verify_supply(root: str, plan: Dict[str, Any], online: bool, fetch_dir: Optional[str] = None,
                  **inspect_kwargs: Any) -> Dict[str, Any]:
    """Fetch (only with --online), verify, inspect and merge. Fetched files
    are parsed like repository evidence but carry their origin."""
    workdir = os.path.abspath(fetch_dir) if fetch_dir else tempfile.mkdtemp(prefix="jankhunt42-verify-")
    if fetch_dir:
        os.makedirs(workdir, exist_ok=True)
    scrub = _Scrub(root, workdir, os.path.dirname(plan["trusted_root"]) if plan.get("trusted_root") else None)
    net = _Net(online, os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or None)
    tools = _Tools(plan)
    results: List[Dict[str, Any]] = []
    fetched: List[Dict[str, Any]] = []
    jobs: List[Tuple[str, str, str, str]] = []
    warnings: List[str] = []
    ident = plan["identity"]
    try:
        for subj in plan["subjects"]:
            label = os.path.basename(subj["path"]) if subj["path"] else scrub.text(subj["oci"], 200)
            subj["label"] = label
            if subj["path"]:
                if not os.path.isfile(subj["path"]):
                    subj["missing"] = True
                    results.append(_result(subj["verifier"], label, "not-run", "subject file not found"))
                    continue
                subj["sha256"] = _sha256_file(subj["path"])
            if subj.get("bundle") and not os.path.isfile(subj["bundle"]):
                results.append(_result(subj["verifier"], label, "not-run",
                                       "bundle %s not found" % os.path.basename(subj["bundle"])))
                subj["missing"] = True
                continue
            if subj.get("bundle"):
                jobs.append((subj["bundle"], "plan/" + os.path.basename(subj["bundle"]), "attestation", "plan"))
        if plan["fetch"]["github_attestations"]:
            if not online:
                warnings.append("fetch.github_attestations skipped: needs --online")
            for subj in plan["subjects"]:
                if not online or subj.get("missing") or subj.get("bundle") or not subj.get("sha256"):
                    continue
                try:
                    info = fetch_github_attestations(net, ident["repo"], subj["sha256"], workdir)
                except FetchError as exc:
                    info = {"kind": "github-attestations", "repo": ident["repo"],
                            "subject": "sha256:" + subj["sha256"], "error": scrub.text(str(exc))}
                fetched.append(info)
                if info.get("file"):
                    path = os.path.join(workdir, info["file"])
                    subj["bundle"] = path
                    jobs.append((path, "fetched/" + info["file"], "attestation", "github-attestations-api"))
        head = _git_head(root)
        for art in plan["fetch"]["actions_artifacts"]:
            if not online:
                warnings.append("fetch.actions_artifacts %r skipped: needs --online" % art["name"])
                continue
            try:
                info = fetch_actions_artifact(net, ident["repo"], art["name"], art["run_id"], workdir, head)
            except FetchError as exc:
                info = {"kind": "actions-artifact", "repo": ident["repo"], "name": art["name"],
                        "error": scrub.text(str(exc))}
            fetched.append(info)
            for name in info.get("files", []):
                jobs.append((os.path.join(workdir, name), "fetched/" + name, "", "github-actions-artifact"))
        for subj in plan["subjects"]:
            if subj.get("missing"):
                continue
            if subj["verifier"] == "gh":
                results.append(_verify_gh(plan, tools, scrub, subj, subj["label"], online))
            else:
                results.append(_verify_cosign(plan, tools, scrub, subj["label"], online, subj.get("bundle"),
                                              subj["predicate_type"], path=subj["path"], sha256=subj.get("sha256")))
        for i, spec in enumerate(plan["jfrog"]):
            res, saved = _verify_jfrog(plan, tools, scrub, spec, i, online, workdir)
            results.extend(res)
            if saved:
                jobs.append((os.path.join(workdir, saved), "fetched/" + saved, "jfrog", "jf-evd-verify"))
        for info in fetched:
            warnings.extend(info.pop("warnings", []) or [])
            if info.get("error"):
                warnings.append("%s fetch failed: %s" % (info["kind"], info["error"]))
        report = jh_supply.inspect(root, extra_files=jobs, **inspect_kwargs)
        verification = {
            "plan": safe_text(plan["label"]),
            "mode": "online" if online else "offline",
            "network_requests": net.requests,
            "fetch_dir": os.path.basename(workdir) if fetch_dir else None,
            "ran_at": _now(),
            "results": results,
            "fetched": fetched,
            "warnings": list(dict.fromkeys(scrub.text(w) for w in warnings)),
            "note": ("results come from the named verifiers; %s performs no cryptographic verification itself"
                     % TOOL),
        }
        return apply(report, verification)
    finally:
        if not fetch_dir:
            shutil.rmtree(workdir, ignore_errors=True)
