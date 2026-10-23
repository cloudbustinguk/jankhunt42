#!/usr/bin/env python3
"""Diff-aware review, receipts, coverage, and baseline deltas.

The review command is intentionally a deterministic pre-pass. It answers:
what changed, what did the scanner see, what was skipped, what is new versus
persisting, and what evidence supports each finding. It does not pretend a
static rule is a runtime confirmation.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from jh_core import (
    Finding,
    GENERATED_RE,
    SEV_RANK,
    TOOL,
    VERSION,
    is_test_path,
    sev_at_least,
    source_from_text,
    trim,
)
from jh_rules import RULES, ScanOptions, ScanResult, rule_by_id, scan_sources
import jh_score
import jh_supply

_REVIEW_RECEIPT_VERSION = "1.0"
_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


class ReviewError(Exception):
    pass


@dataclass
class DiffFile:
    path: str
    status: str = "modified"
    added: Set[int] = field(default_factory=set)
    hunk_lines: Set[int] = field(default_factory=set)
    hunks: List[Tuple[int, int, int, int]] = field(default_factory=list)
    binary: bool = False
    old_path: str = ""


@dataclass
class DiffScope:
    mode: str
    text: str
    files: Dict[str, DiffFile]
    base: str = ""
    head: str = ""
    commit: str = ""
    pr: str = ""
    warning: str = ""
    revision: Optional[str] = None
    index: bool = False

    @property
    def changed_files(self) -> List[str]:
        return sorted(self.files)

    @property
    def changed_lines(self) -> int:
        return sum(len(f.added) for f in self.files.values())


# ---------------------------------------------------------------------------
# Git plumbing
# ---------------------------------------------------------------------------

def _run_git(root: str, args: Sequence[str], timeout: int = 45) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(["git", "-C", root] + list(args), capture_output=True,
                              text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ReviewError(str(exc))


def git_root(path: str) -> str:
    path = os.path.abspath(path)
    if os.path.isfile(path):
        path = os.path.dirname(path)
    proc = _run_git(path, ["rev-parse", "--show-toplevel"])
    if proc.returncode != 0:
        raise ReviewError("not a git worktree: %s" % path)
    return proc.stdout.strip()


def _git_head(root: str) -> str:
    proc = _run_git(root, ["rev-parse", "HEAD"])
    return proc.stdout.strip() if proc.returncode == 0 else ""


def _gh_pr_context(root: str, number: str) -> Tuple[str, str]:
    try:
        proc = subprocess.run(
            ["gh", "pr", "view", str(number), "--json", "baseRefOid,headRefOid,baseRefName,headRefName"],
            capture_output=True, text=True, timeout=30, cwd=root,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ReviewError("--pr requires the GitHub CLI (gh): %s" % exc)
    if proc.returncode != 0:
        msg = (proc.stderr or proc.stdout or "gh pr view failed").strip().splitlines()
        raise ReviewError(msg[0] if msg else "gh pr view failed")
    try:
        data = json.loads(proc.stdout)
    except ValueError as exc:
        raise ReviewError("gh returned invalid JSON: %s" % exc)
    head = str(data.get("headRefOid") or "")
    base = str(data.get("baseRefOid") or "")
    if not head or not base:
        raise ReviewError("could not determine PR base/head")
    local = _git_head(root)
    if local != head:
        raise ReviewError(
            "PR head %s is not checked out (local HEAD %s); check out the PR branch first"
            % (head[:12], local[:12] or "unknown")
        )
    return base, head


def _diff_command(root: str, mode: str, base: str = "", commit: str = "",
                  pr: str = "") -> Tuple[str, str, str, str, str, str, Optional[str], bool]:
    """Return (diff_text, mode, base, head, commit, pr, revision, index)."""
    head = _git_head(root)
    base_ref = base
    pr_ref = ""
    revision: Optional[str] = None
    index = False
    warning = ""
    if mode == "staged":
        args = ["diff", "--cached", "--unified=3", "--no-color", "--no-ext-diff", "--find-renames"]
        revision, index = None, True
    elif mode == "base":
        if not base:
            raise ReviewError("--base requires a git ref")
        args = ["diff", "%s...HEAD" % base, "--unified=3", "--no-color", "--no-ext-diff", "--find-renames"]
        revision = "HEAD"
    elif mode == "commit":
        if not commit:
            raise ReviewError("--commit requires a commit")
        args = ["show", "--format=", "--unified=3", "--no-color", "--no-ext-diff",
                "--find-renames", commit]
        revision = commit
        head = commit
    elif mode == "pr":
        if not pr:
            raise ReviewError("--pr requires a PR number or URL")
        base_ref, pr_ref = _gh_pr_context(root, pr)
        args = ["diff", "%s...HEAD" % base_ref, "--unified=3", "--no-color", "--no-ext-diff", "--find-renames"]
        revision = "HEAD"
    else:
        # Default review: everything not committed, including staged changes.
        args = ["diff", "HEAD", "--unified=3", "--no-color", "--no-ext-diff", "--find-renames"]
        if not head:
            args = ["diff", "--cached", "--unified=3", "--no-color", "--no-ext-diff", "--find-renames"]
            index = True
        revision = None
    proc = _run_git(root, args)
    if proc.returncode != 0:
        msg = (proc.stderr or "git diff failed").strip().splitlines()
        raise ReviewError(msg[0] if msg else "git diff failed")
    return proc.stdout, mode, base_ref, head, commit, pr_ref, revision, index


def _clean_diff_path(raw: str) -> str:
    value = raw.strip()
    if value.startswith("/dev/null"):
        return "/dev/null"
    if value.startswith(("a/", "b/")):
        value = value[2:]
    if value.startswith('"') and value.endswith('"'):
        value = value[1:-1].replace("\\t", "\t").replace('\\"', '"').replace("\\\\", "\\")
    return value.replace("\\", "/")


def parse_diff(text: str) -> Dict[str, DiffFile]:
    files: Dict[str, DiffFile] = {}
    current: Optional[DiffFile] = None
    old_path = ""
    rename_from = ""
    in_hunk = False
    new_ln = 0
    hunk_end = 0
    for line in text.splitlines():
        if line.startswith("diff --git "):
            in_hunk = False
            current = None
            old_path = ""
            rename_from = ""
            continue
        if not in_hunk and line.startswith("rename from "):
            rename_from = _clean_diff_path(line[12:])
            continue
        if not in_hunk and line.startswith("rename to "):
            new_path = _clean_diff_path(line[10:])
            if new_path:
                current = files.setdefault(new_path, DiffFile(
                    path=new_path, status="renamed", old_path=rename_from))
                current.status = "renamed"
                current.old_path = rename_from
            continue
        if line.startswith("Binary files ") and line.endswith(" differ"):
            # Keep the current path; no line-level findings are possible.
            if current is not None:
                current.binary = True
            continue
        if not in_hunk and line.startswith("--- "):
            old_path = _clean_diff_path(line[4:])
            continue
        if not in_hunk and line.startswith("+++ "):
            new_path = _clean_diff_path(line[4:])
            if new_path == "/dev/null":
                path = old_path
                if path and path != "/dev/null":
                    current = files.setdefault(path, DiffFile(path=path, status="deleted",
                                                              old_path=old_path))
                else:
                    current = None
            else:
                path = new_path
                status = "added" if old_path == "/dev/null" else "modified"
                current = files.setdefault(path, DiffFile(path=path, status=status,
                                                          old_path=old_path))
            continue
        m = _HUNK_RE.match(line)
        if m and current is not None:
            old_start = int(m.group(1))
            old_count = int(m.group(2)) if m.group(2) is not None else 1
            new_start = int(m.group(3))
            new_count = int(m.group(4)) if m.group(4) is not None else 1
            current.hunks.append((old_start, old_count, new_start, new_count))
            current.hunk_lines.update(range(new_start, new_start + max(0, new_count)))
            new_ln = new_start
            hunk_end = new_start + max(0, new_count)
            in_hunk = True
            continue
        if not in_hunk or current is None:
            continue
        if line.startswith("\\ No newline"):
            continue
        if line.startswith("+"):
            current.added.add(new_ln)
            current.hunk_lines.add(new_ln)
            new_ln += 1
        elif line.startswith(" "):
            new_ln += 1
        elif line.startswith("-"):
            pass
        else:
            # A malformed or truncated hunk; stop treating content as diff.
            if new_ln >= hunk_end:
                in_hunk = False
    return files


def _untracked(root: str) -> List[str]:
    proc = _run_git(root, ["ls-files", "--others", "--exclude-standard", "-z"])
    if proc.returncode != 0:
        return []
    return [p.replace("\\", "/") for p in proc.stdout.split("\0") if p]


def collect_diff(root: str, mode: str, base: str = "", commit: str = "",
                 pr: str = "") -> DiffScope:
    text, mode, base_ref, head, commit_ref, pr_ref, revision, index = _diff_command(
        root, mode, base, commit, pr
    )
    files = parse_diff(text)
    if mode == "working":
        for rel in _untracked(root):
            if rel in files:
                continue
            files[rel] = DiffFile(path=rel, status="untracked")
            # Filled after the source is loaded; see load_sources().
    return DiffScope(
        mode=mode, text=text, files=files, base=base_ref, head=head,
        commit=commit_ref, pr=pr_ref, revision=revision, index=index,
        warning="",
    )


def _git_show(root: str, rev: str, rel: str) -> Optional[str]:
    try:
        proc = subprocess.run(
            ["git", "-C", root, "show", "%s:%s" % (rev, rel)],
            capture_output=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    raw = proc.stdout
    if b"\x00" in raw[:8192]:
        return None
    return raw.decode("utf-8", "replace")


def _index_text(root: str, rel: str) -> Optional[str]:
    try:
        proc = subprocess.run(["git", "-C", root, "show", ":%s" % rel],
                              capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0 or b"\x00" in proc.stdout[:8192]:
        return None
    return proc.stdout.decode("utf-8", "replace")


def load_review_source(root: str, rel: str, scope: DiffScope, status: str = ""):
    text: Optional[str] = None
    if scope.index and status != "untracked":
        text = _index_text(root, rel)
    elif scope.revision and status != "untracked":
        text = _git_show(root, scope.revision, rel)
    else:
        try:
            raw = (Path(root) / rel).read_bytes()
        except OSError:
            raw = b""
        if b"\x00" not in raw[:8192]:
            text = raw.decode("utf-8", "replace") if raw else None
    if text is None:
        return None
    return source_from_text(rel, os.path.join(root, rel), text)


# ---------------------------------------------------------------------------
# Scope and scanning
# ---------------------------------------------------------------------------

def _path_selected(rel: str, paths: Sequence[str], root: str = "") -> bool:
    if not paths:
        return True
    rel = rel.replace("\\", "/")
    for raw in paths:
        p = raw.replace("\\", "/").strip()
        if root and os.path.isabs(p):
            try:
                p = os.path.relpath(p, root).replace("\\", "/")
            except ValueError:
                pass
        while p.startswith("./"):
            p = p[2:]
        p = p.rstrip("/")
        if not p or p == ".":
            return True
        if rel == p or rel.startswith(p + "/"):
            return True
    return False


def _excluded(rel: str, patterns: Sequence[str]) -> bool:
    import fnmatch
    for pat in patterns:
        if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(os.path.basename(rel), pat):
            return True
    return False


def _source_size(sf) -> int:
    return len(sf.text.encode("utf-8", "replace"))


def build_review_scope(root: str, scope: DiffScope, args: Any) -> Tuple[List[Any], Dict[str, Any]]:
    sources = []
    reviewed: List[str] = []
    skipped: List[Dict[str, str]] = []
    handled: Set[str] = set()
    untracked = [p for p, f in scope.files.items() if f.status == "untracked"]
    for rel in sorted(scope.files):
        handled.add(rel)
        df = scope.files[rel]
        if not _path_selected(rel, getattr(args, "paths", ()) or (), root):
            skipped.append({"path": rel, "reason": "outside selected paths"})
            continue
        if df.status == "deleted":
            skipped.append({"path": rel, "reason": "deleted"})
            continue
        if _excluded(rel, getattr(args, "exclude", ()) or ()):
            skipped.append({"path": rel, "reason": "excluded by pattern"})
            continue
        if GENERATED_RE.search(rel):
            skipped.append({"path": rel, "reason": "generated/vendor"})
            continue
        sf = load_review_source(root, rel, scope, df.status)
        if sf is None:
            skipped.append({"path": rel, "reason": "binary or unreadable"})
            continue
        if _source_size(sf) > int(getattr(args, "max_file_bytes", 1_500_000)):
            skipped.append({"path": rel, "reason": "larger than max-file-bytes"})
            continue
        if df.status == "untracked" or df.status == "added":
            lines = set(range(1, len(sf.raw) + 1))
            df.added.update(lines)
            df.hunk_lines.update(lines)
        sources.append(sf)
        reviewed.append(rel)
        if len(sources) >= int(getattr(args, "max_files", 20000)):
            break
    for rel in sorted(scope.files):
        if rel not in handled:
            skipped.append({"path": rel, "reason": "max-files reached"})
    changed_lines = sum(len(scope.files[p].added) for p in reviewed)
    hunk_lines = sum(len(scope.files[p].hunk_lines) for p in reviewed)
    meta = {
        "mode": scope.mode,
        "base": scope.base,
        "head": scope.head,
        "commit": scope.commit,
        "pr": scope.pr,
        "files_changed": len(scope.files),
        "files_reviewed": len(reviewed),
        "changed_lines": changed_lines,
        "hunk_lines": hunk_lines,
        "reviewed_loc": sum(s.loc for s in sources),
        "reviewed_files": reviewed,
        "skipped_files": skipped,
        "deleted_files": [p for p, f in scope.files.items() if f.status == "deleted"],
        "untracked_files": untracked,
        "test_files": sum(1 for p in reviewed if is_test_path(p)),
        "languages": sorted({s.lang for s in sources}),
        "rev": scope.revision or ("INDEX" if scope.index else "WORKTREE"),
    }
    return sources, meta


def scan_review(sources: Sequence[Any], args: Any) -> ScanResult:
    opts = ScanOptions(
        min_severity=getattr(args, "min_severity", "minor"),
        categories=set(getattr(args, "category", ()) or ()) or None,
        rule_ids=set(getattr(args, "rule", ()) or ()) or None,
        max_per_file_rule=getattr(args, "max_per_file_rule", 5),
        max_per_rule=getattr(args, "max_per_rule", 200),
    )
    return scan_sources(sources, opts)


# ---------------------------------------------------------------------------
# Receipts and baseline
# ---------------------------------------------------------------------------

def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _receipt_hash(receipt: Dict[str, Any]) -> str:
    payload = {k: v for k, v in receipt.items() if k != "receipt_hash"}
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def rulepack_hash() -> str:
    payload = {
        "version": VERSION,
        "rules": [{"id": r.id, "severity": r.severity, "category": r.category,
                   "confidence": r.confidence, "patterns": list(r.patterns),
                   "check": r.check} for r in RULES],
    }
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def _repro(f: Finding) -> str:
    path = shlex.quote(f.path)
    if f.rule == "JH901":
        return "jankhunt scan %s --cve --rule JH901 --json" % path
    return "jankhunt scan %s --rule %s --min-severity info --json" % (path, f.rule)


def make_receipt(f: Finding, scope_status: str, scan_id: str) -> Dict[str, Any]:
    verification = "supported" if f.confidence in ("high", "medium") and f.evidence else "unverified"
    receipt: Dict[str, Any] = {
        "id": "",
        "rule": f.rule,
        "title": f.title,
        "severity": f.severity,
        "category": f.category,
        "confidence": f.confidence,
        "path": f.path,
        "line": f.line,
        "column": f.column,
        "end_line": f.end_line,
        "location": {"file": f.path, "line": f.line, "column": f.column,
                     **({"end_line": f.end_line} if f.end_line else {})},
        "scope": scope_status,
        "verification": verification,
        "evidence": f.evidence,
        "message": f.message,
        "fix": f.fix,
        "counterevidence": (
            "Static pattern/structural rule only. Reachability, guards, and runtime behavior "
            "were not reproduced by this review."
        ),
        "repro": _repro(f),
        "tags": list(f.tags),
        "scan_id": scan_id,
        "receipt_version": _REVIEW_RECEIPT_VERSION,
    }
    receipt["receipt_hash"] = _receipt_hash(receipt)
    receipt["id"] = "JH-" + receipt["receipt_hash"][:12]
    return receipt


def _finding_from_any(item: Dict[str, Any]) -> Dict[str, Any]:
    loc = item.get("location") if isinstance(item.get("location"), dict) else {}
    return {
        "rule": item.get("rule") or item.get("rule_id") or "",
        "title": item.get("title") or "",
        "severity": item.get("severity") or "info",
        "confidence": item.get("confidence") or "low",
        "path": item.get("path") or loc.get("file") or item.get("file") or "",
        "line": int(item.get("line") or loc.get("line") or 0),
        "evidence": item.get("evidence") or "",
        "message": item.get("message") or item.get("why") or "",
        "fix": item.get("fix") or "",
    }


def _fingerprints(findings: Sequence[Dict[str, Any]]) -> List[str]:
    counts: Dict[str, int] = {}
    out: List[str] = []
    for item in findings:
        f = _finding_from_any(item)
        basis = "%s|%s|%s" % (f["rule"], f["path"], trim(f["evidence"] or f["title"], 500))
        n = counts.get(basis, 0) + 1
        counts[basis] = n
        out.append("%s#%d" % (basis, n))
    return out


def load_baseline(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        raise ReviewError("baseline unreadable: %s" % exc)
    findings: Any = []
    score: Optional[int] = None
    if isinstance(data, list):
        findings = data
    elif isinstance(data, dict):
        review = data.get("review") if isinstance(data.get("review"), dict) else {}
        findings = review.get("findings") or data.get("findings") or data.get("receipts") or []
        for candidate in (
            review.get("score", {}).get("score") if isinstance(review.get("score"), dict) else None,
            review.get("summary", {}).get("jank", {}).get("score")
            if isinstance(review.get("summary"), dict) else None,
            data.get("summary", {}).get("jank_score") if isinstance(data.get("summary"), dict) else None,
            data.get("summary", {}).get("jank", {}).get("score")
            if isinstance(data.get("summary"), dict) else None,
            data.get("score"),
        ):
            if isinstance(candidate, (int, float)):
                score = int(candidate)
                break
    if not isinstance(findings, list):
        raise ReviewError("baseline has no findings list")
    normalized = [_finding_from_any(x) for x in findings if isinstance(x, dict)]
    fps = _fingerprints(normalized)
    index = {fp: f for fp, f in zip(fps, normalized)}
    return {"path": path, "score": score, "findings": normalized, "fingerprints": index}


def compare_baseline(current: Sequence[Dict[str, Any]], baseline: Dict[str, Any],
                     current_score: int) -> Dict[str, Any]:
    current_fps = _fingerprints(current)
    current_index = {fp: f for fp, f in zip(current_fps, current)}
    base_index = baseline["fingerprints"]
    new = [current_index[fp] for fp in current_fps if fp not in base_index]
    persisting = [current_index[fp] for fp in current_fps if fp in base_index]
    resolved = [f for fp, f in base_index.items() if fp not in set(current_fps)]
    base_score = baseline.get("score")
    delta = (current_score - base_score) if isinstance(base_score, int) else None
    return {
        "path": baseline["path"],
        "baseline_score": base_score,
        "current_score": current_score,
        "delta": delta,
        "new": len(new),
        "persisting": len(persisting),
        "resolved": len(resolved),
        "new_findings": new,
        "persisting_fingerprints": [fp for fp in current_fps if fp in base_index],
        "resolved_findings": resolved,
    }


# ---------------------------------------------------------------------------
# Review assembly
# ---------------------------------------------------------------------------

def _supply_report(root: str, args: Any) -> Optional[Dict[str, Any]]:
    if getattr(args, "no_supply_chain", False):
        return None
    req = {
        "sbom": bool(getattr(args, "require_sbom", False)),
        "attestation": bool(getattr(args, "require_attestation", False)),
        "verified_attestation": bool(getattr(args, "require_verified_attestation", False)),
    }
    return jh_supply.inspect(
        root,
        sbom_paths=getattr(args, "sbom", ()) or (),
        attestation_paths=getattr(args, "attestation", ()) or (),
        jfrog_paths=getattr(args, "jfrog_evidence", ()) or (),
        requirements=req,
        discover=not bool(getattr(args, "no_supply_chain_discovery", False)),
    )


def _risk_rank(f: Finding) -> Tuple[int, str, int, str]:
    return (SEV_RANK.get(f.severity, 99), f.path, f.line, f.rule)


def run_review(args: Any) -> Dict[str, Any]:
    t0 = time.time()
    if getattr(args, "no_supply_chain", False):
        explicit = (getattr(args, "sbom", ()) or ()) + (getattr(args, "attestation", ()) or ()) \
            + (getattr(args, "jfrog_evidence", ()) or ())
        required = (getattr(args, "require_sbom", False)
                    or getattr(args, "require_attestation", False)
                    or getattr(args, "require_verified_attestation", False))
        if explicit or required:
            raise ReviewError("--no-supply-chain cannot be combined with evidence paths or "
                              "supply-chain requirements")
    start = (getattr(args, "paths", ()) or ["."])[0] or "."
    root = git_root(start)
    mode = "working"
    base = getattr(args, "base", "") or ""
    commit = getattr(args, "commit", "") or ""
    pr = getattr(args, "pr", "") or ""
    if getattr(args, "staged", False):
        mode = "staged"
    elif base:
        mode = "base"
    elif commit:
        mode = "commit"
    elif pr:
        mode = "pr"
    diff_scope = collect_diff(root, mode, base=base, commit=commit, pr=pr)
    sources, scope_meta = build_review_scope(root, diff_scope, args)
    untracked_set = set(scope_meta.get("untracked_files", []))
    diff_material = diff_scope.text + "\n" + "\n".join(
        s.text for s in sources if s.rel in untracked_set
    )
    diff_hash = hashlib.sha256(diff_material.encode("utf-8", "replace")).hexdigest()
    result = scan_review(sources, args)

    new: List[Finding] = []
    contextual: List[Finding] = []
    unchanged: List[Finding] = []
    for f in result.findings:
        df = diff_scope.files.get(f.path)
        if df is None:
            unchanged.append(f)
            continue
        lines = set(range(f.line, (f.end_line or f.line) + 1))
        if lines & df.added:
            new.append(f)
        elif lines & df.hunk_lines:
            contextual.append(f)
        else:
            unchanged.append(f)
    new.sort(key=_risk_rank)
    contextual.sort(key=_risk_rank)
    changed_lines = max(0, scope_meta["changed_lines"])
    jank = jh_score.compute(new, changed_lines)
    jank_dict = jank.to_dict()
    jank_dict["new_code"] = {
        "since": diff_scope.revision or diff_scope.mode,
        "changed_files": scope_meta["files_reviewed"],
        "changed_lines": changed_lines,
        "findings": len(new),
        "score": jank.score,
        "grade": jank.grade,
        "label": jank.label,
        "policy": jank.policy,
        "dimensions": {k: v.to_dict() for k, v in jank.dimensions.items()},
    }
    scan_id = hashlib.sha256(
        _canonical({
            "mode": diff_scope.mode, "base": diff_scope.base,
            "head": diff_scope.head, "changed": scope_meta["reviewed_files"],
            "diff_hash": diff_hash, "rulepack": rulepack_hash(),
        }).encode("utf-8")
    ).hexdigest()
    receipts = [make_receipt(f, "new", scan_id) for f in new]
    contextual_receipts = [make_receipt(f, "contextual", scan_id) for f in contextual]

    baseline = None
    if getattr(args, "baseline", ""):
        baseline_data = load_baseline(args.baseline)
        baseline = compare_baseline(receipts, baseline_data, jank.score)
        # Mark current findings that already existed in the baseline.
        persisting_fps = set(baseline.get("persisting_fingerprints", []))
        current_fps = _fingerprints(receipts)
        for receipt, fp in zip(receipts, current_fps):
            if fp in persisting_fps:
                receipt["scope"] = "persisting"
                receipt["receipt_hash"] = _receipt_hash(receipt)
                receipt["id"] = "JH-" + receipt["receipt_hash"][:12]
        receipts = [r for r in receipts if r.get("scope") != "persisting"] + [
            r for r in receipts if r.get("scope") == "persisting"
        ]

    supply = _supply_report(root, args)
    gate_reasons: List[str] = []
    fail_on = getattr(args, "fail_on", None)
    include_unverified = bool(getattr(args, "include_unverified", False))
    if fail_on:
        gated = [r for r in receipts
                 if r.get("scope") == "new" and sev_at_least(r["severity"], fail_on)
                 and (include_unverified or r.get("verification") != "unverified")]
        if gated:
            gate_reasons.append("%d new finding%s at or above %s"
                                % (len(gated), "" if len(gated) == 1 else "s", fail_on))
    if supply and supply.get("gate", {}).get("result") == "fail":
        gate_reasons.extend(supply["gate"].get("reasons", []))
    gate = {
        "fail_on": fail_on,
        "result": "fail" if gate_reasons else "pass",
        "reasons": gate_reasons,
    }
    scope_meta.update({
        "changed_files": diff_scope.changed_files,
        "changed_file_status": {p: f.status for p, f in diff_scope.files.items()},
    })
    unknowns = [
        "No runtime or test execution was performed by this review.",
        "Static rules only; the project compiler, typechecker, tests, and native linters were not run.",
        "Only changed files and diff hunks were considered; unchanged code and full-repo context were not re-reviewed.",
        "Cryptographic attestation verification is delegated to gh, cosign, or jf; unverified means exactly that.",
    ]
    unknowns.append("Dependency CVE lookup was not run by this review; use `jankhunt scan --cve` separately.")
    if scope_meta["skipped_files"]:
        unknowns.append("%d changed file%s were skipped; see scope.skipped_files."
                        % (len(scope_meta["skipped_files"]),
                           "" if len(scope_meta["skipped_files"]) == 1 else "s"))
    if supply is None:
        unknowns.append("Supply-chain evidence discovery was disabled.")
    elif not supply.get("sboms") and not supply.get("attestations"):
        unknowns.append("No SBOM or attestation evidence was found in the reviewed tree.")

    new_receipts = [r for r in receipts if r.get("scope") == "new"]
    summary = {
        "files_changed": scope_meta["files_changed"],
        "files_reviewed": scope_meta["files_reviewed"],
        "changed_lines": changed_lines,
        "findings": len(receipts),
        "new_findings": len(new_receipts),
        "persisting_findings": len(receipts) - len(new_receipts),
        "contextual_findings": len(contextual_receipts),
        "unchanged_findings": len(unchanged),
        "counts": _counts(new_receipts),
        "verification": _verification_counts(new_receipts),
        "jank_score": jank.score,
        "jank": jank_dict,
        "elapsed_seconds": round(time.time() - t0, 3),
    }
    review = {
        "mode": diff_scope.mode,
        "base": diff_scope.base,
        "head": diff_scope.head,
        "commit": diff_scope.commit,
        "pr": diff_scope.pr,
        "revision": scope_meta.get("rev"),
        "diff_hash": diff_hash,
        "scope": scope_meta,
        "summary": summary,
        "score": jank_dict,
        "baseline": baseline,
        "supply_chain": supply,
        "findings": receipts,
        "contextual": contextual_receipts,
        "resolved": (baseline or {}).get("resolved_findings", []),
        "unknowns": unknowns,
        "gate": gate,
        "receipt_version": _REVIEW_RECEIPT_VERSION,
        "rulepack_hash": rulepack_hash(),
    }
    data: Dict[str, Any] = {
        "tool": TOOL,
        "version": VERSION,
        "command": "review",
        "root": root,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scan_id": scan_id,
        "summary": summary,
        "review": review,
        "findings": receipts,
        "warnings": list(dict.fromkeys(
            (supply or {}).get("warnings", [])
            + ([] if not diff_scope.warning else [diff_scope.warning])
        )),
    }
    return data


def _counts(receipts: Sequence[Dict[str, Any]]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for r in receipts:
        out[r["severity"]] = out.get(r["severity"], 0) + 1
    return out


def _verification_counts(receipts: Sequence[Dict[str, Any]]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for r in receipts:
        key = r.get("verification", "unverified")
        out[key] = out.get(key, 0) + 1
    return out


# ---------------------------------------------------------------------------
# Output renderers
# ---------------------------------------------------------------------------

def _sev_chip(sev: str) -> str:
    return {"blocker": "BLOCKER", "critical": "CRITICAL", "major": "MAJOR",
            "minor": "MINOR", "info": "INFO"}.get(sev, sev.upper())


def _scope_line(review: Dict[str, Any]) -> str:
    scope = review["scope"]
    bits = [
        "%s → %s" % (review.get("base") or "working tree", review.get("head") or "HEAD"),
        "%d/%d files" % (scope.get("files_reviewed", 0), scope.get("files_changed", 0)),
        "%d changed lines" % scope.get("changed_lines", 0),
    ]
    if scope.get("skipped_files"):
        bits.append("%d skipped" % len(scope["skipped_files"]))
    return " · ".join(bits)


def _receipt_block(receipt: Dict[str, Any], index: int) -> List[str]:
    out = [
        "### %d. `%s` · **%s** · %s" % (
            index, receipt["rule"], _sev_chip(receipt["severity"]),
            "`%s:%d`" % (receipt["path"], receipt["line"])),
        "",
        "- **Title:** %s" % receipt["title"],
        "- **Scope:** %s · **Verification:** %s · **Confidence:** %s"
        % (receipt["scope"], receipt["verification"], receipt["confidence"]),
    ]
    if receipt.get("evidence"):
        out.append("- **Evidence:** `%s`" % receipt["evidence"].replace("`", "\\`"))
    if receipt.get("message"):
        out.append("- **Why:** %s" % receipt["message"])
    out.append("- **Counterevidence:** %s" % receipt["counterevidence"])
    out.append("- **Repro:** `%s`" % receipt["repro"])
    if receipt.get("fix"):
        out.append("- **Fix direction:** %s" % receipt["fix"])
    out.append("- **Receipt:** `%s`" % receipt["id"])
    out.append("")
    return out


def markdown(review: Dict[str, Any], max_findings: int = 300) -> str:
    scope = review["scope"]
    summary = review["summary"]
    out: List[str] = ["# JankHunt42 review", ""]
    out.append("**%s**" % _scope_line(review))
    out.append("")
    out.append("**New-code Jank:** %d/100 · %s · %s · policy **%s** · gate **%s**"
               % (review["score"]["score"], review["score"]["grade"],
                  review["score"]["label"], review["score"]["policy"],
                  review["gate"]["result"]))
    baseline = review.get("baseline")
    if baseline:
        delta = baseline.get("delta")
        delta_text = ("%+d" % delta) if isinstance(delta, int) else "n/a"
        out.append("**Baseline:** %s → %s (**%s**) · new %d · persisting %d · resolved %d"
                   % (baseline.get("baseline_score", "?"), baseline.get("current_score", "?"),
                      delta_text, baseline.get("new", 0), baseline.get("persisting", 0),
                      baseline.get("resolved", 0)))
    out.append("")
    out.append("| Metric | Value |")
    out.append("|---|---|")
    out.append("| Findings on added lines | %d |" % summary["findings"])
    out.append("| New findings | %d |" % summary.get("new_findings", summary["findings"]))
    out.append("| Persisting baseline findings | %d |" % summary.get("persisting_findings", 0))
    out.append("| Contextual findings | %d |" % summary["contextual_findings"])
    out.append("| Unchanged-line findings suppressed | %d |" % summary["unchanged_findings"])
    out.append("| Verification (new) | %s |" % (", ".join("%s %d" % (k, v) for k, v in summary["verification"].items()) or "none"))
    out.append("| Reviewed LOC | %d |" % scope.get("reviewed_loc", 0))
    out.append("| Test files touched | %d |" % scope.get("test_files", 0))
    out.append("| Languages | %s |" % (", ".join(scope.get("languages", [])) or "—"))
    out.append("")
    new_receipts = [r for r in review.get("findings", []) if r.get("scope") == "new"]
    persisting_receipts = [r for r in review.get("findings", []) if r.get("scope") == "persisting"]
    if new_receipts:
        out.append("## New findings")
        out.append("")
        for idx, receipt in enumerate(new_receipts[:max_findings], 1):
            out.extend(_receipt_block(receipt, idx))
        if len(new_receipts) > max_findings:
            out.append("_Showing %d of %d new findings. Use `--json` for the full set._"
                       % (max_findings, len(new_receipts)))
    else:
        out.append("## New findings")
        out.append("")
        out.append("No new deterministic finding on the added lines. This is not proof of correctness; "
                   "run the compiler, tests, linters, and the human review path.")
        out.append("")
    if persisting_receipts:
        out.append("## Persisting baseline findings")
        out.append("")
        out.append("These fingerprints existed in the baseline. They are reported for context and "
                   "do not participate in the default `--fail-on` gate.")
        out.append("")
        for idx, receipt in enumerate(persisting_receipts[:max_findings], 1):
            out.extend(_receipt_block(receipt, idx))
    if review.get("contextual"):
        out.append("## Contextual findings")
        out.append("")
        out.append("These are in the changed hunks but not on added lines. They are leads, not PR-blocking findings.")
        out.append("")
        for idx, receipt in enumerate(review["contextual"][:max_findings], 1):
            out.extend(_receipt_block(receipt, idx))
    if review.get("resolved"):
        out.append("## Resolved since baseline")
        out.append("")
        for item in review["resolved"][:max_findings]:
            out.append("- `%s` · %s · `%s:%d`"
                       % (item.get("rule"), item.get("title"), item.get("path"), item.get("line", 0)))
        out.append("")
    if review.get("supply_chain"):
        out.append(jh_supply.markdown(review["supply_chain"]))
        out.append("")
    out.append("## Coverage and unknowns")
    out.append("")
    for unknown in review.get("unknowns", []):
        out.append("- %s" % unknown)
    out.append("")
    out.append("## Scope")
    out.append("")
    out.append("| Kind | Count / detail |")
    out.append("|---|---|")
    out.append("| Changed files | %d |" % scope.get("files_changed", 0))
    out.append("| Reviewed files | %d |" % scope.get("files_reviewed", 0))
    out.append("| Skipped files | %d |" % len(scope.get("skipped_files", [])))
    out.append("| Deleted files | %d |" % len(scope.get("deleted_files", [])))
    out.append("| Untracked files | %d |" % len(scope.get("untracked_files", [])))
    out.append("| Changed lines | %d |" % scope.get("changed_lines", 0))
    if scope.get("skipped_files"):
        out.append("")
        for item in scope["skipped_files"]:
            out.append("- `%s` — %s" % (item.get("path"), item.get("reason")))
    out.append("")
    out.append("## Gate")
    out.append("")
    if review["gate"]["result"] == "pass":
        out.append("**PASS** — no gated finding or required supply-chain evidence is missing.")
    else:
        out.append("**FAIL**")
        for reason in review["gate"].get("reasons", []):
            out.append("- %s" % reason)
    out.append("")
    out.append("> A review receipt is evidence of a deterministic check, not a runtime proof. "
               "`supported` is static evidence; `unverified` is a lead.")
    return "\n".join(out)


def brief(review: Dict[str, Any]) -> str:
    """A compact pack for the host agent or an external LLM reviewer."""
    out = [
        "# Review brief",
        "",
        "You are reviewing a diff. The deterministic pre-pass below is not a verdict.",
        "",
        "## Contract",
        "",
        "1. Do not repeat a listed receipt unless you can add new evidence.",
        "2. For each lead, classify it as `confirmed`, `supported`, `contested`, `unverified`, or `rejected`.",
        "3. `confirmed` requires a repro command, a test result, or direct runtime evidence.",
        "4. Review only the changed lines and the context needed to judge them.",
        "5. Report concrete impact and the cheapest discriminating test; do not invent style nits.",
        "",
        "## Diff scope",
        "",
        _scope_line(review),
        "",
        "```json",
        json.dumps({"scope": review["scope"], "gate": review["gate"],
                    "summary": review["summary"]}, indent=2),
        "```",
        "",
        "## Deterministic leads",
        "",
    ]
    if review.get("findings"):
        for idx, r in enumerate(review["findings"], 1):
            out.extend(_receipt_block(r, idx))
    else:
        out.append("_No deterministic leads on added lines._")
        out.append("")
    if review.get("contextual"):
        out.append("## Contextual leads")
        out.append("")
        out.append("These are in the changed hunks but not on added lines. Treat them as optional context.")
        out.append("")
        for idx, r in enumerate(review["contextual"], 1):
            out.extend(_receipt_block(r, idx))
    if review.get("supply_chain"):
        out.append(jh_supply.markdown(review["supply_chain"]))
        out.append("")
    out.append("## Output contract")
    out.append("")
    out.append("Return JSON with `agent`, `findings`, and `rejected`. Each finding needs "
               "`title`, `severity`, `confidence`, `status`, `path`, `line`, `evidence`, "
               "and either `repro` or `runtime_evidence` when status is `confirmed`. "
               "Then run `jankhunt merge`.")
    return "\n".join(out)


def tty(review: Dict[str, Any], max_findings: int = 300, no_color: bool = False) -> str:
    import jh_render
    color = jh_render.Colors(not no_color)
    width = jh_render._width()
    scope = review["scope"]
    out = jh_render.banner(
        "diff review // evidence first",
        "%s  ·  %s → %s" % (review.get("root", ""), review.get("base") or "worktree",
                            review.get("head") or "HEAD"),
        color, width,
    )
    out.append("")
    out.append("  " + color.grey(_scope_line(review)))
    out.append("")
    score = review["score"]
    score_line = "  NEW CODE  %s/%s  %s  policy %s  gate %s" % (
        color.bold(str(score["score"])), color.bold(score["grade"]),
        color.sev("major" if score["score"] >= 36 else "minor", score["label"]),
        color.grey(score["policy"]),
        color.sev("critical" if review["gate"]["result"] == "fail" else "minor",
                  review["gate"]["result"].upper()),
    )
    out.append(score_line)
    baseline = review.get("baseline")
    if baseline:
        delta = baseline.get("delta")
        out.append("  " + color.grey("baseline %s → %s  delta %s  new %d  persisting %d  resolved %d"
                                     % (baseline.get("baseline_score", "?"),
                                        baseline.get("current_score", "?"),
                                        ("%+d" % delta) if isinstance(delta, int) else "n/a",
                                        baseline.get("new", 0), baseline.get("persisting", 0),
                                        baseline.get("resolved", 0))))
    out.append("")
    counts = review["summary"]["counts"]
    bits = []
    for sev in ("blocker", "critical", "major", "minor", "info"):
        if counts.get(sev):
            bits.append("%s %s" % (color.chip(sev), color.bold(str(counts[sev]))))
    out.append("  " + ("   ".join(bits) if bits else color.green("no new deterministic findings")))
    if review["summary"].get("persisting_findings"):
        out.append("  " + color.grey("persisting baseline findings: %d"
                                     % review["summary"]["persisting_findings"]))
    out.append("")
    if review.get("supply_chain"):
        out.append("  " + color.magenta("SUPPLY") + "  " + color.grey(jh_supply.summary_line(review["supply_chain"])))
        out.append("")
    if review.get("findings"):
        out.append("  " + color.dim("─" * (width - 4)))
        out.append("")
        for idx, r in enumerate(review["findings"][:max_findings], 1):
            out.append("  %02d  %s  %s  %s" % (
                idx, color.chip(r["severity"]), color.bold(r["rule"]),
                color.bold(jh_render._truncate(r["title"], width - 30))))
            out.append("      " + color.cyan("%s:%d" % (r["path"], r["line"]))
                       + color.grey("  ·  %s  ·  %s" % (r["scope"], r["verification"])))
            if r.get("evidence"):
                out.append("      " + color.grey("│ ") + color.dim(jh_render._truncate(r["evidence"], width - 10)))
            out.append("      " + color.grey("repro ") + color.cyan(r["repro"]))
            out.append("      " + color.grey("receipt ") + r["id"])
            out.append("")
    else:
        out.append("  " + color.green("✦ no deterministic finding on added lines"))
        out.append("  " + color.grey("That is not proof of correctness: run the project's compiler, tests, and linters."))
        out.append("")
    if review.get("unknowns"):
        out.append("  " + color.bold("UNKNOWNS"))
        for unknown in review["unknowns"][:4]:
            out.append("    " + color.grey("· " + unknown))
        out.append("")
    if review["gate"]["result"] == "fail":
        out.append("  " + color.red("GATE FAIL") + color.grey("  ·  " + "; ".join(review["gate"]["reasons"])))
    return "\n".join(out)


def sarif(review: Dict[str, Any]) -> str:
    import urllib.parse
    levels = {"blocker": "error", "critical": "error", "major": "warning",
              "minor": "note", "info": "note"}
    rules: Dict[str, Any] = {}
    results = []
    for r in review.get("findings", []):
        if r["rule"] not in rules:
            rule = rule_by_id(r["rule"])
            rules[r["rule"]] = {
                "id": r["rule"],
                "name": r["title"],
                "shortDescription": {"text": r["title"]},
                "fullDescription": {"text": r.get("message") or (rule.message if rule else r["title"])},
                "help": {"text": r.get("fix") or ""},
                "properties": {"category": r["category"], "severity": r["severity"],
                               "confidence": r["confidence"]},
            }
        result = {
            "ruleId": r["rule"],
            "level": levels.get(r["severity"], "note"),
            "message": {"text": r.get("message") or r["title"]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": urllib.parse.quote(r["path"].replace(os.sep, "/"), safe="/")},
                    "region": {"startLine": max(1, r["line"]),
                               "startColumn": max(1, r.get("column", 1)),
                               **({"endLine": r["end_line"]} if r.get("end_line") else {})},
                }
            }],
            "partialFingerprints": {"jankhunt": r["receipt_hash"]},
            "properties": {
                "severity": r["severity"], "confidence": r["confidence"],
                "scope": r["scope"], "verification": r["verification"],
                "evidence": r.get("evidence", ""), "fix": r.get("fix", ""),
                "repro": r.get("repro", ""), "receipt": r["id"],
                "receipt_hash": r["receipt_hash"],
            },
        }
        results.append(result)
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "jankhunt", "version": VERSION,
                                "informationUri": "https://github.com/anomalyco/opencode",
                                "rules": list(rules.values())}},
            "results": results,
        }],
    }, indent=2, ensure_ascii=False)
