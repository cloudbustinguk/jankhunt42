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
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from jh_core import (  # noqa: F401
    display_path,
    tree_skip_reason,
    run_git,
    Finding,
    safe_text,
    GENERATED_RE,
    skipped_dir_reason,
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
        return sorted(display_path(p) for p in self.files)

    @property
    def changed_lines(self) -> int:
        return sum(len(f.added) for f in self.files.values())


# ---------------------------------------------------------------------------
# Git plumbing
# ---------------------------------------------------------------------------

def _run_git(root: str, args: Sequence[str], timeout: int = 45) -> subprocess.CompletedProcess:
    try:
        # a file name that is not UTF-8 survives decoding (the file system's own rule), never crashes it
        return run_git(["git", "-C", root] + list(args), capture_output=True,
                              text=True, errors="surrogateescape", timeout=timeout)
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
            # Before the first commit: the working tree against the empty tree, read from the working tree, so an
            # edit made after `git add` is reviewed (the staged copy is what --staged reviews)
            empty = _run_git(root, ["hash-object", "-t", "tree", "/dev/null"])
            if empty.returncode != 0:
                raise ReviewError("git could not name the empty tree")
            args = ["diff", empty.stdout.strip(), "--unified=3", "--no-color", "--no-ext-diff", "--find-renames"]
        revision = None
    proc = _run_git(root, args)
    if proc.returncode != 0:
        msg = (proc.stderr or "git diff failed").strip().splitlines()
        raise ReviewError(msg[0] if msg else "git diff failed")
    return proc.stdout, mode, base_ref, head, commit, pr_ref, revision, index, _inventory(root, args)


_STATUS = {"A": "added", "M": "modified", "D": "deleted", "R": "renamed", "C": "added", "T": "modified"}


def _inventory(root: str, args: Sequence[str]) -> List[Tuple[str, str, str]]:
    """Every changed path, exactly as git names it, with its status: (status, old path, new path). A binary file has
    no text header in the patch, so the patch alone cannot be the inventory."""
    proc = _run_git(root, [a for a in args if not a.startswith("--unified")] + ["--name-status", "-z"])
    if proc.returncode != 0:
        return []
    parts = proc.stdout.split("\0")
    out: List[Tuple[str, str, str]] = []
    i = 0
    while i < len(parts) and parts[i]:
        code = parts[i][:1]
        if code in ("R", "C") and i + 2 < len(parts):
            out.append((_STATUS[code], parts[i + 1], parts[i + 2]))
            i += 3
        elif i + 1 < len(parts):
            out.append((_STATUS.get(code, "modified"), parts[i + 1], parts[i + 1]))
            i += 2
        else:
            break
    return out


_C_ESCAPES = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13, '"': 34, "\\": 92}


def _unquote_git_path(value: str) -> str:
    """Undo git's C-style quoting ("p\\303\\252che.py" is pêche.py): octal escapes are bytes of the UTF-8 name."""
    if not (len(value) >= 2 and value[0] == '"' and value[-1] == '"'):
        return value
    s, out, i = value[1:-1], bytearray(), 0
    while i < len(s):
        ch = s[i]
        if ch == "\\" and i + 1 < len(s):
            nxt = s[i + 1]
            if re.match(r"[0-3][0-7]{2}", s[i + 1:i + 4]):
                out.append(int(s[i + 1:i + 4], 8))
                i += 4
                continue
            if nxt in _C_ESCAPES:
                out.append(_C_ESCAPES[nxt])
                i += 2
                continue
        out.extend(ch.encode("utf-8", "surrogateescape"))
        i += 1
    return out.decode("utf-8", "surrogateescape")


def _clean_diff_path(raw: str) -> str:
    # git ends a ---/+++ path that holds a space with a tab; the quotes come off before the a/ or b/ prefix
    value = _unquote_git_path(raw.rstrip("\t\r\n").strip(" "))
    if value.startswith("/dev/null"):
        return "/dev/null"
    if value.startswith(("a/", "b/")):
        value = value[2:]
    return value


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
    text, mode, base_ref, head, commit_ref, pr_ref, revision, index, inventory = _diff_command(
        root, mode, base, commit, pr
    )
    files = parse_diff(text)
    for status, old, new in inventory:       # a path the patch gave no text header (a binary file) is still changed
        path = old if status == "deleted" else new
        if path not in files:
            files[path] = DiffFile(path=path, status=status, old_path=old if status == "renamed" else "",
                                   binary=True)
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
        proc = run_git(
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
        proc = run_git(["git", "-C", root, "show", ":%s" % rel],
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
        # a relative path names a place as seen from where the command runs ("review one" from the parent folder);
        # one that does not exist from there keeps its meaning inside the repository
        if root and p and not os.path.isabs(p) and os.path.exists(p):
            p = os.path.abspath(p)
        if root and os.path.isabs(p):
            try:
                p = os.path.relpath(p, root).replace("\\", "/")
            except ValueError:  # jankhunt42: ignore JH201 (a path on another Windows drive stays absolute)
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
        # the shared folder rule: an env folder holding pyvenv.cfg (on disk or among the changes) is installed code,
        # and so is an installed plugin's bundle
        folder_why = tree_skip_reason(rel, lambda q: q in scope.files or os.path.isfile(os.path.join(root, q)))
        if GENERATED_RE.search(rel) or folder_why:
            skipped.append({"path": rel, "reason": "generated/vendor" if not folder_why else folder_why})
            continue
        sf = load_review_source(root, rel, scope, df.status)
        if sf is None:
            skipped.append({"path": rel, "reason": "binary or unreadable"})
            continue
        if _source_size(sf) > int(getattr(args, "max_file_bytes", 1_500_000)):
            skipped.append({"path": rel, "reason": "larger than max-file-bytes"})
            continue
        if df.status == "untracked" or df.status == "added":
            real = len(sf.raw) - (1 if sf.raw and sf.raw[-1] == "" else 0)   # a final newline ends a line, adds none
            lines = set(range(1, real + 1))
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
        # paths as reports show them (a name byte that is not UTF-8 is written \xNN), the same form findings use
        "reviewed_files": [display_path(p) for p in reviewed],
        "skipped_files": [dict(s, path=display_path(s["path"])) for s in skipped],
        "deleted_files": [display_path(p) for p, f in scope.files.items() if f.status == "deleted"],
        "untracked_files": [display_path(p) for p in untracked],
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
        ignore_rule_ids=set(getattr(args, "ignore_rule_ids", None) or ()) or None,
        # the caps are applied after findings are sorted into new, contextual and unchanged (cap_review): a finding
        # on an unchanged line must never take the slot of one on a changed line
        max_per_file_rule=10 ** 9,
        max_per_rule=10 ** 9,
    )
    result = scan_sources(sources, opts)
    for f in result.findings:                  # a ruleset's severity changes (prepare_rules)
        f.severity = (getattr(args, "severity_map", None) or {}).get(f.rule, f.severity)
    return result


# ---------------------------------------------------------------------------
# Receipts and baseline
# ---------------------------------------------------------------------------

def _review_aside(result: ScanResult, capped: int, floor: str, ignored: Sequence[str] = ()) -> Dict[str, Any]:
    """What the review's scan of the changed files held back, in the same shape as a scan's set_aside."""
    out: Dict[str, Any] = {k: v for k, v in result.set_aside.items() if v and k not in ("capped", "ignored_rules")}
    if ignored:
        out["ignored_rules"] = {"rules": sorted(ignored)}      # set aside by name: these rules did not run
    if out.get("below_floor"):
        out["below_floor"] = dict(out["below_floor"], floor=floor)
    if capped:
        out["capped"] = capped
    return out


def cap_review(new: List[Finding], others: List[List[Finding]], max_per_file_rule: int,
               max_per_rule: int) -> Tuple[List[List[Finding]], int]:
    """Apply the per-file-rule and per-rule caps after classification. Findings on changed lines are never capped
    (they are what the review is for, and the gate must see every one); they use up slots first, and the contextual
    and unchanged findings share what is left. Returns the capped lists and how many findings the caps held back."""
    per_file: Dict[Tuple[str, str], int] = {}
    per_rule: Dict[str, int] = {}
    for f in new:
        per_file[(f.rule, f.path)] = per_file.get((f.rule, f.path), 0) + 1
        per_rule[f.rule] = per_rule.get(f.rule, 0) + 1
    out, held = [], 0
    for group in others:
        kept = []
        for f in group:
            if per_file.get((f.rule, f.path), 0) >= max_per_file_rule or per_rule.get(f.rule, 0) >= max_per_rule:
                held += 1
                continue
            per_file[(f.rule, f.path)] = per_file.get((f.rule, f.path), 0) + 1
            per_rule[f.rule] = per_rule.get(f.rule, 0) + 1
            kept.append(f)
        out.append(kept)
    return out, held


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _receipt_hash(receipt: Dict[str, Any]) -> str:
    payload = {k: v for k, v in receipt.items() if k != "receipt_hash"}
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def rulepack_hash() -> str:
    payload = {
        "version": VERSION,
        # every field that changes what a rule reports, so a site rule narrowed to other files is a different pack
        "rules": [{"id": r.id, "severity": r.severity, "category": r.category,
                   "confidence": r.confidence, "patterns": list(r.patterns),
                   "check": r.check, "langs": list(r.langs), "files": list(r.files), "target": r.target,
                   "ignore": r.ignore} for r in RULES],
    }
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def _repro(f: Finding, policy: str = "") -> str:
    path = shlex.quote(f.path)
    return "jankhunt42 scan %s --rule %s --min-severity info --json%s" % (path, f.rule, policy)


def _repro_policy(args: Any, root: str) -> str:
    """The --ruleset arguments a replay needs (from the repository root, where the receipt's path is relative): a site
    rule, or a ruleset's severity change, is lost without them. Their digests are in the report's `rulesets`."""
    out = ""
    for given in getattr(args, "ruleset", None) or ():
        full = os.path.abspath(given)
        try:
            shown = os.path.relpath(full, root)
        except ValueError:                       # another drive: only the full path names it
            shown = full
        out += " --ruleset %s" % shlex.quote(shown.replace(os.sep, "/"))
    return out


def make_receipt(f: Finding, scope_status: str, scan_id: str, policy: str = "") -> Dict[str, Any]:
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
        "repro": _repro(f, policy),
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
    except (OSError, ValueError, RecursionError) as exc:
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
                     current_score: int, context: Sequence[Dict[str, Any]] = (),
                     reviewed_paths: Optional[Sequence[str]] = None) -> Dict[str, Any]:
    """`context`: the other current findings in the same files (unchanged and contextual lines). Occurrences of the
    same finding are numbered across all of them in line order, so a second copy added on a new line is the second
    occurrence and stays new while the original sits unchanged."""
    if context:
        everything = sorted([(dict(c), False) for c in context] + [(dict(c), True) for c in current],
                            key=lambda pair: (_finding_from_any(pair[0])["path"], _finding_from_any(pair[0])["line"]))
        fps_all = _fingerprints([pair[0] for pair in everything])
        mine = iter(fp for fp, (_, is_current) in zip(fps_all, everything) if is_current)
        order = sorted(range(len(current)), key=lambda i: (_finding_from_any(current[i])["path"],
                                                           _finding_from_any(current[i])["line"]))
        current_fps = [""] * len(current)
        for i in order:
            current_fps[i] = next(mine)
        all_fps = set(fps_all)
    else:
        current_fps = _fingerprints(current)
        all_fps = set(current_fps)
    current_index = {fp: f for fp, f in zip(current_fps, current)}
    base_index = baseline["fingerprints"]
    new = [current_index[fp] for fp in current_fps if fp not in base_index]
    persisting = [current_index[fp] for fp in current_fps if fp in base_index]
    gone = [f for fp, f in base_index.items() if fp not in all_fps]
    # a baseline finding is resolved only when its file was reviewed this time; in a file the review skipped or did
    # not reach, its state is unknown, and saying "resolved" would be a claim nobody checked
    if reviewed_paths is None:
        resolved, unassessed = gone, []
    else:
        seen = set(reviewed_paths)
        resolved = [f for f in gone if _finding_from_any(f)["path"] in seen]
        unassessed = [f for f in gone if _finding_from_any(f)["path"] not in seen]
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
        "unassessed": len(unassessed),
        "new_findings": new,
        "persisting_fingerprints": [fp for fp in current_fps if fp in base_index],
        "current_fingerprints": current_fps,
        "resolved_findings": resolved,
        "unassessed_findings": unassessed,
    }


# ---------------------------------------------------------------------------
# Review assembly
# ---------------------------------------------------------------------------


def _risk_rank(f: Finding) -> Tuple[int, str, int, str]:
    return (SEV_RANK.get(f.severity, 99), f.path, f.line, f.rule)


def run_review(args: Any) -> Dict[str, Any]:
    t0 = time.time()
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
    overrun = ["site rule %s ran over its time budget and was switched off for this run; its findings are incomplete"
               % rid for rid in sorted(result.site_overrun)]
    for note in overrun:
        print("jankhunt42: %s" % note, file=sys.stderr)

    new: List[Finding] = []
    contextual: List[Finding] = []
    unchanged: List[Finding] = []
    shown_files = {display_path(k): v for k, v in diff_scope.files.items()}
    for f in result.findings:
        df = diff_scope.files.get(f.path) or shown_files.get(f.path)   # a finding names the path as shown
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
    (contextual, unchanged), review_capped = cap_review(new, [contextual, unchanged],
                                                        getattr(args, "max_per_file_rule", 5),
                                                        getattr(args, "max_per_rule", 200))
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
            # the policy that shaped this review: which rulesets, which rules switched off, which ratings changed
            "rulesets": [r.get("sha256") for r in getattr(args, "rulesets", None) or []],
            "ignored": sorted(getattr(args, "ignore_rule_ids", None) or ()),
            "severity": dict(sorted((getattr(args, "severity_map", None) or {}).items())),
        }).encode("utf-8")
    ).hexdigest()
    policy = _repro_policy(args, root)
    receipts = [make_receipt(f, "new", scan_id, policy) for f in new]
    contextual_receipts = [make_receipt(f, "contextual", scan_id, policy) for f in contextual]

    baseline = None
    if getattr(args, "baseline", ""):
        baseline_data = load_baseline(args.baseline)
        context = [{"rule": f.rule, "title": f.title, "path": f.path, "line": f.line, "evidence": f.evidence}
                   for f in unchanged + contextual]
        baseline = compare_baseline(receipts, baseline_data, jank.score, context, scope_meta["reviewed_files"])
        # Mark current findings that already existed in the baseline.
        persisting_fps = set(baseline.get("persisting_fingerprints", []))
        current_fps = baseline["current_fingerprints"]
        for receipt, fp in zip(receipts, current_fps):
            if fp in persisting_fps:
                receipt["scope"] = "persisting"
                receipt["receipt_hash"] = _receipt_hash(receipt)
                receipt["id"] = "JH-" + receipt["receipt_hash"][:12]
        receipts = [r for r in receipts if r.get("scope") != "persisting"] + [
            r for r in receipts if r.get("scope") == "persisting"
        ]

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
    gate = {
        "fail_on": fail_on,
        "result": "fail" if gate_reasons else "pass",
        "reasons": gate_reasons,
    }
    scope_meta.update({
        "changed_files": diff_scope.changed_files,
        "changed_file_status": {display_path(p): f.status for p, f in diff_scope.files.items()},
    })
    unknowns = [
        "No runtime or test execution was performed by this review.",
        "Static rules only; the project compiler, typechecker, tests, and native linters were not run.",
        "Only changed files and diff hunks were considered; unchanged code and full-repo context were not re-reviewed.",
        "Dependency advisories (CVEs) are out of scope; use Dependabot, osv-scanner or your registry's audit.",
    ]
    if scope_meta["skipped_files"]:
        unknowns.append("%d changed file%s were skipped; see scope.skipped_files."
                        % (len(scope_meta["skipped_files"]),
                           "" if len(scope_meta["skipped_files"]) == 1 else "s"))

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
        "capped_findings": review_capped,          # contextual and unchanged findings the caps held back
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
        "findings": receipts,
        "contextual": contextual_receipts,
        "resolved": (baseline or {}).get("resolved_findings", []),
        "unknowns": unknowns,
        "gate": gate,
        "set_aside": _review_aside(result, review_capped, getattr(args, "min_severity", "minor"),
                                   sorted(getattr(args, "ignore_rule_ids", None) or ())),
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
            ([] if not diff_scope.warning else [diff_scope.warning])
            + overrun
        )),
    }
    if getattr(args, "rulesets", None):              # name and digest of each policy, as a scan records them
        data["rulesets"] = args.rulesets
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
        out.append("- **Evidence:** `%s`" % safe_text(receipt["evidence"]).replace("`", "\\`"))
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
    out: List[str] = ["# jankhunt42 review", ""]
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
        out.append("**Baseline:** %s → %s (**%s**) · new %d · persisting %d · resolved %d%s"
                   % (baseline.get("baseline_score", "?"), baseline.get("current_score", "?"),
                      delta_text, baseline.get("new", 0), baseline.get("persisting", 0),
                      baseline.get("resolved", 0),
                      " · not reassessed %d (file not reviewed this time)" % baseline["unassessed"]
                      if baseline.get("unassessed") else ""))
    import jh_render
    aside = jh_render.set_aside_lines({"set_aside": review.get("set_aside") or {}})
    if aside:
        out += ["", "### Set aside in this review", ""] + ["- %s" % text for _, text in aside]
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
        out.append("**PASS** — no gated finding.")
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
    out.append("## Output contract")
    out.append("")
    out.append("Return JSON with `agent`, `findings`, and `rejected`. Each finding needs "
               "`title`, `severity`, `confidence`, `status`, `path`, `line`, `evidence`, "
               "and either `repro` or `runtime_evidence` when status is `confirmed`.")
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
        out.append("  " + color.grey("baseline %s → %s  delta %s  new %d  persisting %d  resolved %d%s"
                                     % (baseline.get("baseline_score", "?"),
                                        baseline.get("current_score", "?"),
                                        ("%+d" % delta) if isinstance(delta, int) else "n/a",
                                        baseline.get("new", 0), baseline.get("persisting", 0),
                                        baseline.get("resolved", 0),
                                        "  not reassessed %d" % baseline["unassessed"]
                                        if baseline.get("unassessed") else "")))
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
    if review.get("findings"):
        out.append("  " + color.dim("─" * (width - 4)))
        out.append("")
        for idx, r in enumerate(review["findings"][:max_findings], 1):
            out.append("  %02d  %s  %s  %s" % (
                idx, color.chip(r["severity"]), color.bold(r["rule"]),
                color.bold(jh_render._truncate(r["title"], width - 30))))
            out.append("      " + color.cyan("%s:%d" % (safe_text(r["path"]), r["line"]))
                       + color.grey("  ·  %s  ·  %s" % (r["scope"], r["verification"])))
            if r.get("evidence"):
                out.append("      " + color.grey("│ ") + color.dim(jh_render._truncate(safe_text(r["evidence"]), width - 10)))
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
    # an alert's identity is the finding itself (rule, path, evidence, occurrence), the identity baselines compare;
    # the receipt hash also covers the whole review, so an unrelated change elsewhere would rename every alert
    stable = [hashlib.sha256(fp.encode("utf-8", "surrogateescape")).hexdigest()
              for fp in _fingerprints(review.get("findings", []))]
    for n, r in enumerate(review.get("findings", [])):
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
            "partialFingerprints": {"jankhunt42": stable[n]},
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
            "tool": {"driver": {"name": "jankhunt42", "version": VERSION,
                                "informationUri": "https://github.com/anomalyco/opencode",
                                "rules": list(rules.values())}},
            "results": results,
        }],
    }, indent=2, ensure_ascii=False)
