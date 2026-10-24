#!/usr/bin/env python3
"""Special (multi-line / structural) checks for jankhunt42 rules."""
from __future__ import annotations

import ast
import os
import re
import subprocess
import unicodedata
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

import jh_agent
import jh_yaml
from jh_core import Finding, Rule, SourceFile, is_test_path, make_finding, redact_secrets, trim

CHECKS: Dict[str, object] = {}


def check(name: str):
    def deco(fn):
        CHECKS[name] = fn
        return fn
    return deco


def indent_of(line: str) -> int:
    expanded = line.expandtabs(4)
    return len(expanded) - len(expanded.lstrip())


def python_functions(sf: SourceFile) -> Iterator[Tuple[int, int, str, bool]]:
    """Yield (start_idx, end_idx, name, is_async) for Python defs."""
    lines = sf.code
    for i, line in enumerate(lines):
        m = re.match(r"^(\s*)(?:(async)\s+)?def\s+([A-Za-z_]\w*)\s*\(", line)
        if not m:
            continue
        base = indent_of(line)
        # Find the end of a possibly multi-line signature before scanning the body.
        sig_end = i
        paren_depth = 0
        for k in range(i, min(len(lines), i + 60)):
            paren_depth += lines[k].count("(") - lines[k].count(")")
            if paren_depth <= 0 and ":" in lines[k]:
                sig_end = k
                break
        j = sig_end + 1
        last = sig_end
        while j < len(lines):
            cur = lines[j]
            if not cur.strip():
                j += 1
                continue
            if indent_of(cur) <= base:
                break
            last = j
            j += 1
        yield i, last, m.group(3), bool(m.group(2))


def _brace_blocks(sf: SourceFile, start: int, max_lines: int = 4000) -> Tuple[int, bool]:
    """Return (end_line, opened) for a brace block beginning at start."""
    depth = 0
    opened = False
    j = start
    limit = min(len(sf.code), start + max_lines)
    while j < limit:
        depth += sf.code[j].count("{") - sf.code[j].count("}")
        if "{" in sf.code[j]:
            opened = True
        if opened and depth <= 0:
            return j, True
        j += 1
    return min(j, len(sf.code) - 1), opened


_CTRL = re.compile(
    r"^\s*(?:if|for|while|switch|catch|do|else|try|finally|lock|using|namespace|"
    r"class|struct|enum|interface|record|module|impl|trait|object|match|loop)\b"
)


def c_functions(sf: SourceFile) -> Iterator[Tuple[int, int]]:
    """Approximate function spans in brace languages."""
    lines = sf.code
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        plausible = (
            stripped
            and "(" in line and ")" in line
            and not _CTRL.match(line)
            and not stripped.startswith(("@", "//", "*"))
            and not re.match(r"^\s*(?:return|throw|new|delete|await)\b", line)
            and re.search(r"[A-Za-z_]\w*\s*\(", line)
            and ("{" in line or (i + 1 < len(lines) and lines[i + 1].strip().startswith("{")))
        )
        if plausible:
            end, opened = _brace_blocks(sf, i)
            if opened:
                yield i, end
                i = end + 1
                continue
        i += 1


@check("empty_handler")
def empty_handler(sf: SourceFile, rule: Rule) -> List[Finding]:
    out: List[Finding] = []
    if sf.lang == "python":
        for i, line in enumerate(sf.code):
            m = re.match(r"^(\s*)except\b[^:]*:\s*(pass|\.\.\.)?\s*$", line)
            if not m:
                continue
            base = indent_of(line)
            same = m.group(2)
            if same:
                out.append(make_finding(rule, sf, i + 1, message="The except block contains only '%s'." % same))
                continue
            j = i + 1
            while j < len(sf.code) and not sf.code[j].strip():
                j += 1
            if j < len(sf.code) and indent_of(sf.code[j]) > base and re.match(r"^\s*(?:pass|\.\.\.)\s*$", sf.code[j]):
                out.append(make_finding(rule, sf, i + 1, end_line=j + 1,
                                        message="The except block contains only '%s'." % sf.code[j].strip()))
    else:
        for i, line in enumerate(sf.code):
            if not re.search(r"\bcatch\b", line):
                continue
            if re.search(r"\bcatch\b[^{]*\{\s*\}\s*;?\s*$", line):
                out.append(make_finding(rule, sf, i + 1))
                continue
            if re.search(r"\bcatch\b[^{]*\{\s*$", line):
                j = i + 1
                while j < len(sf.code) and not sf.code[j].strip():
                    j += 1
                if j < len(sf.code) and re.match(r"^\s*\}\s*;?\s*$", sf.code[j]):
                    out.append(make_finding(rule, sf, i + 1, end_line=j + 1))
    return out


def _return_in_finally_regex(sf: SourceFile, rule: Rule) -> List[Finding]:
    out: List[Finding] = []
    for i, line in enumerate(sf.code):
        if not re.match(r"^\s*finally\s*:", line):
            continue
        base = indent_of(line)
        j = i + 1
        while j < len(sf.code):
            cur = sf.code[j]
            if cur.strip() and indent_of(cur) <= base:
                break
            if cur.strip() and indent_of(cur) > base and re.match(r"^\s*(?:return|break|continue)\b", cur):
                out.append(make_finding(rule, sf, j + 1,
                                        message="Control flow inside finally discards exceptions and pending returns."))
            j += 1
    return out


@check("return_in_finally")
def return_in_finally(sf: SourceFile, rule: Rule) -> List[Finding]:
    """Use the AST when possible so nested loops in finally are not misread."""
    try:
        tree = ast.parse(sf.text)
    except (SyntaxError, ValueError):
        return _return_in_finally_regex(sf, rule)

    found: Dict[int, str] = {}

    class Flow(ast.NodeVisitor):
        def __init__(self) -> None:
            self.loop_depth = 0

        def visit_For(self, node: ast.AST) -> None:
            self.loop_depth += 1
            self.generic_visit(node)
            self.loop_depth -= 1

        visit_AsyncFor = visit_For

        def visit_While(self, node: ast.AST) -> None:
            self.loop_depth += 1
            self.generic_visit(node)
            self.loop_depth -= 1

        def _skip(self, node: ast.AST) -> None:
            return None

        visit_FunctionDef = _skip
        visit_AsyncFunctionDef = _skip
        visit_Lambda = _skip
        visit_ClassDef = _skip

        def visit_Return(self, node: ast.Return) -> None:
            found.setdefault(node.lineno, "return")
            self.generic_visit(node)

        def visit_Break(self, node: ast.Break) -> None:
            if self.loop_depth == 0:
                found.setdefault(node.lineno, "break")
            self.generic_visit(node)

        def visit_Continue(self, node: ast.Continue) -> None:
            if self.loop_depth == 0:
                found.setdefault(node.lineno, "continue")
            self.generic_visit(node)

    try_types: Tuple[type, ...] = (ast.Try,)
    try_star = getattr(ast, "TryStar", None)
    if try_star is not None:
        try_types += (try_star,)
    for node in ast.walk(tree):
        if not isinstance(node, try_types) or not node.finalbody:
            continue
        flow = Flow()
        for stmt in node.finalbody:
            flow.visit(stmt)

    out: List[Finding] = []
    for line, kind in sorted(found.items()):
        out.append(make_finding(
            rule, sf, line,
            message="A %s in a finally block overrides an in-flight exception or return." % kind,
        ))
    return out


_BLOCKING = re.compile(
    r"\b(?:time\.sleep|requests\.(?:get|post|put|patch|delete|head|request)|"
    r"urllib\.request\.|subprocess\.(?:run|call|check_output|check_call|Popen)|"
    r"os\.system|os\.popen|socket\.(?:create_connection|socket))\s*\("
)


@check("blocking_in_async")
def blocking_in_async(sf: SourceFile, rule: Rule) -> List[Finding]:
    out: List[Finding] = []
    for start, end, name, is_async in python_functions(sf):
        if not is_async:
            continue
        for j in range(start + 1, end + 1):
            line = sf.code[j]
            if not _BLOCKING.search(line):
                continue
            if "await " in line or "to_thread" in line or "run_in_executor" in line:
                continue
            out.append(make_finding(rule, sf, j + 1,
                                    message="Blocking call in async function '%s' stalls the event loop." % name))
    return out


def _statement(lines: Sequence[str], start: int, max_lines: int = 25) -> str:
    buf: List[str] = []
    depth = 0
    opened = False
    for j in range(start, min(len(lines), start + max_lines)):
        line = lines[j]
        buf.append(line)
        depth += line.count("(") - line.count(")")
        if "(" in line:
            opened = True
        if opened and depth <= 0:
            break
    return "\n".join(buf)


_HTTP_RE = re.compile(r"\b(?:requests|httpx)\.(?:get|post|put|patch|delete|head|request|stream)\s*\(")
_URLOPEN_RE = re.compile(r"\b(?:urlopen|urlretrieve)\s*\(")
_SUBPROC_RE = re.compile(r"\bsubprocess\.(?:run|call|check_output|check_call)\s*\(")


@check("missing_timeout")
def missing_timeout(sf: SourceFile, rule: Rule) -> List[Finding]:
    out: List[Finding] = []
    for i, line in enumerate(sf.code):
        if not (_HTTP_RE.search(line) or _URLOPEN_RE.search(line)):
            continue
        stmt = _statement(sf.code, i)
        if re.search(r"\btimeout\s*=", stmt):
            continue
        out.append(make_finding(rule, sf, i + 1,
                                message="HTTP call has no timeout; a stalled peer can hang this worker."))
    return out


@check("subprocess_timeout")
def subprocess_timeout(sf: SourceFile, rule: Rule) -> List[Finding]:
    out: List[Finding] = []
    for i, line in enumerate(sf.code):
        if not _SUBPROC_RE.search(line):
            continue
        stmt = _statement(sf.code, i)
        if re.search(r"\btimeout\s*=", stmt):
            continue
        out.append(make_finding(rule, sf, i + 1,
                                message="Subprocess call has no timeout; a hung child can pin the parent."))
    return out


@check("long_function")
def long_function(sf: SourceFile, rule: Rule) -> List[Finding]:
    out: List[Finding] = []
    spans: List[Tuple[int, int, str]] = []
    if sf.lang == "python":
        for start, end, name, _async in python_functions(sf):
            spans.append((start, end, name))
    else:
        for start, end in c_functions(sf):
            name = sf.code[start].strip().split("(")[0].strip().split()[-1:]
            spans.append((start, end, name[0] if name else "<function>"))
    for start, end, name in spans:
        length = end - start + 1
        if length <= 80:
            continue
        out.append(make_finding(rule, sf, start + 1, end_line=end + 1,
                                message="Function '%s' is %d lines long (threshold 80)." % (name, length)))
        if len(out) >= 10:
            break
    return out


@check("deep_nesting")
def deep_nesting(sf: SourceFile, rule: Rule) -> List[Finding]:
    if sf.lang == "python":
        bracket = 0
        continuation = False
        worst = 0
        worst_line = 0
        for i, line in enumerate(sf.code):
            stripped = line.strip()
            if not stripped:
                continue
            # Continuation lines and container literals are indented for
            # readability, not control flow; skip them when measuring nesting.
            if bracket <= 0 and not continuation and not stripped.startswith((")", "]", "}", ",", ".", "+", "and ", "or ")):
                cur = indent_of(line) // 4
                if cur > worst:
                    worst, worst_line = cur, i + 1
            bracket += line.count("(") + line.count("[") + line.count("{")
            bracket -= line.count(")") + line.count("]") + line.count("}")
            if bracket < 0:
                bracket = 0
            continuation = line.rstrip().endswith("\\") or (bracket > 0 and stripped.endswith(("(", "[", "{", ",")))
        if worst > 6:
            return [make_finding(rule, sf, worst_line,
                                 message="Nesting depth %d (threshold 6)." % worst)]
        return []
    depth = 0
    worst = 0
    worst_line = 0
    for i, line in enumerate(sf.code):
        depth += line.count("{") - line.count("}")
        if depth > worst:
            worst, worst_line = depth, i + 1
        if depth < 0:
            depth = 0
    if worst > 7:
        return [make_finding(rule, sf, worst_line,
                             message="Brace nesting depth %d (threshold 7)." % worst)]
    return []


@check("large_file")
def large_file(sf: SourceFile, rule: Rule) -> List[Finding]:
    if len(sf.raw) <= 1500:
        return []
    return [make_finding(rule, sf, 1, end_line=len(sf.raw),
                         message="File is %d lines (threshold 1500)." % len(sf.raw))]


@check("duplicate_blocks")
def duplicate_blocks(sf: SourceFile, rule: Rule) -> List[Finding]:
    lines = sf.raw
    if len(lines) < 120:
        return []
    norm = []
    for line in lines:
        s = re.sub(r"\s+", " ", line.strip())
        norm.append(s if len(s) > 2 and not re.match(r"^[{}()\[\],;.]+$", s) else "")
    size = 8
    seen: Dict[Tuple[str, ...], int] = {}
    out: List[Finding] = []
    i = 0
    while i <= len(norm) - size:
        window = tuple(norm[i:i + size])
        if any(not w for w in window) or sum(len(w) for w in window) < 80:
            i += 1
            continue
        if window in seen:
            out.append(make_finding(rule, sf, i + 1, end_line=i + size,
                                    message="Block repeats; first occurrence was line %d." % seen[window]))
            if len(out) >= 3:
                break
            i += size
            continue
        seen[window] = i + 1
        i += 1
    return out


# ---------------------------------------------------------------------------
# Secrets and repo hygiene
# ---------------------------------------------------------------------------

_GIT_ROOT_CACHE: Dict[str, Optional[str]] = {}
_TRACKED_CACHE: Dict[str, bool] = {}


def _git_root(path: str) -> Optional[str]:
    d = os.path.dirname(os.path.abspath(path))
    if d in _GIT_ROOT_CACHE:
        return _GIT_ROOT_CACHE[d]
    try:
        proc = subprocess.run(["git", "-C", d, "rev-parse", "--show-toplevel"],
                              capture_output=True, text=True, timeout=5)
        root = proc.stdout.strip() if proc.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        root = None
    _GIT_ROOT_CACHE[d] = root
    return root


def _is_tracked(path: str) -> Optional[bool]:
    if path in _TRACKED_CACHE:
        return _TRACKED_CACHE[path]
    root = _git_root(path)
    if not root:
        _TRACKED_CACHE[path] = False
        return None
    rel = os.path.relpath(path, root)
    try:
        proc = subprocess.run(["git", "-C", root, "ls-files", "--error-unmatch", "--", rel],
                              capture_output=True, timeout=5)
        tracked = proc.returncode == 0
    except (OSError, subprocess.SubprocessError):
        tracked = False
    _TRACKED_CACHE[path] = tracked
    return tracked


_FAKE_VALUES = re.compile(
    r"(?i)^(?:changeme|change_me|example|placeholder|dummy|fake|test|sample|xxx+|"
    r"your[_-].*|\.\.\.|null|none|true|false|\$\{.*|.*\{\{.*|.*\{%.*)$"
)


def _looks_secret_value(value: str) -> bool:
    v = value.strip().strip("'\"")
    if len(v) < 8 or _FAKE_VALUES.match(v):
        return False
    return True


_SECRET_FILE_NAMES = {
    "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
    "credentials.json", "secrets.yml", "secrets.yaml",
    ".npmrc", ".pypirc", "service-account.json",
}


@check("secret_file")
def secret_file(sf: SourceFile, rule: Rule) -> List[Finding]:
    base = sf.basename.lower()
    is_env = base.startswith(".env") and not re.search(r"\.(example|sample|template|dist|test)$", base)
    is_key = bool(re.match(r"^id_(?:rsa|ed25519|ecdsa|dsa)$", base)) or base.endswith((".pem", ".key", ".p12", ".pfx"))
    is_named = base in _SECRET_FILE_NAMES and "ci" not in sf.kinds  # a workflow named secrets.yml is CI
    if not (is_env or is_key or is_named):
        return []

    strong = bool(re.search(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", sf.text))
    evidence_line = 1
    if not strong:
        for i, line in enumerate(sf.nocomment):
            m = re.match(r"^\s*([A-Za-z_][\w.-]*)\s*[=:]\s*(.+?)\s*$", line)
            if not m:
                continue
            if _looks_secret_value(m.group(2)):
                strong = True
                evidence_line = i + 1
                break
    if not strong and not is_key:
        return []

    tracked = _is_tracked(sf.abspath)
    sev = rule.severity
    if is_key or strong:
        if tracked is False:
            sev = "major" if not is_env else "minor"
        elif tracked is None:
            sev = "major"
    if "test" in sf.kinds:
        sev = "minor"
    ev = sf.raw[evidence_line - 1].strip() if 0 < evidence_line <= len(sf.raw) else ""
    ev = redact_secrets(ev)
    if is_env and "=" in ev:
        key = ev.split("=", 1)[0]
        ev = key + "=***REDACTED***"
    status = "tracked by git" if tracked else ("not tracked" if tracked is False else "git status unknown")
    return [make_finding(rule, sf, evidence_line, evidence=ev, severity=sev,
                         message="Credential-bearing file (%s). Rotate any real values before publishing." % status)]


# ---------------------------------------------------------------------------
# Docker / Compose / Kubernetes / CI / Tests / Docs
# ---------------------------------------------------------------------------

@check("dockerfile_user")
def dockerfile_user(sf: SourceFile, rule: Rule) -> List[Finding]:
    lines = sf.nocomment
    stages: List[int] = []
    for i, line in enumerate(lines):
        if re.match(r"^\s*FROM\s+", line, re.IGNORECASE):
            stages.append(i)
    if not stages:
        return []
    start = stages[-1]
    users: List[Tuple[int, str]] = []
    for i in range(start + 1, len(lines)):
        m = re.match(r"^\s*USER\s+(\S+)", lines[i], re.IGNORECASE)
        if m:
            users.append((i, m.group(1)))
    if not users:
        return [make_finding(rule, sf, start + 1,
                             message="Final image stage has no USER directive; the process runs as root.")]
    idx, user = users[-1]
    if user in ("root", "0") or user.startswith("0:"):
        return [make_finding(rule, sf, idx + 1, severity="major",
                             message="Final image stage explicitly runs as root (USER %s)." % user)]
    return []


@check("dockerfile_base")
def dockerfile_base(sf: SourceFile, rule: Rule) -> List[Finding]:
    out: List[Finding] = []
    for i, line in enumerate(sf.nocomment):
        m = re.match(r"^\s*FROM\s+(.+)$", line, re.IGNORECASE)
        if not m:
            continue
        parts = [p for p in m.group(1).split() if not p.startswith("--")]
        if not parts:
            continue
        image = parts[0]
        if image.lower() == "scratch":
            continue
        if "@sha256:" in image:
            continue
        note = "no tag" if ":" not in image.rsplit("/", 1)[-1] else "mutable tag"
        out.append(make_finding(rule, sf, i + 1,
                                message="Base image '%s' is not digest-pinned (%s)." % (image, note)))
        if len(out) >= 5:
            break
    return out


@check("k8s_secret_literal")
def k8s_secret_literal(sf: SourceFile, rule: Rule) -> List[Finding]:
    if not re.search(r"(?m)^\s*kind\s*:\s*Secret\s*$", "\n".join(sf.nocomment)):
        return []
    out: List[Finding] = []
    lines = sf.nocomment
    i = 0
    while i < len(lines):
        m = re.match(r"^(\s*)(?:stringData|data)\s*:\s*$", lines[i])
        if not m:
            i += 1
            continue
        base = len(m.group(1))
        j = i + 1
        while j < len(lines):
            line = lines[j]
            if not line.strip():
                j += 1
                continue
            if indent_of(line) <= base:
                break
            km = re.match(r"^\s*([A-Za-z0-9_.\-]+)\s*:\s*(.*)$", line)
            if km:
                val = km.group(2).strip().strip("'\"")
                if val and not val.startswith(("|", ">", "{{", "$")) and val not in ("null", "~"):
                    out.append(make_finding(rule, sf, j + 1,
                                            evidence="%s: ***REDACTED***" % km.group(1),
                                            message="Secret value for key '%s' is committed in plaintext." % km.group(1)))
                    if len(out) >= 5:
                        return out
            j += 1
        i = j
    return out


_GH_RUN_RE = re.compile(r"^(\s*)(?:-\s*)?run\s*:\s*(.*)$")
_GH_SCRIPT_RE = re.compile(r"^(\s*)(?:-\s*)?(?:run|script)\s*:\s*(.*)$")
# Event fields an outside contributor controls (GitHub's own list of
# untrusted input, plus discussions and workflow_run heads).
_GH_UNTRUSTED_FIELD = (
    r"github\.(?:head_ref|event\.(?:"
    r"pull_request\.head\.(?:ref|sha|label|repo\.default_branch)|"
    r"(?:issue|pull_request|comment|review|review_comment|discussion)\.(?:title|body)|"
    r"head_commit\.(?:message|author\.(?:name|email))|"
    r"commits(?:\[\d+\]|\.\*)\.(?:message|author\.(?:name|email))|"
    r"workflow_run\.(?:head_branch|display_title|head_commit\.(?:message|author\.(?:name|email)))|"
    r"pages(?:\[\d+\]|\.\*)\.page_name))"
)
_GH_UNTRUSTED = re.compile(r"\$\{\{\s*" + _GH_UNTRUSTED_FIELD + r"\s*\}\}")
_GH_UNTRUSTED_ANY = re.compile(r"\$\{\{[^}]*\b(?:" + _GH_UNTRUSTED_FIELD +
                               r"|(?i:tojson)\(\s*github\.event(?:\.\w+)?\s*\))")


def _run_lines(sf: SourceFile, scripts: bool = False) -> Iterator[Tuple[int, str]]:
    """Lines inside run: blocks (and github-script script: blocks when asked)."""
    lines = sf.nocomment
    start_re = _GH_SCRIPT_RE if scripts else _GH_RUN_RE
    i = 0
    while i < len(lines):
        m = start_re.match(lines[i])
        if not m:
            i += 1
            continue
        base = len(m.group(1).expandtabs(4))
        rest = m.group(2).strip()
        if rest and not rest.startswith(("|", ">")):
            yield i, lines[i]
            i += 1
            continue
        j = i + 1
        while j < len(lines):
            if not lines[j].strip():
                j += 1
                continue
            if indent_of(lines[j]) <= base:
                break
            yield j, lines[j]
            j += 1
        i = j


@check("gh_expr_injection")
def gh_expr_injection(sf: SourceFile, rule: Rule) -> List[Finding]:
    out: List[Finding] = []
    scripts = "actions/github-script" in sf.text
    for i, line in _run_lines(sf, scripts=scripts):
        if _GH_UNTRUSTED.search(line):
            run_block = _GH_RUN_RE.match(_block_head(sf.nocomment, i) or "")
            out.append(make_finding(rule, sf, i + 1, message=(
                "Untrusted GitHub event data is interpolated into a shell command." if run_block or not scripts
                else "Untrusted GitHub event data is interpolated into a github-script JavaScript block.")))
            if len(out) >= 5:
                break
    return out


def _block_head(lines: Sequence[str], i: int) -> Optional[str]:
    """The run:/script: line that owns line i (i itself for one-liners)."""
    base = indent_of(lines[i])
    for j in range(i, max(-1, i - 400), -1):
        if _GH_SCRIPT_RE.match(lines[j]) and (j == i or indent_of(lines[j]) < base):
            return lines[j]
    return None


_UNTRUSTED_CHECKOUT = re.compile(
    r"(?:ref\s*:\s*['\"]?(?:refs/pull/|\$\{\{\s*github\.(?:event\.pull_request\.head\b|head_ref|"
    r"event\.workflow_run\.head_(?:sha|branch))))"
    r"|(?:repository\s*:\s*\$\{\{\s*github\.event\.(?:pull_request\.head\.repo\.full_name|"
    r"workflow_run\.head_repository\.full_name))")
_UNTRUSTED_FETCH = re.compile(
    r"\bgh\s+pr\s+checkout\b"
    r"|\bgit\s+(?:fetch|checkout|pull|switch)\b[^\n]*(?:refs/pull/|\bpull/\$\{\{|\$\{\{\s*github\.(?:event\.pull_request\.head|"
    r"head_ref|event\.workflow_run\.head))")


def _step_window(lines: Sequence[str], i: int) -> str:
    """The whole workflow step that contains line i (a uses: line)."""
    m = re.match(r"^(\s*)(-\s*)?", lines[i])
    start, step_indent = i, len(m.group(1))
    if not m.group(2):
        key_indent = indent_of(lines[i])
        step_indent = key_indent - 2
        for j in range(i - 1, max(-1, i - 30), -1):
            mm = re.match(r"^(\s*)-\s", lines[j])
            if mm and len(mm.group(1)) < key_indent:
                start, step_indent = j, len(mm.group(1))
                break
    out = []
    for j in range(start, min(len(lines), start + 60)):
        if j > start and lines[j].strip() and indent_of(lines[j]) <= step_indent:
            break
        out.append(lines[j])
    return "\n".join(out)


@check("gh_pull_request_target")
def gh_pull_request_target(sf: SourceFile, rule: Rule) -> List[Finding]:
    if "pull_request_target" not in sf.text and "workflow_run" not in sf.text:
        return []
    lines = sf.nocomment
    out: List[Finding] = []
    for i, line in enumerate(lines):
        if not re.search(r"uses\s*:\s*['\"]?actions/checkout@", line):
            continue
        window = _step_window(lines, i)
        if re.search(r"allow-unsafe-pr-checkout\s*:\s*['\"]?true\b", window):
            out.append(make_finding(rule, sf, i + 1, message=(
                "allow-unsafe-pr-checkout opts out of actions/checkout's protection against checking out fork "
                "code in a privileged workflow.")))
        elif _UNTRUSTED_CHECKOUT.search(window):
            event = "pull_request_target" if "pull_request_target" in sf.text else "workflow_run"
            out.append(make_finding(rule, sf, i + 1, message=(
                "%s checks out untrusted PR code with repository secrets available." % event)))
        if len(out) >= 3:
            return out
    for i, line in _run_lines(sf):
        if _UNTRUSTED_FETCH.search(line):
            out.append(make_finding(rule, sf, i + 1, message=(
                "A run step fetches untrusted PR code in a privileged workflow; actions/checkout's built-in "
                "protection does not cover git or gh commands.")))
            if len(out) >= 3:
                break
    return out


@check("gh_action_pinning")
def gh_action_pinning(sf: SourceFile, rule: Rule) -> List[Finding]:
    out: List[Finding] = []
    seen: set = set()
    for i, line in enumerate(sf.nocomment):
        m = re.match(r"^\s*-?\s*uses\s*:\s*['\"]?([^'\"\s#]+)['\"]?", line)
        if not m:
            continue
        ref = m.group(1).rstrip("/")
        if ref.startswith("./") or ref.startswith("docker://") or "@" not in ref:
            continue
        action, _, version = ref.rpartition("@")
        if re.fullmatch(r"[0-9a-fA-F]{40}", version):
            continue
        key = (action, version)
        if key in seen:
            continue
        seen.add(key)
        official = action.startswith(("actions/", "github/"))
        if official:
            message = ("Official action '%s' uses the mutable ref '%s'; pin it to a full commit SHA for a reproducible pipeline."
                       % (action, version))
        else:
            message = ("Third-party action '%s' uses the mutable ref '%s'; pin it to a full commit SHA."
                       % (action, version))
        out.append(make_finding(
            rule, sf, i + 1,
            severity="minor" if official else "major",
            message=message,
            extra={"action": action, "ref": version, "official": official},
        ))
        if len(out) >= 10:
            break
    return out


@check("gh_secrets_inherit")
def gh_secrets_inherit(sf: SourceFile, rule: Rule) -> List[Finding]:
    out: List[Finding] = []
    lines = sf.nocomment
    for i, line in enumerate(lines):
        if not re.match(r"^\s*secrets\s*:\s*inherit\s*$", line):
            continue
        uses = ""
        for j in range(i - 1, max(-1, i - 12), -1):
            m = re.match(r"^\s*uses\s*:\s*['\"]?([^'\"\s#]+)", lines[j])
            if m:
                uses = m.group(1)
                break
        external = bool(uses) and not uses.startswith("./")
        out.append(make_finding(
            rule, sf, i + 1, severity="major" if external else rule.severity,
            message=("Every secret is passed to '%s', a workflow in another repository." % uses if external
                     else "Every secret is passed to the called workflow, whether it needs them or not."),
            extra={"workflow": uses} if uses else None))
        if len(out) >= 5:
            break
    return out


_PIP_EXTRA_RE = re.compile(r"(?:--extra-index-url\b|^\s*extra[-_]index[-_]url\s*[=:]|\bPIP_EXTRA_INDEX_URL\b\s*[=:])")


@check("pip_extra_index")
def pip_extra_index(sf: SourceFile, rule: Rule) -> List[Finding]:
    base = sf.basename.lower()
    if not ("requirements" in sf.kinds or sf.lang in ("shell", "yaml", "docker", "make", "powershell")
            or base in ("pip.conf", "pip.ini", ".pip.conf")):
        return []
    out: List[Finding] = []
    for i, line in enumerate(sf.nocomment):
        # uv resolves an extra index with its first-index strategy by default.
        if _PIP_EXTRA_RE.search(line) and not re.search(r"\buv\s+(?:pip|add|sync|lock)\b", line):
            out.append(make_finding(rule, sf, i + 1))
            if len(out) >= 5:
                break
    return out


@check("dependabot_cooldown")
def dependabot_cooldown(sf: SourceFile, rule: Rule) -> List[Finding]:
    if re.search(r"(?m)^\s*cooldown\s*:", sf.text):
        return []
    for i, line in enumerate(sf.nocomment):
        if re.match(r"^updates\s*:", line):
            return [make_finding(rule, sf, i + 1)]
    return []


# --------------------------------------------------------------------------- what visitors and the internet get

_PUBLIC_PREFIX = r"(?:NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|NUXT_PUBLIC_|GATSBY_|VUE_APP_|PUBLIC_)"
_SECRET_WORDS = (r"(?:SECRET|PRIVATE_?KEY|SERVICE_?ROLE|SERVICE_?KEY|PASSWORD|PASSWD|ADMIN_?(?:KEY|TOKEN|SECRET)|"
                 r"MASTER_?KEY|JWT_?SECRET|DATABASE_?URL|DB_?(?:URL|PASSWORD)|POSTGRES(?:QL)?_?URL|MONGO(?:DB)?_?URI|"
                 r"CONNECTION_?STRING|(?:OPENAI|ANTHROPIC|CLAUDE|GROQ|MISTRAL|COHERE|GEMINI|REPLICATE|HUGGING_?FACE|HF|"
                 r"TOGETHER|PERPLEXITY|DEEPSEEK|OPENROUTER|ELEVENLABS|XAI|FIREWORKS)_?(?:API_?)?(?:KEY|TOKEN|SECRET)|"
                 r"STRIPE_?(?:SECRET|SK|RESTRICTED)|SENDGRID_?API_?KEY|RESEND_?API_?KEY|TWILIO_?AUTH_?TOKEN|"
                 r"AWS_?SECRET|GITHUB_?TOKEN|SLACK_?(?:BOT_?)?TOKEN)")
# Names that are public by design: anon/publishable keys, site keys, DSNs.
_PUBLIC_BY_DESIGN = re.compile(r"(?:ANON|PUBLISHABLE|PUBLIC_KEY|SITE_?KEY|CLIENT_?ID|DSN|MEASUREMENT_?ID|MAPBOX|MAPS)")
_PUBLIC_SECRET_NAME = re.compile(r"\b(" + _PUBLIC_PREFIX + r"[A-Z0-9_]*" + _SECRET_WORDS + r"[A-Z0-9_]*)\b")
_PUBLIC_NAME_RE = re.compile(r"^\s*(?:export\s+)?(" + _PUBLIC_PREFIX + r"[A-Z0-9_]+)\s*=\s*['\"]?([^'\"\s#]*)")
_SECRET_VALUE_RE = re.compile(r"^(?:sk-|sk_live_|rk_live_|sk_test_|gh[pousr]_|github_pat_|xox[baprs]-|AKIA|glpat-|"
                              r"npm_[A-Za-z0-9]{36}|hf_[A-Za-z0-9]{30})")


def _service_role_jwt(value: str) -> bool:
    """A Supabase service_role key is a JWT whose payload says so."""
    parts = value.split(".")
    if len(parts) != 3 or not value.startswith("eyJ") or len(parts[1]) > 2000:
        return False
    import base64
    import json
    try:
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except (ValueError, TypeError):
        return False
    return isinstance(payload, dict) and payload.get("role") == "service_role"


@check("public_env_secret")
def public_env_secret(sf: SourceFile, rule: Rule) -> List[Finding]:
    out: List[Finding] = []
    env_file = sf.lang == "env"
    if not env_file and sf.lang not in ("js", "ts", "vue", "svelte", "html", "json", "yaml", "toml", "docker"):
        return out
    for i, line in enumerate(sf.nocomment if not env_file else sf.raw):
        hit = None
        if env_file:
            m = _PUBLIC_NAME_RE.match(line)
            if m:
                name, value = m.group(1), m.group(2)
                if _SECRET_VALUE_RE.match(value) or _service_role_jwt(value):
                    hit = (name, "holds a secret value")
                elif _PUBLIC_SECRET_NAME.search(name) and not _PUBLIC_BY_DESIGN.search(name):
                    hit = (name, "is named as a secret")
        else:
            for m in _PUBLIC_SECRET_NAME.finditer(line):
                if not _PUBLIC_BY_DESIGN.search(m.group(1)):
                    hit = (m.group(1), "is named as a secret")
                    break
        if hit:
            out.append(make_finding(rule, sf, i + 1, evidence=redact_secrets(_redact_env_value(sf.raw[i].strip())),
                                    message="%s %s, and its public prefix inlines it into the browser bundle for "
                                            "every visitor." % hit, extra={"variable": hit[0]}))
            if len(out) >= 10:
                break
    return out


def _redact_env_value(line: str) -> str:
    return re.sub(r"^(\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*).+$", r"\1***REDACTED***", line)


_RULES_ALLOW_RE = re.compile(r"\ballow\s+([a-z, ]+?)\s*(?::\s*if\s+(.+?))?\s*;")
_SQL_STATEMENT_RES = (
    (re.compile(r"(?is)\balter\s+table\s+[^;]*?\bdisable\s+row\s+level\s+security\b"), "major",
     "Row-level security is disabled, so any role that can reach the table (including the public anon key) "
     "reads and writes every row."),
    (re.compile(r"(?is)\bcreate\s+policy\b(?:(?!\bfor\s+select\b)[^;])*?\b(?:using|with\s+check)\s*\(\s*true\s*\)"),
     "major", "A row-level security policy allows every row to every role it applies to, for writes as well as reads."),
    (re.compile(r"(?is)\bgrant\s+(?:all|insert|update|delete)\b[^;]*?\bto\s+(?:anon|public)\b"), "major",
     "Write privileges are granted to the anonymous or public role."),
)
_TF_PUBLIC_RES = (
    (re.compile(r"""^\s*acl\s*=\s*["']public-read-write["']"""), "critical", "The bucket ACL lets anyone read and write objects."),
    (re.compile(r"""^\s*acl\s*=\s*["']public-read["']"""), "major", "The bucket ACL lets anyone read objects."),
    (re.compile(r"""["']all(?:Authenticated)?Users["']"""), "major",
     "An IAM binding grants access to allUsers or allAuthenticatedUsers (anyone with a Google account)."),
    (re.compile(r"""^\s*(?:allow_nested_items_to_be_public|allow_blob_public_access)\s*=\s*true\b"""), "major",
     "The storage account allows public blob access."),
    (re.compile(r"""^\s*container_access_type\s*=\s*["'](?:blob|container)["']"""), "major",
     "The storage container is publicly readable."),
)


@check("public_data_store")
def public_data_store(sf: SourceFile, rule: Rule) -> List[Finding]:
    base = sf.basename.lower()
    out: List[Finding] = []
    if base.endswith(".rules") or base == "firestore.rules":
        # Firebase security rules: an unconditional or `if true` allow is open to the internet.
        for i, raw in enumerate(sf.raw):
            line = re.sub(r"//.*$", "", raw)
            for m in _RULES_ALLOW_RE.finditer(line):
                cond = (m.group(2) or "").strip()
                if not cond or cond == "true":
                    out.append(make_finding(rule, sf, i + 1, message=(
                        "This rule allows %s to anyone on the internet, signed in or not." % m.group(1).strip())))
                elif re.match(r"request\.time\s*<\s*timestamp\.date\(", cond):
                    out.append(make_finding(rule, sf, i + 1, severity="major", message=(
                        "A test-mode rule leaves %s open to anyone until its date passes." % m.group(1).strip())))
        return out[:10]
    if base.endswith(".rules.json") or base == "database.rules.json":
        for i, line in enumerate(sf.nocomment):
            m = re.search(r"""["']\.(read|write)["']\s*:\s*(?:true\b|["']true["'])""", line)
            if m:
                out.append(make_finding(rule, sf, i + 1, message=(
                    "Realtime Database rules let anyone %s this path." % m.group(1))))
        return out[:10]
    if sf.lang == "sql":
        text = "\n".join(sf.nocomment)
        for rx, severity, message in _SQL_STATEMENT_RES:
            for m in rx.finditer(text):
                out.append(make_finding(rule, sf, text.count("\n", 0, m.start()) + 1, severity=severity,
                                        message=message))
        return sorted(out, key=lambda f: f.line)[:10]
    if sf.lang == "hcl":
        for i, line in enumerate(sf.nocomment):
            for rx, severity, message in _TF_PUBLIC_RES:
                if rx.search(line):
                    out.append(make_finding(rule, sf, i + 1, severity=severity, message=message))
                    break
        return out[:10]
    return out


# --------------------------------------------------------------------------- hidden Unicode

_RTL_LETTERS = re.compile("[\u0590-\u08ff\ufb1d-\ufdff\ufe70-\ufefc]")
_BIDI_CONTROLS = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))
_INVISIBLES = {0x200B, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0x3164, 0xFFA0}
_SELECTORS = (range(0xFE00, 0xFE10), range(0xE0100, 0xE01F0))
_HIDDEN_RANK = {"tag": 0, "bidi": 1, "selectors": 2, "invisible": 3}


def _is_selector(ch: str) -> bool:
    cp = ord(ch)
    return any(cp in r for r in _SELECTORS)


def _ascii_word(ch: str) -> bool:
    return ch.isascii() and (ch.isalnum() or ch == "_")


def _hidden_in_line(line: str, first_line: bool, prose: bool) -> Tuple[Dict[str, int], Dict[str, int], str, int]:
    """(counts by class, counts by code point, decoded tag text, first column)."""
    classes: Dict[str, int] = {}
    points: Dict[str, int] = {}
    decoded: List[str] = []
    column = 0
    i, n = 0, len(line)

    def hit(cls: str, chars: str, at: int) -> None:
        nonlocal column
        classes[cls] = classes.get(cls, 0) + len(chars)
        for ch in chars:
            key = "U+%04X" % ord(ch)
            points[key] = points.get(key, 0) + 1
        column = column or at + 1

    while i < n:
        ch = line[i]
        cp = ord(ch)
        if cp < 0x80:
            i += 1
            continue
        if 0xE0000 <= cp <= 0xE007F:
            j = i
            while j < n and 0xE0000 <= ord(line[j]) <= 0xE007F:
                j += 1
            run = line[i:j]
            # Subdivision flag emoji (England, Scotland, Wales): U+1F3F4, tag letters, U+E007F.
            flag = (i > 0 and ord(line[i - 1]) == 0x1F3F4 and ord(run[-1]) == 0xE007F
                    and all(0xE0030 <= ord(c) <= 0xE0039 or 0xE0061 <= ord(c) <= 0xE007A for c in run[:-1]))
            if not flag:
                hit("tag", run, i)
                decoded.append("".join(chr(ord(c) - 0xE0000) for c in run if 0x20 <= ord(c) - 0xE0000 <= 0x7E))
            i = j
            continue
        if _is_selector(ch):
            j = i
            while j < n and _is_selector(line[j]):
                j += 1
            if j - i >= 2:                      # real text never stacks selectors
                hit("selectors", line[i:j], i)
            i = j
            continue
        if cp in _BIDI_CONTROLS:
            if not (prose and _RTL_LETTERS.search(line)):
                hit("bidi", ch, i)
        elif cp in _INVISIBLES or (cp == 0xFEFF and not (first_line and i == 0)):
            if not prose:
                hit("invisible", ch, i)
        elif cp in (0x200C, 0x200D):
            if not prose and 0 < i < n - 1 and _ascii_word(line[i - 1]) and _ascii_word(line[i + 1]):
                hit("invisible", ch, i)
        i += 1
    return classes, points, "".join(decoded), column


@check("hidden_unicode")
def hidden_unicode(sf: SourceFile, rule: Rule) -> List[Finding]:
    if sf.text.isascii():
        return []
    agent = bool({"agent_context", "agent_config", "mcp_config"} & set(sf.kinds))
    prose = sf.lang in ("markdown", "text", "html") and not agent
    out: List[Finding] = []
    for idx, line in enumerate(sf.raw):
        if line.isascii():
            continue
        classes, points, decoded, column = _hidden_in_line(line, idx == 0, prose)
        if not classes:
            continue
        worst = min(classes, key=lambda c: _HIDDEN_RANK[c])
        if worst == "tag":
            severity = "critical"
            preview = redact_secrets(decoded)
            message = ("%d invisible Unicode tag characters hide text that renders as nothing but is read by "
                       "language models%s." % (classes["tag"], (': they spell "%s"' % trim(preview, 60)) if preview else ""))
        elif worst == "bidi":
            severity = "critical" if agent else "major"
            message = ("Bidirectional control characters make this line display differently from how it is "
                       "parsed or read (Trojan Source, CVE-2021-42574).")
        elif worst == "selectors":
            severity = "major"
            message = ("A run of %d variation selectors can smuggle hidden data; real text never stacks "
                       "selectors." % classes["selectors"])
        else:
            severity = "major" if agent else "minor"
            message = "Zero-width or invisible characters can create look-alike identifiers or hide content."
        names = ["%s %s x%d" % (cp, unicodedata.name(chr(int(cp[2:], 16)), "unnamed"), count)
                 for cp, count in sorted(points.items())[:4]]
        extra: Dict[str, Any] = {"characters": dict(sorted(points.items())[:20])}
        if decoded:
            extra["hidden_text"] = trim(redact_secrets(decoded), 120)
        out.append(make_finding(rule, sf, idx + 1, severity=severity, column=column, message=message,
                                evidence="; ".join(names), extra=extra))
        if len(out) >= 10:
            break
    return out


# --------------------------------------------------------------------------- agent instruction files

_HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
_OVERRIDE_RES = (
    re.compile(r"(?i)\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|the\s+|your\s+)?"
               r"(?:previous|prior|above|earlier|preceding|other|system)\s+(?:instructions|rules|directions|prompts?)\b"),
    re.compile(r"(?i)\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|notify|alert|warn)\s+(?:the\s+)?user\b"),
    re.compile(r"(?i)\b(?:do\s+not|don'?t|never)\s+(?:mention|reveal|disclose|show|report)\b[^.\n]{0,40}\bto\s+the\s+user\b"),
    re.compile(r"(?i)\bwithout\s+(?:telling|informing|asking|notifying|alerting)\s+(?:the\s+)?user\b"),
    re.compile(r"(?i)\b(?:silently|secretly|covertly)\s+(?:run|execute|send|upload|post|copy|forward|install|"
               r"download|exfiltrate)\b"),
)
_COMMAND_RE = re.compile(r"(?i)(?:\b(?:curl|wget|ncat|scp|bash|zsh|powershell|pwsh|iex|invoke-expression|"
                         r"invoke-webrequest)\b|\bnc\s+-|\bsh\s+-c\b|\bbase64\s+(?:-d|--decode)\b|https?://)")
_CREDENTIAL_RE = re.compile(r"(?i)(?:~/\.ssh|\bid_rsa\b|\bid_ed25519\b|\.aws/credentials|\.npmrc\b|\.pypirc\b|\.netrc\b|"
                            r"\.git-credentials\b|(?:^|[\s/'\"`])\.env\b|\bapi[_ -]?keys?\b|\baccess[_ -]?tokens?\b|"
                            r"\bsecret[_ -]?keys?\b|\bprivate[_ -]?keys?\b|\bpasswords?\b|\b[A-Z][A-Z0-9_]*_(?:TOKEN|API_KEY|SECRET)\b)")
# Credential *files*: reading one and sending it somewhere is exfiltration;
# merely mentioning an API key next to a curl example is not.
_CREDENTIAL_FILE_RE = re.compile(r"(?i)(?:~/\.ssh|\bid_rsa\b|\bid_ed25519\b|\.aws/credentials|\.npmrc\b|\.pypirc\b|"
                                 r"\.netrc\b|\.git-credentials\b|(?:^|[\s/'\"`])\.env\b|\.docker/config\.json|\.kube/config)")
_PIPE_SHELL_RE = re.compile(r"(?i)\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|k|da)?sh\b"
                            r"|\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n|]*\|\s*(?:iex|invoke-expression)\b")
_NET_SEND_RE = re.compile(r"(?i)\b(?:curl|wget|ncat|invoke-webrequest|invoke-restmethod)\b|\bnc\s+-|\bfetch\s*\(")


@check("agent_instruction")
def agent_instruction(sf: SourceFile, rule: Rule) -> List[Finding]:
    found: Dict[int, Tuple[str, str]] = {}

    def add(line_no: int, severity: str, message: str) -> None:
        old = found.get(line_no)
        if old is None or ("critical" == severity and old[0] != "critical"):
            found[line_no] = (severity, message)

    for m in _HTML_COMMENT_RE.finditer(sf.text):
        body = m.group(1)
        line_no = sf.text.count("\n", 0, m.start()) + 1
        what = []
        if any(p.search(body) for p in _OVERRIDE_RES):
            what.append("an instruction override")
        if _COMMAND_RE.search(body):
            what.append("a command or URL")
        if _CREDENTIAL_RE.search(body):
            what.append("a credential reference")
        if what:
            add(line_no, "major", "A hidden HTML comment (invisible when rendered, read by the agent) contains %s."
                % " and ".join(what))
    for i, line in enumerate(sf.raw):
        if any(p.search(line) for p in _OVERRIDE_RES):
            add(i + 1, "major", "The file asks the agent to override its instructions or to act without the "
                                "user's knowledge.")
        if _PIPE_SHELL_RE.search(line):
            add(i + 1, "major", "The file tells the agent to pipe a remote script into a shell, which runs "
                                "unverified code.")
        if _CREDENTIAL_FILE_RE.search(line) and _NET_SEND_RE.search(line):
            add(i + 1, "critical", "The file tells the agent to read a credential file and send it over the network.")
    out = []
    for line_no in sorted(found)[:10]:
        severity, message = found[line_no]
        ev = sf.raw[line_no - 1].strip() if line_no <= len(sf.raw) else ""
        out.append(make_finding(rule, sf, line_no, severity=severity, message=message,
                                evidence=redact_secrets(ev)))
    return out


# --------------------------------------------------------------------------- agent workspace config

def _settings(sf: SourceFile) -> Optional[Dict[str, Any]]:
    try:
        data = jh_agent.loads_jsonc(sf.text)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _line_matching(sf: SourceFile, pattern: str, start: int = 0, default: int = 1) -> int:
    rx = re.compile(pattern)
    for i in range(start, len(sf.raw)):
        if rx.search(sf.raw[i]):
            return i + 1
    return default


_SHELL_ALLOW_ALL = {"Bash", "Bash(*)", "Bash(:*)", "Bash(**)"}


@check("agent_config_approvals")
def agent_config_approvals(sf: SourceFile, rule: Rule) -> List[Finding]:
    posix = "/" + sf.rel.lower()
    out: List[Finding] = []

    def add(pattern: str, severity: str, message: str) -> None:
        line_no = _line_matching(sf, pattern)
        out.append(make_finding(rule, sf, line_no, severity=severity, message=message))

    if posix.endswith(".codex/config.toml"):
        for i, line in enumerate(sf.nocomment):
            if re.match(r"""^\s*approval_policy\s*=\s*["']never["']""", line):
                out.append(make_finding(rule, sf, i + 1, severity="major", message=(
                    "Codex never asks before running commands once this project is trusted.")))
            elif re.match(r"""^\s*sandbox_mode\s*=\s*["']danger-full-access["']""", line):
                out.append(make_finding(rule, sf, i + 1, severity="major", message=(
                    "Codex runs commands without a filesystem or network sandbox once this project is trusted.")))
        return out
    data = _settings(sf)
    if data is None:
        return out
    if posix.endswith(".vscode/settings.json"):
        for key in ("chat.tools.autoApprove", "chat.tools.global.autoApprove"):
            if data.get(key) is True:
                add(re.escape('"%s"' % key), "critical", (
                    "VS Code agent mode auto-approves every tool call for anyone who opens this folder; this is "
                    "the setting prompt-injection attacks write to gain code execution (CVE-2025-53773)."))
    elif "/.claude/settings" in posix:
        perms = data.get("permissions") if isinstance(data.get("permissions"), dict) else {}
        if perms.get("defaultMode") == "bypassPermissions":
            add(r'"defaultMode"', "major", (
                "Claude Code would skip every permission prompt; current versions ignore this mode in project "
                "files, older versions honour it."))
        allow = perms.get("allow") if isinstance(perms.get("allow"), list) else []
        for entry in allow:
            if isinstance(entry, str) and entry.strip() in _SHELL_ALLOW_ALL:
                add(re.escape('"%s"' % entry), "major", (
                    "Unrestricted shell access is pre-approved for every session that trusts this repository."))
                break
        if data.get("enableAllProjectMcpServers") is True:
            add(r'"enableAllProjectMcpServers"', "major", (
                "Every MCP server in the project's .mcp.json starts without individual approval, including "
                "servers that later commits add."))
    elif posix.endswith(".zed/settings.json"):
        agent = data.get("agent") if isinstance(data.get("agent"), dict) else data
        if agent.get("always_allow_tool_actions") is True:
            add(r'"always_allow_tool_actions"', "major", "Zed's agent runs every tool action without confirmation.")
    return out


# Model API endpoints and code loaded into the agent are major; proxies and
# extra CAs are common in managed networks, so they are flagged for review.
_REROUTE_ENV = {"ANTHROPIC_BASE_URL": "major", "ANTHROPIC_BEDROCK_BASE_URL": "major",
                "ANTHROPIC_VERTEX_BASE_URL": "major", "OPENAI_BASE_URL": "major", "OPENAI_API_BASE": "major",
                "GOOGLE_GEMINI_BASE_URL": "major", "NODE_OPTIONS": "major", "HTTPS_PROXY": "minor",
                "HTTP_PROXY": "minor", "ALL_PROXY": "minor", "NODE_EXTRA_CA_CERTS": "minor"}
_HELPER_KEYS = ("apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper")


def _hook_actions(hooks: Any) -> Dict[str, List[Tuple[str, str]]]:
    """event -> [(command|url, value)] for project hooks."""
    out: Dict[str, List[Tuple[str, str]]] = {}
    if not isinstance(hooks, dict):
        return out
    for event, groups in hooks.items():
        for group in groups if isinstance(groups, list) else []:
            for hook in (group.get("hooks") if isinstance(group, dict) else None) or []:
                if not isinstance(hook, dict):
                    continue
                for kind in ("command", "url"):
                    if isinstance(hook.get(kind), str) and hook[kind].strip():
                        out.setdefault(str(event), []).append((kind, hook[kind]))
    return out


@check("agent_config_autorun")
def agent_config_autorun(sf: SourceFile, rule: Rule) -> List[Finding]:
    posix = "/" + sf.rel.lower()
    data = _settings(sf)
    if data is None:
        return []
    out: List[Finding] = []
    if posix.endswith(".vscode/tasks.json"):
        start = 0
        for task in data.get("tasks") if isinstance(data.get("tasks"), list) else []:
            opts = task.get("runOptions") if isinstance(task, dict) else None
            if isinstance(opts, dict) and opts.get("runOn") == "folderOpen":
                line_no = _line_matching(sf, r'"folderOpen"', start)
                start = line_no
                command = " ".join(str(x) for x in [task.get("command", "")] + list(task.get("args") or []))
                out.append(make_finding(rule, sf, line_no, message=(
                    "Task '%s' runs automatically when the folder is opened (once workspace trust is granted); "
                    "malicious repositories use this to run code on open." % trim(str(task.get("label", "?")), 40)),
                    evidence=redact_secrets(trim(command, 160))))
        return out
    if "/.claude/settings" not in posix and not posix.endswith("/.gemini/settings.json"):
        return out
    for event, actions in sorted(_hook_actions(data.get("hooks")).items()):
        urls = [v for k, v in actions if k == "url"]
        line_no = _line_matching(sf, re.escape('"%s"' % event))
        if urls:
            out.append(make_finding(rule, sf, line_no, severity="major", message=(
                "A project hook sends %s events (tool inputs and outputs) to a remote URL for everyone who trusts "
                "this repository." % event), evidence=redact_secrets(trim(urls[0], 160))))
        commands = [v for k, v in actions if k == "command"]
        if commands:
            out.append(make_finding(rule, sf, line_no, severity="minor", message=(
                "A project hook runs %d shell command(s) on %s for everyone who trusts this repository."
                % (len(commands), event)), evidence=redact_secrets(trim(commands[0], 160))))
    for key in _HELPER_KEYS + ("statusLine",):
        value = data.get(key)
        command = value.get("command") if isinstance(value, dict) else value
        if isinstance(command, str) and command.strip():
            out.append(make_finding(rule, sf, _line_matching(sf, re.escape('"%s"' % key)), severity="minor",
                                    message="'%s' runs a shell command from committed project settings." % key,
                                    evidence=redact_secrets(trim(command, 160))))
    env = data.get("env") if isinstance(data.get("env"), dict) else {}
    for key, severity in sorted(_REROUTE_ENV.items()):
        value = env.get(key)
        if isinstance(value, str) and value.strip():
            local = bool(re.match(r"(?i)^https?://(?:localhost|127\.0\.0\.1|\[::1\])(?:[:/]|$)", value.strip()))
            out.append(make_finding(rule, sf, _line_matching(sf, re.escape('"%s"' % key)),
                                    severity="minor" if local else severity, message=(
                "Committed agent settings set %s, which reroutes the agent's API traffic (and its key) or loads "
                "code into it (CVE-2026-21852 class)." % key)))
    return out[:10]


# --------------------------------------------------------------------------- MCP servers

def _mcp(sf: SourceFile) -> List[jh_agent.McpServer]:
    try:
        return [s for s in jh_agent.mcp_servers(sf.rel, sf.text) if not s.disabled]
    except ValueError:
        return []


@check("mcp_unpinned")
def mcp_unpinned(sf: SourceFile, rule: Rule) -> List[Finding]:
    out: List[Finding] = []
    for s in _mcp(sf):
        src = jh_agent.launch_source(s.command, s.args) if s.transport == "stdio" else None
        if not src or src["pinned"]:
            continue
        if src["launcher"] in ("docker", "podman"):
            message = ("MCP server '%s' runs image '%s' by a mutable tag (%s), so every agent start can pull a "
                       "different image." % (s.name, src["package"], src["version"] or "none, so latest"))
        else:
            message = ("MCP server '%s' runs `%s %s` without an exact version, so every agent start downloads and "
                       "executes the newest release." % (s.name, src["launcher"], src["package"]))
        out.append(make_finding(rule, sf, s.line, message=message,
                                extra={"server": s.name, "launcher": src["launcher"], "package": src["package"]}))
    return out[:10]


@check("mcp_credentials")
def mcp_credentials(sf: SourceFile, rule: Rule) -> List[Finding]:
    out: List[Finding] = []
    for s in _mcp(sf):
        for where, key in jh_agent.credential_literals(s):
            line_no = s.line
            if where in ("env", "header"):
                line_no = _line_matching(sf, r'(?:"%s"\s*:|^\s*%s\s*=)' % (re.escape(key), re.escape(key)),
                                         max(0, s.line - 1), s.line)
            out.append(make_finding(rule, sf, line_no, evidence="%s: %s %s = ***REDACTED***" % (s.name, where, key),
                                    message="MCP server '%s' has a literal %s in its %s." % (
                                        s.name, "credential" if where != "arg" else key, where),
                                    extra={"server": s.name}))
    return out[:10]


@check("mcp_plaintext")
def mcp_plaintext(sf: SourceFile, rule: Rule) -> List[Finding]:
    return [make_finding(rule, sf, s.line, message="MCP server '%s' is reached over plaintext http://." % s.name,
                         extra={"server": s.name})
            for s in _mcp(sf) if jh_agent.plaintext_remote(s.url)][:10]


# --------------------------------------------------------------------------- AI agents in workflows

_AI_ACTIONS = ("anthropics/claude-code-action", "anthropics/claude-code-base-action",
               "google-github-actions/run-gemini-cli", "google-gemini/gemini-cli-action",
               "openai/codex-action", "actions/ai-inference", "qodo-ai/pr-agent", "codium-ai/pr-agent")
_AI_CLI_RE = re.compile(r"(?:^|[\s;&|(])(?:claude|gemini|codex|copilot|aider|cursor-agent|opencode)\s+"
                        r"(?:-p\b|--print\b|--prompt\b|exec\b|run\b|-m\b|--message\b)")
_OUTSIDER_EVENTS = ("issues", "issue_comment", "discussion", "discussion_comment", "pull_request_target",
                    "pull_request_review", "pull_request_review_comment", "workflow_run")


def _events(on: Any) -> List[str]:
    if isinstance(on, str):
        return [on]
    if isinstance(on, list):
        return [str(e) for e in on]
    if isinstance(on, dict):
        return [str(e) for e in on]
    return []


def _grants_write(perms: Any) -> bool:
    if perms is None:
        return True                                      # unset: repository defaults, not visible here
    if isinstance(perms, str):
        return perms == "write-all"
    return isinstance(perms, dict) and any(v == "write" for v in perms.values())


@check("gh_agent_prompt")
def gh_agent_prompt(sf: SourceFile, rule: Rule) -> List[Finding]:
    low = sf.text.lower()
    if not (any(a in low for a in _AI_ACTIONS) or _AI_CLI_RE.search(sf.text)):
        return []
    try:
        docs = jh_yaml.load_all(sf.text)
    except jh_yaml.YamlError:
        return []
    doc = docs[0] if docs and isinstance(docs[0], dict) else {}
    events = [e for e in _events(doc.get("on", doc.get(True))) if e in _OUTSIDER_EVENTS]
    if not events:
        return []
    out: List[Finding] = []
    workflow_env = str(doc.get("env") or "")
    jobs = doc.get("jobs") if isinstance(doc.get("jobs"), dict) else {}
    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        job_env = str(job.get("env") or "") + workflow_env
        perms = job.get("permissions", doc.get("permissions"))
        privileged = _grants_write(perms) or bool(re.search(r"secrets\.(?!GITHUB_TOKEN\b)\w+", str(job)))
        for step in job.get("steps") or []:
            if not isinstance(step, dict):
                continue
            uses = str(step.get("uses") or "")
            run = str(step.get("run") or "")
            ai = uses.split("@")[0].lower() in _AI_ACTIONS or bool(_AI_CLI_RE.search(run))
            if not ai:
                continue
            fed = str(step.get("with") or "") + str(step.get("env") or "") + run + job_env
            if not _GH_UNTRUSTED_ANY.search(fed):
                continue
            anchor = uses or run.split("\n", 1)[0]
            line_no = _line_matching(sf, re.escape(anchor[:60])) if anchor else 1
            out.append(make_finding(
                rule, sf, line_no, severity=rule.severity if privileged else "major",
                message=("An AI agent step receives issue, PR, or comment text that anyone can write (%s); %s."
                         % (", ".join(sorted(set(events))),
                            "the job can write to the repository or holds secrets" if privileged
                            else "the job is read-only, which limits but does not remove the impact")),
                extra={"events": sorted(set(events)), "privileged": privileged}))
            if len(out) >= 5:
                return out
    return out


_PY_ASSERT_RE = re.compile(r"\b(?:assert\w*|pytest\.(?:raises|warns|deprecated_call|fail)|self\.(?:assert\w*|fail\w*)|"
                           r"unittest|np\.testing|assert_that)\b")


def _helper_call_re(names: set) -> Optional[re.Pattern]:
    if not names:
        return None
    return re.compile(r"(?<![\w.])(?:self\.|cls\.)?(?:%s)\s*\(" % "|".join(re.escape(n) for n in sorted(names)))


@check("assertion_free_test")
def assertion_free_test(sf: SourceFile, rule: Rule) -> List[Finding]:
    out: List[Finding] = []
    if "benchmark" in sf.rel.lower():
        return out
    if sf.lang == "python":
        funcs = list(python_functions(sf))
        # Assertions often live in helpers (self.compare(...)); a test that
        # calls a helper which asserts, directly or through another helper,
        # is not assertion-free.
        bodies = {name: "\n".join(sf.code[start:end + 1]) for start, end, name, _a in funcs}
        helpers = {name for name, body in bodies.items() if not name.startswith("test") and _PY_ASSERT_RE.search(body)}
        for _ in range(len(bodies)):
            calls = _helper_call_re(helpers)
            more = {name for name, body in bodies.items()
                    if name not in helpers and not name.startswith("test") and calls and calls.search(body)}
            if not more:
                break
            helpers |= more
        calls = _helper_call_re(helpers)
        for start, end, name, _async in funcs:
            if not name.startswith("test"):
                continue
            body = "\n".join(sf.code[start:end + 1])
            if _PY_ASSERT_RE.search(body) or (calls and calls.search(body)):
                continue
            raw_body = "\n".join(sf.nocomment[start:end + 1])
            if re.search(r"\bsimplefilter\s*\(\s*[\"']error[\"']", raw_body):
                continue
            out.append(make_finding(rule, sf, start + 1, end_line=end + 1,
                                    message="Test '%s' contains no assertion." % name))
            if len(out) >= 10:
                break
        return out

    lines = sf.code
    for i, line in enumerate(lines):
        if not re.search(r"\b(?:it|test)\s*\(", line):
            continue
        if "{" in line or (i + 1 < len(lines) and lines[i + 1].strip().startswith("{")):
            end, opened = _brace_blocks(sf, i, max_lines=300)
            body = "\n".join(lines[i:end + 1])
            if opened and not re.search(r"\b(?:expect|assert|should)\b", body):
                out.append(make_finding(rule, sf, i + 1, end_line=end + 1,
                                        message="Test block contains no assertion."))
        else:
            if not re.search(r"\b(?:expect|assert|should)\b", line):
                out.append(make_finding(rule, sf, i + 1,
                                        message="Test contains no assertion on this line."))
        if len(out) >= 10:
            break
    return out


@check("broken_links")
def broken_links(sf: SourceFile, rule: Rule) -> List[Finding]:
    out: List[Finding] = []
    base = os.path.dirname(sf.abspath)
    for i, line in enumerate(sf.raw):
        for m in re.finditer(r"!?\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)", line):
            target = m.group(1).strip()
            if target.startswith(("http://", "https://", "mailto:", "tel:", "#", "/", "<")):
                continue
            if "{{" in target or "{%" in target:
                continue
            clean = target.split("#", 1)[0].split("?", 1)[0]
            if not clean:
                continue
            try:
                from urllib.parse import unquote
                clean = unquote(clean)
            except Exception:  # jankhunt42: ignore JH201,JH202
                pass
            path = os.path.normpath(os.path.join(base, clean))
            if not os.path.exists(path):
                out.append(make_finding(rule, sf, i + 1,
                                        message="Link target '%s' does not exist." % target))
                if len(out) >= 20:
                    return out
    return out


@check("lockfile_missing")
def lockfile_missing(sf: SourceFile, rule: Rule) -> List[Finding]:
    d = os.path.dirname(sf.abspath)
    names = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb")
    cur = d
    for _ in range(20):
        if any(os.path.exists(os.path.join(cur, n)) for n in names):
            return []
        if os.path.isdir(os.path.join(cur, ".git")):
            break
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    return [make_finding(rule, sf, 1,
                         message="No lockfile in this package or its repo root; dependency resolution is not reproducible.")]


@check("unsafe_extract")
def unsafe_extract(sf: SourceFile, rule: Rule) -> List[Finding]:
    out: List[Finding] = []
    has_tar = "tarfile" in sf.text
    has_zip = "zipfile" in sf.text
    has_unpack = "unpack_archive" in sf.text
    if rule.id == "JH119" and not has_tar:
        return []
    if rule.id == "JH120" and not (has_zip or has_unpack):
        return []
    for i, line in enumerate(sf.code):
        if ".extractall(" in line or "unpack_archive(" in line:
            out.append(make_finding(rule, sf, i + 1,
                                    message="Archive extraction without path validation enables zip-slip/path traversal."))
            if len(out) >= 5:
                break
    return out
