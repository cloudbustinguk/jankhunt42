#!/usr/bin/env python3
"""Special (multi-line / structural) checks for jankhunt42 rules."""
from __future__ import annotations

import ast
import os
import re
import subprocess
from typing import Dict, Iterator, List, Optional, Sequence, Tuple

from jh_core import Finding, Rule, SourceFile, is_test_path, make_finding, redact_secrets

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
    is_named = base in _SECRET_FILE_NAMES
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
_GH_UNTRUSTED = re.compile(
    r"\$\{\{\s*github\.(?:head_ref|event\.pull_request\.head\.(?:ref|sha)|"
    r"event\.(?:issue|pull_request|comment|review)\.(?:title|body)|"
    r"event\.review_comment\.body)\s*\}\}"
)


def _run_lines(sf: SourceFile) -> Iterator[Tuple[int, str]]:
    lines = sf.nocomment
    i = 0
    while i < len(lines):
        m = _GH_RUN_RE.match(lines[i])
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
    for i, line in _run_lines(sf):
        if _GH_UNTRUSTED.search(line):
            out.append(make_finding(rule, sf, i + 1,
                                    message="Untrusted GitHub event data is interpolated into a shell command."))
            if len(out) >= 5:
                break
    return out


@check("gh_pull_request_target")
def gh_pull_request_target(sf: SourceFile, rule: Rule) -> List[Finding]:
    if "pull_request_target" not in sf.text:
        return []
    lines = sf.nocomment
    out: List[Finding] = []
    for i, line in enumerate(lines):
        if not re.search(r"uses\s*:\s*actions/checkout@", line):
            continue
        window = "\n".join(lines[i:i + 15])
        if re.search(r"ref\s*:\s*\$\{\{\s*github\.(?:event\.pull_request\.head|head_ref)", window):
            out.append(make_finding(rule, sf, i + 1,
                                    message="pull_request_target checks out untrusted PR code with repository secrets available."))
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


@check("assertion_free_test")
def assertion_free_test(sf: SourceFile, rule: Rule) -> List[Finding]:
    out: List[Finding] = []
    if "benchmark" in sf.rel.lower():
        return out
    if sf.lang == "python":
        for start, end, name, _async in python_functions(sf):
            if not name.startswith("test"):
                continue
            body = "\n".join(sf.code[start:end + 1])
            if re.search(r"\b(?:assert|pytest\.(?:raises|warns|deprecated_call)|"
                         r"self\.assert|unittest|np\.testing|assert_that)\b", body):
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
