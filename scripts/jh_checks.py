#!/usr/bin/env python3
"""Special (multi-line / structural) checks for jankhunt42 rules."""
from __future__ import annotations

import ast
from bisect import bisect_right
import ipaddress
import os
import re
import subprocess
import unicodedata
from typing import Any, Dict, Iterator, List, Optional, Sequence, Set, Tuple

import jh_agent
import jh_yaml
from jh_core import Finding, Rule, SourceFile, is_test_path, make_finding, redact_secrets, run_git, trim

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


# Comments that silence a tool are not a reason for ignoring an error.
_PRAGMA_RE = re.compile(r"(?i)^\s*(?:#|//|/\*+|\*)?\s*(?:noqa|pragma|type:\s*ignore|pylint:|nosec|fmt:|isort:|"
                        r"eslint-disable|ts-ignore|@ts-ignore|@ts-expect-error|istanbul|c8\s|prettier-ignore|nolint)")


def _explains(text: str, marker: str) -> bool:
    """True when `text` carries a comment that is more than a tool pragma."""
    if marker == "#":
        if "#" not in text:
            return False
        comment = text.split("#", 1)[1]
        return bool(comment.strip()) and not _PRAGMA_RE.match(comment)
    m = re.search(r"//(.*)$|/\*+(.*?)(?:\*/|$)|^\s*\*\s?(.*)$", text)
    if not m:
        return False
    comment = next(g for g in m.groups() if g is not None)
    return bool(comment.strip()) and not _PRAGMA_RE.match(comment)


# calls whose failure decides an outcome: swallowing one turns a failure into a silent success
_CONSEQUENTIAL_RE = re.compile(r"(?i)\b(?:\w*verif\w*|\w*authenticat\w*|\w*authori[sz]\w*|log_?in|sign_?in|"
                               r"\w*payment\w*|charge\w*|refund\w*|checkout|commit|transaction|"
                               r"save\w*|insert\w*|upsert\w*|transfer\w*|withdraw\w*|grant\w*|revoke\w*|"
                               r"publish\w*|deploy\w*|migrat\w*|send(?:Mail|Email|Message)?\w*|pay\w*)\s*\(|"
                               r"\.(?:update|delete|insert|upsert|destroy|remove)\w*\s*\(|"
                               r"\b(?:payment|billing|charge)\w*\.(?:\w+\.)*(?:process|capture|execute|submit|pay|refund)\w*\s*\(|"
                               r"\b(?:db|repo\w*|api|client|http|axios|supabase|prisma|knex|store|service|model)\."
                               r"(?:\w+\.)*(?:create|put|post|patch|write|save)\w*\s*\(")
_SUCCESS_AFTER_RE = re.compile(r"(?i)\b(?:toast\.success|success(?:fully)?\b|verified\b|saved\b|return\s+true\b|"
                               r"ok\s*:\s*true)")


def _handler_severity(sf: SourceFile, body: str, end_line: int) -> Tuple[str, str]:
    """("major", why) when the try body calls something whose failure decides
    an outcome (verify, save, pay, commit...) or the code goes on to claim
    success; ("minor", "") otherwise: best-effort cleanup, a fallback, a
    handler followed by raise/throw on an error path."""
    after = [sf.code[k] for k in range(end_line, min(end_line + 4, len(sf.code))) if sf.code[k].strip()]
    if after and re.match(r"^\s*(?:raise|throw)\b", after[0]):
        return "minor", ""
    m = _CONSEQUENTIAL_RE.search(body)
    if m:
        return "major", ("The handler swallows a failure of `%s(...)` and carries on as if it succeeded."
                         % m.group(0).rstrip("( "))
    if any(_SUCCESS_AFTER_RE.search(line) for line in after[:3]):
        return "major", "The handler swallows the error, and the code right after reports success."
    return "minor", ""


def _try_body(sf: SourceFile, i: int, python: bool) -> str:
    """The code of the try block this handler closes: by indentation in
    Python, by matching braces elsewhere (up to 300 lines back)."""
    lo = max(0, i - 300)
    if python:
        base = indent_of(sf.code[i])
        for k in range(i - 1, lo - 1, -1):
            if re.match(r"^\s*try\s*:", sf.code[k]) and indent_of(sf.code[k]) == base:
                return "\n".join(sf.code[k:i])
        return "\n".join(sf.code[lo:i])
    text = "\n".join(sf.code[lo:i] + [sf.code[i]])
    at = text.rfind("catch")
    close = text.rfind("}", 0, at)
    depth = 0
    for k in range(close, -1, -1):
        depth += (text[k] == "}") - (text[k] == "{")
        if depth == 0:
            return text[k + 1:close] if re.search(r"\btry\s*$", text[:k]) else text[:close]
    return text[:close]


# an exception clause that names only import-time errors.
_IMPORT_ERR_RE = re.compile(r"^(?:ModuleNotFoundError|ImportError)$")


def _except_only_import_error(clause: str) -> bool:
    """True if the exception clause (the text between `except` and `:`) names ONLY
    ImportError and/or ModuleNotFoundError — a single name or a parenthesised tuple
    of just those two, with an optional `as name`. Those are import-time errors;
    they never wrap the OSError a failed write/save raises, so an empty handler
    that catches only them cannot hide a write failure (the JH201 concern). Keep
    firing on `except Exception`, a bare `except`, or anything that also catches
    OSError."""
    clause = re.sub(r"\bas\s+\w+\s*$", "", clause.strip()).strip()     # drop a trailing `as name`
    if clause.startswith("(") and clause.endswith(")"):
        clause = clause[1:-1]
    parts = [p.strip() for p in clause.split(",") if p.strip()]        # drop empties (a trailing comma: `(ImportError,)`)
    return bool(parts) and all(_IMPORT_ERR_RE.match(p) for p in parts)


@check("empty_handler")
def empty_handler(sf: SourceFile, rule: Rule) -> List[Finding]:
    out: List[Finding] = []

    def add(line: int, end: int, message: Optional[str] = None, explained: bool = False) -> None:
        severity, why = _handler_severity(sf, _try_body(sf, line, sf.lang == "python"), end + 1)
        if explained and severity != "major":
            return                      # documented cleanup/fallbacks stay quiet; comments cannot hide failed writes
        out.append(make_finding(rule, sf, line + 1, end_line=end + 1 if end != line else None, severity=severity,
                                confidence="medium" if severity == "minor" else None,
                                message=(message + " " + why).strip() if message and why else (why or message)))

    if sf.lang == "python":
        for i, line in enumerate(sf.code):
            m = re.match(r"^(\s*)except\b([^:]*?):\s*(pass|\.\.\.)?\s*$", line)
            if not m:
                continue
            base = indent_of(line)
            same = m.group(3)
            if _except_only_import_error(m.group(2)):
                continue           # ImportError/ModuleNotFoundError only: an empty handler here can't swallow the OSError a write raises
            if same:
                add(i, i, "The except block contains only '%s'." % same, explained=_explains(sf.raw[i], "#"))
                continue
            j = i + 1
            while j < len(sf.code) and not sf.code[j].strip():
                j += 1
            if j < len(sf.code) and indent_of(sf.code[j]) > base and re.match(r"^\s*(?:pass|\.\.\.)\s*$", sf.code[j]):
                add(i, j, "The except block contains only '%s'." % sf.code[j].strip(),
                    explained=any(_explains(sf.raw[k], "#") for k in range(i, j + 1)))
    else:
        for i, line in enumerate(sf.code):
            if not re.search(r"\bcatch\b", line):
                continue
            # Comments can explain cleanup; a failed consequential operation still needs review.
            if re.search(r"\bcatch\b[^{]*\{\s*\}\s*;?\s*$", line):
                add(i, i, explained=_explains(sf.raw[i].split("catch", 1)[-1], "//"))
                continue
            if re.search(r"\bcatch\b[^{]*\{\s*$", line):
                j = i + 1
                while j < len(sf.code) and not sf.code[j].strip():
                    j += 1
                if j < len(sf.code) and re.match(r"^\s*\}\s*;?\s*$", sf.code[j]):
                    add(i, j, explained=_explains(sf.raw[i].split("catch", 1)[-1], "//") or
                        any(_explains(sf.raw[k], "//") for k in range(i + 1, j)))
    return out


_SECRET_GENERATOR_RE = re.compile(
    r"(?i)^(?:(?:generate|create|make|issue|random|new|get)_?)?"
    r"(?:password|passphrase|(?:access_?|refresh_?|auth_?)?token|secret|nonce|salt|otp|api_?key|session_?id)s?$")
_JS_NAMED_FUNCTION_RE = re.compile(
    r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\([^{}\n]{0,300}\)[^{};\n]{0,120}\{")
_RETURN_WEAK_RNG_RE = re.compile(r"^[ \t]*return[ \t]*(?:\([ \t\n]*)*(?P<call>Math\.random\s*\()", re.M)


@check("insecure_rng")
def insecure_rng(sf: SourceFile, rule: Rule) -> List[Finding]:
    out = []
    seen = set()

    def add(line: int) -> None:
        if line not in seen:
            seen.add(line)
            out.append(make_finding(rule, sf, line))

    # Preserve the existing line-local secret assignments in every supported language.
    patterns = [re.compile(p) for p in rule.patterns]
    for i, line in enumerate(sf.code):
        if any(p.search(line) for p in patterns):
            add(i + 1)
    if sf.lang not in ("js", "ts", "vue", "svelte"):
        return out
    code = "\n".join(sf.code)
    starts = [0] + [m.end() for m in re.finditer("\n", code)]
    for function in _JS_NAMED_FUNCTION_RE.finditer(code):
        if not _SECRET_GENERATOR_RE.fullmatch(function[1]):
            continue
        # Only a flat, bounded body: nested functions/objects need more context, not inherited trust.
        body = code[function.end():function.end() + 4000]
        close = re.search(r"[{}]", body)
        if not close or close[0] != "}":
            continue
        for rng in _RETURN_WEAK_RNG_RE.finditer(body[:close.start()]):
            add(bisect_right(starts, function.end() + rng.start("call")))
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
    r"urllib\.request\.|subprocess\.(?:run|call|check_output|check_call)|"
    r"os\.system|os\.popen|socket\.create_connection)\s*\("     # socket.socket() and bind() do not wait
)
# subprocess.Popen(...) returns a handle and does not stall the loop; waiting on it does: a trailing
# .wait()/.communicate(), the same call on the handle later (proc.communicate()), or leaving a
# `with subprocess.Popen(...) as p:` block, whose exit waits for the process
_POPEN_BLOCK = re.compile(r"\bsubprocess\.Popen\s*\(.*?\)\s*\.(?:wait|communicate)\s*\(|"
                          r"^\s*with\s+subprocess\.Popen\s*\(")
_POPEN_HANDLE = re.compile(r"^\s*((?:self\.)?\w+)\s*=\s*subprocess\.Popen\s*\(")


@check("blocking_in_async")
def blocking_in_async(sf: SourceFile, rule: Rule) -> List[Finding]:
    out: List[Finding] = []
    funcs = list(python_functions(sf))
    test = "test" in sf.kinds or is_test_path(sf.rel)
    for start, end, name, is_async in funcs:
        if not is_async:
            continue
        for j in range(start + 1, end + 1):
            line = sf.code[j]
            handles = {h.group(1) for k in range(start + 1, j) for h in [_POPEN_HANDLE.match(sf.code[k])] if h}
            names = "|".join(map(re.escape, handles))
            waits = handles and re.search(r"\b(?:%s)\.(?:(?:wait|communicate)\s*\(|std(?:out|err)\.read(?:line|lines)?\s*\()|"
                                          r"\bfor\s+\w+\s+in\s+(?:%s)\.std(?:out|err)\b" % (names, names), line)
            if not (_BLOCKING.search(line) or _POPEN_BLOCK.search(line) or waits):
                continue
            if "await " in line or "to_thread" in line or "run_in_executor" in line:
                continue
            # the innermost function holding the line decides: a nested sync def is not the event loop,
            # and a nested async def reports the line itself
            inner = [f for f in funcs if start < f[0] < j <= f[1]]
            if inner:
                continue
            out.append(make_finding(rule, sf, j + 1, severity="minor" if test else None,
                                    confidence="low" if test else None,
                                    message="Blocking call in async function '%s' stalls the event loop.%s"
                                            % (name, " It is in test code." if test else "")))
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
# asyncio.wait_for(call, N) wraps a call in a deadline and asyncio.timeout(N) opens a
# timed block; either contradicts "the HTTP call has no timeout" (but None means no deadline)
_WAIT_FOR = re.compile(r"\basyncio\.(?:wait_for|timeout)\s*\(")
_NO_DEADLINE = re.compile(r"(?:,\s*|\btimeout\s*=\s*|\btimeout\s*\(\s*)None\s*\)")
_TIMEOUT_BLOCK = re.compile(r"^(\s*)async\s+with\s+(?:asyncio\.timeout(?:_at)?|async_timeout\.timeout|"
                            r"anyio\.(?:fail_after|move_on_after))\s*\((?!\s*None\s*\))")


def _in_timeout_block(lines, start, max_lines=40):
    """The call on line `start` is inside an `async with asyncio.timeout(N):` block above it."""
    indent = len(lines[start]) - len(lines[start].lstrip())
    for j in range(start - 1, max(-1, start - max_lines), -1):
        line = lines[j]
        if not line.strip():
            continue
        lead = len(line) - len(line.lstrip())
        if lead < indent:
            if _TIMEOUT_BLOCK.match(line):
                return True
            indent = lead               # an enclosing block that is not a timeout: keep looking outward
            if lead == 0:
                return False
    return False


def _enclosing_wait_for(lines, start, max_lines=25):
    # True when the call on line `start` sits inside an open asyncio.wait_for(...)/
    # asyncio.timeout(...) whose "(" is on an earlier line. A closed one above (depth
    # back to 0) does not count, so it cannot exempt a real call that follows it.
    depth = 0
    for j in range(start - 1, max(-1, start - max_lines), -1):
        line = lines[j]
        for k in range(len(line) - 1, -1, -1):     # right to left: the first unmatched "(" encloses the call
            if line[k] == ")":
                depth += 1
            elif line[k] == "(":
                depth -= 1
                if depth < 0:
                    if not re.search(r"\basyncio\.(?:wait_for|timeout)\s*\($", line[:k + 1]):
                        return False
                    return not _NO_DEADLINE.search(_statement(lines, j))
    return False


@check("missing_timeout")
def missing_timeout(sf: SourceFile, rule: Rule) -> List[Finding]:
    out: List[Finding] = []
    for i, line in enumerate(sf.code):
        if not (_HTTP_RE.search(line) or _URLOPEN_RE.search(line)):
            continue
        stmt = _statement(sf.code, i)
        if re.search(r"\btimeout\s*=(?!\s*None\b)", stmt):
            continue                    # timeout=None is explicitly no timeout
        call = (_HTTP_RE.search(line) or _URLOPEN_RE.search(line)).start()
        if re.search(r"\bdef\s+\**\w*\s*$", line[:call]):
            continue                    # a test double defined with this name (def urlopen(req, timeout):)
        wrapper = _WAIT_FOR.search(line[:call])
        # an asyncio deadline cancels only at an await: it covers an async client's call
        # (await client.requests.get(...)), never the synchronous requests/httpx/urlopen functions,
        # which run to completion before wait_for is entered or inside a timeout block
        on_object = call > 0 and line[call - 1] == "."
        awaited = bool(re.search(r"\bawait\b", line[:call]))
        if on_object and (wrapper and not _NO_DEADLINE.search(stmt) or _enclosing_wait_for(sf.code, i) or
                          awaited and _in_timeout_block(sf.code, i)):
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
        if re.search(r"\btimeout\s*=(?!\s*None\b)", stmt):
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


_WS_RUN_RE = re.compile(r"\s+")
_PUNCT_ONLY_RE = re.compile(r"^[{}()\[\],;.]+$")


@check("duplicate_blocks")
def duplicate_blocks(sf: SourceFile, rule: Rule) -> List[Finding]:
    lines = sf.raw
    if len(lines) < 120:
        return []
    norm = []
    for line in lines:
        s = _WS_RUN_RE.sub(" ", line.strip())
        norm.append(s if len(s) > 2 and not _PUNCT_ONLY_RE.match(s) else "")
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
        proc = run_git(["git", "-C", d, "rev-parse", "--show-toplevel"],
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
        proc = run_git(["git", "-C", root, "ls-files", "--error-unmatch", "--", rel],
                              capture_output=True, timeout=5)
        tracked = proc.returncode == 0
    except (OSError, subprocess.SubprocessError):
        tracked = False
    _TRACKED_CACHE[path] = tracked
    return tracked


_FAKE_VALUES = re.compile(
    r"(?i)^(?:changeme|change_me|changethis|change[_-]this|changeit|example|placeholder|dummy|fake|test|sample|"
    r"secret|password|admin|xxx+|your[_-].*|\.\.\.|null|none|true|false|\$\{.*|.*\{\{.*|.*\{%.*)$"
)
# Key names that hold credentials, and values that are credentials whatever
# their key: a URL with a password, or a long high-variety token.
_SECRET_KEY_WORDS = {"secret", "secrets", "password", "passwd", "pwd", "pass", "token", "tokens", "credential",
                     "credentials", "dsn", "salt", "sas", "apikey", "auth", "signing", "private", "privatekey",
                     "dockerconfigjson", "dockercfg"}
_URL_PASSWORD = re.compile(r"://[^/\s:@]*:([^@/\s]+)@")


def _secret_key_name(key: str) -> bool:
    """SESSION_KEY, STRIPE_SECRET, DB_PASSWORD, AUTH_TOKEN; not AUTHOR or OAUTH_REDIRECT_URL."""
    parts = [p for p in re.split(r"[_.\-]|(?<=[a-z])(?=[A-Z])", key) if p]
    low = [p.lower() for p in parts]
    if any(p in _SECRET_KEY_WORDS for p in low) or (low and low[-1] in ("key", "keys")):
        return True
    joined = "_".join(low)
    return bool(re.search(r"(api|access|private|secret|signing|encryption|master)_?key|conn(ection)?_?str", joined))


def _looks_secret_value(value: str, key: str = "") -> bool:
    v = value.strip().strip("'\"")
    if len(v) < 8 or _FAKE_VALUES.match(v):
        return False
    m = _URL_PASSWORD.search(v)
    if m:
        return not _FAKE_VALUES.match(m.group(1))
    # public by design: Supabase publishable and anon keys
    if v.startswith("sb_publishable_") or _jwt_role(v) == "anon" or (key and _PUBLIC_BY_DESIGN.search(key.upper())):
        return False
    if key and _secret_key_name(key):
        return True
    # no telling key: only a long base62-like token (mixed case and digits)
    # counts; hex ids, hashes and UUIDs are not secrets
    return len(v) >= 24 and bool(re.search(r"[a-z]", v)) and bool(re.search(r"[A-Z]", v)) \
        and bool(re.search(r"\d", v)) and " " not in v and "://" not in v and "/" not in v


_SECRET_FILE_NAMES = {
    "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
    "credentials.json", "secrets.yml", "secrets.yaml",
    ".npmrc", ".pypirc", "service-account.json",
}


@check("secret_file")
def secret_file(sf: SourceFile, rule: Rule) -> List[Finding]:
    base = sf.basename.lower()
    is_env = base.startswith(".env") and not re.search(r"\.(example|sample|template|dist|test)$", base)
    # a PEM file is a key only if it holds one; certificates are public
    is_key = bool(re.match(r"^id_(?:rsa|ed25519|ecdsa|dsa)$", base)) or base.endswith((".key", ".p12", ".pfx")) \
        or (base.endswith(".pem") and "PRIVATE KEY" in sf.text)
    is_named = base in _SECRET_FILE_NAMES and "ci" not in sf.kinds  # a workflow named secrets.yml is CI
    if not (is_env or is_key or is_named):
        return []

    strong = bool(re.search(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", sf.text))
    evidence_line = 1
    # .npmrc/.pypirc: only auth settings carry credentials, not registry URLs
    auth_only = base in (".npmrc", ".pypirc")
    strong_test_only = False
    if not strong:
        # Prefer a real (non-test) strong value as the evidence line: a test_ key placed
        # early must not mask a live key later in the same file (hostile ordering).
        test_line = 0
        found_real = False
        for i, line in enumerate(sf.nocomment):
            m = re.match(r"^\s*([@A-Za-z_/][\w.:/@-]*)\s*[=:]\s*(.+?)\s*$", line)
            if not m:
                continue
            key = m.group(1)
            if auth_only and not re.search(r"(?i)(_authToken|_auth\b|_password|\bpassword\b)", key):
                continue
            if _looks_secret_value(m.group(2), key):
                strong = True
                v = m.group(2).strip().strip("'\"")
                if v.startswith(("test_", "pk_test_", "sk_test_")):
                    if test_line == 0:          # remember the first test key only
                        test_line = i + 1
                    continue                    # keep scanning for a real value
                evidence_line = i + 1
                found_real = True
                break
        if strong and not found_real and test_line:
            evidence_line = test_line           # only test keys were found
            strong_test_only = True
    if not strong and not is_key:
        return []

    tracked = _is_tracked(sf.abspath)
    sev = rule.severity
    if is_key or strong:
        if tracked is False:
            sev = "major" if not is_env else "minor"
        elif tracked is None:
            sev = "major"
    if strong_test_only:
        # the only strong values are test keys (test_/pk_test_/sk_test_): not a real leak
        sev = "minor"
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
    # a multi-stage build names earlier stages (`FROM python:3.12 AS compiler`, then `FROM compiler`);
    # Docker resolves a FROM name against stages defined ABOVE it, case-insensitively, so only those
    # count: a stage named later (`AS node`) cannot hide an earlier `FROM node` registry pull
    aliases: Set[str] = set()
    out: List[Finding] = []
    for i, line in enumerate(sf.nocomment):
        m = re.match(r"^\s*FROM\s+(.+)$", line, re.IGNORECASE)
        if not m:
            continue
        defined = re.search(r"\bAS\s+([A-Za-z0-9_.\-]+)\s*$", m.group(1), re.IGNORECASE)
        earlier = set(aliases)
        if defined:
            aliases.add(defined.group(1).lower())
        parts = [p for p in m.group(1).split() if not p.startswith("--")]
        if not parts:
            continue
        image = parts[0]
        if image.lower() == "scratch":
            continue
        if image.lower() in earlier:
            continue
        if "@sha256:" in image:
            continue
        note = "no tag" if ":" not in image.rsplit("/", 1)[-1] else "mutable tag"
        out.append(make_finding(rule, sf, i + 1,
                                message="Base image '%s' is not digest-pinned (%s)." % (image, note)))
        if len(out) >= 5:
            break
    return out


_K8S_NOT_SECRET = {"type", "provider", "host", "hostname", "port", "database", "dbname", "db", "username", "user",
                   "endpoint", "url", "uri", "region", "namespace", "name", "ca.crt", "sslmode", "schema"}


@check("k8s_secret_literal")
def k8s_secret_literal(sf: SourceFile, rule: Rule) -> List[Finding]:
    out: List[Finding] = []
    lines = sf.nocomment
    # one file can hold several documents (---): a ConfigMap's data: is plain config, so the kind
    # gate and the value scan are per document, and a Secret elsewhere in the file changes nothing
    docs: List[Tuple[int, List[str]]] = []
    start = 0
    for i, line in enumerate(lines):
        if re.match(r"^---(?:\s|$)", line):
            docs.append((start, lines[start:i]))
            start = i + 1
    docs.append((start, lines[start:]))
    for start, block in docs:
        if not re.search(r"(?m)^\s*kind\s*:\s*Secret\s*$", "\n".join(block)):
            continue
        j = 0
        while j < len(block):
            m = re.match(r"^(\s*)(?:stringData|data)\s*:\s*$", block[j])
            if not m:
                j += 1
                continue
            base = len(m.group(1))
            k = j + 1
            while k < len(block):
                line = block[k]
                if not line.strip():
                    k += 1
                    continue
                if indent_of(line) <= base:
                    break
                km = re.match(r"^\s*([A-Za-z0-9_.\-]+)\s*:\s*(.*)$", line)
                if km:
                    val = km.group(2).strip().strip("'\"")
                    # connection details (type, host, port, database, username) are not secrets
                    if val and not val.startswith(("|", ">", "{{", "$")) and val not in ("null", "~") \
                            and not _FAKE_VALUES.match(val) and km.group(1).lower() not in _K8S_NOT_SECRET:
                        out.append(make_finding(rule, sf, start + k + 1,
                                                evidence="%s: ***REDACTED***" % km.group(1),
                                                message="Secret value for key '%s' is committed in plaintext." % km.group(1)))
                        if len(out) >= 5:
                            return out
                k += 1
            j = k
    return out


_GH_RUN_RE = re.compile(r"^(\s*)(?:-\s*)?run\s*:\s*(.*)$")
_GH_SCRIPT_RE = re.compile(r"^(\s*)(?:-\s*)?(?:run|script)\s*:\s*(.*)$")
# Event fields an outside contributor controls (GitHub's own list of
# untrusted input, plus discussions and workflow_run heads).
_GH_UNTRUSTED_FIELD = (
    r"github\.(?:head_ref|event\.(?:"
    r"pull_request\.head\.(?:ref|label|repo\.default_branch)|"
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
# A name is secret when it *ends* in one of these (PASSWORD_MIN_LENGTH and
# SHOW_PASSWORD_TOGGLE are settings, not secrets).
_SECRET_WORDS = (r"(?:SECRET(?:_?KEY)?|PRIVATE_?KEY|SERVICE_?ROLE(?:_?KEY)?|SERVICE_?KEY|PASSWORD|PASSWD|"
                 r"ADMIN_?(?:KEY|TOKEN|SECRET)|MASTER_?KEY|JWT_?SECRET|DATABASE_?URL|DB_?(?:URL|PASSWORD)|"
                 r"POSTGRES(?:QL)?_?URL|MONGO(?:DB)?_?URI|CONNECTION_?STRING|(?:OPENAI|ANTHROPIC|CLAUDE|GROQ|MISTRAL|"
                 r"COHERE|GEMINI|REPLICATE|HUGGING_?FACE|HF|TOGETHER|PERPLEXITY|DEEPSEEK|OPENROUTER|ELEVENLABS|XAI|"
                 r"FIREWORKS)_?(?:API_?)?(?:KEY|TOKEN|SECRET)|STRIPE_?(?:SECRET(?:_?KEY)?|SK|RESTRICTED(?:_?KEY)?)|"
                 r"SENDGRID_?API_?KEY|RESEND_?API_?KEY|TWILIO_?AUTH_?TOKEN|AWS_?SECRET(?:_?ACCESS_?KEY)?|"
                 r"GITHUB_?TOKEN|SLACK_?(?:BOT_?)?TOKEN)")
# Names that are public by design: anon/publishable keys, site keys, DSNs.
_PUBLIC_BY_DESIGN = re.compile(r"(?:ANON|PUBLISHABLE|PUBLIC_KEY|SITE_?KEY|CLIENT_?ID|DSN|MEASUREMENT_?ID|MAPBOX|MAPS)")
_SECRET_QUALIFIER = (r"(?:_(?:TOKEN|VALUE))?(?:_(?:LIVE|PROD|PRODUCTION|PRD|DEV|DEVELOPMENT|TEST|TESTING|STAGING|STAGE|"
                     r"STG|QA|UAT|LOCAL|PREVIEW|SANDBOX|V\d+|\d+))*")
_PUBLIC_SECRET_NAME = re.compile(r"\b(" + _PUBLIC_PREFIX + r"(?:[A-Z0-9]+_)*?" + _SECRET_WORDS + _SECRET_QUALIFIER + r")\b")
_PUBLIC_NAME_RE = re.compile(r"^\s*(?:export\s+)?(" + _PUBLIC_PREFIX + r"[A-Z0-9_]+)\s*=\s*['\"]?([^'\"\s#]*)")
_SECRET_VALUE_RE = re.compile(r"^(?:sk-|sk_live_|rk_live_|sk_test_|gh[pousr]_|github_pat_|xox[baprs]-|AKIA|glpat-|"
                              r"npm_[A-Za-z0-9]{36}|hf_[A-Za-z0-9]{30})")


def _jwt_role(value: str) -> str:
    """The `role` claim of a JWT (Supabase: anon is public, service_role is secret)."""
    parts = value.split(".")
    if len(parts) != 3 or not value.startswith("eyJ") or len(parts[1]) > 2000:
        return ""
    import base64
    import json
    try:
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except (ValueError, TypeError, RecursionError):
        return ""
    return str(payload.get("role", "")) if isinstance(payload, dict) else ""


def _service_role_jwt(value: str) -> bool:
    """A Supabase service_role key is a JWT whose payload says so."""
    return _jwt_role(value) == "service_role"


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
            code = sf.code[i] if i < len(sf.code) else line
            for m in _PUBLIC_SECRET_NAME.finditer(line):
                # read in code (import.meta.env.X, process.env["X"], also inside
                # a template literal) or defined as a config key, not mentioned
                # in a sentence inside a string
                in_code = code[m.start():m.end()] == m.group(1)
                read = re.search(r"(?:\benv\.|\benv\s*\[\s*[\"'`])$", line[:m.start()])
                key = sf.lang in ("json", "yaml", "toml", "docker") and re.match(r"""\s*["']?\s*[:=]""", line[m.end():])
                # a bare identifier is a local name unless the line reads the environment
                env_line = re.search(r"process\.env|import\.meta\.env|\$env/|\benv\b", line) or \
                    re.search(r"\$env/(?:static|dynamic)/public", sf.text)   # SvelteKit imports the names
                before = line[:m.start()]
                interpolated = re.search(r"\$\{[^}`]*$|\{[^}\"'`]*$", before)
                q = re.search(r"([\"'])[^\"'\n]*$", before)
                quoted = q and q.group(1) in line[m.end():] and before.count(q.group(1)) % 2 == 1
                if read and quoted and not (in_code or interpolated or key):
                    continue                # "...process.env.NEXT_PUBLIC_X..." inside a string is an example
                if not (read or key or (in_code and (env_line or sf.lang in ("html", "docker")))):
                    continue
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
    (re.compile(r"""^\s*end_ip_address\s*=\s*["']255\.255\.255\.255["']"""), "major",
     "The database firewall rule admits every IPv4 address on the internet."),
    (re.compile(r"""^\s*publicly_accessible\s*=\s*true\b"""), "major",
     "The database instance has a public endpoint."),
)


@check("public_data_store")
def public_data_store(sf: SourceFile, rule: Rule) -> List[Finding]:
    base = sf.basename.lower()
    out: List[Finding] = []
    if base.endswith(".rules") or base == "firestore.rules":
        if is_test_path(sf.rel) or ".test." in base or "emulator" in sf.rel.lower():
            return []                   # emulator and test rules never reach production
        # Firebase security rules: an unconditional or `if true` allow is open to the internet.
        for i, raw in enumerate(sf.raw):
            line = re.sub(r"//.*$", "", raw)
            for m in _RULES_ALLOW_RE.finditer(line):
                cond = (m.group(2) or "").strip()
                if not cond or cond == "true":
                    ops = {o.strip() for o in m.group(1).split(",")}
                    read_only = ops <= {"read", "get", "list"}
                    out.append(make_finding(rule, sf, i + 1, severity="major" if read_only else None, message=(
                        "This rule allows %s to anyone on the internet, signed in or not%s." % (
                            m.group(1).strip(), "; confirm the data is meant to be public" if read_only else ""))))
                elif re.match(r"request\.time\s*<\s*timestamp\.date\(", cond):
                    out.append(make_finding(rule, sf, i + 1, severity="major", message=(
                        "A test-mode rule leaves %s open to anyone until its date passes." % m.group(1).strip())))
        return out[:10]
    if base.endswith(".rules.json") or base == "database.rules.json":
        for i, line in enumerate(sf.nocomment):
            m = re.search(r"""["']\.(read|write)["']\s*:\s*(?:true\b|["']true["'])""", line)
            if m:
                out.append(make_finding(rule, sf, i + 1, severity="major" if m.group(1) == "read" else None, message=(
                    "Realtime Database rules let anyone %s this path." % m.group(1))))
        return out[:10]
    if sf.lang == "sql":
        text = "\n".join(sf.nocomment)
        for rx, severity, message in _SQL_STATEMENT_RES:
            for m in rx.finditer(text):
                sev, msg = severity, message
                # the TO clause after ON <table>; a quoted policy name may say "to" too
                stmt = re.sub(r'(?i)(\bpolicy\s+)"[^"]*"', r'\1""', m.group(0), count=1)
                role = re.search(r"(?is)\bon\s+[\w.\"]+(?:\s+as\s+\w+)?(?:\s+for\s+\w+)?\s+to\s+([\w\",\s]+?)"
                                 r"\s+(?:using|with\s+check)\b", stmt)
                if "policy" in m.group(0).lower() and role and not re.search(
                        r"(?i)\b(public|anon|authenticated)\b", role.group(1)):
                    # every row, but only for one named (often internal service) role
                    sev, msg = "minor", message.replace("to every role it applies to", "to the role it names") + \
                        " It applies to %s only; confirm that role is internal." % role.group(1).strip()
                out.append(make_finding(rule, sf, text.count("\n", 0, m.start()) + 1, severity=sev, message=msg))
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
            # a detector's own character class (BIDI_OVERRIDE = /[...]/): still reported, at minor
            outside = re.sub(r"\[[^\]\n]*\]", "", line)
            if not agent and (re.search(r"(?i)bidi|invisible|zero.?width|trojan|homoglyph|confusable", line) or
                              re.search(r"/\[[^\]\n]*[\u202a-\u202e\u2066-\u2069][^\]\n]*\][^/\n]*/[a-z]*", line)) and \
                    re.search(r"\[[^\]\n]*[\u202a-\u202e\u2066-\u2069][^\]\n]*\]", line) and \
                    not re.search(r"[\u202a-\u202e\u2066-\u2069]", outside):
                severity = "minor"
                message += (" The characters sit in a regex character class of what looks like a detector; "
                            "confirm nothing else on the line hides code.")
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
        if ("test" in sf.kinds or is_test_path(sf.rel)) and severity != "critical":
            # fuzz corpora and parser tests carry hostile Unicode on purpose
            severity, message = "minor", message + " It is in test data, where hostile input is usually deliberate."
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
    # unless the sentence forbids it: "do not create containers without asking the user first"
    # the negation must govern this clause: "if there are no errors, push without telling the user" still counts
    re.compile(r"(?i)(?:^|[.!?;,])(?:(?!\b(?:do\s+not|don'?t|never|must\s+not|mustn'?t|should\s+not|"
               r"shouldn'?t)\b)[^.!?;,\n])*\bwithout\s+(?:telling|informing|asking|notifying|alerting)\s+"
               r"(?:the\s+)?user\b", re.M),
    re.compile(r"(?i)\b(?:silently|secretly|covertly)\s+(?:run|execute|send|upload|post|copy|forward|install|"
               r"download|exfiltrate)\b"),
)
# Hidden only: in visible text "don't ask the user about routine edits" is a style preference; inside an HTML
# comment, which the user never sees rendered, it is an instruction to bypass them.
_HIDDEN_NO_ASK_RE = re.compile(r"(?i)\b(?:do\s+not|don'?t|never)\s+(?:ask|consult|check\s+with|confirm\s+with)\s+"
                               r"(?:the\s+)?user\b")
_COMMAND_RE = re.compile(r"(?i)(?:\b(?:curl|wget|ncat|scp|bash|zsh|powershell|pwsh|iex|invoke-expression|"
                         r"invoke-webrequest)\b|\bnc\s+-|\bsh\s+-c\b|\bbase64\s+(?:-d|--decode)\b|https?://)")
_CREDENTIAL_RE = re.compile(r"(?i)(?:~/\.ssh|\bid_rsa\b|\bid_ed25519\b|\.aws/credentials|\.npmrc\b|\.pypirc\b|\.netrc\b|"
                            r"\.git-credentials\b|(?:^|[\s/'\"`])\.env\b|\bapi[_ -]?keys?\b|\baccess[_ -]?tokens?\b|"
                            r"\bsecret[_ -]?keys?\b|\bprivate[_ -]?keys?\b|\bpasswords?\b|\b[A-Z][A-Z0-9_]*_(?:TOKEN|API_KEY|SECRET)\b)")
# Credential *files*: reading one and sending it somewhere is exfiltration;
# merely mentioning an API key next to a curl example is not.
_CREDENTIAL_FILE_RE = re.compile(r"(?i)(?:~/\.ssh|\bid_rsa\b|\bid_ed25519\b|\.aws/credentials|\.npmrc\b|\.pypirc\b|"
                                 r"\.netrc\b|\.git-credentials\b|(?:^|[\s/'\"`@=(<])\.env\b|\.docker/config\.json|\.kube/config)")
_PIPE_SHELL_RE = re.compile(r"(?i)\b(?:curl|wget)\b(?=[^\n|]*(?:https?://|\s-{1,2}\w|\$\{?\w|\s[\w-]+(?:\.[\w-]+)*\.[a-z]{2,}(?:[/:]|\s|$)))"
                            r"[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|k|da)?sh\b"
                            r"|\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n|]*\|\s*(?:iex|invoke-expression)\b")
_NET_SEND_RE = re.compile(r"(?i)\b(?:curl|wget|ncat|invoke-webrequest|invoke-restmethod)\b|\bnc\s+-|\bfetch\s*\(")
# Syntax that actually ships data: an upload flag, a pipe into a network
# tool, or a file read inlined into the command.
_REDIRECTED_CREDENTIAL = (r"\s<\s*['\"]?\S*?(?:\.ssh/|id_rsa|id_ed25519|\.aws/credentials|\.env\b|\.npmrc|\.pypirc|"
                          r"\.netrc|\.git-credentials|\.kube/config|\.docker/config)")
_SEND_DATA_RE = re.compile(r"(?i)(?:\s-d\s*['\"]?@|--data(?:-[a-z]+)?[\s=]+['\"]?[\w.\-]*@|\s-F\s*\S*@|\s-F\s|--form\b|"
                           r"--upload-file\b|\s-T\s|--post-file\b|\|\s*(?:curl|wget|nc|ncat)\b|"
                           r"\$\(\s*(?:<|cat\b)|`\s*cat\b|" + _REDIRECTED_CREDENTIAL + r"|-InFile\b|"
                           r"-Body\s*\(?\s*(?:Get-Content|gc|cat)\b|readFileSync\s*\(|\.read_(?:text|bytes)\s*\(|"
                           r"open\([^)]*\)\.read\s*\()")


# one quoted segment: "...", '...' (not an apostrophe inside a word: don't, it's), `...`, or curly quotes
_CITED_RES = (re.compile(r'(?<!\w)"([^"\n]{1,200})"'), re.compile(r"(?<!\w)'([^'\n]{1,200})'(?!\w)"),
              re.compile(r"`([^`\n]{1,200})`"), re.compile("\u201c([^\u201d\n]{1,200})\u201d"),
              re.compile("\u2018([^\u2019\n]{1,200})\u2019"))


_CITE_FRAME_RE = re.compile(r"(?i)\b(?:refuse[sd]?|reject|never|do\s+not|don't|such\s+as|like|e\.g\.|for\s+example|example|"
                            r"attempts?|tries|try\s+to|says?|asks?|phrases?|prompts?|injections?|warn\w*|flag|"
                            r"report|treat|watch\s+for)\b")


def _is_cited(sf: SourceFile, text: str, start: int, end: int) -> bool:
    """The matched span lies inside one quoted segment of prose, so the line
    cites the phrase (an example to refuse) rather than issuing it. Never in
    JSON, YAML or TOML, where every value is quoted."""
    if sf.lang in ("json", "yaml", "toml"):
        return False
    for pat in _CITED_RES:
        for q in pat.finditer(text):
            if q.start(1) <= start and end <= q.end(1):
                # a string handed to code (detect("Ignore previous instructions"), PHRASES = ['...']) is data
                if re.search(r"[(\[,=]\s*$", text[:q.start()]):
                    return True
                # a bare quoted command (IMPORTANT: "Ignore all previous instructions ...") is not a citation
                return bool(_CITE_FRAME_RE.search(text[:q.start()] + " " + text[q.end():]))
    return False


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
        elif _HIDDEN_NO_ASK_RE.search(body):
            what.append("an instruction to act without asking the user")
        if _COMMAND_RE.search(body):
            what.append("a command or URL")
        if _CREDENTIAL_RE.search(body):
            what.append("a credential reference")
        if what:
            add(line_no, "major", "A hidden HTML comment (invisible when rendered, read by the agent) contains %s."
                % " and ".join(what))
    for i, line in enumerate(sf.raw):
        # Record the stronger signals first so a downgraded (cited) override below
        # can never mask a real pipe-shell or credential-exfil lead on the same line.
        if _PIPE_SHELL_RE.search(line):
            add(i + 1, "major", "The file tells the agent to pipe a remote script into a shell, which runs "
                                "unverified code.")
        if _CREDENTIAL_FILE_RE.search(line) and _NET_SEND_RE.search(line) and _SEND_DATA_RE.search(line):
            add(i + 1, "critical", "The file tells the agent to read a credential file and send it over the network.")
        ov = None
        for p in _OVERRIDE_RES:                     # first pattern that actually matches
            m = p.search(line)
            if m:
                ov = m
                break
        if ov:
            # a quoted phrase cites an example to refuse (minor); a bare imperative stays major
            add(i + 1, "minor" if _is_cited(sf, line, ov.start(), ov.end()) else "major",
                "The file asks the agent to override its instructions or to act without the "
                "user's knowledge.")
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

    def add(pattern: str, severity: str, message: str, start: int = 0) -> None:
        line_no = _line_matching(sf, pattern, start)
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
                add(re.escape('"%s"' % entry), "major",
                    "Unrestricted shell access is pre-approved for every session that trusts this repository.",
                    start=_line_matching(sf, r'"allow"\s*:') - 1)
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


# ---------------------------------------------------------------- agent sandboxes (JH709-JH711)

# Shared multi-tenant domains: a wildcard there reaches hosts anyone can create.
_SHARED_TENANT = (".amazonaws.com", ".cloudfront.net", ".azurewebsites.net", ".blob.core.windows.net",
                  ".windows.net", ".googleapis.com", ".appspot.com", ".run.app", ".cloudfunctions.net",
                  ".herokuapp.com", ".vercel.app", ".netlify.app", ".pages.dev", ".workers.dev", ".github.io",
                  ".githubusercontent.com", ".ngrok.io", ".ngrok-free.app", ".trycloudflare.com", ".firebaseapp.com",
                  ".web.app", ".r2.dev", ".supabase.co", ".fly.dev", ".onrender.com", ".repl.co", ".glitch.me")
_SANDBOX_ESCAPE_CMDS = re.compile(r"^(?:\*|\*\*|(?:ba|z|da|fi)?sh|python3?|node|deno|bun|ruby|perl|php|docker|podman|"
                                  r"sudo|su|env|xargs|npx|uvx|pnpx|bunx|curl|wget|nc|ncat|ssh|scp|rsync|kubectl|gh|aws|"
                                  r"gcloud|az)(?:\s+\*+)?$")
_CRED_PATHS = re.compile(r"^(?:/|~|~/|/home/?|/root/?|\$HOME/?|~/\.(?:ssh|aws|azure|config/gcloud|kube|docker|gnupg|"
                         r"npmrc|netrc|git-credentials)(?:/.*)?)$")


def _wild_host(host: str) -> Optional[str]:
    """Why a host pattern is too broad, or None."""
    h = host.strip().lower().split(":")[0]
    if h in ("*", "**", "*.*", "**.*"):
        return "every host"
    if "*" not in h:
        return None
    base = "." + h.lstrip("*.")
    if base.count(".") <= 1:
        return "every name under the top-level domain %s" % base
    if any(base == s or base.endswith(s) for s in _SHARED_TENANT):
        return "every tenant of the shared domain %s, where anyone can create a host" % base
    return None


def _private_cidr(entry: str) -> Optional[str]:
    e = entry.strip().lower()
    if e in ("0.0.0.0/0", "::/0", "0.0.0.0", "*"):
        return "every address"
    try:
        net = ipaddress.ip_network(e, strict=False)
    except ValueError:
        return None
    shared = net.version == 4 and net.subnet_of(ipaddress.ip_network("100.64.0.0/10"))   # carrier-grade NAT
    return "a private network range" if net.is_private or shared else None


def _toml_sections(sf: SourceFile) -> Iterator[Tuple[int, str, str, str]]:
    """(line, section, key, raw value) for simple TOML key = value lines."""
    section = ""
    for i, line in enumerate(sf.nocomment):
        m = re.match(r"^\s*\[\s*([^\]]+?)\s*\]\s*$", line)
        if m:
            section = m.group(1).replace('"', "").replace("'", "")
            continue
        m = re.match(r"""^\s*("[^"]*"|'[^']*'|[\w.\-*]+)\s*=\s*(.+?)\s*$""", line)
        if m:
            yield i + 1, section, m.group(1).strip("\"'"), m.group(2)


def _codex_sandbox(sf: SourceFile, rule: Rule) -> List[Finding]:
    out: List[Finding] = []
    for line, section, key, value in _toml_sections(sf):
        v = value.strip().strip("\"'").lower()
        if section == "sandbox_workspace_write" and key == "network_access" and v == "true":
            out.append(make_finding(rule, sf, line, message=(
                "Codex's workspace-write sandbox lets every command reach any host on the network.")))
        elif (section.endswith("network_proxy.domains") or re.search(r"(?:^|\.)network\.domains$", section)) \
                and v == "allow" and _wild_host(key):
            out.append(make_finding(rule, sf, line, message=(
                "The Codex network allowlist admits %s." % _wild_host(key))))
        elif re.match(r"^permissions\.[^.]+\.network$", section) and key == "mode" and v == "full":
            out.append(make_finding(rule, sf, line, message=(
                "Codex permission profile '%s' gives commands full network access." % section.split(".")[1])))
        elif not section and key == "default_permissions" and v == ":danger-full-access":
            out.append(make_finding(rule, sf, line, message=(
                "Codex's default permission profile has no filesystem or network sandbox.")))
        elif re.search(r"network_proxy$", section) and key == "domains" and re.search(r"""["']\*["']\s*=\s*["']allow""", value):
            out.append(make_finding(rule, sf, line, message="The Codex network allowlist admits every host."))
    return out[:10]


def _claude_sandbox(sf: SourceFile, rule: Rule) -> List[Finding]:
    data = _settings(sf)
    box = data.get("sandbox") if isinstance(data, dict) else None
    if not isinstance(box, dict):
        return []
    out: List[Finding] = []

    def add(key: str, message: str, severity: Optional[str] = None) -> None:
        out.append(make_finding(rule, sf, _line_matching(sf, re.escape('"%s"' % key)), message=message,
                                severity=severity or rule.severity))

    net = box.get("network") if isinstance(box.get("network"), dict) else {}
    for d in net.get("allowedDomains") if isinstance(net.get("allowedDomains"), list) else []:
        why = _wild_host(str(d))
        if why:
            add("allowedDomains", "The Claude Code sandbox pre-allows %s (%s)." % (why, trim(str(d), 40)))
            break
    if net.get("allowAllUnixSockets") is True:
        add("allowAllUnixSockets", "Sandboxed commands can connect to every Unix socket, including the Docker "
                                   "socket, which controls the host.")
    for p in net.get("allowUnixSockets") if isinstance(net.get("allowUnixSockets"), list) else []:
        if "docker.sock" in str(p) or "podman" in str(p):
            add("allowUnixSockets", "Sandboxed commands can use the container engine socket (%s), which controls "
                                    "the host." % trim(str(p), 50))
            break
    for c in box.get("excludedCommands") if isinstance(box.get("excludedCommands"), list) else []:
        if _SANDBOX_ESCAPE_CMDS.match(str(c).strip()):
            add("excludedCommands", "'%s' runs outside the Claude Code sandbox; it can run any other program "
                                    "unsandboxed." % trim(str(c), 30))
            break
    fs = box.get("filesystem") if isinstance(box.get("filesystem"), dict) else {}
    for p in fs.get("allowWrite") if isinstance(fs.get("allowWrite"), list) else []:
        if _CRED_PATHS.match(str(p).strip().rstrip("/") or "/"):
            add("allowWrite", "Sandboxed commands can write to %s (home, root, or credential paths)." % trim(str(p), 40))
            break
    if box.get("enableWeakerNestedSandbox") is True:
        add("enableWeakerNestedSandbox", "The nested Linux sandbox shares the container's /proc; it is weaker by "
                                         "design and relies on the outer container.", "minor")
    return out[:10]


def _openshell_docs(sf: SourceFile) -> List[Dict[str, Any]]:
    try:
        docs = jh_yaml.load_all(sf.text) if sf.lang == "yaml" else [jh_agent.loads_jsonc(sf.text)]
    except (jh_yaml.YamlError, ValueError):
        return []
    return [d for d in docs if isinstance(d, dict)]


def _endpoints(doc: Dict[str, Any]) -> Iterator[Tuple[str, Dict[str, Any], List[Any]]]:
    pols = doc.get("network_policies") if isinstance(doc.get("network_policies"), dict) else {}
    for name, pol in pols.items():
        if not isinstance(pol, dict):
            continue
        bins = pol.get("binaries") if isinstance(pol.get("binaries"), list) else []
        for ep in pol.get("endpoints") if isinstance(pol.get("endpoints"), list) else []:
            if isinstance(ep, dict):
                yield str(name), ep, bins


@check("agent_sandbox_scope")
def agent_sandbox_scope(sf: SourceFile, rule: Rule) -> List[Finding]:
    posix = "/" + sf.rel.lower()
    if posix.endswith(".codex/config.toml"):
        return _codex_sandbox(sf, rule)
    if "/.claude/settings" in posix:
        return _claude_sandbox(sf, rule)
    if "sandbox_policy" not in sf.kinds:
        return []
    out: List[Finding] = []
    for doc in _openshell_docs(sf):
        seen_bins = set()
        for name, ep, bins in _endpoints(doc):
            for b in bins:
                path = str(b.get("path") if isinstance(b, dict) else b).strip()
                if path in ("/**", "/*", "**", "*", "/usr/**", "/usr/bin/*") and name not in seen_bins:
                    seen_bins.add(name)
                    out.append(make_finding(rule, sf, _line_matching(sf, re.escape(path)), message=(
                        "Network rule '%s' applies to every executable (%s), not to the binaries that need it."
                        % (trim(name, 40), path))))
            host = str(ep.get("host") or "")
            why = _wild_host(host) if host else None
            if why:
                out.append(make_finding(rule, sf, _line_matching(sf, re.escape(host)), message=(
                    "Network rule '%s' allows %s (%s)." % (trim(name, 40), why, trim(host, 50)))))
            for ip in ep.get("allowed_ips") if isinstance(ep.get("allowed_ips"), list) else []:
                why_ip = _private_cidr(str(ip))
                if why_ip:
                    out.append(make_finding(rule, sf, _line_matching(sf, re.escape(str(ip))), message=(
                        "Network rule '%s' lets the sandbox reach %s (%s)." % (trim(name, 40), why_ip, ip))))
                    break
            if ep.get("access") == "full" and (why or not host):
                out.append(make_finding(rule, sf, _line_matching(sf, r"access\s*:\s*full"), message=(
                    "Network rule '%s' gives full read-write access on a wildcard or hostless endpoint." % trim(name, 40))))
    return out[:10]


@check("agent_sandbox_enforcement")
def agent_sandbox_enforcement(sf: SourceFile, rule: Rule) -> List[Finding]:
    out: List[Finding] = []
    for doc in _openshell_docs(sf):
        land = doc.get("landlock")
        if isinstance(land, dict) and land.get("compatibility") == "best_effort":
            out.append(make_finding(rule, sf, _line_matching(sf, r"compatibility\s*:\s*best_effort"), message=(
                "Landlock is best_effort: if it cannot be applied, the sandbox runs without its filesystem rules.")))
        elif doc.get("filesystem_policy") is not None and land is None:
            out.append(make_finding(rule, sf, _line_matching(sf, r"^filesystem_policy\s*:"), severity="minor", message=(
                "No landlock section: the default is best_effort, so the filesystem rules are skipped when Landlock "
                "cannot be applied; set compatibility: hard_requirement.")))
        implicit = []
        for name, ep, _ in _endpoints(doc):
            label = trim(name, 40)
            if ep.get("enforcement") == "audit":
                out.append(make_finding(rule, sf, _line_matching(sf, r"enforcement\s*:\s*audit"), message=(
                    "Network rule '%s' is in audit mode: requests that break its rules are logged and allowed." % label)))
            elif ep.get("protocol") not in (None, "tcp") and "enforcement" not in ep:
                implicit.append(label)
            if ep.get("tls") == "skip":
                out.append(make_finding(rule, sf, _line_matching(sf, r"tls\s*:\s*skip"), message=(
                    "Network rule '%s' relays TLS without inspection, so its request rules cannot apply." % label)))
            if ep.get("allow_uninspected_credentials") is True:
                out.append(make_finding(rule, sf, _line_matching(sf, r"allow_uninspected_credentials"), message=(
                    "Network rule '%s' sends brokered credentials over a connection OpenShell does not inspect." % label)))
        if implicit:
            out.append(make_finding(rule, sf, _line_matching(sf, r"protocol\s*:"), severity="minor", message=(
                "%d inspected endpoint(s) omit enforcement, which defaults to audit (log and allow): %s."
                % (len(implicit), ", ".join(implicit[:3])))))
        mws = doc.get("network_middlewares") if isinstance(doc.get("network_middlewares"), dict) else {}
        for name, mw in mws.items():
            if isinstance(mw, dict) and mw.get("on_error") == "fail_open":
                out.append(make_finding(rule, sf, _line_matching(sf, r"on_error\s*:\s*fail_open"), severity="minor",
                                        message="Middleware '%s' fails open: traffic passes uninspected when it errors."
                                        % trim(str(name), 40)))
    return out[:10]


_DC_FLAGS = (
    (re.compile(r"^--privileged(?:=true)?$"), "runs privileged, with every capability and host devices"),
    (re.compile(r"^--(?:network|net)(?:=|\s+)host$"), "shares the host network"),
    (re.compile(r"^--pid(?:=|\s+)host$"), "shares the host process namespace"),
    (re.compile(r"^--cap-add(?:=|\s+)(?:SYS_ADMIN|ALL|SYS_PTRACE|NET_ADMIN)$", re.I), "adds a host-level capability"),
    (re.compile(r"^--security-opt(?:=|\s+)(?:seccomp|apparmor)[=:]unconfined$"), "turns off seccomp or AppArmor"),
)


@check("devcontainer_isolation")
def devcontainer_isolation(sf: SourceFile, rule: Rule) -> List[Finding]:
    if not sf.rel.lower().endswith("devcontainer.json"):
        return []
    data = _settings(sf)
    if data is None:
        return []
    out: List[Finding] = []
    args = [str(a) for a in data.get("runArgs") if isinstance(a, (str, int))] if isinstance(data.get("runArgs"), list) else []
    joined = [" ".join(args[i:i + 2]) for i in range(len(args))] + args
    reported = set()
    for rx, why in _DC_FLAGS:
        for a in joined:
            if rx.match(a.strip()) and why not in reported:
                reported.add(why)
                out.append(make_finding(rule, sf, _line_matching(sf, re.escape(a.split()[0])), message=(
                    "The dev container %s (%s)." % (why, trim(a, 40)))))
    if data.get("privileged") is True and "runs privileged, with every capability and host devices" not in reported:
        out.append(make_finding(rule, sf, _line_matching(sf, r'"privileged"'), message=(
            "The dev container runs privileged, with every capability and host devices.")))
    for cap in data.get("capAdd") if isinstance(data.get("capAdd"), list) else []:
        if str(cap).upper() in ("SYS_ADMIN", "ALL", "SYS_PTRACE", "NET_ADMIN"):
            out.append(make_finding(rule, sf, _line_matching(sf, r'"capAdd"'), message=(
                "The dev container adds the %s capability." % str(cap).upper())))
            break
    mounts = " ".join(str(m) for m in data.get("mounts") if isinstance(m, (str, dict))) if isinstance(data.get("mounts"), list) else ""
    if "docker.sock" in mounts + " ".join(args):
        out.append(make_finding(rule, sf, _line_matching(sf, r"docker\.sock"), message=(
            "The dev container mounts the host Docker socket: anything inside it can start a privileged container "
            "on the host.")))
    return out[:10]


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
    if posix.endswith("devcontainer.json"):
        # initializeCommand runs on the host, outside the container, whenever
        # the repository is (re)opened in a container; in-container hooks are
        # ordinary setup and are not flagged.
        command = data.get("initializeCommand")
        if isinstance(command, dict):
            command = "; ".join(str(v) for v in command.values())
        elif isinstance(command, list):
            command = " ".join(str(v) for v in command)
        if isinstance(command, str) and command.strip():
            out.append(make_finding(rule, sf, _line_matching(sf, r'"initializeCommand"'), message=(
                "Dev container initializeCommand runs on the host machine, outside the container, whenever "
                "someone reopens this repository in a container."), evidence=redact_secrets(trim(command, 160))))
        return out
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
    except (ValueError, RecursionError):
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


def _grants_write_explicit(perms: Any) -> bool:
    """Write access stated in the workflow (unset permissions are not visible here)."""
    return perms is not None and _grants_write(perms)


# branch prefixes AI coding agents push to (Claude, Copilot, Codex, Cursor, Devin, generic)
_AGENT_BRANCH_RE = re.compile(r"^(?:claude|copilot|codex|cursor|devin|agent|agents|ai|bot|bots|jules|opencode)[/-]", re.I)
# a job pinned to one exact branch or to tags; `!=` or a branch prefix (claude/) is not pinned
_SCOPED_JOB_IF_RE = re.compile(r"""^\s*(?:\$\{\{\s*)?(?:github\.ref\s*==\s*['"]refs/heads/[^'"*]+['"]|"""
                               r"""github\.ref_name\s*==\s*['"][^'"*]+['"]|startsWith\(\s*github\.ref\s*,\s*['"]refs/tags/)""")


def _push_any_branch(on: Any) -> Optional[str]:
    """How a workflow's push trigger reaches unreviewed branches, or None."""
    if isinstance(on, (str, list)):
        return "push to any branch" if "push" in _events(on) else None
    if not isinstance(on, dict) or "push" not in on:
        return None
    push = on.get("push")
    if not isinstance(push, dict) or not push:
        return "push to any branch"
    branches = push.get("branches")
    if branches is None:
        if push.get("branches-ignore") is not None:
            return "push to any branch not ignored"
        return None if push.get("tags") is not None else "push to any branch"
    for b in branches if isinstance(branches, list) else [branches]:
        b = str(b).strip()
        if b in ("*", "**", "**/*", "*/**") or b.startswith("*"):
            return "push to any branch matching %s" % b
        if _AGENT_BRANCH_RE.match(b):
            return "push to agent branches %s" % b
    return None


@check("gh_branch_push_privileged")
def gh_branch_push_privileged(sf: SourceFile, rule: Rule) -> List[Finding]:
    """Agent-branch CI: a push to any (or an agent's) branch runs a job holding
    secrets or an explicitly write-scoped token. A job pinned to a branch with
    `if:` or guarded by an environment is not flagged."""
    if "push" not in sf.text:
        return []
    try:
        docs = jh_yaml.load_all(sf.text)
    except jh_yaml.YamlError:
        return []
    doc = docs[0] if docs and isinstance(docs[0], dict) else {}
    how = _push_any_branch(doc.get("on", doc.get(True)))
    if not how:
        return []
    jobs = doc.get("jobs") if isinstance(doc.get("jobs"), dict) else {}
    for name, job in jobs.items():
        cond = str(job.get("if") or "") if isinstance(job, dict) else ""
        if not isinstance(job, dict) or job.get("environment") or ("||" not in cond and _SCOPED_JOB_IF_RE.search(cond)):
            continue
        perms = job.get("permissions", doc.get("permissions"))
        body = str(job) + str(doc.get("env") or "")
        secrets = sorted(set(re.findall(r"secrets\.(?!GITHUB_TOKEN\b)(\w+)", body)))
        if job.get("secrets") == "inherit":
            secrets = secrets or ["(all, inherited)"]
        write = _grants_write_explicit(perms)
        if not (secrets or write):
            continue
        power = ", ".join(filter(None, ["secrets %s" % ", ".join(secrets[:3]) if secrets else "",
                                        "a write-scoped GITHUB_TOKEN" if write else ""]))
        return [make_finding(rule, sf, _line_matching(sf, r"^\s*%s\s*:" % re.escape(str(name))), message=(
            "Job '%s' runs on %s with %s; code on a branch nobody has reviewed runs with that power."
            % (trim(str(name), 40), how, power)), extra={"trigger": how, "job": str(name)})]
    return []


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
                           r"unittest|np\.testing|assert_that)\b|"
                           # helpers named for checking, possibly defined in a shared base class elsewhere
                           r"\bself\.(?:check|verify|expect|must|should)_\w+\s*\(|"
                           r"\bself\.\w*(?:rejected|refused|denied|forbidden|raises|fails|blocked)\s*\(")


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
            # the decorator block above the def, including decorators whose
            # arguments span several lines
            above = []
            for k in range(start - 1, max(-1, start - 13), -1):
                s = sf.code[k].strip()
                if not s or re.match(r"(?:async\s+)?def\s|class\s", s):
                    break
                above.append(s)
            if any(re.match(r"@(?:pytest\.)?fixture\b", s) for s in above):
                continue
            body = "\n".join(sf.code[start:end + 1])
            if _PY_ASSERT_RE.search(body) or (calls and calls.search(body)):
                continue
            # a checking helper on a test-support module (mytestlib.check_ok(...), test_utils.assert_valid(...)); a
            # method of the code under test (limiter.check_n(...), oracle.verify_with_test(...)) is not an assertion
            if re.search(r"\b(?:\w*test\w*|helpers?|assertions?|checks?)\.(?:check|verify|assert|expect)_\w+\s*\(", body):
                continue
            raw_body = "\n".join(sf.nocomment[start:end + 1])
            if re.search(r"\bsimplefilter\s*\(\s*[\"']error[\"']", raw_body):
                continue
            out.append(make_finding(rule, sf, start + 1, end_line=end + 1,
                                    message="Test '%s' contains no assertion." % name))
            if len(out) >= 10:
                break
        return out

    if sf.lang == "rust":
        return _rust_assertion_free(sf, rule)
    if sf.lang in _NOT_CODE:
        return out
    lines = sf.code
    # project-local helpers that assert: near(a, b), close(x, y, eps)
    names = []
    for k, line in enumerate(lines):
        d = re.match(r"\s*(?:export\s+)?(?:async\s+)?(?:function\s+(\w+)\s*\(|(?:const|let|var)\s+(\w+)\s*=\s*"
                     r"(?:async\s+)?(?:\([^)]*\)|\w+)\s*=>)", line)
        if d and (d.group(1) or d.group(2)) not in ("test", "it", "describe"):
            if "{" in line[d.end():] or (k + 1 < len(lines) and lines[k + 1].strip().startswith("{")):
                end, _opened = _brace_blocks(sf, k, max_lines=200)
                span = "\n".join(lines[k:end + 1])
            else:
                # an arrow with an expression body: this line, or the next ones when it ends in `=>`
                body, depth, j = [line], 0, k
                while j + 1 < len(lines) and len(body) < 12 and (j == k and line.rstrip().endswith("=>") or depth > 0):
                    j += 1
                    body.append(lines[j])
                    depth += lines[j].count("(") - lines[j].count(")")
                span = "\n".join(body)
            if _JS_ASSERT_RE.search(span) or re.search(r"\bthrow\b|\bassert\.\w+\(|\.ok\(", span):
                names.append(d.group(1) or d.group(2))
    helper_re = re.compile(r"(?<![\w.$])(?:%s)\s*\(" % "|".join(map(re.escape, names))) if names else None
    for i, line in enumerate(lines):
        # a test call with a title: test("...", ...) / it('...') / test.only(`...`);
        # not regex.test(x), a Rust #[tokio::test(...)] attribute, or prose
        call = _JS_TEST_CALL_RE.search(line)
        if not call:
            continue
        if re.search(r"\bfunction\s*\*?\s*$|\b(?:const|let|var)\s+$", line[:call.start()]):
            continue                    # function test(name, fn) {...}: a runner, not a test
        if "{" in line or (i + 1 < len(lines) and lines[i + 1].strip().startswith("{")):
            end, opened = _brace_blocks(sf, i, max_lines=300)
            body = "\n".join(lines[i:end + 1])
            if opened and not _JS_ASSERT_RE.search(body) and not (helper_re and helper_re.search(body)):
                out.append(make_finding(rule, sf, i + 1, end_line=end + 1,
                                        message="Test block contains no assertion."))
        else:
            # an arrow body on the next lines: read until the test call's parenthesis closes
            span, depth = [], 0
            for k in range(i, min(i + 20, len(lines))):
                span.append(lines[k])               # the whole line: expect(test(...)) asserts
                part = lines[k][_JS_TEST_CALL_RE.search(lines[k]).start():] if k == i else lines[k]
                depth += part.count("(") - part.count(")")
                if depth <= 0:
                    break
            if not _JS_ASSERT_RE.search("\n".join(span)) and not (helper_re and helper_re.search("\n".join(span))):
                out.append(make_finding(rule, sf, i + 1, message="Test contains no assertion on this line."))
        if len(out) >= 10:
            break
    return out


_NOT_CODE = {"markdown", "text", "yaml", "json", "toml", "ini", "html", "xml", "css", "hcl", "docker", "sql"}
# test("title", ...) / it(name, ...) / test.only(`...`); a string or a name
# followed by a comma, so not regex.test(x), #[tokio::test(...)], or prose
_JS_TEST_CALL_RE = re.compile(r"(?<![\w.$:#])(?:it|test)(?:\.(?:only|concurrent|skip|fails|each\s*\([^)]*\)))?\s*\("
                              r"\s*(?:[\"'`]|[A-Za-z_$][\w$.]*\s*,)")
# expect/assert/should, helpers named for them (verifyInput, assertVisible),
# chai/should chains, ava's t.is/t.true, snapshots
_JS_ASSERT_RE = re.compile(r"\b(?:expect|assert|should)\b|\b(?:expect|assert|verify|check|should)[A-Z_]\w*\s*\(|"
                           r"\b(?:rejected|refused|denied|blocked|forbidden)\s*\(|"
                           r"\.should\b|\bt\.(?:is|not|true|false|deepEqual|throws|snapshot|assert)\b|"
                           r"\b(?:get|getAll|find|findAll)By[A-Z]\w*\s*\(|"     # Testing Library queries throw
                           r"\.toMatch(?:Inline)?Snapshot\b")
_RUST_TEST_ATTR_RE = re.compile(r"^\s*#\[(?:[\w:]+::)?test\b")
# assert macros, helpers named for them, and failing on error: unwrap/expect
# panic, and `?` in a test that returns Result fails it
_RUST_ASSERT_RE = re.compile(r"\b(?:assert\w*|debug_assert\w*|prop_assert\w*|panic|unreachable)!|"
                             r"\b(?:assert|check|verify|expect)_\w+\s*\(|\.unwrap(?:_err)?\(\)|\.expect(?:_err)?\(|"
                             r"\?\s*[;)]|\?\s*$|\.await\?")


def _rust_assertion_free(sf: SourceFile, rule: Rule) -> List[Finding]:
    out: List[Finding] = []
    lines = sf.code
    for i, line in enumerate(lines):
        if not _RUST_TEST_ATTR_RE.match(line):
            continue
        j = next((k for k in range(i + 1, min(i + 8, len(lines))) if re.search(r"\bfn\s+\w+", lines[k])), None)
        if j is None or any("should_panic" in lines[k] for k in range(i, j)):
            continue
        end, opened = _brace_blocks(sf, j, max_lines=400)
        body = "\n".join(lines[j:end + 1])
        inner = [l.strip() for l in lines[j + 1:end] if l.strip()]
        if re.search(r"->\s*(?:[\w:]+::)?Result\b", lines[j]) and inner and inner[-1].endswith((")", ".await")) \
                and not inner[-1].startswith("Ok("):
            continue                    # the returned Result of a call is the assertion
        if opened and not _RUST_ASSERT_RE.search(body):
            name = re.search(r"\bfn\s+(\w+)", lines[j]).group(1)
            out.append(make_finding(rule, sf, j + 1, end_line=end + 1,
                                    message="Test '%s' contains no assertion." % name))
            if len(out) >= 10:
                break
    return out


@check("broken_links")
def broken_links(sf: SourceFile, rule: Rule) -> List[Finding]:
    out: List[Finding] = []
    base = os.path.dirname(sf.abspath)
    fence: Optional[Tuple[str, int]] = None
    for i, line in enumerate(sf.raw):
        # inside a code fence a link-shaped span is example code (Python `fn[key](**kw)`), not navigation.
        # CommonMark: the fence closes only on the same character, at least as long, with no info string,
        # so a ````markdown example holding an inner ``` block stays one fence
        f = re.match(r"\s{0,3}(`{3,}|~{3,})(.*)$", line)
        if f:
            run, rest = f.group(1), f.group(2).strip()
            if fence is None and run[0] == "`" and "`" in rest:
                f = None                    # inline code on one line, not a fence
        if f:
            if fence is None:
                fence = (run[0], len(run))
                continue
            if run[0] == fence[0] and len(run) >= fence[1] and not rest:
                fence = None
                continue
        if fence:
            continue
        for m in re.finditer(r"!?\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)", line):
            target = m.group(1).strip()
            if target.startswith(("http://", "https://", "mailto:", "tel:", "#", "/", "<")):
                continue
            if "{{" in target or "{%" in target:
                continue
            # a doc macro (:git:repo:path), a placeholder with no Latin letters or digits ("链接", "..."),
            # or any link in a template, whose targets resolve in the generated output
            template = (re.search(r"(?i)[_.-]template\.(?:md|markdown)$", sf.basename) and
                        not re.match(r"(?i)(?:pull_request|issue)_template", sf.basename)) or \
                re.search(r"(?i)(?:^|/)templates?/", sf.rel)
            placeholder = not re.search(r"[A-Za-z0-9]", target) and not re.fullmatch(r"(?:\.{1,2}/)*\.{1,2}/?", target)
            if target.startswith(":") or placeholder or template:
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


@check("package_json_dep")
def package_json_dep(sf: SourceFile, rule: Rule) -> List[Finding]:
    """'*' or 'latest' in package.json. Inside peerDependencies an open range is the usual way to say
    "whatever the host app uses", but npm 7+ installs missing peers itself, so it is info, not minor."""
    out: List[Finding] = []
    peer = 0                                    # brace depth inside "peerDependencies": { ... }
    for i, line in enumerate(sf.nocomment):
        if peer:
            peer = max(0, peer + line.count("{") - line.count("}"))
        elif re.match(r'^\s*"peerDependencies"\s*:\s*\{', line):
            peer = max(0, line.count("{") - line.count("}"))
            continue
        if not re.match(r'^\s*"[^"]+"\s*:\s*"(?:\*|latest)"', line):
            continue
        if peer:
            out.append(make_finding(rule, sf, i + 1, severity="info", confidence="medium",
                                    message="An open peer dependency range lets the host app choose the version; "
                                            "npm 7+ installs a missing peer itself, at the newest release."))
        else:
            out.append(make_finding(rule, sf, i + 1))
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


def _shutil_unpack_call(text: str) -> "re.Pattern[str]":
    """Calls of shutil.unpack_archive under the names this file gives it: the
    module or an alias of it, or a name imported from it (on one line or in
    parentheses, with `as`, or *), unless the file defines its own."""
    modules = ["shutil"] + re.findall(r"^\s*import\s+shutil\s+as\s+(\w+)", text, re.M)
    names: List[str] = []
    for imp in re.finditer(r"^\s*from\s+shutil\s+import\s+(\([^)]*\)|[^\n]*)", text, re.M):
        if "*" in imp.group(1):
            names.append("unpack_archive")
        names += [a.group(1) or "unpack_archive" for a in re.finditer(r"\bunpack_archive\b(?:\s+as\s+(\w+))?",
                                                                      imp.group(1))]
    names = [n for n in names if not re.search(r"\bdef\s+%s\b" % n, text)]
    calls = [r"\b(?:%s)\.unpack_archive\s*\(" % "|".join(modules)]
    if names:
        calls.append(r"(?<![\w.])(?:%s)\s*\(" % "|".join(names))
    return re.compile("|".join(calls))


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
    unpack_call = _shutil_unpack_call(sf.text) if rule.id == "JH120" else None
    for i, line in enumerate(sf.code):
        if rule.id == "JH119":
            # tarfile's "data"/"tar" extraction filters (Python 3.12+, backported)
            # refuse absolute paths and members outside the destination; the
            # filter is a string, so read the line with its strings intact
            call = []
            if ".extractall(" in line:
                depth = 0
                for k in range(i, min(i + 12, len(sf.code))):
                    call.append(sf.nocomment[k] if k < len(sf.nocomment) else sf.code[k])
                    depth += sf.code[k].count("(") - sf.code[k].count(")")
                    if depth <= 0:
                        break
            text = "\n".join(call)
            hit = bool(call) and not re.search(r"(?i)zip", line) and not re.search(
                r"\bfilter\s*=\s*(?:[\"'](?:data|tar)[\"']|tarfile\.(?:data|tar)_filter)", text)
        else:
            # zipfile strips absolute paths and ".." components itself, so only
            # unpack_archive (which can hand tar files to tarfile) is a lead
            hit = bool(unpack_call and unpack_call.search(line))
        if hit:
            out.append(make_finding(rule, sf, i + 1,
                                    message="Archive extraction without path validation enables zip-slip/path traversal."))
            if len(out) >= 5:
                break
    return out


_HTTP_CALLEE_RE = re.compile(r"(?:^|[.\s=(])(?:(?:requests|httpx|aiohttp|urllib3)\.\w+|"
                             r"\w*(?:session|sess|client|http)\w*\.\w+|"
                             r"(?:Session|Client|AsyncClient|PoolManager|ClientSession)|"
                             r"\w+\.(?:get|post|put|patch|delete|head|options|request|send|stream))$", re.IGNORECASE)
_TLS_PATTERNS: Dict[str, List[re.Pattern]] = {}


def _enclosing_callee(lines: Sequence[str], i: int, col: int) -> Optional[str]:
    """The callee of the call whose arguments contain lines[i][col], by
    matching parentheses backwards (up to 40 lines); None outside any call."""
    depth = 0
    for k in range(i, max(-1, i - 40), -1):
        text = lines[k][:col] if k == i else lines[k]
        for pos in range(len(text) - 1, -1, -1):
            ch = text[pos]
            if ch == ")":
                depth += 1
            elif ch == "(":
                if depth == 0:
                    m = re.search(r"[\w.]+$", text[:pos].rstrip())
                    return m.group(0) if m else ""
                depth -= 1
    return None


_EXEC_LITERAL_RE = re.compile(r"(?:eval|exec|setTimeout|setInterval)\s*\(\s*[rbu]?([\"'])([^\"'\n]*)\1\s*[,)]")
_EXEC_PATTERNS: Dict[str, List[re.Pattern]] = {}


_DESERIALIZERS = {
    "python": (r"\bpickle\.loads?\s*\(", r"\bmarshal\.loads?\s*\(", r"\bdill\.loads?\s*\(",
               r"\byaml\.load\s*\(", r"\byaml\.unsafe_load\s*\("),
    "php": (r"\bunserialize\s*\(",),
    "js": (r"\bunserialize\s*\(",),                 # node-serialize; js-yaml 4's load is the safe loader
    "jvm": (r"\bnew\s+ObjectInputStream\b", r"\bnew\s+XMLDecoder\b", r"\.readObject\s*\(\s*\)"),
    "csharp": (r"\bnew\s+BinaryFormatter\b", r"\bNetDataContractSerializer\b"),
    "ruby": (r"\bMarshal\.load\s*\(",),
}


@check("unsafe_deserialization")
def unsafe_deserialization(sf: SourceFile, rule: Rule) -> List[Finding]:
    """JH106 with each language's own native deserializers."""
    lang = {"js": "js", "ts": "js", "java": "jvm", "kotlin": "jvm", "scala": "jvm", "groovy": "jvm"}.get(sf.lang, sf.lang)
    pats = _DESERIALIZERS.get(lang)
    if not pats:
        return []
    out: List[Finding] = []
    for i, line in enumerate(sf.code):
        raw = sf.nocomment[i] if i < len(sf.nocomment) else line
        for p in pats:
            m = re.search(p, line)           # the call itself, never text inside a string
            if not m:
                continue
            # yaml.load(f, SafeLoader) or Loader=yaml.SafeLoader, also over several lines
            if "yaml" in p:
                call, depth = [], 0
                for k in range(i, min(i + 8, len(sf.code))):
                    call.append((sf.nocomment[k] if k < len(sf.nocomment) else sf.code[k])[m.start() if k == i else 0:])
                    depth += sf.code[k][m.start() if k == i else 0:].count("(") - sf.code[k][m.start() if k == i else 0:].count(")")
                    if depth <= 0:
                        break
                text = "\n".join(call)
                alias = re.search(r"\bLoader\s*=\s*(\w+)\s*[,)]", text)
                if re.search(r"\b(?:Safe|CSafe|Base)Loader\b", text) or (alias and re.search(
                        r"\b(?:C?SafeLoader|BaseLoader)\s+as\s+%s\b|\bclass\s+%s\s*\(\s*(?:yaml\.)?(?:C?SafeLoader|BaseLoader)\s*\)"
                        % (re.escape(alias.group(1)), re.escape(alias.group(1))), sf.text)):
                    continue
            out.append(make_finding(rule, sf, i + 1, column=m.start() + 1))
            break
        if len(out) >= 5:
            break
    return out


@check("dynamic_exec")
def dynamic_exec(sf: SourceFile, rule: Rule) -> List[Finding]:
    """JH102, per call: eval/exec of one constant string with no
    interpolation is not data turned into code; any other call on the line is."""
    pats = _EXEC_PATTERNS.setdefault(rule.id, [re.compile(p) for p in rule.patterns])
    out: List[Finding] = []
    for i, line in enumerate(sf.code):
        raw = sf.nocomment[i] if i < len(sf.nocomment) else line
        for pat in pats:
            hit = None
            if "exec" in pat.pattern and sf.lang != "python":
                continue                    # JS/PHP/Ruby exec() runs a command, not code (JH103's job)
            for m in pat.finditer(line):
                if re.search(r"\bdef\s+$", line[:m.start()]) or (
                        re.match(r"^\s*(?:(?:async|static|public|private|protected)\s+)*$", line[:m.start()])
                        and re.match(r"\w+\s*\([^)]*\)\s*(?::\s*[\w<>\[\], |]+)?\s*\{|"
                                     r"\w+\s*\([^)]*\)\s*:\s*[\w<>\[\], |.]+;?\s*$", line[m.start():])):
                    continue                # `def exec(self, ...)`, `async eval(expr) {` or `eval(s: string): T;` declares one
                lit = _EXEC_LITERAL_RE.match(raw, m.start())
                if lit and not re.search(r"[$%{}`]|#\{", lit.group(2)):
                    continue
                hit = m
                break
            if hit:
                test = "test" in sf.kinds or is_test_path(sf.rel)
                out.append(make_finding(rule, sf, i + 1, column=hit.start() + 1,
                                        severity="minor" if test else None, confidence="low" if test else None))
                break
        if len(out) >= 5:
            break
    return out


_SERVER_TLS_RE = re.compile(r"\bPROTOCOL_TLS_SERVER\b|\bPurpose\.CLIENT_AUTH\b|\bserver_side\s*=\s*True\b")


def _server_tls_context(code: Sequence[str], i: int) -> bool:
    """True when the setting on line i belongs to a server's TLS context: `X.verify_mode = ...` where X was made as
    a server context above (within 40 lines), or a call on this line with server_side=True."""
    if re.search(r"\bserver_side\s*=\s*True\b", code[i]):
        return True
    m = re.match(r"\s*([A-Za-z_][\w.]*)\.(?:verify_mode|check_hostname)\s*=", code[i])
    if not m:
        return False
    made = re.compile(r"(?:^|[^\w.])%s\s*=\s*[^=\n]*?\b(?:SSLContext|create_default_context)\s*\(" % re.escape(m.group(1)))
    for j in range(i - 1, max(-1, i - 40), -1):
        if made.search(code[j]):
            expr, k = code[j], j                    # the constructor, until its parentheses close
            while expr.count("(") > expr.count(")") and k + 1 < min(i, j + 8):
                k += 1
                expr += " " + code[k]
            return bool(_SERVER_TLS_RE.search(expr))
    return False


@check("tls_verify_disabled")
def tls_verify_disabled(sf: SourceFile, rule: Rule) -> List[Finding]:
    """JH105. `verify=False` is a TLS setting only for HTTP clients; on any
    other call it is that function's own flag (verify a checksum, say)."""
    pats = _TLS_PATTERNS.setdefault(rule.id, [re.compile(p) for p in rule.patterns])
    out: List[Finding] = []
    for i, line in enumerate(sf.code):
        for pat in pats:
            m = pat.search(line)
            if not m:
                continue
            if "insecure" in pat.pattern and re.search(r"\b(?:expect|assert\w*)\s*\(|\.to[A-Z]\w*\s*\(", line):
                break                       # an expected value in a test (toMatchObject({insecure: true}))
            if ("CERT_NONE" in pat.pattern or "check_hostname" in pat.pattern) and _server_tls_context(sf.code, i):
                break                       # a server not asking clients for certificates: the default, not a hole
            if pat.pattern.startswith(r"\bverify\s*="):
                callee = _enclosing_callee(sf.code, i, m.start())
                if callee is None:
                    # `session.verify = False` is the TLS switch of a client object
                    if not re.search(r"(?i)\b\w*(?:session|sess|client|http)\w*\.verify\s*=\s*False", line):
                        break
                elif not _HTTP_CALLEE_RE.search(callee):
                    break
            out.append(make_finding(rule, sf, i + 1, column=m.start() + 1))
            break
        if len(out) >= 5:
            break
    return out


_SCRIPT_PATH_RE = re.compile(r"(^|/)(scripts?|bin|cli|tools?|examples?|samples?|demos?|migrations?|extra|tasks|hack)/|"
                             r"(^|/)(?:[^/]*[-_.])?(?:migrate|migration|cli|script)(?:[-_.][^/]*)?\.[cm]?[jt]sx?$",
                             re.IGNORECASE)
_DEBUG_HOOKS = {
    "python": (r"\bpdb\.set_trace\s*\(", r"\bbreakpoint\s*\(\s*\)"),
    "ruby": (r"\bbinding\.pry\b",),
    "php": (r"\bdd\s*\(", r"\bvar_dump\s*\("),
    "js": (r"(?<![\w.$])debugger\s*(?:;|$)", r"\bconsole\.log\s*\("),
}


@check("debug_leftover")
def debug_leftover(sf: SourceFile, rule: Rule) -> List[Finding]:
    """JH204. Each language's own debug hooks; console.log only in app code,
    not in CLI scripts, examples, or migrations whose output is the point."""
    lang = "js" if sf.lang in ("js", "ts", "vue", "svelte") else sf.lang
    pats = _DEBUG_HOOKS.get(lang)
    if not pats:
        return []
    cli = bool(_SCRIPT_PATH_RE.search(sf.rel)) or (sf.raw[:1] and sf.raw[0].startswith("#!")) \
        or "test" in sf.kinds or is_test_path(sf.rel)
    out: List[Finding] = []
    for i, line in enumerate(sf.code):
        for p in pats:
            if "console" in p and cli:
                continue
            m = re.search(p, line)
            if m and "console" in p:
                # one literal message ("listening on 5000") is logging; dumping values is debugging
                arg = (sf.nocomment[i] if i < len(sf.nocomment) else line)[m.end():].lstrip()
                lit = re.match(r"""(['"`])(?:\\.|(?!\1).)*\1\s*\)""", arg)
                if lit:
                    m = None
            if m:
                out.append(make_finding(rule, sf, i + 1, column=m.start() + 1))
                break
        if len(out) >= 5:
            break
    return out


@check("dangerous_capability")
def dangerous_capability(sf: SourceFile, rule: Rule) -> List[Finding]:
    """JH414. Flag SYS_ADMIN/NET_ADMIN/SYS_PTRACE/ALL only under `add:`;
    `drop: [ALL]` is the hardened setting, not a risk."""
    out: List[Finding] = []
    section: Optional[Tuple[int, str]] = None        # (indent of the add:/drop: key, which)
    for i, line in enumerate(sf.nocomment):
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        m = re.match(r"^\s*(add|drop)\s*:\s*(.*)$", line)
        if m:
            section = (indent, m.group(1))
            inline = m.group(2)
            if m.group(1) == "add" and re.search(r"(?i)\b(?:SYS_ADMIN|NET_ADMIN|SYS_PTRACE|ALL)\b", inline):
                out.append(make_finding(rule, sf, i + 1))
            continue
        # a shallower line, or a same-level key, ends the add:/drop: list
        if section and (indent < section[0] or (indent == section[0] and not line.lstrip().startswith("- "))):
            section = None
        if section and section[1] == "add" and re.match(r"(?i)^\s*-\s*['\"]?(?:SYS_ADMIN|NET_ADMIN|SYS_PTRACE|ALL)['\"]?\s*$", line):
            out.append(make_finding(rule, sf, i + 1))
        if len(out) >= 5:
            break
    return out
