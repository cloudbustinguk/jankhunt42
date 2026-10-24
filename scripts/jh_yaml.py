#!/usr/bin/env python3
"""A deliberately small, bounded YAML-subset reader (stdlib has no YAML).

Supports what Kubernetes manifests, docker-compose files, and GitHub Actions
workflows use in practice: block mappings and sequences, plain/quoted
scalars, flow sequences/maps of scalars (also spread over several lines,
as formatters write long `needs:` lists), comments, `---` document breaks,
and block scalars (`|`, `>`), which are kept as opaque strings. Anchors,
aliases, tags, and merge keys are not interpreted; their text is kept as a
plain scalar. Anything it cannot parse raises YamlError so callers can
record a parse limitation instead of guessing.

It never evaluates anything, never resolves tags to Python objects, and
caps nesting depth and document count so hostile input stays bounded.
"""
from __future__ import annotations

import re
from typing import Any, List, Optional, Tuple

MAX_DEPTH = 64
MAX_DOCS = 500
MAX_LINES = 200000


class YamlError(ValueError):
    pass


_COMMENT_RE = re.compile(r"(^|\s)#.*$")
# `key: |`, `- >-`, `run: |2`: the lines that follow are an opaque block scalar.
_BLOCK_INDICATOR_RE = re.compile(r"(?:^|:\s+|^-\s+)[|>][-+0-9]*$")


def _opens_quote(text: str, i: int) -> bool:
    """A quote starts a quoted scalar only where a scalar starts; the
    apostrophe in `don't` is part of a plain scalar."""
    return i == 0 or text[i - 1] in " \t[{,:"


def _flow_depth(text: str) -> int:
    """Open flow brackets ([ and {) outside quotes."""
    depth, quote = 0, ""
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = ""
            continue
        if ch in ("'", '"') and _opens_quote(text, i):
            quote = ch
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
    return depth


def _flow_starts(content: str) -> bool:
    """The value on this line (or the line itself) opens a flow collection."""
    if content.startswith(("[", "{")):
        return True
    rest = content[2:].lstrip() if content.startswith("- ") else content
    kv = _split_key(rest)
    return bool(kv and kv[1].startswith(("[", "{")))


def _strip_comment(line: str) -> str:
    if "#" not in line:
        return line.rstrip()
    out = []
    quote = ""
    for i, ch in enumerate(line):
        if quote:
            out.append(ch)
            if ch == quote:
                quote = ""
            continue
        if ch in ("'", '"') and _opens_quote(line, i):
            quote = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            break
        out.append(ch)
    return "".join(out).rstrip()


def _scalar(text: str) -> Any:
    t = text.strip()
    if not t:
        return None
    if (t[0] == t[-1]) and t[0] in ("'", '"') and len(t) >= 2:
        return t[1:-1]
    if t.startswith("[") and t.endswith("]"):
        inner = t[1:-1].strip()
        return [_scalar(p) for p in _split_flow(inner)] if inner else []
    if t.startswith("{") and t.endswith("}"):
        inner = t[1:-1].strip()
        out = {}
        for part in _split_flow(inner) if inner else []:
            if ":" in part:
                k, v = part.split(":", 1)
                out[str(_scalar(k))] = _scalar(v)
        return out
    low = t.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if low in ("null", "~"):
        return None
    if re.fullmatch(r"-?\d+", t):
        try:
            return int(t)
        except ValueError:
            return t
    return t


def _split_flow(text: str) -> List[str]:
    parts, depth, quote, cur = [], 0, "", []
    for i, ch in enumerate(text):
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = ""
            continue
        if ch in ("'", '"') and _opens_quote(text, i):
            quote = ch
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
            continue
        cur.append(ch)
    if "".join(cur).strip():
        parts.append("".join(cur).strip())
    return parts


def _split_key(text: str) -> Optional[Tuple[str, str]]:
    """Split `key: value` at the first unquoted ': ' (or trailing ':')."""
    quote = ""
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = ""
            continue
        if ch in ("'", '"') and i == 0:
            quote = ch
            continue
        if ch == ":" and (i + 1 == len(text) or text[i + 1] in " \t"):
            key = text[:i].strip()
            if (key[:1] == key[-1:]) and key[:1] in ("'", '"') and len(key) >= 2:
                key = key[1:-1]
            return key, text[i + 1:].strip()
    return None


class _Parser:
    def __init__(self, lines: List[Tuple[int, int, str]]):
        # (line_no, indent, content) with comments and blank lines removed
        self.lines = lines
        self.i = 0

    def parse_block(self, indent: int, depth: int) -> Any:
        if depth > MAX_DEPTH:
            raise YamlError("nesting too deep")
        if self.i >= len(self.lines):
            return None
        _, ind, content = self.lines[self.i]
        if ind < indent:
            return None
        if content.startswith("- ") or content == "-":
            return self.parse_seq(ind, depth)
        if content.startswith(("[", "{")) and _flow_depth(content) == 0:
            # a flow collection on its own line(s) as a block value
            self.i += 1
            return _scalar(content)
        return self.parse_map(ind, depth)

    def _block_scalar(self, parent_indent: int) -> str:
        out = []
        while self.i < len(self.lines) and self.lines[self.i][1] > parent_indent:
            out.append(self.lines[self.i][2])
            self.i += 1
        return "\n".join(out)

    def _value(self, rest: str, ind: int, depth: int) -> Any:
        if rest in ("|", ">", "|-", ">-", "|+", ">+"):
            return self._block_scalar(ind)
        if rest == "" or rest.startswith(("&", "!")) and " " not in rest:
            if self.i < len(self.lines) and (self.lines[self.i][1] > ind or
                                             (self.lines[self.i][1] == ind and self.lines[self.i][2].startswith("- "))):
                return self.parse_block(self.lines[self.i][1], depth + 1)
            return None if rest == "" else rest
        return _scalar(rest)

    def parse_map(self, indent: int, depth: int) -> Any:
        out = {}
        while self.i < len(self.lines):
            ln, ind, content = self.lines[self.i]
            if ind < indent:
                break
            if ind > indent:
                raise YamlError("line %d: unexpected indentation" % ln)
            if content.startswith("- "):
                break
            kv = _split_key(content)
            if kv is None:
                raise YamlError("line %d: expected 'key: value'" % ln)
            self.i += 1
            key, rest = kv
            out[key] = self._value(rest, ind, depth)
        return out

    def parse_seq(self, indent: int, depth: int) -> Any:
        out = []
        while self.i < len(self.lines):
            ln, ind, content = self.lines[self.i]
            if ind < indent or not (content.startswith("- ") or content == "-"):
                break
            if ind > indent:
                raise YamlError("line %d: unexpected indentation" % ln)
            rest = content[2:].strip() if content != "-" else ""
            if rest == "":
                self.i += 1
                out.append(self.parse_block(indent + 1, depth + 1) if self.i < len(self.lines)
                           and self.lines[self.i][1] > indent else None)
                continue
            kv = _split_key(rest)
            if kv is not None and not rest.startswith(("'", '"', "[", "{")):
                # "- key: value" opens a mapping whose further keys sit at ind+2
                child_indent = ind + 2
                self.lines[self.i] = (ln, child_indent, rest)
                out.append(self.parse_map(child_indent, depth + 1))
            else:
                self.i += 1
                out.append(self._value(rest, ind, depth))
        return out


def load_all(text: str) -> List[Any]:
    raw = text.splitlines()
    if len(raw) > MAX_LINES:
        raise YamlError("too many lines")
    docs: List[List[Tuple[int, int, str]]] = [[]]
    pending: Optional[Tuple[int, int, str]] = None     # a flow collection still open
    block_indent: Optional[int] = None                  # inside a block scalar deeper than this
    for no, line in enumerate(raw, 1):
        if pending is None and (line.startswith("---") and line[3:].strip() in ("",) or line.strip() == "---"):
            docs.append([])
            block_indent = None
            continue
        if line.startswith("...") and pending is None:
            continue
        if "\t" in line[: len(line) - len(line.lstrip())]:
            raise YamlError("line %d: tab indentation" % no)
        stripped = _strip_comment(line)
        if not stripped.strip():
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        content = stripped.strip()
        if pending is not None:
            pno, pind, ptext = pending
            joined = ptext + " " + content
            if _flow_depth(joined) <= 0:
                docs[-1].append((pno, pind, joined))
                pending = None
            elif len(joined) > 100000:
                raise YamlError("line %d: flow collection too long" % pno)
            else:
                pending = (pno, pind, joined)
            continue
        if block_indent is not None:
            if indent > block_indent:
                docs[-1].append((no, indent, content))
                continue
            block_indent = None
        if content.startswith("%"):
            continue
        if _flow_starts(content) and _flow_depth(content) > 0:
            pending = (no, indent, content)
            continue
        docs[-1].append((no, indent, content))
        if _BLOCK_INDICATOR_RE.search(content):
            block_indent = indent
        if len(docs) > MAX_DOCS:
            raise YamlError("too many documents")
    if pending is not None:
        raise YamlError("line %d: unterminated flow collection" % pending[0])
    out = []
    for lines in docs:
        if not lines:
            continue
        if len(lines) == 1 and _split_key(lines[0][2]) is None and not lines[0][2].startswith(("- ", "[", "{")) \
                and lines[0][2] != "-":
            out.append(_scalar(lines[0][2]))     # a document that is a single plain scalar
            continue
        p = _Parser(lines)
        value = p.parse_block(lines[0][1], 0)
        if p.i < len(lines):
            raise YamlError("line %d: could not parse" % lines[p.i][0])
        out.append(value)
    return out
