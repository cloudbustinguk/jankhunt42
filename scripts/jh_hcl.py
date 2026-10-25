#!/usr/bin/env python3
"""A small, bounded HCL block reader for Terraform files.

It reads structure only: blocks with labels, nested blocks (repeated blocks
become lists), and attributes as raw expression text. Nothing is evaluated:
variables, locals, functions, count and for_each stay as written. Strings,
`${...}` interpolation, heredocs and comments are skipped correctly, so a
brace inside a string never changes the nesting.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Iterator, List, Optional, Tuple

MAX_DEPTH = 32
MAX_TOKENS = 2_000_000

Token = Tuple[str, str, int]          # (kind, text, line)


def _tokens(text: str) -> Iterator[Token]:
    i, n, line = 0, len(text), 1
    count = 0
    while i < n:
        count += 1
        if count > MAX_TOKENS:
            return
        c = text[i]
        if c == "\n":
            yield ("nl", "\n", line)
            line += 1
            i += 1
        elif c in " \t\r":
            i += 1
        elif c == "#" or text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            line += text.count("\n", i, j)
            i = j
        elif text.startswith("<<", i) and re.match(r"<<-?([A-Za-z_]\w*)", text[i:i + 40]):
            m = re.match(r"<<-?([A-Za-z_]\w*)", text[i:])
            end = re.compile(r"^\s*%s\s*$" % re.escape(m.group(1)), re.M)
            em = end.search(text, i + m.end())
            j = n if not em else em.end()
            yield ("str", text[i:j], line)
            line += text.count("\n", i, j)
            i = j
        elif c == '"':
            j, depth = i + 1, 0
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text.startswith("${", j) or text.startswith("%{", j):
                    depth += 1
                    j += 2
                    continue
                if text[j] == "}" and depth:
                    depth -= 1
                elif text[j] == '"' and not depth:
                    break
                elif text[j] == "\n" and not depth:
                    break
                j += 1
            yield ("str", text[i:j + 1], line)
            line += text.count("\n", i, j)
            i = j + 1
        elif c in "{}[]()=,":
            yield (c, c, line)
            i += 1
        else:
            m = re.match(r"[^\s{}\[\]()=,\"#]+", text[i:])
            word = m.group(0) if m else c
            yield ("word", word, line)
            i += len(word)


class _Parser:
    def __init__(self, text: str) -> None:
        self.toks = list(_tokens(text))
        self.i = 0

    def peek(self, k: int = 0) -> Optional[Token]:
        j = self.i + k
        return self.toks[j] if j < len(self.toks) else None

    def skip_nl(self) -> None:
        while self.peek() and self.peek()[0] == "nl":
            self.i += 1

    def expr(self) -> str:
        """Raw expression text up to the end of the line at bracket depth 0."""
        parts: List[str] = []
        depth = 0
        while self.peek():
            kind, text, _ = self.peek()
            if kind == "nl" and depth == 0:
                break
            if kind in "{[(":
                depth += 1
            elif kind in "}])":
                if depth == 0:
                    break
                depth -= 1
            parts.append(" " if kind == "nl" else text)
            self.i += 1
        return re.sub(r"\s+", " ", " ".join(parts)).replace("[ ", "[").replace(" ]", "]").replace(" ,", ",").strip()

    def body(self, depth: int) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        while True:
            self.skip_nl()
            tok = self.peek()
            if tok is None:
                return out
            kind, text, line = tok
            if kind == "}":
                self.i += 1
                return out
            if kind not in ("word", "str"):
                self.i += 1
                continue
            name = text.strip('"')
            nxt = self.peek(1)
            if nxt and nxt[0] == "=":
                self.i += 2
                out[name] = self.expr()
                continue
            # a block: name label* {
            labels: List[str] = []
            j = 1
            while self.peek(j) and self.peek(j)[0] in ("word", "str"):
                labels.append(self.peek(j)[1].strip('"'))
                j += 1
            if self.peek(j) and self.peek(j)[0] == "{" and depth < MAX_DEPTH:
                self.i += j + 1
                block = self.body(depth + 1)
                block["__line__"] = line
                if labels:
                    block["__labels__"] = labels
                out.setdefault(name, []).append(block)
                continue
            self.i += 1


def parse(text: str) -> Dict[str, Any]:
    """The whole file as nested dicts: blocks map to lists of bodies."""
    return _Parser(text).body(0)


def resources(text: str, prefix: str = "") -> List[Dict[str, Any]]:
    """Resource and data blocks: [{"mode", "type", "name", "line", "body"}]."""
    tree = parse(text)
    out = []
    for mode in ("resource", "data"):
        for block in tree.get(mode, []):
            labels = block.get("__labels__") or []
            if len(labels) >= 2 and labels[0].startswith(prefix):
                out.append({"mode": mode, "type": labels[0], "name": labels[1], "line": block.get("__line__", 1),
                            "body": block})
    return out


def first(body: Dict[str, Any], name: str) -> Dict[str, Any]:
    blocks = body.get(name)
    return blocks[0] if isinstance(blocks, list) and blocks and isinstance(blocks[0], dict) else {}


def as_bool(value: Any) -> Optional[bool]:
    v = str(value).strip().lower() if value is not None else ""
    return True if v == "true" else False if v == "false" else None


def as_int(value: Any) -> Optional[int]:
    m = re.fullmatch(r"\s*(\d+)\s*", str(value)) if value is not None else None
    return int(m.group(1)) if m else None


def as_str(value: Any) -> str:
    v = str(value).strip() if value is not None else ""
    return v[1:-1] if len(v) >= 2 and v[0] == v[-1] == '"' else ""


def as_list(value: Any) -> List[str]:
    """Items of a literal list; references stay as raw text."""
    v = str(value).strip() if value is not None else ""
    if not (v.startswith("[") and v.endswith("]")):
        return []
    return [x.strip().strip('"') for x in re.findall(r'"(?:[^"\\]|\\.)*"|[^,\[\]\s][^,\[\]]*', v[1:-1]) if x.strip()]
