#!/usr/bin/env python3
"""Core types, language detection, sanitizing, and file discovery for jankhunt42."""
from __future__ import annotations

import fnmatch
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

TOOL = "jankhunt42"
VERSION = "3.6.0"

SEVERITIES = ("blocker", "critical", "major", "minor", "info")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
SEV_WEIGHT = {"blocker": 50, "critical": 20, "major": 8, "minor": 3, "info": 1}
SEV_LABEL = {
    "blocker": "BLOCKER",
    "critical": "CRITICAL",
    "major": "MAJOR",
    "minor": "MINOR",
    "info": "INFO",
}


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    category: str
    message: str
    fix: str
    confidence: str = "medium"
    langs: Tuple[str, ...] = ()
    kinds: Tuple[str, ...] = ()
    files: Tuple[str, ...] = ()
    patterns: Tuple[str, ...] = ()
    target: str = "code"  # raw | code | nocomment | comments
    ignore: str = ""
    check: str = ""
    tags: Tuple[str, ...] = ()


@dataclass
class Finding:
    rule: str
    title: str
    severity: str
    category: str
    path: str
    line: int
    column: int = 1
    end_line: Optional[int] = None
    evidence: str = ""
    message: str = ""
    fix: str = ""
    confidence: str = "medium"
    tags: Tuple[str, ...] = ()
    extra: Dict[str, object] = field(default_factory=dict)

    def sort_key(self) -> Tuple[int, str, int, str]:
        return (SEV_RANK.get(self.severity, 99), self.path, self.line, self.rule)


@dataclass
class SourceFile:
    rel: str
    abspath: str
    lang: str
    kinds: Tuple[str, ...]
    text: str
    raw: List[str]
    code: List[str]
    nocomment: List[str]
    comments: List[str]
    loc: int

    @property
    def basename(self) -> str:
        return os.path.basename(self.rel)


# ---------------------------------------------------------------------------
# Language and file-kind detection
# ---------------------------------------------------------------------------

EXT_LANG = {
    ".py": "python", ".pyi": "python", ".pyw": "python",
    ".js": "js", ".jsx": "js", ".mjs": "js", ".cjs": "js",
    ".ts": "ts", ".tsx": "ts", ".mts": "ts", ".cts": "ts",
    ".java": "java", ".kt": "kotlin", ".kts": "kotlin", ".scala": "scala", ".groovy": "groovy",
    ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
    ".hpp": "cpp", ".hh": "cpp", ".hxx": "cpp", ".m": "c", ".mm": "cpp",
    ".cs": "csharp", ".go": "go", ".rs": "rust", ".rb": "ruby", ".php": "php",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell", ".ksh": "shell", ".fish": "shell",
    ".ps1": "powershell", ".psm1": "powershell",
    ".sql": "sql", ".lua": "lua", ".r": "r", ".pl": "perl", ".pm": "perl",
    ".swift": "swift", ".dart": "dart",
    ".ex": "elixir", ".exs": "elixir", ".erl": "erlang", ".hrl": "erlang",
    ".hs": "haskell", ".lhs": "haskell", ".ml": "ocaml", ".mli": "ocaml",
    ".clj": "clojure", ".cljs": "clojure", ".cljc": "clojure",
    ".vue": "vue", ".svelte": "svelte",
    ".html": "html", ".htm": "html", ".xml": "xml", ".xsl": "xml", ".svg": "xml",
    ".css": "css", ".scss": "css", ".sass": "css", ".less": "css",
    ".yaml": "yaml", ".yml": "yaml", ".json": "json", ".jsonc": "json", ".json5": "json",
    ".toml": "toml", ".ini": "ini", ".cfg": "ini", ".conf": "ini", ".properties": "ini",
    ".md": "markdown", ".mdx": "markdown", ".mdc": "markdown", ".rst": "markdown", ".txt": "text",
    ".tf": "hcl", ".hcl": "hcl", ".tfvars": "hcl",
    ".dockerfile": "docker",
    ".sol": "solidity", ".zig": "zig", ".nim": "nim", ".jl": "julia",
    ".fs": "fsharp", ".fsx": "fsharp", ".vb": "vb", ".asm": "asm", ".s": "asm",
}

TEST_PATH_RE = re.compile(
    r"(^|/)(tests?|testing|specs?|__tests__|testdata|fixtures?|e2e|integration-tests?|testutils?|"
    r"test[_-]?(?:support|helpers?|vectors)|apitests?|__mocks__)(/|$)"
    r"|(^|/)test_[^/]*\.py$|(^|/)conftest\.py$"
    r"|(_test\.|\.test\.|\.spec\.|_spec\.|Test\.java$|Tests?\.cs$|_test\.go$|_tests\.rs$|(^|/)tests\.rs$)",
    re.IGNORECASE,
)

GENERATED_RE = re.compile(
    r"(\.min\.(js|css)$|\.map$|\.generated\.|_pb2(_grpc)?\.py$|\.pb\.go$|"
    r"\.designer\.cs$|\.g\.dart$|\.freezed\.dart$|lock$|\.lock$|"
    r"(^|/)(dist|build|target|out|coverage|\.next|\.nuxt|vendor|node_modules|"
    r"bower_components|Pods|DerivedData|__pycache__|\.venv|venv|site-packages)(/|$))",
    re.IGNORECASE,
)

DEFAULT_SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build", "target",
    "out", "coverage", ".venv", "venv", "env", "__pycache__", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", ".tox", ".idea", ".gradle",
    ".next", ".nuxt", ".cache", ".terraform", "bower_components", "Pods",
    "DerivedData", "site-packages", ".yarn", ".pnpm-store", "tmp", "temp",
}
# Agent and editor workspace directories are walked too: what a coding agent
# or editor does when it opens the repository is part of the attack surface.
AGENT_DIRS = {".vscode", ".claude", ".cursor", ".gemini", ".codex", ".amazonq", ".windsurf",
              ".agents", ".opencode", ".roo", ".kiro", ".clinerules", ".continue", ".zed", ".devcontainer"}
ALLOWED_HIDDEN_DIRS = {".github", ".gitlab", ".circleci", ".azure"} | AGENT_DIRS

# Instruction files that coding agents load into their context.
AGENT_CONTEXT_NAMES = {"agents.md", "agent.md", "claude.md", "claude.local.md", "gemini.md", "skill.md",
                       ".cursorrules", ".windsurfrules", ".clinerules", ".roorules", "copilot-instructions.md"}
AGENT_CONTEXT_DIRS = (".cursor/rules/", ".windsurf/rules/", ".clinerules/", ".kiro/steering/", ".roo/",
                      ".amazonq/rules/", ".continue/rules/", ".claude/commands/", ".claude/agents/",
                      ".gemini/commands/", ".github/instructions/", ".github/prompts/", ".github/chatmodes/",
                      ".opencode/agent/", ".opencode/command/")
# Settings files that change what an agent or editor may do without asking.
AGENT_CONFIG_FILES = (".vscode/settings.json", ".vscode/tasks.json", ".claude/settings.json",
                      ".claude/settings.local.json", ".codex/config.toml", ".gemini/settings.json",
                      ".zed/settings.json")
MCP_CONFIG_FILES = (".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", ".gemini/settings.json",
                    ".codex/config.toml", ".amazonq/mcp.json", ".roo/mcp.json", ".kiro/settings/mcp.json",
                    "claude_desktop_config.json", "opencode.json", "opencode.jsonc")


def _ends_with_path(posix: str, suffix: str) -> bool:
    return ("/" + posix.lower()).endswith("/" + suffix)


def is_agent_context(rel: str) -> bool:
    posix = rel.replace(os.sep, "/")
    low = "/" + posix.lower()
    base = os.path.basename(low)
    if base in AGENT_CONTEXT_NAMES or base.endswith((".instructions.md", ".prompt.md", ".chatmode.md")):
        return True
    return any("/" + d in low for d in AGENT_CONTEXT_DIRS) and not base.endswith(".json")


def is_mcp_config(rel: str, text: str = "") -> bool:
    posix = rel.replace(os.sep, "/")
    if any(_ends_with_path(posix, f) for f in MCP_CONFIG_FILES) or os.path.basename(posix).lower() == "mcp.json":
        return True
    return posix.lower().endswith((".json", ".jsonc")) and '"mcpServers"' in text[:65536]


def detect_lang(path: str) -> str:
    base = os.path.basename(path)
    low = base.lower()
    if base == "Dockerfile" or base.startswith("Dockerfile.") or low.endswith(".dockerfile"):
        return "docker"
    if base in ("Makefile", "GNUmakefile"):
        return "make"
    if low.startswith(".env") or low.endswith(".env"):
        return "env"
    if base in (".gitignore", ".dockerignore", ".npmignore"):
        return "config"
    if base in (".gitlab-ci.yml", ".gitlab-ci.yaml"):
        return "yaml"
    ext = os.path.splitext(low)[1]
    return EXT_LANG.get(ext, "text")


def _looks_like_sandbox_policy(text: str) -> bool:
    """An OpenShell sandbox policy: schema version 1 with network_policies or
    filesystem/landlock sections at the top level."""
    head = text[:200000]
    if head.lstrip().startswith("{"):
        return bool(re.search(r'"version"\s*:\s*1\b', head)
                    and re.search(r'"(?:network_policies|filesystem_policy|landlock)"\s*:', head))
    return bool(re.search(r"(?m)^version\s*:\s*1\s*$", head)
                and re.search(r"(?m)^(?:network_policies|filesystem_policy|landlock)\s*:", head))


# build output: dist/, build/, assets/, public/, static/, vendor/, .next/, bundles and hashed chunk names
_MINIFIED_PATH_RE = re.compile(r"(?i)(?:^|/)(?:dist|build|out|assets|static|public|vendors?|bundles?|_next|\.next|\.nuxt|"
                               r"wwwroot/lib|wwwroot/_framework|third[_-]?party)/|\.min\.(?:js|mjs|cjs|css)$|"
                               r"(?:bundle|chunk|vendor)[\w.-]*\.(?:js|mjs|css)$|"
                               r"[-.](?=[A-Za-z0-9_]*\d)[A-Za-z0-9_]{8,}\.(?:js|mjs|css)$")


def detect_kinds(rel: str, text: str, lang: str) -> Tuple[str, ...]:
    """Classify a file for infrastructure-specific rules."""
    kinds: Set[str] = set()
    base = os.path.basename(rel).lower()
    posix = rel.replace(os.sep, "/")
    if posix.startswith(".github/workflows/") or (
        base in ("action.yml", "action.yaml") and ".github/" in posix
    ):
        kinds.add("github_actions")
    if base in (".gitlab-ci.yml", ".gitlab-ci.yaml"):
        kinds.add("gitlab_ci")
    if base == "package.json":
        kinds.add("package_json")
    if base in ("package-lock.json", "npm-shrinkwrap.json"):
        kinds.add("package_lock")
    if base in ("yarn.lock", "pnpm-lock.yaml", "bun.lockb"):
        kinds.add("package_lock")
    if base.startswith("requirements") and base.endswith(".txt"):
        kinds.add("requirements")
    if base in ("pyproject.toml", "pipfile", "pipfile.lock", "poetry.lock", "uv.lock"):
        kinds.add("python_manifest")
    if base == "cargo.lock":
        kinds.add("cargo_lock")
    if base == "go.mod":
        kinds.add("gomod")
    if base == "go.sum":
        kinds.add("gosum")
    if base in ("pom.xml", "build.gradle", "build.gradle.kts"):
        kinds.add("jvm_manifest")
    if base.endswith((".csproj", ".fsproj", ".vbproj")):
        kinds.add("nuget")
    if base == "gemfile.lock":
        kinds.add("gem_lock")
    if base == "composer.lock":
        kinds.add("composer_lock")
    if base == "pubspec.lock":
        kinds.add("pub_lock")
    if base in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml") or base.startswith("docker-compose"):
        kinds.add("compose")
    if lang == "docker":
        kinds.add("dockerfile")
    if lang == "markdown":
        kinds.add("markdown")
    if lang in ("yaml", "json") and _looks_like_k8s(text):
        kinds.add("kubernetes")
    if lang == "hcl":
        kinds.add("terraform")
    if is_agent_context(rel):
        kinds.add("agent_context")
    if any(_ends_with_path(posix, f) for f in AGENT_CONFIG_FILES) or base == ".devcontainer.json" \
            or (base == "devcontainer.json" and "/.devcontainer/" in "/" + posix.lower()):
        kinds.add("agent_config")
    if is_mcp_config(rel, text):
        kinds.add("mcp_config")
    if lang in ("yaml", "json") and _looks_like_sandbox_policy(text):
        kinds.add("sandbox_policy")
    if _ends_with_path(posix, ".github/dependabot.yml") or _ends_with_path(posix, ".github/dependabot.yaml"):
        kinds.add("dependabot")
    if is_test_path(rel):
        kinds.add("test")
    if "github_actions" in kinds or "gitlab_ci" in kinds:
        kinds.add("ci")
    # a minified bundle needs a build-output name or path AND the shape, so one long string cannot
    # turn a hand-written file into a "bundle"; secret, hidden-Unicode and agent rules still read it,
    # and the scan lists every such file
    if lang in ("js", "ts", "css", "html") and _MINIFIED_PATH_RE.search(posix):
        head = text[:400000].split("\n")
        if head and max(len(x) for x in head) > 3000 and sum(len(x) for x in head) / len(head) > 300:
            kinds.add("minified")
    return tuple(sorted(kinds))


def _looks_like_k8s(text: str) -> bool:
    head = text[:12000]
    if not re.search(r"(?m)^\s*apiVersion\s*:", head):
        return False
    if not re.search(r"(?m)^\s*kind\s*:", head):
        return False
    return bool(re.search(
        r"(?m)^\s*kind\s*:\s*(Pod|Deployment|StatefulSet|DaemonSet|Job|CronJob|"
        r"Service|Ingress|ConfigMap|Secret|Role|ClusterRole|RoleBinding|"
        r"ClusterRoleBinding|ServiceAccount|NetworkPolicy|PersistentVolumeClaim|"
        r"HorizontalPodAutoscaler|PodDisruptionBudget|CustomResourceDefinition)\s*$",
        head,
    ))


def is_test_path(rel: str) -> bool:
    return bool(TEST_PATH_RE.search(rel.replace(os.sep, "/")))


def path_matches(rule: Rule, sf: SourceFile) -> bool:
    if rule.langs and sf.lang not in rule.langs:
        return False
    if rule.kinds and not (set(rule.kinds) & set(sf.kinds)):
        return False
    if rule.files:
        for pat in rule.files:
            if fnmatch.fnmatch(sf.rel, pat) or fnmatch.fnmatch(sf.basename, pat):
                return True
        return False
    return True


# ---------------------------------------------------------------------------
# Sanitizer: produce code / no-comment / comment views without changing lines
# ---------------------------------------------------------------------------

_ANY_LINE_COMMENTS: Dict[str, Tuple[str, ...]] = {
    "python": ("#",), "ruby": ("#",), "perl": ("#",), "r": ("#",),
    "js": ("//",), "ts": ("//",), "java": ("//",), "c": ("//",), "cpp": ("//",),
    "csharp": ("//",), "go": ("//",), "rust": ("//",), "php": ("//",),
    "swift": ("//",), "kotlin": ("//",), "scala": ("//",), "dart": ("//",),
    "groovy": ("//",), "solidity": ("//",), "zig": ("//",), "nim": ("#",),
    "julia": ("#",), "fsharp": ("//",), "vb": ("'",), "asm": (";",),
    "clojure": (";",), "hcl": ("//",),
}

_WS_LINE_COMMENTS: Dict[str, Tuple[str, ...]] = {
    "shell": ("#",), "yaml": ("#",), "toml": ("#",), "make": ("#",),
    "docker": ("#",), "config": ("#",), "env": ("#",),
    "ini": (";", "#"), "sql": ("--",), "lua": ("--",),
    "haskell": ("--",), "erlang": ("%",), "hcl": ("#",),
}

_BLOCK_COMMENTS: Dict[str, Tuple[Tuple[str, str], ...]] = {
    "js": (("/*", "*/"),), "ts": (("/*", "*/"),), "java": (("/*", "*/"),),
    "c": (("/*", "*/"),), "cpp": (("/*", "*/"),), "csharp": (("/*", "*/"),),
    "go": (("/*", "*/"),), "rust": (("/*", "*/"),), "php": (("/*", "*/"),),
    "swift": (("/*", "*/"),), "kotlin": (("/*", "*/"),), "scala": (("/*", "*/"),),
    "dart": (("/*", "*/"),), "groovy": (("/*", "*/"),), "css": (("/*", "*/"),),
    "sql": (("/*", "*/"),), "solidity": (("/*", "*/"),), "zig": (("/*", "*/"),),
    "lua": (("--[[", "]]"),), "html": (("<!--", "-->"),), "xml": (("<!--", "-->"),),
    "markdown": (("<!--", "-->"),), "powershell": (("<#", "#>"),),
    "haskell": (("{-", "-}"),), "ocaml": (("(*", "*)"),), "fsharp": (("(*", "*)"),),
    "matlab": (("%{", "%}"),),
}

_QUOTES: Dict[str, Tuple[str, ...]] = {
    "js": ("'", '"', "`"), "ts": ("'", '"', "`"), "vue": ("'", '"', "`"),
    "svelte": ("'", '"', "`"), "python": ("'", '"'), "ruby": ("'", '"'),
    "shell": ("'", '"'), "sql": ("'", '"'), "sqlite": ("'", '"'),
    "yaml": ("'", '"'), "toml": ("'", '"'), "json": ('"',), "ini": ("'", '"'),
    "markdown": (), "text": (), "html": ("'", '"'), "xml": ("'", '"'),
    "css": ("'", '"'), "c": ("'", '"'), "cpp": ("'", '"'), "java": ("'", '"'),
    "csharp": ("'", '"'), "go": ('"', "`"), "rust": ("'", '"'),
    "php": ("'", '"'), "swift": ('"',), "kotlin": ("'", '"'),
    "scala": ("'", '"'), "dart": ("'", '"'), "groovy": ("'", '"'),
    "hcl": ('"',), "docker": ("'", '"'), "make": ("'", '"'),
}


def _comment_token(line: str, i: int, lang: str) -> Optional[str]:
    for tok in _ANY_LINE_COMMENTS.get(lang, ()):
        if line.startswith(tok, i):
            return tok
    for tok in _WS_LINE_COMMENTS.get(lang, ()):
        if line.startswith(tok, i) and (i == 0 or line[i - 1].isspace()):
            return tok
    return None


def _blank(chars: List[str], start: int, end: int) -> None:
    for k in range(start, min(end, len(chars))):
        chars[k] = " "


_REGEX_PREV_RE = re.compile(r"(?:^|=>|[(,=:\[!&|?{;+\-*%~^]|\b(?:return|typeof|case|in|of|void|delete|throw|new|yield|await))\s*$")


def _regex_literal_end(line: str, i: int) -> Optional[int]:
    """The index after a JS regex literal starting at line[i] == "/", or None
    when the slash is division (after a name, a number or a closing bracket)
    or the literal does not close on this line."""
    before = line[:i].rstrip()
    if not _REGEX_PREV_RE.search(line[:i]) or before.endswith(("++", "--")):
        return None                     # i++ / 2, </div>: division or a closing tag, not a regex
    k, in_class, n = i + 1, False, len(line)
    while k < n:
        c = line[k]
        if c == "\\":
            k += 2
            continue
        if c == "[":
            in_class = True
        elif c == "]":
            in_class = False
        elif c == "/" and not in_class:
            k += 1
            while k < n and line[k].isalpha():
                k += 1
            return k
        k += 1
    return None


class _Sanitizer:
    """Line-oriented comment/string masking with cross-line state."""

    def __init__(self, lang: str) -> None:
        self.lang = lang
        self.blocks = _BLOCK_COMMENTS.get(lang, ())
        self.quotes = _QUOTES.get(lang, ("'", '"'))
        self.triple = lang == "python"
        self.backtick = "`" in self.quotes and lang in ("js", "ts", "vue", "svelte")
        self.regex = lang in ("js", "ts", "vue", "svelte")
        self.block_end: Optional[str] = None
        self.str_end: Optional[str] = None
        starts = {token[0] for token in self.quotes}
        starts.update(start[0] for start, _ in self.blocks)
        starts.update(token[0] for token in _ANY_LINE_COMMENTS.get(lang, ()))
        starts.update(token[0] for token in _WS_LINE_COMMENTS.get(lang, ()))
        if self.regex:
            starts.add("/")
        self.opener_chars = "".join(sorted(starts))
        self.openers = re.compile("[" + re.escape(self.opener_chars) + "]") if starts else None

    def run(self, text: str) -> Tuple[List[str], List[str], List[str]]:
        code_lines: List[str] = []
        nc_lines: List[str] = []
        comment_lines: List[str] = []
        for line in text.split("\n"):
            code = list(line)
            nc = list(line)
            comments: List[str] = []
            self._scan_line(line, code, nc, comments)
            code_lines.append("".join(code))
            nc_lines.append("".join(nc))
            comment_lines.append("".join(comments))
        return code_lines, nc_lines, comment_lines

    def _consume_block(self, line: str, code: List[str], nc: List[str],
                       comments: List[str], i: int, n: int) -> int:
        end = self.block_end
        if end is None:
            return n
        j = line.find(end, i)
        if j < 0:
            _blank(code, i, n)
            _blank(nc, i, n)
            comments.append(line[i:])
            return n
        stop = j + len(end)
        _blank(code, i, stop)
        _blank(nc, i, stop)
        comments.append(line[i:stop])
        self.block_end = None
        return stop

    def _consume_string(self, line: str, code: List[str], i: int, n: int) -> int:
        end = self.str_end
        if end is None:
            return n
        j = line.find(end, i)
        if j < 0:
            _blank(code, i, n)
            return n
        stop = j + len(end)
        _blank(code, i, stop)
        self.str_end = None
        return stop

    def _start_block(self, line: str, code: List[str], nc: List[str],
                     comments: List[str], i: int) -> Optional[int]:
        for start, end in self.blocks:
            if line.startswith(start, i):
                _blank(code, i, i + len(start))
                _blank(nc, i, i + len(start))
                comments.append(line[i:i + len(start)])
                self.block_end = end
                return i + len(start)
        return None

    @staticmethod
    def _consume_quoted(line: str, code: List[str], i: int, n: int, quote: str) -> int:
        i += 1
        while i < n:
            ch = line[i]
            if ch == "\\" and i + 1 < n:
                code[i] = " "
                code[i + 1] = " "
                i += 2
                continue
            if ch == quote:
                return i + 1
            code[i] = " "
            i += 1
        return i

    def _scan_line(self, line: str, code: List[str], nc: List[str],
                   comments: List[str]) -> None:
        i = 0
        n = len(line)
        while i < n:
            if self.block_end is not None:
                i = self._consume_block(line, code, nc, comments, i, n)
                continue
            if self.str_end is not None:
                i = self._consume_string(line, code, i, n)
                continue
            # Ordinary spans cannot change lexical state or mask a character.
            # Visit every possible opener; the existing state machine decides it.
            if line[i] not in self.opener_chars:
                opener = self.openers.search(line, i) if self.openers is not None else None
                if opener is None:
                    return
                i = opener.start()
            block_i = self._start_block(line, code, nc, comments, i)
            if block_i is not None:
                i = block_i
                continue
            if self.regex and line[i] == "/" and not line.startswith(("//", "/*"), i):
                end = _regex_literal_end(line, i)
                if end:
                    i = end                 # /^https:\/\//i: the // inside is not a comment
                    continue
            if _comment_token(line, i, self.lang):
                _blank(code, i, n)
                _blank(nc, i, n)
                comments.append(line[i:])
                return
            ch = line[i]
            if self.triple and ch in ("'", '"') and line.startswith(ch * 3, i):
                _blank(code, i, i + 3)
                i += 3
                self.str_end = ch * 3
                continue
            if self.backtick and ch == "`":
                code[i] = " "
                i += 1
                self.str_end = "`"
                continue
            if ch in self.quotes:
                i = self._consume_quoted(line, code, i, n, ch)
                continue
            i += 1


def sanitize(text: str, lang: str) -> Tuple[List[str], List[str], List[str]]:
    """Return (code, nocomment, comments) line views.

    code: comments and string contents blanked (quote delimiters kept)
    nocomment: comments blanked, string contents kept
    comments: comment text only (markers included)
    """
    return _Sanitizer(lang).run(text)


# ---------------------------------------------------------------------------
# File discovery and loading
# ---------------------------------------------------------------------------

SKIP_FILENAMES = {
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "bun.lockb", "cargo.lock", "poetry.lock", "uv.lock", "pipfile.lock",
    "go.sum", "composer.lock", "gemfile.lock", "pubspec.lock", "mix.lock",
}


def _is_skipped_file(path: Path) -> bool:
    name = path.name
    low = name.lower()
    if low in SKIP_FILENAMES:
        return True
    if GENERATED_RE.search(path.as_posix()):
        return True
    if low.endswith((".min.js", ".min.css", ".map", ".snap")):
        return True
    return False


# Git reads the repository's own .git/config, attributes and hooks, and an untrusted folder controls
# all three: core.fsmonitor and hooks run programs, diff drivers and filters run converters, and
# log.showSignature runs gpg.program. Every git call goes through run_git(), which overrides those
# settings on the command line (it outranks the repository's config), runs no hooks, never writes
# the index, never uses the network, and drops inherited GIT_* variables.
_GIT_SAFE_CONFIG = (
    # empty values: git before 2.36 reads core.fsmonitor as a hook command, so "false" would run a program
    "core.fsmonitor=", "core.hooksPath=/dev/null", "core.untrackedCache=false",
    "diff.external=", "core.pager=cat", "log.showSignature=false", "gpg.program=",
    "credential.helper=", "core.askPass=", "protocol.allow=never",
    "submodule.recurse=false", "diff.ignoreSubmodules=all", "status.submoduleSummary=false",
)
# commands that run diff drivers; an empty diff.<driver>.textconv makes git fail, so they get flags instead
_GIT_DIFF_COMMANDS = {"diff": True, "log": True, "show": True, "whatchanged": True, "format-patch": True,
                      "blame": False, "grep": False}       # value: also takes --no-ext-diff
# commands that never apply filters, so they need no per-repository config lookup
_GIT_NO_FILTER_COMMANDS = {"rev-parse", "symbolic-ref", "rev-list", "ls-tree", "cat-file", "config", "branch",
                           "ls-files", "stash"}
# inherited variables that name a program; the caller's other GIT_* settings (GIT_DIR, GIT_WORK_TREE,
# GIT_INDEX_FILE in a hook) are their own and are kept
_GIT_PROGRAM_ENV = {"GIT_EXTERNAL_DIFF", "GIT_PAGER", "GIT_SSH", "GIT_SSH_COMMAND", "GIT_ASKPASS", "GIT_EDITOR",
                    "GIT_SEQUENCE_EDITOR", "GIT_PROXY_COMMAND", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT"}
_git_filter_cache: Dict[str, List[Tuple[str, str]]] = {}


def git_env(extra: Sequence[Tuple[str, str]] = ()) -> Dict[str, str]:
    """The caller's environment without the GIT_* variables that name programs (_GIT_PROGRAM_ENV and
    GIT_CONFIG_KEY_n/VALUE_n), plus no optional index writes, no prompts, and `extra` as command-line config."""
    env = {k: v for k, v in os.environ.items()
           if k not in _GIT_PROGRAM_ENV and not k.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_"))}
    env.update(GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0", GIT_PAGER="cat")
    if extra:
        # GIT_CONFIG_KEY_n/VALUE_n keep key and value apart, so a filter named "a=b" is still overridden
        env["GIT_CONFIG_COUNT"] = str(len(extra))
        for n, (key, value) in enumerate(extra):
            env["GIT_CONFIG_KEY_%d" % n], env["GIT_CONFIG_VALUE_%d" % n] = key, value
    return env


def _git_filter_overrides(root: str) -> List[Tuple[str, str]]:
    """Every configured filter driver, blanked: a clean, smudge or process command of "" runs nothing,
    and required=false lets git carry on without it (git-lfs marks its filter required)."""
    if root not in _git_filter_cache:
        names: Set[str] = set()
        try:
            proc = subprocess.run(["git", "-C", root] + [a for kv in _GIT_SAFE_CONFIG for a in ("-c", kv)] +
                                  ["config", "-z", "--get-regexp", r"^filter\..*\.(clean|smudge|process)$"],
                                  capture_output=True, timeout=10, env=git_env(), stdin=subprocess.DEVNULL)
            for entry in proc.stdout.decode("utf-8", "replace").split("\0"):
                key = entry.split("\n", 1)[0]
                if key.startswith("filter.") and key.count(".") >= 2:
                    names.add(key[len("filter."):key.rfind(".")])
        except (OSError, subprocess.SubprocessError):
            pass
        _git_filter_cache[root] = [("filter.%s.%s" % (n, part), value) for n in sorted(names)
                                   for part, value in (("clean", ""), ("smudge", ""), ("process", ""),
                                                       ("required", "false"))]
    return _git_filter_cache[root]


def run_git(argv: Sequence[str], **kwargs: object) -> "subprocess.CompletedProcess[Any]":
    """subprocess.run for `["git", "-C", root, command, ...]` on a repository that may be hostile."""
    argv = [str(a) for a in argv]
    if argv[:2] != ["git", "-C"] or len(argv) < 4:
        raise ValueError("run_git expects ['git', '-C', root, command, ...]")
    root, rest = argv[2], argv[3:]
    # the subcommand is the first argument that is not an option (or an option's value)
    pos = next((i for i, a in enumerate(rest) if not a.startswith("-") and (i == 0 or rest[i - 1] not in ("-c", "-C"))),
               len(rest))
    command = rest[pos] if pos < len(rest) else ""
    if command in _GIT_DIFF_COMMANDS:
        flags = ["--no-ext-diff", "--no-textconv"] if _GIT_DIFF_COMMANDS[command] else ["--no-textconv"]
        rest = rest[:pos + 1] + flags + rest[pos + 1:]
    if "input" not in kwargs and "stdin" not in kwargs:
        kwargs["stdin"] = subprocess.DEVNULL
    opts = [a for kv in _GIT_SAFE_CONFIG for a in ("-c", kv)]
    filters = [] if command in _GIT_NO_FILTER_COMMANDS else _git_filter_overrides(root)
    # the environment carries every filter override (git 2.31+); -c repeats those whose names can be
    # written as key=value, for older git
    opts += [a for key, value in filters if "=" not in key and "\n" not in key for a in ("-c", key + "=" + value)]
    return subprocess.run(["git", "-C", root] + opts + rest,  # type: ignore[call-overload]
                          env=git_env(filters), **kwargs)


def _git_files(root: Path) -> Optional[List[str]]:
    try:
        proc = run_git(
            ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            capture_output=True, timeout=25,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    out = proc.stdout.decode("utf-8", "replace")
    return [p for p in out.split("\0") if p]


def discover_files(
    paths: Sequence[str],
    excludes: Sequence[str] = (),
    max_files: int = 20000,
    max_bytes: int = 1500000,
    on_file: Optional[Callable[[int, int, str], None]] = None,
) -> Tuple[Path, List[Path]]:
    if not paths:
        paths = ["."]
    roots = [Path(p).expanduser().resolve() for p in paths]
    if len(roots) == 1 and roots[0].is_dir():
        root = roots[0]
    else:
        root = Path.cwd().resolve()

    exclude_patterns = list(excludes) + [
        "*.min.js", "*.min.css", "*.map", "*.snap", "*.lock",
    ]
    found: List[Path] = []
    seen: Set[str] = set()

    def excluded(rel: str) -> bool:
        for pat in exclude_patterns:
            if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(os.path.basename(rel), pat):
                return True
        return False

    def add(p: Path, base: Optional[Path] = None, allow_symlink: bool = False) -> None:
        if p.is_symlink() and not allow_symlink:
            try:
                resolved = p.resolve()
            except OSError:
                return
            if base is not None:
                try:
                    resolved.relative_to(base)
                except ValueError:
                    return
        key = str(p.resolve())
        if key in seen:
            return
        if not p.is_file() or _is_skipped_file(p):
            return
        try:
            if p.stat().st_size > max_bytes:
                return
        except OSError:
            return
        seen.add(key)
        found.append(p)

    for target in roots:
        if target.is_file():
            add(target, base=target.parent, allow_symlink=True)
            continue
        if not target.is_dir():
            continue
        git_list = _git_files(target)
        if git_list is not None:
            for rel in git_list:
                if excluded(rel):
                    continue
                add(target / rel, base=target)
                if len(found) >= max_files:
                    break
        else:
            for dirpath, dirnames, filenames in os.walk(target):
                rel_dir = os.path.relpath(dirpath, target)
                rel_dir = "" if rel_dir == "." else rel_dir.replace(os.sep, "/")
                keep = []
                for d in dirnames:
                    if d == ".git" or d in DEFAULT_SKIP_DIRS:
                        continue
                    if d.startswith(".") and d not in ALLOWED_HIDDEN_DIRS:
                        continue
                    keep.append(d)
                dirnames[:] = keep
                for fn in filenames:
                    rel = f"{rel_dir}/{fn}" if rel_dir else fn
                    if excluded(rel):
                        continue
                    add(Path(dirpath) / fn, base=target)
                    if len(found) >= max_files:
                        break
                if len(found) >= max_files:
                    break
        if len(found) >= max_files:
            break

    found.sort(key=lambda p: str(p))
    total = len(found)
    for idx, p in enumerate(found, 1):
        if on_file:
            on_file(idx, total, str(p))
    return root, found


def source_from_text(rel: str, abspath: str, text: str) -> Optional[SourceFile]:
    """Build a SourceFile from text that may come from the working tree or git.

    Kept separate from load_source() so review mode can scan the exact tree or
    index revision that the diff describes.
    """
    if not text or "\x00" in text[:8192]:
        return None
    rel = rel.replace(os.sep, "/")
    lang = detect_lang(rel)
    kinds = detect_kinds(rel, text, lang)
    code, nocomment, comments = sanitize(text, lang)
    raw_lines = text.split("\n")
    loc = sum(1 for line in raw_lines if line.strip())
    return SourceFile(
        rel=rel, abspath=abspath, lang=lang, kinds=kinds, text=text,
        raw=raw_lines, code=code, nocomment=nocomment, comments=comments, loc=loc,
    )


def load_source(path: Path, root: Path) -> Optional[SourceFile]:
    try:
        raw_bytes = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in raw_bytes[:8192]:
        return None
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        text = raw_bytes.decode("utf-8", "replace")
    if not text:
        return None
    rel = os.path.relpath(str(path), str(root)).replace(os.sep, "/")
    return source_from_text(rel, str(path), text)


# ---------------------------------------------------------------------------
# Misc helpers
# ---------------------------------------------------------------------------

# wider than JH101's detection on purpose: prefixed names (AWS_SECRET_ACCESS_KEY) and quoted keys
# ("db_password": ...) are redacted whatever the value looks like
_SECRET_LINE_RE = re.compile(
    r"(?i)(\b(?:[a-z0-9]+[_-])*(?:api[_-]?key|apikey|secret(?:[_-]?key)?|token|passwd|password|access[_-]?key)\b"
    r"['\"]?\s*[:=]\s*['\"])([^'\"\n]{4,})(['\"])"
)
_TOKEN_RES = [
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{8,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}\b"),
    re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{16,}\b"),
    re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{16,}\b"),
    # Registry and AI-provider tokens: the npm and PyPI publish tokens that
    # 2025's registry worms harvested, and model API keys.
    re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
    re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{20,}"),
    re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b"),
    re.compile(r"\bhf_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bgsk_[A-Za-z0-9]{40,}\b"),
    re.compile(r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{30,}\b"),
    re.compile(r"\bdop_v1_[a-f0-9]{64}\b"),
    re.compile(r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b"),
    re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
]


def redact_secrets(text: str) -> str:
    out = _SECRET_LINE_RE.sub(r"\1***REDACTED***\3", text)
    for pat in _TOKEN_RES:
        out = pat.sub("***REDACTED-TOKEN***", out)
    return out


def make_finding(
    rule: Rule,
    sf: SourceFile,
    line: int,
    evidence: Optional[str] = None,
    message: Optional[str] = None,
    severity: Optional[str] = None,
    confidence: Optional[str] = None,
    end_line: Optional[int] = None,
    column: int = 1,
    extra: Optional[Dict[str, object]] = None,
) -> Finding:
    ev = evidence
    if ev is None and 0 < line <= len(sf.raw):
        ev = sf.raw[line - 1].strip()
    return Finding(
        rule=rule.id,
        title=rule.title,
        severity=severity or rule.severity,
        category=rule.category,
        path=sf.rel,
        line=line,
        column=max(1, column),
        end_line=end_line,
        evidence=trim(visible_text(ev or ""), 200),
        message=message or rule.message,
        fix=rule.fix,
        confidence=confidence or rule.confidence,
        tags=rule.tags,
        extra=extra or {},
    )


def sev_at_least(sev: str, threshold: str) -> bool:
    return SEV_RANK.get(sev, 99) <= SEV_RANK.get(threshold, 99)


_UNSAFE_CHARS_RE = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u200b-\u200f\u2028-\u202e\u2060-\u2069\u206a-\u206f"
                              "\ufeff\U000e0000-\U000e007f]")
# Invisible characters that can carry hidden text: bidi controls, zero-width
# and invisible operators, the BOM, and Unicode tag characters.
_INVISIBLE_RE = re.compile("[\u200b\u200e\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\U000e0000-\U000e007f]")


def visible_text(text: str) -> str:
    """Show invisible, bidi and tag characters as <U+XXXX> in machine output,
    so a finding cannot carry hidden text to a reader or into an agent's
    context. A leading byte-order mark is dropped."""
    return _INVISIBLE_RE.sub(lambda m: "<U+%04X>" % ord(m.group()), text.lstrip("\ufeff"))


def safe_text(text: object) -> str:
    """Neutralize control, escape, and bidi-override characters from
    repository-sourced strings before they reach a terminal or report.

    Repository content is untrusted: an ANSI escape inside a string literal
    must not be able to recolor, hide, or rewrite the reviewer's terminal.
    Each unsafe character becomes U+FFFD so its presence stays visible.
    """
    return _UNSAFE_CHARS_RE.sub("\ufffd", str(text))


def trim(text: str, width: int = 160) -> str:
    text = " ".join(text.strip().split())
    return text if len(text) <= width else text[: width - 1] + "…"


def rel_link(rel: str, line: int) -> str:
    return f"{rel}:{line}"


def is_probably_text(path: Path) -> bool:
    try:
        chunk = path.read_bytes()[:4096]
    except OSError:
        return False
    return b"\x00" not in chunk
