#!/usr/bin/env python3
"""Core types, language detection, sanitizing, and file discovery for jankhunt42."""
from __future__ import annotations

import fnmatch
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from itertools import groupby
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

TOOL = "jankhunt42"
VERSION = "4.22.5"

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
    fs_rel: str = ""                 # the name on disk, when the report shows an escaped form (rel)

    @property
    def basename(self) -> str:
        return os.path.basename(self.rel)

    def names(self) -> Tuple[str, ...]:
        """What a file pattern is matched against: the name on disk and its file name. Never the shown form, which
        for one file can equal another file's name on disk (tile\\xFF.md shows as the name tile\\\\xFF.md has)."""
        on_disk = self.fs_rel or self.rel
        return (on_disk, os.path.basename(on_disk))


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

# Files set aside by name: generated code, maps, snapshots, minified libraries and lockfiles. Folders are the shared
# folder rule's job (skipped_dir_reason), which matches names exactly; a name merely ending in "lock" (clock) is read.
GENERATED_RE = re.compile(
    r"(\.min\.(js|css)$|\.map$|\.generated\.|_pb2(_grpc)?\.py$|\.pb\.go$|"
    r"\.designer\.cs$|\.g\.dart$|\.freezed\.dart$|\.lock$)",
    re.IGNORECASE,
)

# Folders never read, in a scan with or without git: version control, installed dependencies, build output and
# caches. Every other folder is read, hidden ones included, and each folder set aside is listed in the report
# (discover_files' not_read), so a quiet result never hides where the scan did not look. An `env` folder is read
# unless it is a Python virtual environment (it holds pyvenv.cfg): on the corpus it was application code every time.
VCS_DIRS = {".git", ".hg", ".svn"}
DEPENDENCY_DIRS = {"node_modules", "vendor", "bower_components", "Pods", "site-packages", ".yarn", ".pnpm-store",
                   ".venv", "venv", ".bundle", ".m2", ".npm"}
BUILD_DIRS = {"dist", "build", "target", "out", "coverage", ".next", ".nuxt", ".svelte-kit", ".turbo", ".vercel",
              ".open-next", ".output", ".firebase", ".serverless", ".aws-sam", ".docusaurus", ".dart_tool",
              ".stack-work", ".pio", "DerivedData", ".nyc_output"}
CACHE_DIRS = {"__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", ".cache", ".gradle", ".terraform",
              ".idea", ".vs", ".parcel-cache", ".angular", ".sass-cache", ".webpack", ".expo", ".metals", ".bloop",
              ".history", ".ipynb_checkpoints"}
DEFAULT_SKIP_DIRS = VCS_DIRS | DEPENDENCY_DIRS | BUILD_DIRS | CACHE_DIRS


# Installed plugin code inside a tool's own folder: an Obsidian plugin's bundle is someone else's released code (on the
# corpus, minified selectors read as secrets), while its data.json beside it holds the user's settings, API keys
# included, and is read. The plugin folder is listed under dependencies.
_INSTALLED_PLUGIN_RE = re.compile(r"(?:^|/)(\.obsidian/plugins/[^/]+)/(?:main\.js|styles\.css)$")


def installed_plugin_dir(rel: str) -> Optional[str]:
    """The plugin folder when `rel` is installed plugin code that is not read, else None."""
    m = _INSTALLED_PLUGIN_RE.search(rel)
    return rel[:m.end(1)] if m else None


def skipped_dir_reason(name: str, path: Optional[str] = None) -> Optional[str]:
    """Why a folder is not read ("dependencies", "build output", "cache", "version control"), or None to read it.
    `path` (the folder on disk) lets an `env` folder be recognised as a virtual environment."""
    if name in VCS_DIRS:
        return "version control"
    if name == ".jankhunt42":                    # this tool's own reports (--out .jankhunt42/...)
        return "jankhunt42 reports"
    if name in DEPENDENCY_DIRS:
        return "dependencies"
    if name in BUILD_DIRS:
        return "build output"
    if name in CACHE_DIRS:
        return "cache"
    if name == "env" and path is not None and os.path.isfile(os.path.join(path, "pyvenv.cfg")):
        return "dependencies"
    return None
def tree_skip_reason(rel: str, has_file: Callable[[str], bool]) -> Optional[str]:
    """The shared folder rule for a path inside a tree that is not walked on disk (a git revision, a review's
    changed files): why it is not read, or None. `has_file(path)` says whether that tree holds a file, so an `env`
    folder counts as a virtual environment only when it holds pyvenv.cfg, as in a walk. Installed plugin code is
    set aside as in discovery."""
    segs = rel.split("/")
    for i, seg in enumerate(segs[:-1]):
        if seg == "env":
            if has_file("/".join(segs[:i + 1]) + "/pyvenv.cfg"):
                return "dependencies"
            continue
        reason = skipped_dir_reason(seg)
        if reason:
            return reason
    return "installed plugin" if installed_plugin_dir(rel) else None


# Agent and editor workspace directories are walked too: what a coding agent
# or editor does when it opens the repository is part of the attack surface.
AGENT_DIRS = {".vscode", ".claude", ".cursor", ".gemini", ".codex", ".amazonq", ".windsurf", ".agent", ".antigravity",
              ".pi", ".copilot",
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
# Claude Code's hook events (code.claude.com/docs/en/hooks, 2026-11-17): a hooks file without one is not Claude's
CLAUDE_HOOK_EVENTS = ("PreToolUse", "PostToolUse", "PostToolUseFailure", "PostToolBatch", "Notification",
                      "UserPromptSubmit", "UserPromptExpansion", "MessageDisplay", "Stop", "StopFailure",
                      "SubagentStart", "SubagentStop", "PreCompact", "PostCompact", "PreModelSwitch",
                      "PostModelSwitch", "SessionStart", "SessionEnd", "Setup", "PermissionRequest",
                      "PermissionDenied", "TeammateIdle", "TaskCreated", "TaskCompleted", "ConfigChange",
                      "CwdChanged", "DirectoryAdded", "FileChanged", "WorktreeCreate", "WorktreeRemove",
                      "InstructionsLoaded", "Elicitation", "ElicitationResult")
AGENT_CONFIG_FILES = (".vscode/settings.json", ".vscode/tasks.json", ".claude/settings.json",
                      ".claude/settings.local.json", ".codex/config.toml", ".gemini/settings.json",
                      ".zed/settings.json", ".cursor/cli.json", "managed-settings.json", ".cursor/hooks.json",
                      ".cursor/sandbox.json")
MCP_CONFIG_FILES = (".mcp.json", ".claude.json", "managed-mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", ".gemini/settings.json",
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
    if base == "data" and path.replace("\\", "/").lower().split("/")[-3:-2] == ["botcomponents"]:
        return "yaml"           # a Copilot Studio component in a solution export: botcomponents/<schema>/data
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


SUBSTRATE_TEMPLATE_EXTS = (".yaml.tmpl", ".yml.tmpl")


def substrate_shape(text: str) -> Optional[str]:
    """An Agent Substrate manifest as `kubectl ate` reads it: an EgressPolicy
    (`rules:` of http, https or tlsPassthrough entries with hostnames) or an
    ActorTemplate (`containers:` with a Substrate-only field)."""
    head = text[:200000]
    if re.search(r"(?m)^rules\s*:", head) and re.search(r"(?m)^\s*hostnames\s*:", head) and \
            re.search(r"(?m)^\s*-\s*(?:https?|tlsPassthrough|tls_passthrough)\s*:\s*$", head):
        return "egress_policy"
    if re.search(r"(?m)^containers\s*:", head) and re.search(
            r"(?m)^(?:workerSelector|snapshotConfig|goldenEgressPolicy|golden_egress_policy|worker_selector)\s*:|"
            r"^metadata\s*:\s*\n\s+atespace\s*:", head):
        return "actor_template"
    return None


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
            or (base.endswith(".json") and "/managed-settings.d/" in "/" + posix.lower()) \
            or (base == "devcontainer.json" and "/.devcontainer/" in "/" + posix.lower()) \
            or (("/" + posix.lower()).endswith("/hooks/hooks.json") and '"hooks"' in text
                and re.search(r'"(?:%s)"\s*:' % "|".join(CLAUDE_HOOK_EVENTS), text)):
        kinds.add("agent_config")       # the last: a Claude Code plugin's hooks/hooks.json, by its event names
    if is_mcp_config(rel, text):
        kinds.add("mcp_config")
    if lang in ("yaml", "json") and _looks_like_sandbox_policy(text):
        kinds.add("sandbox_policy")
    if (lang == "yaml" or base.endswith(SUBSTRATE_TEMPLATE_EXTS)) and substrate_shape(text):
        kinds.add("substrate")
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
            if any(fnmatch.fnmatch(name, pat) for name in sf.names()):
                return True
        return False
    return True


# ---------------------------------------------------------------------------
# Sanitizer: produce code / no-comment / comment views without changing lines
# ---------------------------------------------------------------------------

_ANY_LINE_COMMENTS: Dict[str, Tuple[str, ...]] = {
    "python": ("#",), "ruby": ("#",), "perl": ("#",), "r": ("#",),
    "js": ("//",), "ts": ("//",), "java": ("//",), "c": ("//",), "cpp": ("//",),
    "csharp": ("//",), "go": ("//",), "rust": ("//",), "php": ("//", "#"),
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
            if lang == "php" and tok == "#" and line.startswith("#[", i):
                continue                     # a PHP 8 attribute, not a comment
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
        self.php_line_template = False           # PHP: on a line where a comment closed the block, tags alternate
        starts = {token[0] for token in self.quotes}
        starts.update(start[0] for start, _ in self.blocks)
        starts.update(token[0] for token in _ANY_LINE_COMMENTS.get(lang, ()))
        starts.update(token[0] for token in _WS_LINE_COMMENTS.get(lang, ()))
        if lang == "php":
            starts.add("?")
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
        self.php_line_template = False
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
                # a PHP one-line comment ends at the closing tag: what follows ?> is template text or the next block
                close = line.find("?>", i) if self.lang == "php" else -1
                if close != -1:
                    _blank(code, i, close)
                    _blank(nc, i, close)
                    comments.append(line[i:close])
                    # the text after that tag on this line is template text, not code, until a <? reopens a block
                    reopen = line.find("<?", close + 2)
                    _blank(code, close, n if reopen == -1 else reopen)
                    if reopen == -1:
                        return
                    self.php_line_template = True   # a later ?> on this line closes the reopened block too
                    i = reopen
                    continue
                _blank(code, i, n)
                _blank(nc, i, n)
                comments.append(line[i:])
                return
            if self.php_line_template and line.startswith("?>", i):
                reopen = line.find("<?", i + 2)      # template text again until the next opening tag
                _blank(code, i, n if reopen == -1 else reopen)
                if reopen == -1:
                    return
                i = reopen
                continue
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


def skipped_file_reason(path: Path) -> Optional[str]:
    """Why a file is set aside by its name ("lockfile", "minified", "generated"), or None to read it."""
    low = path.name.lower()
    if low in SKIP_FILENAMES or low.endswith(".lock"):
        return "lockfile"
    if low.endswith((".min.js", ".min.css")):
        return "minified"
    if low.endswith((".map", ".snap")) or GENERATED_RE.search(low):
        return "generated"
    return None


def _is_skipped_file(path: Path) -> bool:
    return skipped_file_reason(path) is not None


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


def _git_files(root: Path, *args: str) -> Optional[List[str]]:
    try:
        proc = run_git(
            ["git", "-C", str(root), "ls-files", "-z", "--exclude-standard", *args],
            capture_output=True, timeout=25,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    out = os.fsdecode(proc.stdout)          # the file system's own decoding: a name that is not UTF-8 is still found
    return [p for p in out.split("\0") if p]


MAX_ARCHIVE_BYTES = 32 * 1024 * 1024


def count_path(counts: Dict[str, Any], reason: str, rel: str) -> None:
    entry = counts.setdefault(reason, {"count": 0, "paths": []})
    entry["count"] += 1
    if len(entry["paths"]) < 20:
        entry["paths"].append(rel)


def discover_files(
    paths: Sequence[str],
    excludes: Sequence[str] = (),
    max_files: int = 20000,
    max_bytes: int = 1500000,
    on_file: Optional[Callable[[int, int, str], None]] = None,
    not_read: Optional[Dict[str, Any]] = None,
    ignored_files: Optional[Set[Path]] = None,
    config_excludes: Sequence[str] = (),
) -> Tuple[Path, List[Path]]:
    """The files to scan. `not_read`, when given, is filled with what was set aside: folders by reason
    {"dirs": {reason: [path, ...]}}, files over the size limit ("too_large"), and whether the file limit cut the
    walk short ("file_limit")."""
    if not paths:
        paths = ["."]
    roots = [Path(p).expanduser().resolve() for p in paths]
    if len(roots) == 1 and roots[0].is_dir():
        root = roots[0]
    else:
        root = Path.cwd().resolve()

    found: List[Path] = []
    seen: Dict[str, int] = {}             # resolved path -> its index in found
    overflow = [False]                    # an eligible file was left out by the file limit (explicit files count too)
    aliases: Dict[str, List[Tuple[Path, Path, bool]]] = {}   # resolved path -> each link spelling (base, git-ignored)
    pending_excludes: Dict[Path, str] = {}   # an overlapping target can still read the file

    def shown(path: Any) -> str:
        """A recorded path, relative to the report's root (the same as the target when one folder is scanned)."""
        return display_path(os.path.relpath(str(path), str(root)).replace(os.sep, "/"))

    def matches(rel: str, patterns: Sequence[str]) -> bool:
        return any(fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(os.path.basename(rel), pat) for pat in patterns)

    def add(p: Path, base: Path, explicit: bool = False, git_ignored: bool = False) -> None:
        if p.is_symlink() and not explicit:
            try:
                resolved = p.resolve()
            except OSError:
                return
            try:
                resolved.relative_to(base)
            except ValueError:
                if not_read is not None:             # never followed outside the scanned folder, and said so
                    not_read.setdefault("dirs", {}).setdefault("link outside the scanned folder", []).append(shown(p))
                return
            if _quiet_is_dir(resolved):
                if not_read is not None:             # a folder link inside the root: its target is read where it is
                    not_read.setdefault("dirs", {}).setdefault("linked folder (not followed)", []).append(shown(p))
                return
        key = str(p.resolve())
        if key in seen:
            # two spellings of one file (a link and its target): keep the real file, whose name decides the language
            # and the checks that run, whichever spelling the listing yields first. A link whose own location gives
            # the file a role its real path lacks (an agent command, settings, MCP config, a CI workflow) is read
            # there too: that is where the tool that loads it finds it.
            # every link spelling is remembered; once discovery ends, each is compared with the file that represents
            # it (see the pass after the walk), so the order the listing yields them in never decides
            prev = found[seen[key]]
            if p.is_symlink():
                link_rel = p.relative_to(base).as_posix()
                cli, config = matches(link_rel, excludes), matches(link_rel, config_excludes)
                if not explicit and (cli or config):          # an excluded spelling stays excluded, whatever its order
                    if not_read is not None:
                        origin = "both" if cli and config else "--exclude" if cli else "config"
                        count_path(not_read.setdefault("files_excluded", {}), origin, shown(p))
                    return
                aliases.setdefault(key, []).append((p, base, git_ignored))
            elif prev.is_symlink():
                # the real file replaces its link as the representative only when the run may read it: an excluded
                # target stays excluded and the allowed link keeps representing the file, whichever comes first
                if not explicit and (excludes or config_excludes):
                    rel_t = p.relative_to(base).as_posix()
                    cli, config = matches(rel_t, excludes), matches(rel_t, config_excludes)
                    if cli or config:
                        if not_read is not None:
                            origin = "both" if cli and config else "--exclude" if cli else "config"
                            count_path(not_read.setdefault("files_excluded", {}), origin, shown(p))
                        return
                # the same name checks as any file (a generated or minified target stays skipped), and the real file
                # carries its own git-ignored status, whichever spelling the listing yields first
                why_name = skipped_file_reason(p.relative_to(base))
                if why_name:
                    if not_read is not None:
                        count_path(not_read.setdefault("files_by_name", {}), why_name, shown(p))
                    return
                found[seen[key]] = p
                if ignored_files is not None and git_ignored:
                    ignored_files.add(p)
            return
        inside = p.relative_to(base)
        if not _quiet_is_file(p):
            return
        if not explicit and (excludes or config_excludes):
            rel = inside.as_posix()
            cli = matches(rel, excludes)
            config = matches(rel, config_excludes)
            if cli or config:
                if not_read is not None:
                    origin = "both" if cli and config else "--exclude" if cli else "config"
                    if len(roots) == 1:
                        count_path(not_read.setdefault("files_excluded", {}), origin, shown(p))
                    else:
                        pending_excludes[p] = origin if pending_excludes.get(p, origin) == origin else "both"
                return
        why_name = skipped_file_reason(inside)
        if why_name:
            if not_read is not None:                 # set aside by name, and counted
                count_path(not_read.setdefault("files_by_name", {}), why_name, shown(p))
            return
        plugin = installed_plugin_dir(inside.as_posix())
        if plugin:
            if not_read is not None:
                count_path(not_read.setdefault("files_by_name", {}), "installed plugin", shown(p))
            return
        try:
            # a Power Platform solution export (.zip) or canvas app (.msapp) is read from inside (jh_powerplatform)
            if p.stat().st_size > (max(max_bytes, MAX_ARCHIVE_BYTES) if p.name.lower().endswith((".zip", ".msapp"))
                                   else max_bytes):
                if not_read is not None:
                    not_read.setdefault("too_large", []).append(shown(p))
                return
        except OSError:
            return
        if len(found) >= max_files:          # an eligible file the limit turns away: only then is the walk cut short
            overflow[0] = True
            return
        seen[key] = len(found)
        found.append(p)
        if p.is_symlink():
            aliases.setdefault(key, []).append((p, base, git_ignored))
        if ignored_files is not None and git_ignored:
            ignored_files.add(p)

    for target in roots:
        if target.is_file():
            ignored = ignored_files is not None and bool(_git_files(target.parent, "--others", "--ignored",
                                                                     "--", ":(literal)" + target.name))
            add(target, base=target.parent, explicit=True, git_ignored=ignored)
            continue
        if not target.is_dir():
            continue
        git_list = _git_files(target, "--cached", "--others")
        ignored_list = _git_files(target, "--others", "--ignored") if git_list is not None else None
        if git_list is not None and ignored_list is not None:
            ignored_paths = set(ignored_list)
            dir_reasons: Dict[str, Optional[str]] = {}
            # Match the sorted directory walk before applying the file limit.
            ordered = sorted(git_list + ignored_list, key=lambda p: (p.split("/")[:-1], p.rsplit("/", 1)[-1]))
            for rel, _ in groupby(ordered):
                segs = rel.split("/")[:-1]
                skip = None
                for i, seg in enumerate(segs):           # the same folders are set aside as in a walk without git
                    prefix = "/".join(segs[:i + 1])
                    if prefix not in dir_reasons:
                        dir_reasons[prefix] = skipped_dir_reason(seg, str(target / prefix))
                        if dir_reasons[prefix] and not_read is not None:
                            not_read.setdefault("dirs", {}).setdefault(dir_reasons[prefix], []).append(shown(target / prefix))
                    if dir_reasons[prefix]:
                        skip = prefix
                        break
                if skip:
                    continue
                if not (target / rel).is_symlink() and _quiet_is_dir(target / rel):   # a submodule or nested repository
                    if not_read is not None:
                        not_read.setdefault("dirs", {}).setdefault("nested repository", []).append(shown(target / rel.rstrip("/")))
                    continue
                add(target / rel, base=target, git_ignored=rel in ignored_paths)
                if overflow[0]:
                    break
        else:
            def walk_error(exc: OSError) -> None:     # a folder the walk cannot enter is counted, never skipped quietly
                if not_read is not None and getattr(exc, "filename", None):
                    not_read.setdefault("dirs", {}).setdefault("unreadable", []).append(shown(exc.filename))
            for dirpath, dirnames, filenames in os.walk(target, onerror=walk_error):
                rel_dir = os.path.relpath(dirpath, target)
                rel_dir = "" if rel_dir == "." else rel_dir.replace(os.sep, "/")
                keep = []
                for d in dirnames:
                    if os.path.islink(os.path.join(dirpath, d)):   # the walk never follows a folder link: list it
                        add(Path(dirpath) / d, base=target)
                        continue
                    reason = skipped_dir_reason(d, os.path.join(dirpath, d))
                    if reason:
                        if not_read is not None:
                            not_read.setdefault("dirs", {}).setdefault(reason, []).append(
                                shown(os.path.join(dirpath, d)))
                        continue
                    keep.append(d)
                dirnames[:] = sorted(keep)
                for fn in sorted(filenames):
                    add(Path(dirpath) / fn, base=target)
                    if overflow[0]:
                        break
                if overflow[0]:
                    break
        if overflow[0]:
            break

    # a link is read where it is, as well as the file it represents, when its own name gives the file something that
    # file's name lacks: a role (agent command, settings, MCP config, CI workflow) or a language with its own checks
    for key, spellings in aliases.items():
        representative = found[seen[key]]
        rep_rel = None
        for link, link_base, link_ignored in spellings:
            if link == representative or link in found:
                continue
            if rep_rel is None:
                try:
                    rep_rel = representative.relative_to(link_base).as_posix()
                except ValueError:
                    rep_rel = representative.name
            if _adds_role(link.relative_to(link_base).as_posix(), rep_rel):
                if len(found) >= max_files:
                    overflow[0] = True
                    break
                found.append(link)
                if ignored_files is not None and link_ignored:   # read, and said to be git-ignored, in either order
                    ignored_files.add(link)

    if not_read is not None:
        for path, origin in pending_excludes.items():
            if str(path.resolve()) not in seen:
                rel = display_path(os.path.relpath(path, root).replace(os.sep, "/"))
                count_path(not_read.setdefault("files_excluded", {}), origin, rel)
        if overflow[0]:
            not_read["file_limit"] = max_files
    found.sort(key=lambda p: str(p))
    total = len(found)
    for idx, p in enumerate(found, 1):
        if on_file:
            on_file(idx, total, str(p))
    return root, found


def _path_kinds(rel: str) -> Set[str]:
    """The kinds a file gets from its path alone (no text): where agents, CI and MCP clients look for it."""
    return set(detect_kinds(rel, "", detect_lang(rel)))


_PLAIN_LANGS = {"text", ""}
RULE_FILE_GLOBS: Set[str] = set()                # every loaded rule's `files` patterns (set by jh_rules)


def _adds_role(link_rel: str, real_rel: str) -> bool:
    """True when a link's own name classifies the file in a way its real name does not: a kind (where agents, CI and
    MCP clients look for it) or a language whose checks the real name would not run."""
    if _path_kinds(link_rel) - _path_kinds(real_rel):
        return True
    def named(rel: str, pat: str) -> bool:
        return fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(os.path.basename(rel), pat)
    if any(named(link_rel, g) and not named(real_rel, g) for g in RULE_FILE_GLOBS):
        return True                              # a rule that selects files by name selects this name, not the real one
    link_lang = detect_lang(link_rel)
    return link_lang not in _PLAIN_LANGS and link_lang != detect_lang(real_rel)


_AMBIGUOUS_BACKSLASH = re.compile(r"\\(?:x[0-9A-Fa-f]{2}|\\)")


def _quiet_is_dir(p: Path) -> bool:
    """is_dir() that reads an unreadable target (a committed link into /root, say) as not a folder, as Python 3.14
    does; Python 3.9-3.13 raise PermissionError, which stopped the whole scan."""
    try:
        return p.is_dir()
    except OSError:
        return False


def _quiet_is_file(p: Path) -> bool:
    try:
        return p.is_file()
    except OSError:
        return False


def display_path(rel: str) -> str:
    """A path as reports show it. A file name byte that is not valid UTF-8 (kept by the file system's decoding as a
    lone surrogate) is written as the text \\xNN, so every report stays valid UTF-8 and the byte can be recovered. A
    name that holds such a byte, or whose own text holds a backslash before xNN or another backslash, has its
    backslashes doubled, so it can never look like another file's name; any other backslash is shown as it is."""
    has_bytes = any("\udc80" <= ch <= "\udcff" for ch in rel)
    if not has_bytes and "\\" not in rel:
        return rel
    # an escaped form doubles every backslash and writes each raw byte as \xNN, so it always holds \\ or \xNN; a
    # name shown as it is never does, which keeps every two names apart
    if has_bytes or _AMBIGUOUS_BACKSLASH.search(rel):
        rel = rel.replace("\\", "\\\\")
    if not has_bytes:
        return rel
    return "".join("\\x%02X" % (ord(ch) - 0xDC00) if "\udc80" <= ch <= "\udcff" else ch for ch in rel)


_ESCAPE_TOKEN = re.compile(r"\\\\|\\x[0-9A-F]{2}")


def fs_bytes(shown: str) -> bytes:
    """The bytes of the name on disk behind a path as display_path shows it: an escaped form always holds \\\\ or
    \\xNN and a name shown as it is never does, so the two are told apart and the escape is undone exactly."""
    if not _ESCAPE_TOKEN.search(shown):
        return os.fsencode(shown)
    out = bytearray()
    i = 0
    while i < len(shown):
        if shown.startswith("\\\\", i):
            out += b"\\"
            i += 2
        elif re.match(r"\\x[0-9A-F]{2}", shown[i:i + 4]):
            out.append(int(shown[i + 2:i + 4], 16))
            i += 4
        else:
            out += shown[i].encode("utf-8", "surrogateescape")
            i += 1
    return bytes(out)


def source_from_text(rel: str, abspath: str, text: str) -> Optional[SourceFile]:
    """Build a SourceFile from text that may come from the working tree or git.

    Kept separate from load_source() so review mode can scan the exact tree or
    index revision that the diff describes.
    """
    if not text or "\x00" in text[:8192]:
        return None
    fs_rel = rel.replace(os.sep, "/")
    rel = display_path(fs_rel)
    lang = detect_lang(rel)
    kinds = detect_kinds(rel, text, lang)
    code, nocomment, comments = sanitize(text, lang)
    raw_lines = text.split("\n")
    loc = sum(1 for line in raw_lines if line.strip())
    return SourceFile(
        rel=rel, abspath=abspath, lang=lang, kinds=kinds, text=text,
        raw=raw_lines, code=code, nocomment=nocomment, comments=comments, loc=loc,
        fs_rel=fs_rel if fs_rel != rel else "",
    )


# Text in UTF-16 or UTF-32 carries NUL bytes, so its byte-order mark is read before the binary check
_TEXT_BOMS = ((b"\xff\xfe\x00\x00", "utf-32"), (b"\x00\x00\xfe\xff", "utf-32"), (b"\xff\xfe", "utf-16"),
              (b"\xfe\xff", "utf-16"))


def load_source(path: Path, root: Path) -> Optional[SourceFile]:
    return load_source_why(path, root)[0]


def load_source_why(path: Path, root: Path) -> Tuple[Optional[SourceFile], Optional[str]]:
    """The file as a SourceFile, or None and why it was not read: "unreadable" (permission or another read
    error), "binary" or "empty"."""
    try:
        raw_bytes = path.read_bytes()
    except OSError:
        return None, "unreadable"
    text = None
    for bom, codec in _TEXT_BOMS:
        if raw_bytes.startswith(bom):
            try:
                text = raw_bytes.decode(codec)
            except UnicodeDecodeError:
                text = None
            break
    if text is None:
        if b"\x00" in raw_bytes[:8192]:
            return None, "binary"
        try:
            text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            text = raw_bytes.decode("utf-8", "replace")
    if not text:
        return None, "empty"
    rel = os.path.relpath(str(path), str(root)).replace(os.sep, "/")
    return source_from_text(rel, str(path), text), None


# ---------------------------------------------------------------------------
# Misc helpers
# ---------------------------------------------------------------------------

# wider than JH101's detection on purpose: prefixed names (AWS_SECRET_ACCESS_KEY) and quoted keys
# ("db_password": ...) are redacted whatever the value looks like
_SECRET_KEY_RE = re.compile(
    r"(?i)\b(?:[a-z0-9]+[_-])*(?:api[_-]?key|apikey|secret(?:[_-]?key)?|token|passwd|password|pass[_-]?phrase|"
    r"credentials?|pwd|access[_-]?key|"
    r"(?:admin|master|private|signing|encryption|hmac|webhook|subscription|licen[cs]e|jwt)[_-]?key)\b"
    r"['\"]?\s*[:=]\s*(?=['\"])"
)
# a camelCase or PascalCase credential name (dbPassword, SmtpPwd, apiToken: string, dbPassword :=), as JH101 reads it
_CAMEL_SECRET_KEY_RE = re.compile(
    r"\b_*(?:[A-Za-z][A-Za-z0-9]*?[a-z0-9])?(?:Password|Passwd|Pwd|Pass|Secret|Token|ApiKey|AccessKey|SecretKey|"
    r"(?:[Aa]dmin|[Mm]aster|[Pp]rivate|[Ss]igning|[Ee]ncryption|[Hh]mac|HMAC|[Ww]ebhook|[Ss]ubscription|[Ll]icen[cs]e|"
    r"[Jj]wt|JWT)Key)"
    r"(?:\s*\{\s*get;[^}\n]*\})?\s*(?::\s*[A-Za-z_][\w<>?\[\]]*\s*)?:?[:=]\s*(?=['\"])"
)
# the password argument of new NetworkCredential("user", "...") or PasswordAuthentication("user", "..."), the token
# of AuthenticationHeaderValue("Bearer", "..."), and the value of a header named for a secret, token or API key
_CREDENTIAL_ARG_RE = re.compile(
    r"(?:\b(?:NetworkCredential|PasswordAuthentication|AuthenticationHeaderValue)\s*\(|"
    r"(?i:\.(?:Add|TryAddWithoutValidation|set|setHeader|setRequestProperty|header|append)\s*\(\s*"
    r"[\"'][\w-]*(?:secret|token|api-?key)[\w-]*[\"']\s*,))"
    r"\s*(?:(?:\"[^\"\n]*\"|'[^'\n]*')\s*,\s*)?(?=['\"])"
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
    # Sentry, CircleCI, Doppler, Shippo, Brevo, Postman, Telegram and Mailchimp (JH101's formats, a little wider)
    re.compile(r"\bsntry[usai]_[A-Za-z0-9+/=_]{40,}"),
    re.compile(r"\bCCIP(?:AT|RJ)_[A-Za-z0-9]{12,}_[0-9a-f]{20,}"),
    re.compile(r"\bdp\.(?:pt|ct|st|sa|said|scim|audit)\.[\w.-]{30,}"),
    re.compile(r"\bshippo_(?:live|test)_[a-fA-F0-9]{30,}"),
    re.compile(r"\bx(?:keysib|smtpsib)-[a-f0-9]{40,}-[A-Za-z0-9]{8,}"),
    re.compile(r"\bPMAK-[a-fA-F0-9]{16,}-[a-fA-F0-9]{20,}"),
    re.compile(r"(?:(?<=/bot)|(?<![\w:/.-]))\d{5,16}:A[A-Za-z0-9_-]{30,}"),     # any Telegram-shaped token
    re.compile(r"(?<![\w-])[0-9a-f]{32}-us\d{1,2}\b"),
    re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
    # any JWT: a service-role key is a credential, and an anon key gains nothing from being shown
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"),
]
# the password inside a connection string or DSN: Password=...; or Pwd=...;
_CONN_PASSWORD_RE = re.compile(r"(?i)\b(?:password|pwd|accountkey|sharedaccesskey)\s*=\s*")
# the literal beside a secret-named variable or key where no = or : separates them: Set(gblApiKey, "..."),
# txtPassword.Text = "...", gblPassword <> "...", MyFlow.Run("clientSecret", "..."), "Bearer " & "..."
_SECRET_ARG_RE = re.compile(
    r"(?i)(?:\bSet\s*\(\s*\w*(?:api_?key|secret|token|passw(?:or)?d|pwd|access_?key)\w*\s*,|"
    r"\b\w*(?:passw(?:or)?d|pwd)\w*(?:\.(?:text|value)\s*(?:<>|!=|==|=)|\s*(?:<>|!=|==))|"
    r"[\"'](?:client_?secret|api_?key|access_?token|passw(?:or)?d|secret)[\"']\s*,|"
    r"[\"']Bearer ?[\"']\s*(?:&|\+|,))\s*(?=[\"'])")
# a credential in a URL's query string (?sig=..., &key=..., token=...), bare up to the next parameter
_QUERY_SECRET_RE = re.compile(r"(?i)(?<!alt=media)[?&](?:sig|signature|api_?key|apikey|access_?token|token|secret|"
                              r"password)=(?!(?:eq|neq|gt|gte|lt|lte|like|ilike|in|is|not)\.|[$<{%@])")
# a header written out in one string ("Authorization: Bearer ..."): the credential after the scheme, bare
_AUTH_HEADER_RE = re.compile(r"(?i)\bAuthorization:\s*(?:[A-Za-z][\w-]{1,20}\s+)?(?=[\w.~+/=-]{8,}(?:[\s\"'`\\]|$))")
# a literal Authorization value ({Authorization: "Bearer ..."}), whole; not "Bearer " + token, not a placeholder
_AUTH_VALUE_RE = re.compile(r"(?i)\bAuthorization[\"']?\s*\]?\s*[:=,]\s*(?=[\"'](?:[A-Za-z][\w-]{1,20}\s+)?[^\s\"']{8,}[\"'])")
# a DSN's password: Go's user:PASS@tcp(...) (the driver splits at the last @), or scheme://user:PASS@host
_DSN_PASSWORD_RES = (re.compile(r"[\w.%+-]{1,64}:([^\s\"'`]+?)@(?:tcp|unix)\("),
                     re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^:@/\s\"']+:([^@/\s\"']+)@"))
_BARE_VALUE_END_RE = re.compile(r"[;\"'\s]")
_QUERY_VALUE_END_RE = re.compile(r"[&#;\"'`\s<>)]")


def _closing_quote(text: str, quote: str, start: int, stop: int) -> int:
    """Where a quoted value opened just before start closes; stop when it does not close before stop. Inside it a
    doubled delimiter is an escaped quote (the DSN rule), whichever way the source spells the delimiter, and a
    one-character delimiter after a backslash is escaped too (libpq's rule and most languages'; also \\\\' as source
    spells it, so a value read either way is redacted whole, or more)."""
    i = start
    while True:
        end = text.find(quote, i, stop)
        if end < 0:
            return stop
        if len(quote) == 1 and end > start and text[end - 1] == "\\":
            i = end + 1                     # \' or \\' inside the value
            continue
        if text.startswith(quote, end + len(quote)):
            i = end + 2 * len(quote)        # a doubled delimiter inside the value: "", '', """" or \"\"
            continue
        return end


def _value_spans(text: str, key_re: "re.Pattern[str]", quotes: Tuple[str, ...], bare: bool, shortest: int,
                 line: bool) -> List[Tuple[int, int]]:
    """Where each value after a key_re match lies, each found on its own. A quoted value runs to its own closing quote
    (_closing_quote), spaces and semicolons included; with bare, an unquoted one runs to the next ; or white space.
    With line, a value that does not close ends with its line. Values shorter than shortest are skipped."""
    spans = []
    for m in key_re.finditer(text):
        start = m.end()
        quote = next((q for q in quotes if text.startswith(q, start)), "")
        if not quote and not bare:
            continue
        start += len(quote)
        stop = text.find("\n", start) if line else -1
        stop = len(text) if stop < 0 else stop
        if quote:
            end = _closing_quote(text, quote, start, stop)
        else:
            m_end = _BARE_VALUE_END_RE.search(text, start, stop)
            end = m_end.start() if m_end else stop
        if end - start >= shortest:
            spans.append((start, end))
    return spans


def _conn_password_spans(text: str) -> List[Tuple[int, int]]:
    """The value after Password= or Pwd=, whole: '...', "...", \\"...\\" (escaped in source), ""..."" (a C# verbatim
    string) or bare."""
    return _value_spans(text, _CONN_PASSWORD_RE, ('\\"', '""', "''", '"', "'"), True, 1, False)


def _secret_assignment_spans(text: str) -> List[Tuple[int, int]]:
    """A quoted value assigned to a secret-looking name (api_key = '...', "db_password": "...", dbPassword = "...")
    or passed as a credential's password, whole."""
    return [span for key_re in (_SECRET_KEY_RE, _CAMEL_SECRET_KEY_RE, _CREDENTIAL_ARG_RE, _AUTH_VALUE_RE, _SECRET_ARG_RE)
            for span in _value_spans(text, key_re, ("'", '"'), False, 4, True)] + \
        _value_spans(text, _AUTH_HEADER_RE, (), True, 4, True) + \
        [(m.end(), e.start() if e else len(text)) for m in _QUERY_SECRET_RE.finditer(text)
         for e in [_QUERY_VALUE_END_RE.search(text, m.end())] if (e.start() if e else len(text)) - m.end() >= 8] + \
        [m.span(1) for dsn_re in _DSN_PASSWORD_RES for m in dsn_re.finditer(text)]


def redact_secrets(text: str) -> str:
    """text with every secret masked: connection-string passwords, values assigned to secret-looking names, and known
    token formats. Each is found in the original text and their union is masked, so a value read too far (a quote
    taken as escaped) can only hide more, never uncover the next secret."""
    spans = [(s, e, "***REDACTED***") for s, e in _conn_password_spans(text) + _secret_assignment_spans(text)]
    spans += [(m.start(), m.end(), "***REDACTED-TOKEN***") for pat in _TOKEN_RES for m in pat.finditer(text)]
    if not spans:
        return text
    spans.sort()
    out, pos = [], 0
    start, end, label = spans[0]
    for s, e, lab in spans[1:]:
        if s < end:                         # overlapping: one mask over both
            end, label = max(end, e), label if lab == label else "***REDACTED***"
            continue
        out += [text[pos:start], label]
        pos, (start, end, label) = end, (s, e, lab)
    out += [text[pos:start], label]
    return "".join(out) + text[end:]


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
        evidence=trim(visible_text(redact_secrets(ev or "")), 200),     # every rule: a line can hold a secret
        # a message built by a check can quote the repository (a path, a host, a name): the same rule as evidence
        message=redact_secrets(message) if message else rule.message,
        fix=rule.fix,
        confidence=confidence or rule.confidence,
        tags=rule.tags,
        extra=_redact_tree(extra) if extra else {},
    )


def cut(text: object, limit: int) -> str:
    """Repository text shortened for a message or evidence: secrets are removed first, because a token cut short
    is no longer recognised as one and its first characters would be shown."""
    return redact_secrets(str(text))[:limit]


def _redact_tree(value: object, depth: int = 0) -> object:
    """A finding's extra data with every string redacted, keys included (a job or server name is repository text)."""
    if isinstance(value, str):
        return redact_secrets(value)
    if depth < 6 and isinstance(value, dict):
        return {(redact_secrets(k) if isinstance(k, str) else k): _redact_tree(v, depth + 1) for k, v in value.items()}
    if depth < 6 and isinstance(value, (list, tuple)):
        return [_redact_tree(v, depth + 1) for v in value]
    return value


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

