#!/usr/bin/env python3
"""AI agent workspace configuration: MCP server definitions and the agent
settings files a repository can carry.

Everything here is static parsing of repository text. Nothing is launched,
resolved, or fetched: a server definition is evidence of what an agent
session in this repository would start, not proof that it runs.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import shlex
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

MAX_SERVERS = 200
# files whose server list reached MAX_SERVERS, with how many definitions were left out: the inventory is partial and
# the map says so (it reads this after each call)
OMITTED: Dict[str, int] = {}


@dataclass
class McpServer:
    name: str
    line: int
    transport: str                      # stdio | http | sse | unknown
    command: str = ""
    args: List[str] = field(default_factory=list)
    env: Dict[str, str] = field(default_factory=dict)
    url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    token_env: str = ""                 # Codex bearer_token_env_var
    disabled: bool = False
    project: str = ""
    approvals: List[str] = field(default_factory=list)
    transport_line: Optional[int] = None


def client_for(rel: str) -> str:
    """The agent that reads this config file, from its location."""
    p = "/" + rel.replace(os.sep, "/").lower()
    for marker, client in (("/.cursor/", "cursor"), ("/.vscode/", "vscode"), ("/.gemini/", "gemini-cli"),
                           ("/.codex/", "codex"), ("/.amazonq/", "amazon-q"), ("/.windsurf/", "windsurf"),
                           ("/.roo/", "roo-code"), ("/.kiro/", "kiro"), ("/.claude/", "claude-code")):
        if marker in p:
            return client
    base = os.path.basename(p)
    if base in (".mcp.json", ".claude.json", "managed-mcp.json"):
        return "claude-code"
    if base == "claude_desktop_config.json":
        return "claude-desktop"
    if base.startswith("opencode.json"):
        return "opencode"
    return "mcp-client"


# ---------------------------------------------------------------------------
# JSON with comments, and the small TOML subset Codex uses for MCP servers
# ---------------------------------------------------------------------------

def _skip_comments(text: str, k: int) -> int:
    n = len(text)
    while k < n:
        if text[k].isspace():
            k += 1
        elif text.startswith("//", k):
            end = text.find("\n", k)
            k = n if end < 0 else end
        elif text.startswith("/*", k):
            end = text.find("*/", k + 2)
            k = n if end < 0 else end + 2
        else:
            break
    return k


def loads_jsonc(text: str) -> Any:
    """json.loads for JSON with // and /* */ comments and trailing commas
    (VS Code and opencode accept both). String contents are copied verbatim."""
    out: List[str] = []
    i, n = 0, len(text)
    if text.startswith("\ufeff"):
        i = 1
    while i < n:
        ch = text[i]
        if ch == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            out.append(text[i:j + 1])
            i = j + 1
        elif text.startswith("//", i) or text.startswith("/*", i):
            i = _skip_comments(text, i)
        else:
            nxt = _skip_comments(text, i + 1) if ch == "," else n
            if not (nxt < n and text[nxt] in "}]"):     # drop a trailing comma
                out.append(ch)
            i += 1
    return json.loads("".join(out))


_TOML_TABLE_RE = re.compile(r'^\s*\[\s*mcp_servers\.(?:"([^"]+)"|([A-Za-z0-9_\-]+))(?:\.(env|http_headers))?\s*\]\s*(?:#.*)?$')
_TOML_KEY_RE = re.compile(r'^\s*(?:"([^"]+)"|([A-Za-z0-9_\-]+))\s*=\s*(.*)$')


def _toml_string(s: str, i: int) -> Tuple[str, int]:
    q = s[i]
    if q == "'":
        end = s.find("'", i + 1)
        end = len(s) if end < 0 else end
        return s[i + 1:end], end + 1
    j = i + 1
    while j < len(s) and s[j] != '"':
        j += 2 if s[j] == "\\" else 1
    raw = s[i:j + 1]
    try:
        return json.loads(raw), j + 1
    except ValueError:
        return raw.strip('"'), j + 1


def _toml_value(s: str) -> Any:
    """Strings, booleans, arrays of strings, and inline tables of strings;
    anything else is returned as None (not interpreted)."""
    s = s.strip()
    if not s:
        return None
    if s[0] in "'\"":
        return _toml_string(s, 0)[0]
    if s.startswith("true"):
        return True
    if s.startswith("false"):
        return False
    if s[0] == "[":
        items: List[Any] = []
        i = 1
        while i < len(s) and s[i] != "]":
            if s[i] in "'\"":
                val, i = _toml_string(s, i)
                items.append(val)
                continue
            i += 1
        return items
    if s[0] == "{":
        table: Dict[str, Any] = {}
        i, key = 1, None
        while i < len(s) and s[i] != "}":
            ch = s[i]
            if ch in "'\"":
                val, i = _toml_string(s, i)
                if key is None:
                    key = val
                else:
                    table[key], key = val, None
                continue
            if ch == ",":
                key = None
            elif key is None and (ch.isalnum() or ch in "_-"):
                m = re.match(r"[A-Za-z0-9_\-]+", s[i:])
                key = m.group(0) if m else ch
                i += len(key)
                continue
            i += 1
        return table
    return None


def _codex_servers(text: str) -> List[McpServer]:
    servers: Dict[str, McpServer] = {}
    current: Optional[McpServer] = None
    sub: Optional[str] = None
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        i += 1
        if line.lstrip().startswith("["):
            m = _TOML_TABLE_RE.match(line)
            if not m:
                current, sub = None, None
                continue
            name = m.group(1) or m.group(2)
            current = servers.get(name)
            if current is None and len(servers) < MAX_SERVERS:
                current = servers[name] = McpServer(name=name, line=i, transport="unknown")
            sub = m.group(3)
            continue
        if current is None:
            continue
        km = _TOML_KEY_RE.match(line)
        if not km:
            continue
        key, raw = km.group(1) or km.group(2), km.group(3)
        # A multi-line array continues until its brackets balance.
        while raw.strip().startswith("[") and raw.count("[") > raw.count("]") and i < len(lines):
            raw += " " + lines[i].strip()
            i += 1
        value = _toml_value(raw)
        if sub == "env":
            if isinstance(value, str):
                current.env[key] = value
        elif sub == "http_headers":
            if isinstance(value, str):
                current.headers[key] = value
        elif key == "command" and isinstance(value, str):
            current.command = value
        elif key == "args" and isinstance(value, list):
            current.args = [str(a) for a in value]
        elif key == "url" and isinstance(value, str):
            current.url = value
        elif key == "env" and isinstance(value, dict):
            current.env.update({str(k): str(v) for k, v in value.items()})
        elif key == "http_headers" and isinstance(value, dict):
            current.headers.update({str(k): str(v) for k, v in value.items()})
        elif key == "bearer_token_env_var" and isinstance(value, str):
            current.token_env = value
        elif key == "enabled" and value is False:
            current.disabled = True
    for s in servers.values():
        s.transport = "http" if s.url else ("stdio" if s.command else "unknown")
    return list(servers.values())


# ---------------------------------------------------------------------------
# Server definitions
# ---------------------------------------------------------------------------

def _strs(value: Any) -> Dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(k): (v if isinstance(v, str) else json.dumps(v)) for k, v in value.items()}


# json_lines locates members down to this depth. Each path is a tuple as long as its depth, so locating every member
# of a document nested 100,000 deep would hold billions of entries; a line is never needed that deep, and a parser
# that accepts such a document (Python 3.14 with an unlimited stack does) must not exhaust the machine.
JSON_LINES_DEPTH = 64


def json_lines(text: str, string_value_keys: Tuple[str, ...] = ()) -> Dict[tuple, int]:
    """Locate members and array entries in an already parsed JSONC document, including duplicate names in
    different objects. Record the key line for a member and the value line for an array element, down to
    JSON_LINES_DEPTH levels. For selected string properties, locate the value itself."""
    tokens = re.finditer(r'//[^\n]*|/\*.*?\*/|"(?:[^"\\]|\\.)*"|[{}\[\],:]|[^\s{}\[\],:/"]+', text.lstrip("\ufeff"), re.S)
    text = text.lstrip("\ufeff")
    lines = {}
    path = ()
    stack = []
    key = None
    index = 0
    line, last = 1, 0
    for token in tokens:
        line += text.count("\n", last, token.start())
        last = token.start()
        val = token[0]
        if val.startswith(("//", "/*")) or val == ":":
            continue
        if val in ("}", "]"):
            path, key, index = stack.pop()
        elif val == ",":
            key = None
            index += 1
        elif stack and key is None and stack[-1][1] != "[":
            key = json.loads(val)
            if len(stack) <= JSON_LINES_DEPTH:
                lines[path + (key,)] = line
        else:
            deep = len(stack) > JSON_LINES_DEPTH                 # deeper members keep the last located path
            child = path + ((index if key is None else key),) if stack and not deep else path
            if not deep:
                if key in string_value_keys and val.startswith('"'):
                    lines[child] = line
                else:
                    lines.setdefault(child, line)
            if val in ("{", "["):
                stack.append((path, val, index))
                path, key, index = child, None, 0
    return lines


_SSE_KINDS = {"sse", "http+sse", "sse+http", "legacy-sse", "http-sse"}


def _server_from_spec(name: str, spec: Dict[str, Any], path: tuple, lines: Dict[tuple, int],
                      client: str, project: str) -> McpServer:
    command = spec.get("command")
    args = spec.get("args") if isinstance(spec.get("args"), list) else []
    if isinstance(command, list):                       # opencode: command is argv
        command, args = (command[0] if command else ""), command[1:] + list(args)
    url = spec.get("url") or spec.get("serverUrl") or spec.get("httpUrl") or ""
    transport_key = "type" if spec.get("type") else "transport"
    kind = str(spec.get(transport_key) or "").lower()
    if client == "gemini-cli":
        if spec.get("httpUrl"):
            url, kind, transport_key = spec["httpUrl"], "http", "httpUrl"
        elif spec.get("url") and not kind:
            kind, transport_key = "sse", "url"
    s = McpServer(name=name, line=lines[path], transport="unknown", transport_line=lines.get(path + (transport_key,)),
                  command=command if isinstance(command, str) else "",
                  args=[a if isinstance(a, str) else json.dumps(a) for a in args],
                  env=_strs(spec.get("env") or spec.get("environment")),
                  url=url if isinstance(url, str) else "",
                  headers=_strs(spec.get("headers") or spec.get("http_headers")))
    # only the documented SSE names are SSE; an unrecognised value is not evidence of the legacy transport
    s.transport = ("sse" if kind in _SSE_KINDS else "http") if s.url else ("stdio" if s.command else "unknown")
    s.project = project
    s.approvals = [x for k in ("autoApprove", "alwaysAllow") if isinstance(spec.get(k), list)
                   for x in spec[k] if isinstance(x, str)]
    s.disabled = spec.get("disabled") is True or spec.get("enabled") is False
    return s


def mcp_servers(rel: str, text: str, limit: Optional[int] = MAX_SERVERS) -> List[McpServer]:
    """MCP servers defined in one config file. Raises ValueError when the
    file cannot be parsed, so callers can record a coverage gap. `limit` bounds the inventory the map and passport
    keep (the rest is counted in OMITTED); the scan's checks pass None and read every server, since the shared
    safety bound already counts what they do not list."""
    posix = rel.replace(os.sep, "/").lower()
    OMITTED.pop(rel, None)
    if posix.endswith(".toml"):
        found = _codex_servers(text)
        if limit is not None and len(found) > limit:
            OMITTED[rel] = len(found) - limit
            found = found[:limit]
        return found
    data = loads_jsonc(text)
    if not isinstance(data, dict):
        return []                                       # valid JSON, but not an MCP client config
    base = os.path.basename(posix)
    containers = [((), data)]
    if base == ".claude.json" and isinstance(data.get("projects"), dict):
        containers.extend((("projects", project), config) for project, config in data["projects"].items()
                          if isinstance(config, dict))
    if not any(isinstance(config.get(key), dict) for _, config in containers for key in ("mcpServers", "servers", "mcp")):
        return []
    lines = json_lines(text, string_value_keys=("type", "transport"))
    out = []
    for path, config in containers:
        key = "mcpServers"
        if key not in config and base == "mcp.json":
            key = "servers"
        if key not in config and base.startswith("opencode.json"):
            key = "mcp"
        container = config.get(key)
        if not isinstance(container, dict):
            continue
        for name, spec in container.items():
            if limit is not None and len(out) >= limit:
                if isinstance(spec, dict):
                    OMITTED[rel] = OMITTED.get(rel, 0) + 1
                continue
            if isinstance(spec, dict):
                out.append(_server_from_spec(name, spec, path + (key, name), lines, client_for(rel),
                                             path[-1] if path else ""))
    return out


# ---------------------------------------------------------------------------
def server_groups(servers: List[McpServer]) -> Dict[str, List[McpServer]]:
    """Each project sees the user servers plus its own overrides. Project keys are never filesystem paths."""
    groups: Dict[str, Dict[str, McpServer]] = {}
    for server in servers:
        groups.setdefault(server.project, {})[server.name] = server
    shared = groups.get("", {})
    return {project: [s for s in {**shared, **local}.values() if not s.disabled]
            for project, local in groups.items()}


# What a stdio server downloads and runs at start
# ---------------------------------------------------------------------------

_EXACT_VERSION = re.compile(r"v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?$")
_DOCKER_VALUE_FLAGS = {"-e", "--env", "-v", "--volume", "--name", "-p", "--publish", "--network", "--net",
                       "--mount", "-w", "--workdir", "--entrypoint", "-u", "--user", "--env-file",
                       "--platform", "-l", "--label", "--add-host", "--cap-add", "--cap-drop", "--pull",
                       "-h", "--hostname", "--memory", "-m", "--cpus", "--device", "--security-opt", "--tmpfs"}


def _first_package(args: List[str], value_flags: Tuple[str, ...] = (),
                   package_flags: Tuple[str, ...] = ("--package", "-p", "--from")) -> Tuple[str, List[str]]:
    rest = list(args)
    for i, a in enumerate(rest):
        for flag in package_flags:
            if a == flag and i + 1 < len(rest):
                return rest[i + 1], rest
            if a.startswith(flag + "="):
                return a.split("=", 1)[1], rest
    skip = False
    for a in rest:
        if skip:
            skip = False
            continue
        if a in value_flags:
            skip = True
            continue
        if not a.startswith("-"):
            return a, rest
    return "", rest


def _npm_version(pkg: str) -> Tuple[str, str]:
    at = pkg.rfind("@")
    if at > 0:
        return pkg[:at], pkg[at + 1:]
    return pkg, ""


def launch_source(command: str, args: List[str]) -> Optional[Dict[str, Any]]:
    """{'launcher', 'package', 'version', 'pinned'} when the server is fetched
    from a registry at start; None when it runs code already on disk."""
    exe = os.path.basename(command.replace("\\", "/")).lower()
    for suffix in (".cmd", ".exe", ".bat"):
        if exe.endswith(suffix):
            exe = exe[:-len(suffix)]
    rest = list(args)
    if exe == "cmd" and rest[:1] and rest[0].lower() == "/c" and len(rest) > 1:
        return launch_source(rest[1], rest[2:])          # Windows wrapper: cmd /c npx ...
    if exe in ("pnpm", "yarn", "bun") and rest[:1] in (["dlx"], ["x"]):
        exe, rest = "npx", rest[1:]
    elif exe == "npm" and rest[:1] in (["exec"], ["x"]):
        exe, rest = "npx", rest[1:]
    elif exe == "uv" and rest[:2] == ["tool", "run"]:
        exe, rest = "uvx", rest[2:]
    elif exe == "pipx" and rest[:1] == ["run"]:
        exe, rest = "uvx", rest[1:]
    if exe in ("npx", "bunx", "pnpx"):
        pkg, _ = _first_package(rest)
        if not pkg or pkg.startswith((".", "/")):
            return None
        name, version = _npm_version(pkg)
        return {"launcher": exe, "package": name, "version": version,
                "pinned": bool(_EXACT_VERSION.match(version))}
    if exe == "uvx":
        pkg, _ = _first_package(rest)
        if not pkg or pkg.startswith((".", "/")):
            return None
        m = re.match(r"([A-Za-z0-9_.\-\[\],]+?)\s*(?:==|@)\s*([^\s;]+)$", pkg)
        name, version = (m.group(1), m.group(2)) if m else (re.split(r"[<>=!~@]", pkg)[0], "")
        return {"launcher": exe, "package": name, "version": version,
                "pinned": bool(m) and bool(_EXACT_VERSION.match(version))}
    if exe in ("docker", "podman") and rest[:1] == ["run"]:
        # -p is --publish for docker, not a package flag.
        image, _ = _first_package(rest[1:], tuple(_DOCKER_VALUE_FLAGS), package_flags=())
        if not image:
            return None
        digest = "@sha256:" in image
        tag = ""
        if not digest:
            last = image.rsplit("/", 1)[-1]
            tag = last.split(":", 1)[1] if ":" in last else ""
        return {"launcher": exe, "package": image.split("@")[0], "version": tag,
                "pinned": digest or bool(tag and tag != "latest")}
    return None


# ---------------------------------------------------------------------------
# Credentials and transport
# ---------------------------------------------------------------------------

_SECRET_NAME_RE = re.compile(r"(?i)(TOKEN|SECRET|PASSWORD|PASSWD|PASSPHRASE|API[_-]?KEY|ACCESS[_-]?KEY|"
                             r"PRIVATE[_-]?KEY|CREDENTIAL|(^|_)PAT($|_)|(^|_)KEY($|_)|^AUTHORIZATION$|^X-API-KEY$)")
_REFERENCE_RE = re.compile(r"\$\{[^}]*\}|\$[A-Za-z_]\w*|%[A-Za-z_]\w*%|\{env:[^}]+\}|\{file:[^}]+\}|<[^>]*>|\{\{[^}]*\}\}")
_PLACEHOLDER_RE = re.compile(r"(?i)(your[_-]|example|placeholder|changeme|change_me|xxx|dummy|fake|sample|"
                             r"redacted|replace[_-]?me|\*\*\*)")
_URL_PASSWORD_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://[^/:@\s]+:([^@/\s]+)@", re.I)
_SECRET_FLAG_RE = re.compile(r"(?i)^--?(?:token|api[-_]?key|access[-_]?token|password|secret|auth[-_]?token|pat)(?:=(.*))?$")


def _literal(value: str) -> bool:
    v = re.sub(r"(?i)^(?:bearer|token|basic)\s+", "", value.strip())
    return len(v) >= 8 and not _REFERENCE_RE.search(v) and not _PLACEHOLDER_RE.search(v)


def credential_literals(server: McpServer) -> List[Tuple[str, str]]:
    """(where, name) for credentials written into the config itself rather
    than referenced from the environment or an input prompt."""
    out: List[Tuple[str, str]] = []
    for where, values in (("env", server.env), ("header", server.headers)):
        for key, value in sorted(values.items()):
            if _SECRET_NAME_RE.search(key) and isinstance(value, str) and _literal(value):
                out.append((where, key))
    for i, arg in enumerate(server.args):
        m = _SECRET_FLAG_RE.match(arg)
        if m:
            value = m.group(1) if m.group(1) is not None else (server.args[i + 1] if i + 1 < len(server.args) else "")
            if _literal(value):
                out.append(("arg", arg.split("=", 1)[0]))
            continue
        pm = _URL_PASSWORD_RE.match(arg)
        if pm and _literal(pm.group(1)):
            out.append(("arg", "connection-string password"))
    pm = _URL_PASSWORD_RE.match(server.url)
    if pm and _literal(pm.group(1)):
        out.append(("url", "password"))
    return out


def credential_names(server: McpServer) -> List[str]:
    """Names of every credential the server is given (values never read)."""
    names = {k for k in server.env if _SECRET_NAME_RE.search(k)}
    names |= {k for k in server.headers if _SECRET_NAME_RE.search(k)}
    if server.token_env:
        names.add(server.token_env)
    return sorted(names)


# A permission is a tool, a fixed command prefix and the kind of wildcard after it.
# Keep the prefix in the permission's spelling for matching, including its path.
@dataclass(frozen=True)
class Permission:
    tool: str
    prefix: str = ""
    wildcard: str = ""                  # all | word | glob | exact (empty)


    def covers(self, grant: Permission) -> bool:
        """A restriction cancels a grant only if it covers every command that grant admits."""
        if self.tool == "*":
            return True
        if self.tool.startswith("mcp__") and grant.tool.startswith("mcp__"):
            pattern = self.tool if "__" in self.tool[5:] else self.tool + "__*"
            name = grant.tool if "__" in grant.tool[5:] else grant.tool + "__*"
            return fnmatch.fnmatchcase(name, pattern)
        if self.tool != grant.tool or not self.tool:
            return False
        if self.wildcard == "all" or self == grant:
            return True
        if grant.wildcard == "all":
            return False
        if self.wildcard == "word":
            return (grant.prefix == self.prefix and grant.wildcard != "glob"
                    or grant.prefix.startswith(self.prefix + " "))
        if self.wildcard == "glob":
            # The trailing star can absorb any continuation of a matching fixed prefix.
            return fnmatch.fnmatchcase(grant.prefix, self.prefix + "*")
        return not grant.wildcard and fnmatch.fnmatchcase(grant.prefix, self.prefix)


def permission(entry: str) -> Permission:
    m = re.fullmatch(r"([\w*.-]+)(?:\((.*)\))?", entry.strip())
    if not m:
        return Permission("", entry)
    tool, value = m[1], (m[2] or "").strip()
    cursor = tool == "Shell"
    if cursor:
        # Cursor matches command basenames, with a colon separating the argument pattern.
        base, sep, args = value.partition(":")
        if sep and args.strip() not in ("*", "**"):
            return Permission(tool, value)
        value = base.strip()
        if value and not value.endswith("*"):
            value += ":*"
    if value in ("", "*", ":*", "**"):
        return Permission(tool, wildcard="all")
    wildcard = ""
    if value.endswith(":*") or value.endswith(" *"):
        value, wildcard = value[:-2], "word"
    elif value.endswith("*"):
        value, wildcard = value[:-1], "glob"
    if tool in ("Bash", "Shell"):
        try:
            words = shlex.split(value)
        except ValueError:
            return Permission("", entry)
        if cursor and words:
            words[0] = os.path.basename(words[0]).lower()
        value = " ".join(shlex.quote(w) for w in words)
    return Permission(tool, value, wildcard)


_RUNNERS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "pwsh", "powershell", "cmd", "deno", "bun",
            "env", "xargs", "sudo", "eval", "exec", "awk", "gawk", "mawk", "nawk", "sed", "gsed", "make", "gmake"}
_EXEC_FLAGS = {"sh": "-c", "bash": "-c", "zsh": "-c", "dash": "-c", "ksh": "-c", "fish": "-c",
               "powershell": "-c", "pwsh": "-c", "cmd": "/c", "python": "-c", "node": "-e", "perl": "-e",
               "ruby": "-e", "php": "-r", "sed": "-e", "gsed": "-e"}


def shell_access(pattern: Permission) -> Optional[str]:
    if pattern.tool not in ("Bash", "Shell") or not pattern.wildcard:
        return None
    if pattern.wildcard == "all":
        return "any shell command"
    words = shlex.split(pattern.prefix)
    if not words:
        return None
    # Match executable basenames case-insensitively, including paths on typical macOS filesystems.
    exe = os.path.basename(words[0]).lower()
    if exe == "env" and len(words) > 1 or re.match(r"^[A-Za-z_]\w*=", words[0]):
        if exe == "env":
            words = words[1:]
        while words and re.match(r"^[A-Za-z_]\w*=", words[0]):
            words = words[1:]
        if not words:
            return "any command run through env"
        exe = os.path.basename(words[0]).lower()
    args = words[1:]
    if exe in ("npm", "pnpm", "yarn") and args == ["run"]:
        return "execution of the project's own scripts through %s run" % exe
    if (exe in ("npx", "bunx", "uvx") and not args or exe == "pipx" and args == ["run"]
            or exe in ("npm", "pnpm", "yarn") and args == ["exec"]
            or exe in ("pnpm", "yarn") and args == ["dlx"]):
        return "execution of package binaries through %s" % " ".join([exe] + args)
    interpreter = re.fullmatch(r"(python|node|ruby|php|perl)(?:\d+(?:\.\d+)*)?", exe)
    family = interpreter[1] if interpreter else exe
    if not interpreter and exe not in _RUNNERS:
        return None
    if not args or args == [_EXEC_FLAGS.get(family)]:
        return "any command run through %s" % exe
    return None


def broad_shell(entry: str) -> Optional[str]:
    return shell_access(permission(entry))


@dataclass(frozen=True)
class Grant:
    entry: str
    pattern: Permission
    file: str
    line: int


@dataclass
class ClaudeSettings:
    allow: List[Grant] = field(default_factory=list)
    deny: List[Permission] = field(default_factory=list)
    ask: List[Permission] = field(default_factory=list)
    disabled: List[str] = field(default_factory=list)
    bypass: Optional[Grant] = None
    gaps: List[str] = field(default_factory=list)

    def decision(self, pattern: Permission) -> str:
        if any(d.covers(pattern) for d in self.deny):
            return "deny"
        if any(a.covers(pattern) for a in self.ask):
            return "ask"
        return "allow"

    def shell_grants(self) -> List[Grant]:
        return [g for g in self.allow if shell_access(g.pattern) and self.decision(g.pattern) == "allow"]


def settings_scope(rel: str) -> Optional[Tuple[str, str]]:
    folder, name = os.path.split(rel)
    if name == "managed-settings.json":
        return "managed", folder
    if os.path.basename(folder) == "managed-settings.d" and name.endswith(".json"):
        return "managed", os.path.dirname(folder)
    if os.path.basename(folder) == ".claude" and name in ("settings.json", "settings.local.json"):
        return "project", os.path.dirname(folder)
    return None


def _unanchored_glob(tool: str) -> bool:
    """A tool name with a wildcard that Claude Code will not honour in an allow list: a glob is accepted there only in
    an MCP tool name after a literal mcp__<server>__ prefix."""
    return "*" in tool and not re.fullmatch(r"mcp__[^*]+?__[^()]*", tool)


def claude_scopes(files: Iterable[Tuple[str, str]]) -> Dict[Tuple[str, str], ClaudeSettings]:
    """Combine only settings present in this scan or snapshot, retaining declaration locations."""
    scopes: Dict[Tuple[str, str], ClaudeSettings] = {}
    for rel, text in files:
        scope = settings_scope(rel)
        if scope is None:
            continue
        try:
            doc = loads_jsonc(text)
        except (ValueError, RecursionError):
            continue
        if not isinstance(doc, dict):
            continue
        settings = scopes.setdefault(scope, ClaudeSettings())
        if isinstance(doc.get("disabledMcpjsonServers"), list):
            settings.disabled.extend(x for x in doc["disabledMcpjsonServers"] if isinstance(x, str))
        perms = doc.get("permissions")
        if not isinstance(perms, dict):
            continue
        lines = json_lines(text)
        if perms.get("defaultMode") == "bypassPermissions":
            settings.bypass = Grant("bypassPermissions", Permission("Bash", wildcard="all"), rel,
                                    lines["permissions", "defaultMode"])
        for key in ("allow", "ask", "deny"):
            entries = perms.get(key, [])
            if not isinstance(entries, list):
                settings.gaps.append("%s: permissions.%s must be a list" % (rel, key))
                continue
            for idx, entry in enumerate(entries):
                if not isinstance(entry, str):
                    continue
                pattern = permission(entry)
                if key == "allow" and _unanchored_glob(pattern.tool):
                    # Claude Code skips an unanchored allow glob ("*", "B*", "mcp__*"): it approves nothing
                    settings.gaps.append("%s: allow entry %r is an unanchored glob, which Claude Code skips"
                                         % (rel, entry.strip()[:60]))
                    continue
                if key == "allow":
                    settings.allow.append(Grant(entry.strip(), pattern, rel, lines["permissions", key, idx]))
                elif key == "ask":
                    settings.ask.append(pattern)
                else:
                    settings.deny.append(pattern)
    return scopes


def settings_for(rel: str, scopes: Dict[Tuple[str, str], ClaudeSettings]) -> ClaudeSettings:
    folder, name = os.path.split(rel)
    scope = settings_scope(rel)
    if scope is None and name in (".mcp.json", ".claude.json", "managed-mcp.json"):
        scope = ("managed" if name == "managed-mcp.json" else "project", folder)
    if scope is None:
        # Skills may live in .claude/skills, .claude/commands or a standalone skills directory.
        while folder:
            if os.path.basename(folder) in (".claude", "skills") and ("project", os.path.dirname(folder)) in scopes:
                return scopes["project", os.path.dirname(folder)]
            folder = os.path.dirname(folder)
    return scopes.get(scope, ClaudeSettings())


_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0", "host.docker.internal"}


def plaintext_remote(url: str) -> bool:
    m = re.match(r"(?i)^http://(\[[^\]]+\]|[^/:?#]+)", url.strip())
    return bool(m) and m.group(1).lower() not in _LOCAL_HOSTS
