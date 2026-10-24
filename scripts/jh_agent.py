#!/usr/bin/env python3
"""AI agent workspace configuration: MCP server definitions and the agent
settings files a repository can carry.

Everything here is static parsing of repository text. Nothing is launched,
resolved, or fetched: a server definition is evidence of what an agent
session in this repository would start, not proof that it runs.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

MAX_SERVERS = 200


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


def client_for(rel: str) -> str:
    """The agent that reads this config file, from its location."""
    p = "/" + rel.replace(os.sep, "/").lower()
    for marker, client in (("/.cursor/", "cursor"), ("/.vscode/", "vscode"), ("/.gemini/", "gemini-cli"),
                           ("/.codex/", "codex"), ("/.amazonq/", "amazon-q"), ("/.windsurf/", "windsurf"),
                           ("/.roo/", "roo-code"), ("/.kiro/", "kiro"), ("/.claude/", "claude-code")):
        if marker in p:
            return client
    base = os.path.basename(p)
    if base == ".mcp.json":
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


def _line_of_name(lines: List[str], name: str) -> int:
    needle = '"%s"' % name
    for idx, line in enumerate(lines, 1):
        pos = line.find(needle)
        if pos >= 0 and line[pos + len(needle):].lstrip().startswith(":"):
            return idx
    return 1


def _server_from_spec(name: str, spec: Dict[str, Any], line: int) -> McpServer:
    command = spec.get("command")
    args = spec.get("args") if isinstance(spec.get("args"), list) else []
    if isinstance(command, list):                       # opencode: command is argv
        command, args = (command[0] if command else ""), command[1:] + list(args)
    url = spec.get("url") or spec.get("serverUrl") or spec.get("httpUrl") or ""
    kind = str(spec.get("type") or spec.get("transport") or "").lower()
    s = McpServer(name=name, line=line, transport="unknown",
                  command=command if isinstance(command, str) else "",
                  args=[a if isinstance(a, str) else json.dumps(a) for a in args],
                  env=_strs(spec.get("env") or spec.get("environment")),
                  url=url if isinstance(url, str) else "",
                  headers=_strs(spec.get("headers") or spec.get("http_headers")))
    s.transport = ("sse" if "sse" in kind else "http") if s.url else ("stdio" if s.command else "unknown")
    s.disabled = spec.get("disabled") is True or spec.get("enabled") is False
    return s


def mcp_servers(rel: str, text: str) -> List[McpServer]:
    """MCP servers defined in one config file. Raises ValueError when the
    file cannot be parsed, so callers can record a coverage gap."""
    posix = rel.replace(os.sep, "/").lower()
    if posix.endswith(".toml"):
        return _codex_servers(text)[:MAX_SERVERS]
    data = loads_jsonc(text)
    if not isinstance(data, dict):
        return []                                       # valid JSON, but not an MCP client config
    base = os.path.basename(posix)
    container = data.get("mcpServers")
    if container is None and base == "mcp.json":
        container = data.get("servers")                 # VS Code .vscode/mcp.json
    if container is None and base.startswith("opencode.json"):
        container = data.get("mcp")
    if not isinstance(container, dict):
        return []
    lines = text.split("\n")
    out = []
    for name, spec in list(container.items())[:MAX_SERVERS]:
        if isinstance(spec, dict):
            out.append(_server_from_spec(str(name), spec, _line_of_name(lines, str(name))))
    return out


# ---------------------------------------------------------------------------
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


_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0", "host.docker.internal"}


def plaintext_remote(url: str) -> bool:
    m = re.match(r"(?i)^http://(\[[^\]]+\]|[^/:?#]+)", url.strip())
    return bool(m) and m.group(1).lower() not in _LOCAL_HOSTS
