"""sandbox: run a repository's own install hooks, its dependencies as they load, and the commands that run when it
is opened, in a disposable sandbox, and report what they try to do.

Opt-in only. jankhunt42 stays stdlib: it orchestrates an external rootless container engine (podman, or docker)
and an operator-built image that holds strace. The repository is copied in read-only, the network is off, the
root filesystem is read-only, every capability is dropped, and resources and time are bounded. Fresh canary
credentials sit in a throwaway HOME. strace, started as the parent of each hook, records file, network and
process activity; a loopback DNS sink records the names looked up.

Three surfaces: `install` (package hooks), `import` (each direct dependency the install put in place, loaded the
way the application loads it, so code that runs only when a package is loaded runs too), and `open` (what an agent
or editor runs because the repository was opened: project hooks and helper commands, dev container commands,
folder-open tasks, MCP servers). Each command is written to its own file and run by `sh` under the tracer, so text
from the repository never becomes part of the runner.

The result is a firewall-style log: DENY for each attempted connection or lookup (nothing can leave), ALERT for a
canary read, a canary passed on, or a persistence attempt. It is evidence of the tier `sandbox-observed`: it adds
to static findings and never refutes them, because a run that did not reach a path says nothing about that path.
Canary values never leave the run: reports name canaries by id only.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Set, Tuple

import jh_agent
import jh_ceiling
import jh_checks
import jh_graph
from jh_core import MCP_CONFIG_FILES, redact_secrets

SCHEMA = "jankhunt.sandbox.v1"
OLD_SCHEMAS = ("jankhunt.detonate.v1",)           # results saved before the rename
OLD_IMAGE = "localhost/jankhunt42-detonate:0.1"   # an image built before the rename
DEFAULT_IMAGE = "localhost/jankhunt42-sandbox:0.1"
DOTNET_IMAGE = "localhost/jankhunt42-sandbox-dotnet:0.1"
NPM_HOOKS = ("preinstall", "install", "postinstall", "prepare")
HOME = "/home/canary"

# where code looks for credentials; each gets a fresh, never-issued value carrying the JH42CANARY marker
CANARY_FILES = (
    ("aws", ".aws/credentials", "[default]\naws_access_key_id = AKIA{u16}\naws_secret_access_key = JH42CANARY{h32}\n"),
    ("git", ".git-credentials", "https://canary:ghp_JH42CANARY{h26}@github.com\n"),
    ("npm", ".npmrc", "//registry.npmjs.org/:_authToken=npm_JH42CANARY{h26}\n"),
    ("ssh", ".ssh/id_ed25519", "-----BEGIN OPENSSH PRIVATE KEY-----\nJH42CANARY{h32}\n-----END OPENSSH PRIVATE KEY-----\n"),
    ("env", ".env", "API_TOKEN=JH42CANARY{h32}\nDATABASE_URL=postgres://canary:JH42CANARY{h16}@db.invalid/app\n"),
    ("gh", ".config/gh/hosts.yml", "github.com:\n    oauth_token: gho_JH42CANARY{h26}\n    user: canary\n"),
    ("docker", ".docker/config.json", '{{"auths": {{"https://index.docker.io/v1/": {{"auth": "JH42CANARY{h32}"}}}}}}\n'),
    ("kube", ".kube/config", "apiVersion: v1\nkind: Config\nusers:\n- name: canary\n  user:\n    token: JH42CANARY{h32}\n"),
    ("pypi", ".pypirc", "[pypi]\nusername = __token__\npassword = pypi-JH42CANARY{h32}\n"),
)
# a write or rename into one of these is a persistence attempt
PERSISTENCE = (".bashrc", ".profile", ".bash_profile", ".zshrc", ".ssh/authorized_keys", ".config/autostart/",
               ".config/systemd/user/", "/etc/cron", "/var/spool/cron", ".local/share/applications/")
LIMITS = ("--pids-limit=256", "--memory=1g", "--cpus=2")
SURFACES = ("install", "import", "open")

# what an agent or editor runs because the repository was opened, read only from these fixed paths
AGENT_SETTINGS = (".claude/settings.json", ".claude/settings.local.json", ".gemini/settings.json")
HELPER_KEYS = jh_checks._HELPER_KEYS + ("statusLine",)
DEVCONTAINER_COMMANDS = ("initializeCommand", "onCreateCommand", "updateContentCommand", "postCreateCommand",
                         "postStartCommand", "postAttachCommand")
MCP_SECONDS = 20          # a server runs until stopped; this long is enough to see what it does at start
MAX_OPEN_STEPS = 40
MAX_IMPORT_STEPS = 40
IMPORT_SECONDS = 20       # loading a module takes a moment; one that is still busy after this is reported
SETTLE_SECONDS = 2        # after a load, time for what it deferred (a timer, a thread) to run where it is seen
# a dependency name reaches a step only as an argument, quoted, and only if it is a package name
_NPM_NAME = re.compile(r"(?:@[A-Za-z0-9][\w.~-]{0,100}/)?[A-Za-z0-9][\w.~-]{0,213}\Z")
_PY_REQUIREMENT = re.compile(r"([A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?)\s*(?:\[[^\]]*\])?\s*(?:[=<>!~;@ ]|$)")
NODE_LOAD = ("node -e 'import(process.argv[1]).then(() => new Promise((r) => setTimeout(r, %d)), (e) => { "
             "console.error(\"jankhunt42: not loadable: \" + ((e && e.code) || e)); process.exitCode = 3 })' -- %%s"
             % (SETTLE_SECONDS * 1000))
PYTHON_LOAD = "python3 -I /jh/load.py %s"
MAX_CONFIG_BYTES = 1000000
# what the sandbox writes is untrusted: read only regular files, never through a link, and only this much
# operator-supplied dependency caches: made outside the sandbox, copied into the run, never fetched by it
MAX_CACHE_BYTES = 768 * 1024 * 1024
CACHE_MOUNTS = {"npm": ("/cache/npm", "rw"), "wheels": ("/cache/wheels", "ro"), "nuget": ("/cache/nuget", "ro")}
NPM_LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json")
# command-line settings override the repository's own .npmrc: scripts on, and every dependency type installed
NPM_CI = ("npm ci --offline --cache /cache/npm --foreground-scripts --no-audit --no-fund --ignore-scripts=false "
          "--include=dev --include=optional --include=peer")
# -I: a pip.py in the repository cannot stand in for the installer
PIP_OFFLINE = "python3 -I -m pip install --no-index --find-links /cache/wheels --no-cache-dir --disable-pip-version-check"
MAX_TRACE_BYTES = 64 * 1024 * 1024
MAX_DNS_BYTES = 1024 * 1024
_HOSTNAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,252}\Z")
_MCP_INIT = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "jankhunt42-sandbox", "version": "1"}}})


def make_canaries() -> List[Dict[str, Any]]:
    out = []
    for kind, rel, template in CANARY_FILES:
        text = template.format(u16=secrets.token_hex(8).upper(), h32=secrets.token_hex(16), h26=secrets.token_hex(13),
                               h16=secrets.token_hex(8))
        values = re.findall(r"[\w/+=-]*JH42CANARY\w+|AKIA[0-9A-F]{16}", text)
        out.append({"id": "canary-%s" % kind, "kind": kind, "path": HOME + "/" + rel, "text": text, "values": values})
    return out


def plan_steps(root: str, surfaces: Tuple[str, ...] = SURFACES,
               caches: Tuple[str, ...] = (), dotnet_ready: bool = True) -> Tuple[List[Dict[str, Any]], List[str]]:
    """The commands to run, and why coverage is partial before anything runs. caches names the operator-supplied
    dependency caches ("npm", "wheels") the sandbox will hold."""
    steps: List[Dict[str, Any]] = []
    gaps: List[str] = []
    if "install" in surfaces:
        _plan_install(root, steps, gaps, caches)
        _plan_dotnet(root, steps, gaps, caches, dotnet_ready)
    if "import" in surfaces:
        _plan_import(root, steps, gaps)
    if "open" in surfaces:
        _plan_open(root, steps, gaps)
    return steps, gaps


def _step(name: str, surface: str, script: str, source: str = "", stdin: str = "", **extra: Any) -> Dict[str, Any]:
    # a name carries repository text (a hook event, a task label, a server name): one plain, bounded line
    name = jh_graph.sanitize_text(name, 80).replace("*", "").replace("`", "'")
    return dict(name=name, surface=surface, script=script, source=source, stdin=stdin, **extra)


def _plan_install(root: str, steps: List[Dict[str, Any]], gaps: List[str], caches: Tuple[str, ...] = ()) -> None:
    pkg = os.path.join(root, "package.json")
    if os.path.isfile(pkg) and not os.path.islink(pkg):
        try:
            with open(pkg, encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, ValueError, RecursionError):
            doc = {}
            gaps.append("package.json could not be read")
        scripts = doc.get("scripts") if isinstance(doc.get("scripts"), dict) else {}
        deps = any(doc.get(k) for k in ("dependencies", "devDependencies", "optionalDependencies"))
        lock = next((f for f in NPM_LOCKFILES if os.path.isfile(os.path.join(root, f)) and
                     not os.path.islink(os.path.join(root, f))), None)
        if "npm" in caches and lock:
            # one install from the cache: the package's own hooks and every dependency's run inside it, once
            steps.append(_step("npm ci (offline, with dependencies)", "install", NPM_CI, lock, npm_ci=True))
        else:
            for hook in NPM_HOOKS:
                if isinstance(scripts.get(hook), str):
                    steps.append(_step("npm %s" % hook, "install", "npm run --if-present %s" % hook, "package.json"))
            if "npm" in caches:
                gaps.append("npm ci needs package-lock.json or npm-shrinkwrap.json, so dependencies were not installed "
                            "and their install hooks did not run")
            elif deps:
                gaps.append("npm dependencies are not installed (no --npm-cache), so their install hooks did not run")
    requirements = os.path.isfile(os.path.join(root, "requirements.txt"))
    declared = [] if requirements else pyproject_dependencies(root)
    if declared and "wheels" in caches:
        # a modern project declares its dependencies in pyproject.toml; each goes to pip as one quoted argument
        steps.append(_step("pip install pyproject dependencies (offline)", "install",
                           PIP_OFFLINE + " --target /work/pydeps " + " ".join(shlex.quote(d) for d in declared),
                           "pyproject.toml", pip=True))
    elif declared:
        gaps.append("pyproject.toml dependencies are not installed (no --wheelhouse), so they did not run or load")
    if requirements and "wheels" in caches:
        steps.append(_step("pip install requirements (offline)", "install",
                           PIP_OFFLINE + " --target /work/pydeps -r requirements.txt", "requirements.txt", pip=True))
    elif requirements:
        gaps.append("Python requirements are not installed (no --wheelhouse), so any source package's setup code "
                    "did not run")
    if os.path.isfile(os.path.join(root, "setup.py")):
        steps.append(_step("python setup.py", "install",
                           ("PYTHONPATH=/work/pydeps " if "wheels" in caches else "") +
                           "python3 setup.py egg_info --egg-base /tmp", "setup.py"))
    elif os.path.isfile(os.path.join(root, "pyproject.toml")):
        if "wheels" in caches:
            # build isolation installs the build backend from the wheelhouse
            steps.append(_step("python build backend", "install",
                               "python3 -I -m pip wheel --no-deps --no-index --find-links /cache/wheels "
                               "--disable-pip-version-check -w /tmp/wheel .", "pyproject.toml", pip=True))
        else:
            steps.append(_step("python build backend", "install",
                               "python3 -I -m pip wheel --no-deps --no-build-isolation --no-index -w /tmp/wheel .",
                               "pyproject.toml"))
            gaps.append("a pyproject build backend that is not in the image cannot run (no --wheelhouse)")


def _plan_dotnet(root: str, steps: List[Dict[str, Any]], gaps: List[str], caches: Tuple[str, ...], ready: bool) -> None:
    import jh_nuget
    tree = jh_nuget.discover(root)
    if not tree["projects"] and not tree["solutions"]:
        return
    gaps.extend(tree["issues"])
    if not ready:
        gaps.append(".NET restore/build did not run: the SDK image %s is not available; build it from "
                    "templates/sandbox-dotnet.Containerfile" % DOTNET_IMAGE)
        return
    if "nuget" not in caches:
        gaps.append(".NET restore/build did not run (no --nuget-cache or fetched NuGet feed)")
        return
    targets = tree["projects"] or tree["solutions"]
    for target in targets[:jh_nuget.MAX_PROJECTS]:
        arg = shlex.quote("./" + target)              # one filename, never a shell fragment or a dotnet option
        source = jh_graph.sanitize_text(target, 200)
        steps.append(_step("dotnet restore %s (locked, offline)" % target, "install",
                           "dotnet restore --locked-mode --source /cache/nuget --packages /work/nuget-packages "
                           "--no-http-cache --disable-build-servers -p:NuGetAudit=false " + arg, source, nuget=True))
        steps.append(_step("dotnet build %s (offline)" % target, "install",
                           "dotnet build --no-restore --disable-build-servers -p:NuGetAudit=false " + arg,
                           source, nuget=True))


def pyproject_dependencies(root: str) -> List[str]:
    """The [project] dependencies a pyproject.toml declares, each a requirement that starts with a package name (so
    none can pass for a pip option) and names no URL. tomllib where Python has it; else a strict reading of that one
    array."""
    path = os.path.join(root, "pyproject.toml")
    if not os.path.isfile(path) or os.path.islink(path):
        return []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read(MAX_CONFIG_BYTES)
    except OSError:
        return []
    try:
        import tomllib                      # Python 3.11+
        project = tomllib.loads(text).get("project")
        deps = project.get("dependencies") if isinstance(project, dict) else None
    except ImportError:
        m = re.search(r"(?ms)^\[project\]\s*$(.*?)(?=^\[|\Z)", text)
        start = re.search(r"(?m)^dependencies\s*=\s*\[", m.group(1)) if m else None
        deps = []
        if start:
            # the quoted strings until the ] that closes the array, read outside quotes ("requests[socks]>=2")
            for q in re.finditer(r"\"([^\"\n]*)\"|'([^'\n]*)'|(\])", m.group(1)[start.end():]):
                if q.group(3):
                    break
                deps.append(q.group(1) if q.group(1) is not None else q.group(2))
    except (ValueError, RecursionError):
        return []
    if not isinstance(deps, list):
        return []
    return [d.strip() for d in deps if isinstance(d, str) and _PY_REQUIREMENT.match(d.strip())
            and "@" not in d and "://" not in d][:MAX_IMPORT_STEPS * 2]


def _plan_import(root: str, steps: List[Dict[str, Any]], gaps: List[str]) -> None:
    """Load each direct dependency that an install step already planned put in place: npm packages after npm ci,
    Python requirements after the offline pip install. One step per dependency, so each event names the package
    that caused it."""
    loads: List[Tuple[str, str, str, str]] = []
    bad = 0
    pkg = os.path.join(root, "package.json")
    if os.path.isfile(pkg) and not os.path.islink(pkg):
        try:
            with open(pkg, encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, ValueError, RecursionError):
            doc = {}
        doc = doc if isinstance(doc, dict) else {}
        names = sorted({n for k in ("dependencies", "optionalDependencies", "devDependencies")
                        if isinstance(doc.get(k), dict) for n in doc[k]})
        if names and not any(s.get("npm_ci") for s in steps):
            gaps.append("npm dependencies were not loaded, because they were not installed (that needs a lockfile "
                        "and --fetch or --npm-cache)")
        elif names:
            for name in names:
                if not _NPM_NAME.match(name):
                    bad += 1
                elif not name.startswith("@types/"):         # type declarations only: nothing to load
                    loads.append(("load %s" % name, NODE_LOAD % shlex.quote(name), "package.json", name))
    req = os.path.join(root, "requirements.txt")
    declared = [] if os.path.isfile(req) else pyproject_dependencies(root)
    if declared:
        names = list(dict.fromkeys(_PY_REQUIREMENT.match(d).group(1) for d in declared))
        if not any(s.get("pip") and s.get("source") == "pyproject.toml" for s in steps):
            gaps.append("pyproject.toml dependencies were not loaded, because they were not installed (that needs "
                        "--wheelhouse)")
        else:
            loads += [("import %s" % n, PYTHON_LOAD % shlex.quote(n), "pyproject.toml", n) for n in names]
    if os.path.isfile(req) and not os.path.islink(req):
        names = []
        try:
            with open(req, encoding="utf-8", errors="replace") as fh:
                lines = fh.read(MAX_CONFIG_BYTES).splitlines()
        except OSError:
            lines = []
        for line in lines:
            line = re.sub(r"(^|\s)#.*", "", line).strip()
            if not line or line.startswith(("-", ".", "/")) or "://" in line:
                continue                    # options, includes, paths and URLs: not a named requirement
            m = _PY_REQUIREMENT.match(line)
            if not m:
                bad += 1
            elif m.group(1) not in names:
                names.append(m.group(1))
        if names and not any(s.get("pip") and s.get("source") == "requirements.txt" for s in steps):
            gaps.append("Python requirements were not loaded, because they were not installed (that needs "
                        "--wheelhouse)")
        elif names:
            loads += [("import %s" % n, PYTHON_LOAD % shlex.quote(n), "requirements.txt", n) for n in names]
    if any(source != "package.json" for _, _, source, _ in loads):
        # a real install runs every .pth file in site-packages at each Python start: once, as its own step
        loads.insert(0, ("python startup (.pth files)", "python3 -I /jh/load.py --pth", "site-packages", ""))
    if bad:
        gaps.append("%d dependency names are not package names, so they were not loaded" % bad)
    if len(loads) > MAX_IMPORT_STEPS:
        gaps.append("%d more direct dependencies were not loaded (the first %d were)"
                    % (len(loads) - MAX_IMPORT_STEPS, MAX_IMPORT_STEPS))
    for name, script, source, dep in loads[:MAX_IMPORT_STEPS]:
        steps.append(_step(name, "import", script, source, limit=IMPORT_SECONDS, import_of=dep))


def _inside(root: str, rel: str) -> bool:
    """True when no part of rel is a link: a repository's .claude may point at the user's own settings."""
    path = root
    for part in rel.split("/"):
        path = os.path.join(path, part)
        if os.path.islink(path):
            return False
    return True


def _read_config(root: str, rel: str, gaps: List[str]) -> Optional[str]:
    path = os.path.join(root, rel)
    if not os.path.lexists(path):
        return None
    if not _inside(root, rel) or not os.path.isfile(path) or os.path.getsize(path) > MAX_CONFIG_BYTES:
        gaps.append("%s was not read: it is a link, not a regular file, or over 1 MB" % rel)
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except (OSError, UnicodeDecodeError):
        gaps.append("%s could not be read" % rel)
        return None


def _read_settings(root: str, rel: str, gaps: List[str]) -> Optional[Dict[str, Any]]:
    text = _read_config(root, rel, gaps)
    if text is None:
        return None
    try:
        data = jh_agent.loads_jsonc(text)
    except (ValueError, RecursionError):
        gaps.append("%s is not valid JSON, so its commands were not run" % rel)
        return None
    return data if isinstance(data, dict) else None


def _hook_input(event: str) -> str:
    """A synthetic event for a hook's standard input; nothing from a real session."""
    doc: Dict[str, Any] = {"session_id": "jankhunt42-sandbox", "transcript_path": "/tmp/transcript.jsonl",
                           "cwd": "/work/repo", "hook_event_name": event}
    if event in ("PreToolUse", "PostToolUse", "PermissionRequest"):
        doc.update(tool_name="Bash", tool_input={"command": "ls"})
    elif event == "UserPromptSubmit":
        doc["prompt"] = "hello"
    elif event == "SessionStart":
        doc["source"] = "startup"
    return json.dumps(doc)


def _command_text(value: Any) -> Optional[str]:
    """A dev container command: a string runs in a shell, a list runs as it is."""
    if isinstance(value, str) and value.strip():
        return value
    if isinstance(value, list) and value and all(isinstance(v, str) for v in value):
        return shlex.join(value)
    return None


def _unquoted_space(value: str) -> bool:
    quote, escaped = "", False
    for ch in value:
        if escaped:
            escaped = False
        elif quote:
            quote = "" if ch == quote else quote
        elif ch == "\\":
            escaped = True              # VS Code skips an escaped character, so "\ " is not a space to quote
        elif ch in "'\"":
            quote = ch
        elif ch == " ":
            return True
    return False


def _vscode_token(value: str, quoting: Optional[str] = None) -> str:
    """One shell-task token as VS Code writes it for a POSIX shell: quoted only when it has an unquoted space (so
    $VAR and $(...) stay live, as they do in VS Code), or as the task asks."""
    if quoting == "strong":
        return "'" + value + "'"        # as VS Code writes it, even when the value holds a quote
    if quoting == "weak":
        return '"' + value + '"'
    if quoting == "escape":
        return value.replace(" ", "\\ ")
    already = len(value) >= 2 and value[0] == value[-1] and value[0] in "'\""
    return "'" + value + "'" if _unquoted_space(value) and not already else value


_VSCODE_VARS = {"${workspaceFolder}": "/work/repo", "${workspaceRoot}": "/work/repo", "${cwd}": "/work/repo",
                "${workspaceFolderBasename}": "repo"}


def _vscode_task(task: Dict[str, Any], gaps: List[str]) -> Optional[str]:
    """The command line VS Code would run for a folder-open task; what is not modelled is a coverage gap."""
    spec = dict(task)
    if isinstance(task.get("linux"), dict):
        spec.update(task["linux"])
    command, args = spec.get("command"), spec.get("args") or []
    label = jh_graph.sanitize_text(str(task.get("label", "?")), 40)
    if not isinstance(command, str) or not command.strip() or not isinstance(args, list):
        gaps.append("folder-open task %s: its command could not be read" % label)
        return None
    tokens: List[Tuple[str, Optional[str]]] = []
    for a in args:
        if isinstance(a, str):
            tokens.append((a, None))
        elif isinstance(a, dict) and isinstance(a.get("value"), str) and a.get("quoting") in (None, "strong", "weak", "escape"):
            tokens.append((a["value"], a.get("quoting")))
        else:
            gaps.append("folder-open task %s: an argument could not be read" % label)
            return None
    if isinstance(spec.get("options"), dict) and set(spec["options"]) & {"shell", "env", "cwd"}:
        gaps.append("folder-open task %s: its shell, environment or working folder options were not applied" % label)
    if spec.get("type") == "process":
        line = shlex.join([command] + [v for v, _ in tokens])
    elif not tokens:
        line = command
    else:
        line = " ".join([_vscode_token(command)] + [_vscode_token(v, q) for v, q in tokens])
    for var, value in _VSCODE_VARS.items():
        line = line.replace(var, value)
    if "${" in line:
        gaps.append("folder-open task %s uses VS Code variables that were not resolved" % label)
    return line


def _vscode_chain(task: Dict[str, Any], by_label: Dict[str, Dict[str, Any]], gaps: List[str],
                  stack: Tuple[str, ...] = ()) -> List[Tuple[Dict[str, Any], str]]:
    """A folder-open task with what VS Code runs before it: its dependsOn tasks first, in order, depth first."""
    label = str(task.get("label", "?"))
    shown_label = jh_graph.sanitize_text(label, 40)
    if label in stack or len(stack) > 5:
        gaps.append("folder-open task %s: its dependencies nest too deep or form a cycle" % shown_label)
        return []
    out: List[Tuple[Dict[str, Any], str]] = []
    deps = task.get("dependsOn")
    for dep in [deps] if isinstance(deps, str) else deps if isinstance(deps, list) else []:
        if isinstance(dep, str) and dep in by_label:
            out.extend(_vscode_chain(by_label[dep], by_label, gaps, stack + (label,)))
        else:
            gaps.append("folder-open task %s depends on a task not defined in .vscode/tasks.json; it was not run"
                        % shown_label)
    if deps and task.get("dependsOrder") != "sequence":
        gaps.append("folder-open task %s: dependencies VS Code runs in parallel ran one after another" % shown_label)
    if "command" in task or not deps:   # a task may only gather its dependencies
        script = _vscode_task(task, gaps)
        if script is not None:
            out.append((task, script))
    return out


def _devcontainer_files(root: str) -> List[str]:
    out = [rel for rel in (".devcontainer/devcontainer.json", ".devcontainer.json")
           if os.path.lexists(os.path.join(root, rel))]
    base = os.path.join(root, ".devcontainer")
    if os.path.isdir(base) and not os.path.islink(base):
        for name in sorted(os.listdir(base))[:20]:
            rel = ".devcontainer/%s/devcontainer.json" % name
            if os.path.lexists(os.path.join(root, rel)):
                out.append(rel)
    return out


def _plan_open(root: str, steps: List[Dict[str, Any]], gaps: List[str]) -> None:
    found: List[Dict[str, Any]] = []
    for rel in AGENT_SETTINGS:
        data = _read_settings(root, rel, gaps)
        if data is None:
            continue
        agent = "gemini" if rel.startswith(".gemini/") else "claude"
        for event, actions in sorted(jh_checks._hook_actions(data.get("hooks")).items()):
            for kind, value in actions:
                if kind == "command":
                    found.append(_step("%s hook %s" % (agent, event), "open", value, rel, _hook_input(event)))
        for key in HELPER_KEYS:
            value = data.get(key)
            command = value.get("command") if isinstance(value, dict) else value
            if isinstance(command, str) and command.strip():
                found.append(_step("%s %s" % (agent, key), "open", command, rel,
                                   _hook_input("StatusLine") if key == "statusLine" else ""))
    for rel in _devcontainer_files(root):
        data = _read_settings(root, rel, gaps)
        if data is None:
            continue
        for key in DEVCONTAINER_COMMANDS:
            value = data.get(key)
            named = sorted(value.items()) if isinstance(value, dict) else [("", value)]
            for label, item in named:
                command = _command_text(item)
                if command:
                    found.append(_step("devcontainer %s%s" % (key, ":" + str(label)[:40] if label else ""), "open",
                                       command, rel, host=key == "initializeCommand"))
    data = _read_settings(root, ".vscode/tasks.json", gaps) or {}
    tasks = [t for t in data.get("tasks") if isinstance(t, dict)] if isinstance(data.get("tasks"), list) else []
    if isinstance(data.get("options"), dict) and set(data["options"]) & {"shell", "env", "cwd"}:
        gaps.append(".vscode/tasks.json: the shell, environment or working folder options for every task were not applied")
    if any(k in data for k in ("command", "args")):
        gaps.append(".vscode/tasks.json: an old-format file with a global command is not modelled")
    by_label: Dict[str, Dict[str, Any]] = {}
    for task in tasks:
        if isinstance(task.get("label"), str):
            by_label.setdefault(task["label"], task)
    ran: set = set()
    for root_task in tasks:
        opts = root_task.get("runOptions")
        if not (isinstance(opts, dict) and opts.get("runOn") == "folderOpen"):
            continue
        for task, script in _vscode_chain(root_task, by_label, gaps):
            if id(task) in ran:
                continue
            ran.add(id(task))
            found.append(_step("vscode task %s" % str(task.get("label", "?"))[:40], "open", script, ".vscode/tasks.json",
                               **({"dependency_of": str(root_task.get("label", "?"))[:40]} if task is not root_task else {})))
    for rel in MCP_CONFIG_FILES:
        text = _read_config(root, rel, gaps)
        if text is None:
            continue
        try:
            servers = jh_agent.mcp_servers(rel, text)
        except (ValueError, TypeError, RecursionError):
            gaps.append("%s could not be parsed, so its MCP servers were not started" % rel)
            continue
        for server in servers:
            if server.transport != "stdio" or not server.command or server.disabled:
                continue
            found.append(_step("mcp server %s" % server.name[:40], "open", shlex.join([server.command] + list(server.args or [])),
                               rel, _MCP_INIT + "\n", limit=MCP_SECONDS, server=True))
            if server.env:
                gaps.append("MCP server %s started without its configured environment"
                            % jh_graph.sanitize_text(server.name, 40))
    if len(found) > MAX_OPEN_STEPS:
        gaps.append("%d more commands that run on open were not run (limit %d)" % (len(found) - MAX_OPEN_STEPS,
                                                                                  MAX_OPEN_STEPS))
    if any(" hook " in f["name"] for f in found):
        gaps.append("each agent hook ran once with a synthetic event; behaviour that depends on real tool input or "
                    "later events was not reached")
    steps.extend(found[:MAX_OPEN_STEPS])


def inner_script(steps: List[Dict[str, Any]], timeout: int) -> str:
    """The runner. Each step's command stays in its own file (/jh/step.N.sh, written by write_steps), read by sh
    under the tracer: nothing the repository wrote is ever pasted into this script."""
    lines = ["set -u", "python3 /jh/sink.py /out/dns.log & sleep 0.3",
             "cp -r /src/. /work/repo 2>/dev/null; cd /work/repo"]
    for i, step in enumerate(steps):
        runner = "sh /jh/step.%d.sh" % i
        lines.append("timeout -k 5 %d strace -f -qq -yy -s 256 -e trace=%%network,%%file,%%process,read,write "
                     "-o /out/trace.%d %s </jh/step.%d.in >/out/step.%d.log 2>&1; echo $? > /out/step.%d.exit"
                     % (step_limit(step, timeout), i, runner, i, i, i))
    return "\n".join(lines) + "\n"


def step_limit(step: Dict[str, Any], timeout: int) -> int:
    return int(min(step.get("limit") or timeout, timeout))


def write_steps(steps: List[Dict[str, Any]], jh_dir: str) -> None:
    for i, step in enumerate(steps):
        with open(os.path.join(jh_dir, "step.%d.sh" % i), "w", encoding="utf-8") as fh:
            fh.write(step["script"] + "\n")
        with open(os.path.join(jh_dir, "step.%d.in" % i), "w", encoding="utf-8") as fh:
            fh.write(step.get("stdin") or "")


def shown(text: str, values: List[Tuple[str, str]] = ()) -> str:
    """A command as it may appear in a report: secrets redacted, canaries masked, one bounded line."""
    return jh_graph.sanitize_text(redact_secrets(mask(text, list(values))), 160)


def container_argv(engine: str, image: str, run_dir: str, src: str, caches: Tuple[str, ...] = ()) -> List[str]:
    z = ",Z" if engine == "podman" else ""
    mounts = []
    if image == DOTNET_IMAGE or "nuget" in caches:
        # .NET 10 named mutexes use HOME/.dotnet despite DOTNET_CLI_HOME. Only this SDK scratch is writable;
        # the parent canary home and all credential files stay read-only, and nothing is written back to the host.
        mounts += ["--tmpfs", HOME + "/.dotnet:rw,size=64m,mode=1777"]
    for name in sorted(caches):
        target, mode = CACHE_MOUNTS[name]
        # the run's own copy of the operator's cache, never the operator's directory itself
        mounts += ["-v", "%s/cache/%s:%s:%s%s" % (run_dir, name, target, mode, z)]
    return [engine, "run", "--rm", "--pull=never", "--network=none", "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", *LIMITS, "--sysctl", "net.ipv4.ip_unprivileged_port_start=0",
            "--tmpfs", "/tmp:rw,size=256m,mode=1777", "--tmpfs", "/work:rw,size=1g,mode=1777", *mounts,
            "-v", "%s:/src:ro%s" % (src, z), "-v", "%s/home:%s:ro%s" % (run_dir, HOME, z),
            "-v", "%s/jh:/jh:ro%s" % (run_dir, z), "-v", "%s/out:/out:rw%s" % (run_dir, z),
            "-v", "%s/jh/resolv.conf:/etc/resolv.conf:ro%s" % (run_dir, z),
            "-e", "HOME=" + HOME, "-e", "CLAUDE_PROJECT_DIR=/work/repo", "-e", "npm_config_cache=/tmp/npm", "-e", "npm_config_update_notifier=false", "-e", "PIP_NO_INDEX=1",
            "-e", "DOTNET_CLI_TELEMETRY_OPTOUT=1", "-e", "DOTNET_NOLOGO=1", "-e", "NUGET_XMLDOC_MODE=skip",
            "-e", "DOTNET_CLI_HOME=/tmp/dotnet", "-e", "NUGET_PACKAGES=/work/nuget-packages",
            "-e", "NUGET_HTTP_CACHE_PATH=/tmp/nuget-http", "-e", "MSBUILDDISABLENODEREUSE=1",
            "-e", "DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE=1",
            image, "sh", "/jh/run.sh"]


_LINE_RE = re.compile(r"^(\d+)\s+(\w+)\((.*)$")
_RESUMED_RE = re.compile(r"^(\d+)\s+<\.\.\. (\w+) resumed>.*= (\d+)$")
# the package manager reading its own configuration is expected, not the repository's doing
_OWN_CONFIG = {"canary-npm": re.compile(r"^(?:npm|npx|node\s+\S*/np[mx](?:-cli\.js)?)\b")}
_CONNECT_RE = re.compile(r'sa_family=AF_INET6?, sin6?_port=htons\((\d+)\).*?(?:inet_addr\("([^"]+)"\)|inet_pton\(AF_INET6, "([^"]+)")')
_PATH_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')


def parse_trace(text: str, canaries: List[Dict[str, Any]], step: str) -> List[Dict[str, Any]]:
    """strace -f -yy output to events. Each event: verdict (DENY / ALERT / INFO), kind, detail, pid, process."""
    values = [(c["id"], v) for c in canaries for v in c["values"]]
    paths = {c["path"]: c["id"] for c in canaries}
    procs: Dict[str, str] = {}
    events: List[Dict[str, Any]] = []
    seen = set()

    def add(verdict: str, kind: str, detail: str, pid: str) -> None:
        key = (verdict, kind, detail, procs.get(pid, ""))
        if key not in seen:
            seen.add(key)
            events.append({"verdict": verdict, "kind": kind, "detail": detail, "pid": pid,
                           "process": procs.get(pid, ""), "step": step})

    for raw in text.splitlines():
        r = _RESUMED_RE.match(raw)
        if r and r.group(2) in ("clone", "clone3", "fork", "vfork"):
            procs.setdefault(r.group(3), procs.get(r.group(1), ""))
            continue
        m = _LINE_RE.match(raw)
        if not m:
            continue
        pid, call, rest = m.groups()
        if call in ("clone", "clone3", "fork", "vfork"):
            child = re.search(r"= (\d+)$", rest.rstrip())
            if child:
                procs.setdefault(child.group(1), procs.get(pid, ""))
            continue
        if call == "execve" and not rest.rstrip().endswith("ENOENT (No such file or directory)"):
            argv = re.search(r"\[(.*?)\]", rest)
            words = _PATH_RE.findall(argv.group(1))[:12] if argv else []
            procs[pid] = mask(" ".join(words), values)[:160]
            for cid, value in values:
                if any(value in w for w in words):
                    add("ALERT", "canary-passed", "a process was started with %s in its arguments" % cid, pid)
            if any(p in " ".join(words) for p in paths):
                add("ALERT", "canary-passed", "a process was started with a canary file in its arguments", pid)
        elif call == "connect":
            c = _CONNECT_RE.search(rest)
            if c:
                port, v4, v6 = c.groups()
                host = v4 or v6
                if host in ("127.0.0.1",) and port == "53":
                    continue                        # the DNS sink; names come from its log
                add("DENY", "network", "%s:%s" % (host, port), pid)
        elif call in ("openat", "open"):
            p = _PATH_RE.search(rest)
            if p and p.group(1) in paths and "= -1" not in rest:
                cid = paths[p.group(1)]
                own = _OWN_CONFIG.get(cid)
                verdict = "INFO" if own and own.match(procs.get(pid, "")) else "ALERT"
                add(verdict, "canary-opened", "%s (%s)" % (p.group(1).replace(HOME, "~"), cid), pid)
            if p and ("O_WRONLY" in rest or "O_RDWR" in rest or "O_CREAT" in rest) and \
                    any(x in p.group(1) for x in PERSISTENCE):
                add("ALERT", "persistence", "write attempt: %s" % p.group(1), pid)
        elif call == "read":
            f = re.match(r"\d+<([^>]+)>", rest)
            if f and f.group(1) in paths and not re.search(r"= 0$", rest.rstrip()):
                cid = paths[f.group(1)]
                own = _OWN_CONFIG.get(cid)
                verdict = "INFO" if own and own.match(procs.get(pid, "")) else "ALERT"
                add(verdict, "canary-read", "%s (%s)" % (f.group(1).replace(HOME, "~"), cid), pid)
        elif call in ("write", "sendto", "sendmsg"):
            f = re.match(r"\d+<([^>]+)>", rest)
            target = f.group(1) if f else ""
            if target.startswith(("TCP", "UDP", "TCPv6", "UDPv6", "UNIX-STREAM", "pipe")):
                for cid, value in values:
                    if value in rest:
                        add("ALERT", "canary-sent", "%s was written to %s" % (cid, target.split(":")[0]), pid)
        elif call in ("rename", "renameat", "renameat2", "symlink", "symlinkat", "link", "linkat"):
            if any(x in rest for x in PERSISTENCE):
                add("ALERT", "persistence", "%s into a startup or login path" % call, pid)
    read = {(e["detail"], e["process"]) for e in events if e["kind"] == "canary-read"}
    return [e for e in events if not (e["kind"] == "canary-opened" and (e["detail"], e["process"]) in read)]


def mask(text: str, values: List[Tuple[str, str]]) -> str:
    for cid, value in values:
        text = text.replace(value, "<%s>" % cid)
    return text


def snapshot(root: str, dest: str) -> None:
    """Copy the repository so the unprivileged sandbox user can read it: links are copied as links, never
    followed, and .git stays out (hooks run on the working tree; the history is not needed)."""
    shutil.copytree(root, dest, symlinks=True, ignore=shutil.ignore_patterns(".git"))
    for base, dirs, files in os.walk(dest):
        for d in dirs:
            if not os.path.islink(os.path.join(base, d)):
                os.chmod(os.path.join(base, d), 0o755)
        for f in files:
            if not os.path.islink(os.path.join(base, f)):
                os.chmod(os.path.join(base, f), 0o644 | (os.stat(os.path.join(base, f)).st_mode & 0o111))
    os.chmod(dest, 0o755)


DIGEST_FORMAT = 2
ALERT_KINDS = ("canary-read", "canary-passed", "canary-sent", "persistence")


def _digest(entries: List[List[Any]]) -> Dict[str, Any]:
    h = hashlib.sha256()
    for entry in sorted(entries, key=lambda e: e[1]):
        h.update((json.dumps(entry) + "\n").encode("utf-8"))
    return {"format": DIGEST_FORMAT, "digest": h.hexdigest(), "entries": len(entries)}


def tree_digest(root: str) -> Dict[str, Any]:
    """What a run was made on, as a digest a passport can match: every path except .git (at any depth, as the
    snapshot leaves it out), its kind, its user-executable bit (as git keeps it) and its content or link target.
    Links are never followed. Anything unreadable raises: a tree that cannot be read whole matches nothing."""
    entries: List[List[Any]] = []
    stack = [""]
    while stack:
        rel_dir = stack.pop()
        base = os.path.join(root, rel_dir) if rel_dir else root
        for name in sorted(os.listdir(base)):
            if name == ".git":
                continue
            rel = rel_dir + "/" + name if rel_dir else name
            path = os.path.join(base, name)
            st = os.lstat(path)
            if stat.S_ISLNK(st.st_mode):
                entries.append(["link", rel, os.readlink(path)])
            elif stat.S_ISDIR(st.st_mode):
                entries.append(["dir", rel])
                stack.append(rel)
            elif stat.S_ISREG(st.st_mode):
                content = hashlib.sha256()
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(fd, "rb") as fh:
                    for chunk in iter(lambda: fh.read(1 << 20), b""):
                        content.update(chunk)
                entries.append(["file", rel, 1 if st.st_mode & 0o100 else 0, content.hexdigest()])
            else:
                entries.append(["other", rel])
    return _digest(entries)


def git_tree_digest(top: str, commit: str, prefix: str = "") -> Dict[str, Any]:
    """The same digest from a commit's own objects (modes, link targets and bytes), so passport --base binds to
    exactly what was committed, whatever its scan filters read. A submodule matches no checked-out tree."""
    import jh_map
    spec = commit if prefix in ("", ".") else "%s:%s" % (commit, prefix)
    entries: List[List[Any]] = []
    blobs: List[Tuple[bytes, bytes, str]] = []
    for record in jh_map._git(top, ["ls-tree", "-r", "-t", "-z", spec], timeout=300).split(b"\0"):
        if not record:
            continue
        meta, path = record.split(b"\t", 1)
        mode, kind, oid = meta.split(b" ")
        rel = path.decode("utf-8", "surrogateescape")
        if kind == b"tree":
            entries.append(["dir", rel])
        elif kind == b"commit":
            entries.append(["submodule", rel])
        else:
            blobs.append((mode, oid, rel))
    for start in range(0, len(blobs), 256):
        chunk = blobs[start:start + 256]
        out = jh_map._git(top, ["cat-file", "--batch"], data=b"".join(oid + b"\n" for _, oid, _ in chunk), timeout=600)
        pos = 0
        for mode, oid, rel in chunk:
            end = out.index(b"\n", pos)
            size = int(out[pos:end].split(b" ")[2])
            content = out[end + 1:end + 1 + size]
            pos = end + 1 + size + 1
            if mode == b"120000":
                entries.append(["link", rel, content.decode("utf-8", "surrogateescape")])
            else:
                entries.append(["file", rel, 1 if mode == b"100755" else 0, hashlib.sha256(content).hexdigest()])
    return _digest(entries)


MAX_RESULT_BYTES = 4 * 1024 * 1024
_VERDICTS = ("ALERT", "DENY", "INFO")


def _result_problem(doc: Any) -> str:
    if not isinstance(doc, dict) or (doc.get("schema") != SCHEMA and doc.get("schema") not in OLD_SCHEMAS):
        return "not a %s result" % SCHEMA
    tree = doc.get("tree")
    if not isinstance(tree, dict) or not re.fullmatch(r"[0-9a-f]{64}", str(tree.get("digest", ""))):
        return "no tree digest (made by a jankhunt42 older than 3.5.0?)"
    if tree.get("format") != DIGEST_FORMAT:
        return "its tree digest is an older format; re-run the sandbox with this version"
    events, cov = doc.get("events"), doc.get("coverage")
    if not isinstance(events, list) or len(events) > 20000 or not all(
            isinstance(e, dict) and e.get("verdict") in _VERDICTS and isinstance(e.get("kind"), str) and
            isinstance(e.get("detail"), str) and isinstance(e.get("step", ""), str) for e in events):
        return "events are malformed"
    if not isinstance(cov, dict) or cov.get("state") not in ("complete", "partial") or \
            not isinstance(cov.get("gaps"), list):
        return "coverage is malformed"
    return ""


def passport_evidence(doc: Optional[Dict[str, Any]], root: str,
                      digest: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """A sandbox result as passport evidence. It counts only when it was made on exactly this tree (digest: the
    assessed tree's, computed from root when not given), and it can only add outcomes: an ALERT needs review, while a
    clean run proves nothing about paths it did not reach."""
    if doc is None:
        return {"state": "not-supplied"}
    problem = _result_problem(doc)
    if problem:
        raise ValueError("sandbox result: " + problem)
    if digest is None:
        try:
            digest = tree_digest(root)
        except OSError:
            return {"state": "stale", "reason": "the assessed tree could not be read whole, so no run can be matched"}
    if digest.get("error"):
        return {"state": "stale", "reason": "the assessed commit could not be read whole, so no run can be matched"}
    if doc["tree"]["digest"] != digest["digest"]:
        return {"state": "stale", "reason": "the run was made on a different tree: files changed since, or another "
                                            "checkout"}
    # kinds from a known set only: a result file is operator input, and its words reach the decision message
    alerts = [{"kind": e["kind"] if e["kind"] in ALERT_KINDS else "other", "detail": jh_graph.sanitize_text(e["detail"], 200),
               "step": jh_graph.sanitize_text(e.get("step", ""), 80)} for e in doc["events"] if e["verdict"] == "ALERT"]
    surfaces = [s for s in doc.get("surfaces") or [] if s in SURFACES] if isinstance(doc.get("surfaces"), list) else []
    # the destinations the run tried to reach: names it looked up, and addresses it connected to directly
    targets = sorted({("dns" if e["kind"] == "dns" else "connect", jh_graph.sanitize_text(e["detail"], 120))
                      for e in doc["events"] if e["verdict"] == "DENY" and e["kind"] in ("dns", "network")})
    return {"state": "matched", "evidence_tier": "sandbox-observed",
            "attempts": [{"kind": k, "target": t} for k, t in targets],     # capped once compared
            "attempts_total": len(targets),
            "tool_version": jh_graph.sanitize_text(str(doc.get("version", "?")), 20), "surfaces": surfaces,
            "counts": {"ALERT": len(alerts), "DENY": sum(1 for e in doc["events"] if e["verdict"] == "DENY")},
            "alerts": alerts[:50],
            "coverage": {"state": doc["coverage"]["state"], "gaps": len(doc["coverage"]["gaps"])}}


MAX_ATTEMPTS = 100


def _endpoint_of(attempt: Dict[str, str]) -> Tuple[str, Optional[int]]:
    """An attempt's host and port: a connection carries its port, a DNS lookup none."""
    host, port = attempt["target"], None
    if attempt["kind"] == "connect":
        head, _, tail = host.rpartition(":")
        if head and tail.isdigit():
            host, port = head, int(tail)
    return host.strip("[]").lower().rstrip("."), port


def _port_of(value: Any) -> Optional[int]:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def compare_declared(ev: Dict[str, Any], map_report: Optional[Dict[str, Any]],
                     ceiling: Optional[Any] = None) -> Dict[str, Any]:
    """Declared versus attempted. A destination the run tried is declared when the repository's own map names that
    host or address, or the operator's network ceiling allows it. A connection must match the port as well, when the
    declaration names one (a ceiling always does); DNS carries no port, so a name matches by host. Everything else is
    undeclared: behaviour the repository does not admit to. Every attempt is compared; only the lists shown are
    capped."""
    if ev.get("state") != "matched":
        return ev
    nodes = ((map_report or {}).get("graph") or {}).get("nodes") or []
    nodes = nodes.values() if isinstance(nodes, dict) else nodes
    ports: Dict[str, Optional[Set[int]]] = {}       # host -> its declared ports; None: any port

    def declare(host: Any, port: Optional[int]) -> None:
        h = str(host or "").lower().rstrip(".")
        if not h:
            return
        if port is None:
            ports[h] = None
        elif ports.get(h, set()) is not None:
            ports.setdefault(h, set()).add(port)

    for node in nodes:
        if isinstance(node, dict):
            attributes = node.get("attributes") or {}
            declare(attributes.get("host"), _port_of(attributes.get("port")))
    for host, port in ceiling or ():
        declare(host, _port_of(port))

    def declared(attempt: Dict[str, str]) -> bool:
        host, port = _endpoint_of(attempt)
        if host not in ports:
            return False
        return ports[host] is None or port is None or port in ports[host]

    attempts = ev.get("attempts", [])
    for a in attempts:
        a["declared"] = declared(a)                 # kept by --redact, which renames the targets
    undeclared = [a["target"] for a in attempts if a.get("declared") is False]
    ev["attempts"] = attempts[:MAX_ATTEMPTS]
    ev["undeclared"] = undeclared[:MAX_ATTEMPTS]
    ev["counts"]["UNDECLARED"] = len(undeclared)
    return ev


def passport_line(ev: Dict[str, Any]) -> str:
    """One plain line for the passport's approver view."""
    state = ev.get("state", "not-supplied")
    if state == "matched":
        undeclared = ev["counts"].get("UNDECLARED")
        return "Sandbox run (sandbox-observed, coverage %s): %d ALERT(s), %d blocked network attempt(s)%s%s." % (
            ev["coverage"]["state"], ev["counts"]["ALERT"], ev["counts"]["DENY"],
            "" if undeclared is None else ", %d to destinations the repository does not declare" % undeclared,
            "" if ev["counts"]["ALERT"] or undeclared else "; a clean run says nothing about what it did not reach")
    if state == "stale":
        return "Sandbox run supplied but not used: " + ev.get("reason", "made on a different tree") + "."
    return ""


def check_cache(path: str, root: str, what: str) -> None:
    """An operator-supplied dependency cache: a real directory (no link anywhere in its path) outside the
    repository. Its size is enforced while it is copied (copy_cache), never by an earlier, separate look."""
    if not os.path.isdir(path):
        raise RuntimeError("%s %s is not a directory" % (what, path))
    if os.path.abspath(path) != os.path.realpath(path):
        raise RuntimeError("%s must be a canonical path without links" % what)
    if jh_ceiling.inside_repository(path, root):
        raise RuntimeError("%s must be outside the repository: what a repository brings cannot be its own cache" % what)


def _under(path: str, base: str) -> bool:
    path, base = os.path.realpath(path), os.path.realpath(base)
    return path == base or path.startswith(base.rstrip(os.sep) + os.sep)


def copy_cache(src: str, dest: str, writable: bool, what: str = "the cache",
               budget: Optional[int] = None) -> Dict[str, int]:
    """Copy a cache in one pass that cannot be steered: every folder is opened from its parent's descriptor and
    never through a link, every file is opened without following links and must be a regular file, and the size
    budget is counted on the bytes actually copied. Links, FIFOs and devices are left out; anything unreadable, or
    a destination inside the source, stops the run."""
    budget = MAX_CACHE_BYTES if budget is None else budget
    if _under(dest, src):
        raise RuntimeError("the run's temporary folder is inside %s; set TMPDIR elsewhere" % what)
    counts = {"files": 0, "bytes": 0}
    dir_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK

    def walk(dfd: int, target: str, depth: int) -> None:
        if depth > 64:
            raise RuntimeError("%s nests deeper than 64 folders" % what)
        os.makedirs(target, exist_ok=True)
        os.chmod(target, 0o777 if writable else 0o755)
        for name in sorted(os.listdir(dfd)):
            st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
            if stat.S_ISDIR(st.st_mode):
                sub = os.open(name, dir_flags, dir_fd=dfd)
                try:
                    walk(sub, os.path.join(target, name), depth + 1)
                finally:
                    os.close(sub)
            elif stat.S_ISREG(st.st_mode):
                fd = os.open(name, file_flags, dir_fd=dfd)
                with os.fdopen(fd, "rb") as fh:
                    if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
                        continue
                    out_path = os.path.join(target, name)
                    with open(out_path, "wb") as out:
                        for chunk in iter(lambda: fh.read(1 << 20), b""):
                            counts["bytes"] += len(chunk)
                            if counts["bytes"] > budget:
                                raise RuntimeError("%s is larger than %d MB" % (what, budget // (1024 * 1024)))
                            out.write(chunk)
                os.chmod(out_path, 0o666 if writable else 0o644)
                counts["files"] += 1

    try:
        root_fd = os.open(src, dir_flags)
    except OSError as exc:
        raise RuntimeError("%s could not be read whole: %s" % (what, exc))
    try:
        walk(root_fd, dest, 0)
    except OSError as exc:
        raise RuntimeError("%s could not be read whole: %s" % (what, exc))
    finally:
        os.close(root_fd)
    return counts


def resolve_image(engine: Optional[str], image: str, root: Optional[str] = None) -> str:
    """The image to use: the one named, or, for the default name when only an image built before the rename exists,
    that one. Settled once, before the fetch and the run, so both use the same image."""
    engine = find_engine(engine)
    if not engine or image != DEFAULT_IMAGE:
        return image
    def present(name: str) -> bool:
        return subprocess.run([engine, "image", "inspect", "--format", "{{.Id}}", name], capture_output=True,
                              text=True).returncode == 0
    if root:
        import jh_nuget
        if jh_nuget.is_dotnet(root) and present(DOTNET_IMAGE):
            return DOTNET_IMAGE
    return OLD_IMAGE if not present(DEFAULT_IMAGE) and present(OLD_IMAGE) else image


def find_engine(prefer: Optional[str] = None) -> Optional[str]:
    for engine in ([prefer] if prefer else ["podman", "docker"]):
        if engine and shutil.which(engine):
            return engine
    return None


def run(root: str, image: str = DEFAULT_IMAGE, engine: Optional[str] = None, timeout: int = 120,
        surfaces: Tuple[str, ...] = SURFACES, npm_cache: Optional[str] = None,
        wheelhouse: Optional[str] = None, nuget_cache: Optional[str] = None) -> Dict[str, Any]:
    root = os.path.abspath(root)
    supplied = {name: (path, label) for name, path, label in
                (("npm", npm_cache, "--npm-cache"), ("wheels", wheelhouse, "--wheelhouse"),
                 ("nuget", nuget_cache, "--nuget-cache")) if path}
    for path, label in supplied.values():
        check_cache(path, root, label)
    result: Dict[str, Any] = {"schema": SCHEMA, "root": root, "image": image, "evidence_tier": "sandbox-observed",
                              "surfaces": [s for s in SURFACES if s in surfaces],
                              "steps": [], "events": [], "dns": [], "canaries": [], "coverage": {}, "limits": [
                                  "absence of an event is not evidence of safety: only the commands listed ran",
                                  "the tracer runs as the same user as the code it watches; deliberate evasion is possible",
                                  "encrypted or transformed sends of a canary are not recognised",
                                  "the code under test can alter its own trace and DNS log; they are read as untrusted "
                                  "(regular files only, never through a link, bounded), not as proof"]}
    import jh_nuget
    dotnet = jh_nuget.is_dotnet(root)
    engine = find_engine(engine)
    if not engine and not dotnet:
        raise RuntimeError("no container engine (podman or docker) is installed")
    image = resolve_image(engine, image, root)
    result["image"] = image
    old_image = image == OLD_IMAGE
    probe = subprocess.run([engine, "image", "inspect", "--format", "{{.Id}}", image], capture_output=True, text=True) \
        if engine else subprocess.CompletedProcess([], 1, "", "no engine")
    runnable = probe.returncode == 0
    if not runnable and not (dotnet and image in (DEFAULT_IMAGE, OLD_IMAGE, DOTNET_IMAGE)):
        raise RuntimeError("image %s is not present; build it once with: %s build -t %s -f "
                           "templates/sandbox.Containerfile templates" % (image, engine, image))
    result["engine"], result["image_id"] = engine, probe.stdout.strip()[:80]
    canaries = make_canaries()
    run_dir = tempfile.mkdtemp(prefix="jh-sandbox-")
    try:
        for c in canaries:
            path = os.path.join(run_dir, "home", c["path"][len(HOME) + 1:])
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write(c["text"])
        if dotnet or "nuget" in supplied:
            os.makedirs(os.path.join(run_dir, "home", ".dotnet"), exist_ok=True)
        snap = os.path.join(run_dir, "src")
        try:
            snapshot(root, snap)
        except OSError as exc:
            raise RuntimeError("could not snapshot %s: %s" % (root, exc))
        # plan from the snapshot, so what runs is exactly what was read; its digest lets a passport match the run
        try:
            result["tree"] = tree_digest(snap)
        except OSError as exc:
            raise RuntimeError("could not read the snapshot whole: %s" % exc)
        result["dependency_caches"] = {
            name: copy_cache(path, os.path.join(run_dir, "cache", name), CACHE_MOUNTS[name][1] == "rw", label)
            for name, (path, label) in supplied.items()}
        dotnet_ready = runnable and image not in (DEFAULT_IMAGE, OLD_IMAGE)
        steps, gaps = plan_steps(snap, surfaces, tuple(supplied), dotnet_ready=dotnet_ready)
        if not runnable:
            gaps.append("no usable runner image/engine: no sandbox commands ran")
            steps = []
        if old_image:
            gaps.append("the image was built before 4.1.0 (%s), without curl or wget, so commands that use them fail; "
                        "build %s from templates/sandbox.Containerfile" % (OLD_IMAGE, DEFAULT_IMAGE))
        if not steps:
            gaps.append("nothing to run was found (package hooks, or commands that run when the repository is opened)")
        os.makedirs(os.path.join(run_dir, "jh"))
        os.makedirs(os.path.join(run_dir, "out"))
        os.chmod(os.path.join(run_dir, "out"), 0o777)
        for helper, name in (("jh_sandbox_sink.py", "sink.py"), ("jh_sandbox_load.py", "load.py")):
            shutil.copy(os.path.join(os.path.dirname(os.path.abspath(__file__)), helper),
                        os.path.join(run_dir, "jh", name))
        with open(os.path.join(run_dir, "jh", "resolv.conf"), "w") as fh:
            fh.write("nameserver 127.0.0.1\noptions attempts:1 timeout:1\n")
        with open(os.path.join(run_dir, "jh", "run.sh"), "w") as fh:
            fh.write(inner_script(steps, int(timeout)))
        write_steps(steps, os.path.join(run_dir, "jh"))
        timed_out = False
        if steps:
            try:
                subprocess.run(container_argv(engine, image, run_dir, snap, tuple(supplied)), capture_output=True,
                               timeout=sum(step_limit(s, int(timeout)) + 5 for s in steps) + 60)
            except subprocess.TimeoutExpired:
                timed_out = True
                gaps.append("the run exceeded its time limit")
        rows, events, dns = collect(os.path.join(run_dir, "out"), steps, canaries, int(timeout), gaps)
        for step, row in zip(steps, rows):
            if (step.get("npm_ci") or step.get("pip") or step.get("nuget")) and row["exit"] not in ("0", None):
                gaps.append("%s failed (exit %s): a package missing from the cache, a git or URL dependency, or "
                            "another error; not every install hook may have run" % (step["name"], row["exit"]))
        result["steps"], result["events"], result["dns"] = rows, events, dns
        result["timed_out"] = timed_out
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)       # the evidence is kept; the sandbox and canaries are not
    values = [(c["id"], v) for c in canaries for v in c["values"]]
    for e in result["events"]:
        # trace text is written by the code under test: masked, redacted and one bounded line, like a command
        e["detail"], e["process"] = shown(e["detail"], values), shown(e["process"], values)
    result["canaries"] = [{"id": c["id"], "kind": c["kind"], "path": c["path"]} for c in canaries]
    gaps = [jh_graph.sanitize_text(g, 300) for g in gaps]
    result["coverage"] = {"state": "partial" if gaps else "complete", "gaps": gaps}
    result["counts"] = {v: sum(1 for e in result["events"] if e["verdict"] == v) for v in ("ALERT", "DENY")}
    return result


def read_guest(dir_fd: int, name: str, limit: int) -> Tuple[Optional[bytes], str]:
    """A file the sandbox wrote, read without trusting it: through the output directory's descriptor, never
    through a link, only a regular file with a single link, at most limit bytes. (data, problem): problem is
    "" when read whole, "missing", "unusable" (a link, a FIFO, a device, a hard link) or "truncated"."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0), dir_fd=dir_fd)
    except FileNotFoundError:
        return None, "missing"
    except OSError:
        return None, "unusable"
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            return None, "unusable"
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(fd, min(1 << 20, limit + 1 - len(data)))
            if not chunk:
                break
            data += chunk
        return (bytes(data[:limit]), "truncated") if len(data) > limit else (bytes(data), "")
    finally:
        os.close(fd)


def _started(text: str, i: int) -> bool:
    """A step was observed only if its trace shows the runner starting it."""
    return re.search(r'^\d+\s+execve\("[^"]*/sh", \["sh", "/jh/step\.%d\.sh"\].*= 0$' % i, text, re.M) is not None


def collect(out: str, steps: List[Dict[str, Any]], canaries: List[Dict[str, Any]], timeout: int,
            gaps: List[str]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    """Step rows, events and DNS names from the sandbox's output directory. Every file in it was writable by the
    code under test, so each is read with read_guest, and anything unusable makes coverage partial."""
    values = [(c["id"], v) for c in canaries for v in c["values"]]
    rows: List[Dict[str, Any]] = []
    events: List[Dict[str, Any]] = []
    try:
        dir_fd = os.open(out, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        gaps.append("the sandbox output could not be opened")
        return rows, events, []
    try:
        for i, step in enumerate(steps):
            raw, problem = read_guest(dir_fd, "step.%d.exit" % i, 16)
            text = raw.decode("ascii", "replace").strip() if raw is not None and not problem else ""
            code = text if re.fullmatch(r"\d{1,3}", text) else None
            if code is None:
                # missing, unusable, cut short or not a number: the step's receipt is incomplete
                gaps.append("%s: no usable exit status (%s)" % (step["name"], problem or "not a plain number"))
            trace, problem = read_guest(dir_fd, "trace.%d" % i, MAX_TRACE_BYTES)
            trace_text = trace.decode("utf-8", "replace") if trace is not None else ""
            traced = trace is not None and problem != "unusable" and _started(trace_text, i)
            row = {"name": step["name"], "surface": step["surface"], "source": step["source"],
                   "command": shown(step["script"], values), "exit": code, "traced": traced}
            if step.get("host"):
                row["note"] = "in real use this runs on the host machine, outside any container"
            if step.get("server"):
                row["note"] = "a server runs until stopped; it was stopped after %d seconds" % step_limit(step, timeout)
            if step.get("import_of") and code not in ("0", "124", None):
                row["note"] = "it did not load as a module: a command-line tool or type declarations only, or its " \
                              "load failed"
            if step.get("dependency_of"):
                row["note"] = "VS Code runs it first, as a dependency of folder-open task %s" % jh_graph.sanitize_text(
                    step["dependency_of"], 40)
            rows.append(row)
            if code == "124" and not step.get("server"):
                gaps.append("%s hit its time limit" % step["name"])
            if problem == "truncated":
                gaps.append("%s: its trace was cut at %d MB" % (step["name"], MAX_TRACE_BYTES // (1024 * 1024)))
            if not traced:
                gaps.append("%s left no usable trace (missing, unusable, or not showing the step start)" % step["name"])
                continue
            events.extend(parse_trace(trace_text, canaries, step["name"]))
        raw, problem = read_guest(dir_fd, "dns.log", MAX_DNS_BYTES)
    finally:
        os.close(dir_fd)
    if problem in ("unusable", "truncated"):
        gaps.append("the DNS log was %s, so the names looked up are incomplete"
                    % ("not a plain file" if problem == "unusable" else "cut at 1 MB"))
    lines = {n.strip() for n in (raw or b"").decode("ascii", "replace").splitlines() if n.strip()}
    names = sorted(n for n in lines if _HOSTNAME.match(n))
    if len(names) < len(lines):
        gaps.append("%d lines in the DNS log were not host names and were ignored" % (len(lines) - len(names)))
    for name in names[:200]:
        events.append({"verdict": "DENY", "kind": "dns", "detail": name, "pid": "", "process": "", "step": ""})
    return rows, events, names[:200]


def _md(text: Any) -> str:
    """A report field: one line, with no Markdown emphasis or code marks a field could use to look like another."""
    return jh_graph.sanitize_text(str(text), 300).replace("`", "'").replace("*", "")


def render_markdown(r: Dict[str, Any]) -> str:
    out = ["# jankhunt42 sandbox", "",
           "Evidence tier: `sandbox-observed`. Image `%s` via %s. Coverage: **%s**." % (
               r["image"], r.get("engine", "?"), r["coverage"]["state"]), ""]
    for gap in r["coverage"]["gaps"]:
        out.append("- coverage gap: %s" % _md(gap))
    for surface, title in (("install", "When it is installed"), ("import", "When its dependencies are loaded"),
                           ("open", "When it is opened")):
        rows = [s for s in r["steps"] if s.get("surface", "install") == surface]
        if not rows:
            continue
        out += ["", "## %s" % title, ""]
        for s in rows:
            out.append("- **%s** (`%s`): `%s`, exit %s%s%s" % (
                _md(s["name"]), _md(s.get("source") or "?"), _md(s["command"]), _md(s["exit"]),
                "" if s["traced"] else " (no trace)", "; %s" % _md(s["note"]) if s.get("note") else ""))
    out += ["", "## Audit log", ""]
    if not r["events"]:
        out.append("No network attempts, canary access or persistence attempts were observed in the steps that ran.")
    for e in sorted(r["events"], key=lambda e: (e["verdict"] != "ALERT", e["kind"], e["detail"])):
        who = " by `%s`" % _md(e["process"]) if e["process"] else ""
        out.append("- **%s** %s: %s%s%s" % (e["verdict"], e["kind"], _md(e["detail"]), who,
                                           " (%s)" % _md(e["step"]) if e["step"] else ""))
    out += ["", "## Limits", ""] + ["- %s" % x for x in r["limits"]]
    return "\n".join(out) + "\n"
