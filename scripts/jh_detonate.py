"""detonate: run a repository's own install hooks, and the commands that run when it is opened, in a disposable
sandbox, and report what they try to do.

Opt-in only. jankhunt42 stays stdlib: it orchestrates an external rootless container engine (podman, or docker)
and an operator-built image that holds strace. The repository is copied in read-only, the network is off, the
root filesystem is read-only, every capability is dropped, and resources and time are bounded. Fresh canary
credentials sit in a throwaway HOME. strace, started as the parent of each hook, records file, network and
process activity; a loopback DNS sink records the names looked up.

Two surfaces: `install` (package hooks) and `open` (what an agent or editor runs because the repository was opened:
project hooks and helper commands, dev container commands, folder-open tasks, MCP servers). Each command is written
to its own file and run by `sh` under the tracer, so text from the repository never becomes part of the runner.

The result is a firewall-style log: DENY for each attempted connection or lookup (nothing can leave), ALERT for a
canary read, a canary passed on, or a persistence attempt. It is evidence of the tier `sandbox-observed`: it adds
to static findings and never refutes them, because a run that did not reach a path says nothing about that path.
Canary values never leave the run: reports name canaries by id only.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shlex
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Tuple

import jh_agent
import jh_checks
import jh_graph
from jh_core import MCP_CONFIG_FILES, redact_secrets

SCHEMA = "jankhunt.detonate.v1"
DEFAULT_IMAGE = "localhost/jankhunt42-detonate:0.1"
NPM_HOOKS = ("preinstall", "install", "postinstall", "prepare")
HOME = "/home/canary"

# where code looks for credentials; each gets a fresh, never-issued value carrying the JH42CANARY marker
CANARY_FILES = (
    ("aws", ".aws/credentials", "[default]\naws_access_key_id = AKIA{u16}\naws_secret_access_key = JH42CANARY{h32}\n"),
    ("git", ".git-credentials", "https://canary:ghp_JH42CANARY{h26}@github.com\n"),
    ("npm", ".npmrc", "//registry.npmjs.org/:_authToken=npm_JH42CANARY{h26}\n"),
    ("ssh", ".ssh/id_ed25519", "-----BEGIN OPENSSH PRIVATE KEY-----\nJH42CANARY{h32}\n-----END OPENSSH PRIVATE KEY-----\n"),
    ("env", ".env", "API_TOKEN=JH42CANARY{h32}\nDATABASE_URL=postgres://canary:JH42CANARY{h16}@db.invalid/app\n"),
)
# a write or rename into one of these is a persistence attempt
PERSISTENCE = (".bashrc", ".profile", ".bash_profile", ".zshrc", ".ssh/authorized_keys", ".config/autostart/",
               ".config/systemd/user/", "/etc/cron", "/var/spool/cron", ".local/share/applications/")
LIMITS = ("--pids-limit=256", "--memory=1g", "--cpus=2")
SURFACES = ("install", "open")

# what an agent or editor runs because the repository was opened, read only from these fixed paths
AGENT_SETTINGS = (".claude/settings.json", ".claude/settings.local.json", ".gemini/settings.json")
HELPER_KEYS = jh_checks._HELPER_KEYS + ("statusLine",)
DEVCONTAINER_COMMANDS = ("initializeCommand", "onCreateCommand", "updateContentCommand", "postCreateCommand",
                         "postStartCommand", "postAttachCommand")
MCP_SECONDS = 20          # a server runs until stopped; this long is enough to see what it does at start
MAX_OPEN_STEPS = 40
MAX_CONFIG_BYTES = 1000000
_MCP_INIT = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "jankhunt42-detonate", "version": "1"}}})


def make_canaries() -> List[Dict[str, Any]]:
    out = []
    for kind, rel, template in CANARY_FILES:
        text = template.format(u16=secrets.token_hex(8).upper(), h32=secrets.token_hex(16), h26=secrets.token_hex(13),
                               h16=secrets.token_hex(8))
        values = re.findall(r"[\w/+=-]*JH42CANARY\w+|AKIA[0-9A-F]{16}", text)
        out.append({"id": "canary-%s" % kind, "kind": kind, "path": HOME + "/" + rel, "text": text, "values": values})
    return out


def plan_steps(root: str, surfaces: Tuple[str, ...] = SURFACES) -> Tuple[List[Dict[str, Any]], List[str]]:
    """The commands to run, and why coverage is partial before anything runs."""
    steps: List[Dict[str, Any]] = []
    gaps: List[str] = []
    if "install" in surfaces:
        _plan_install(root, steps, gaps)
    if "open" in surfaces:
        _plan_open(root, steps, gaps)
    return steps, gaps


def _step(name: str, surface: str, script: str, source: str = "", stdin: str = "", **extra: Any) -> Dict[str, Any]:
    # a name carries repository text (a hook event, a task label, a server name): one plain, bounded line
    name = jh_graph.sanitize_text(name, 80).replace("*", "").replace("`", "'")
    return dict(name=name, surface=surface, script=script, source=source, stdin=stdin, **extra)


def _plan_install(root: str, steps: List[Dict[str, Any]], gaps: List[str]) -> None:
    pkg = os.path.join(root, "package.json")
    if os.path.isfile(pkg) and not os.path.islink(pkg):
        try:
            with open(pkg, encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, ValueError):
            doc = {}
            gaps.append("package.json could not be read")
        scripts = doc.get("scripts") if isinstance(doc.get("scripts"), dict) else {}
        for hook in NPM_HOOKS:
            if isinstance(scripts.get(hook), str):
                steps.append(_step("npm %s" % hook, "install", "npm run --if-present %s" % hook, "package.json"))
        if doc.get("dependencies") or doc.get("devDependencies"):
            gaps.append("npm dependencies are not installed (the network is off), so their install hooks did not run")
    if os.path.isfile(os.path.join(root, "setup.py")):
        steps.append(_step("python setup.py", "install", "python3 setup.py egg_info --egg-base /tmp", "setup.py"))
    elif os.path.isfile(os.path.join(root, "pyproject.toml")):
        steps.append(_step("python build backend", "install",
                           "python3 -m pip wheel --no-deps --no-build-isolation --no-index -w /tmp/wheel .",
                           "pyproject.toml"))
        gaps.append("a pyproject build backend that is not in the image cannot run")


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
    doc: Dict[str, Any] = {"session_id": "jankhunt42-detonate", "transcript_path": "/tmp/transcript.jsonl",
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
    quote = ""
    for ch in value:
        if quote:
            quote = "" if ch == quote else quote
        elif ch in "'\"":
            quote = ch
        elif ch == " ":
            return True
    return False


def _vscode_token(value: str, quoting: Optional[str] = None) -> str:
    """One shell-task token as VS Code writes it for a POSIX shell: quoted only when it has an unquoted space (so
    $VAR and $(...) stay live, as they do in VS Code), or as the task asks."""
    if quoting == "strong":
        return "'" + value.replace("'", "'\\''") + "'"
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
    data = _read_settings(root, ".vscode/tasks.json", gaps)
    for task in (data or {}).get("tasks") if isinstance((data or {}).get("tasks"), list) else []:
        opts = task.get("runOptions") if isinstance(task, dict) else None
        if not (isinstance(opts, dict) and opts.get("runOn") == "folderOpen"):
            continue
        script = _vscode_task(task, gaps)
        if script is None:
            continue
        found.append(_step("vscode task %s" % str(task.get("label", "?"))[:40], "open", script, ".vscode/tasks.json"))
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
                gaps.append("MCP server %s started without its configured environment" % server.name[:40])
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


def container_argv(engine: str, image: str, run_dir: str, src: str) -> List[str]:
    z = ",Z" if engine == "podman" else ""
    return [engine, "run", "--rm", "--pull=never", "--network=none", "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", *LIMITS, "--sysctl", "net.ipv4.ip_unprivileged_port_start=0",
            "--tmpfs", "/tmp:rw,size=256m,mode=1777", "--tmpfs", "/work:rw,size=1g,mode=1777",
            "-v", "%s:/src:ro%s" % (src, z), "-v", "%s/home:%s:ro%s" % (run_dir, HOME, z),
            "-v", "%s/jh:/jh:ro%s" % (run_dir, z), "-v", "%s/out:/out:rw%s" % (run_dir, z),
            "-v", "%s/jh/resolv.conf:/etc/resolv.conf:ro%s" % (run_dir, z),
            "-e", "HOME=" + HOME, "-e", "CLAUDE_PROJECT_DIR=/work/repo", "-e", "npm_config_cache=/tmp/npm", "-e", "npm_config_update_notifier=false", "-e", "PIP_NO_INDEX=1",
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


def find_engine(prefer: Optional[str] = None) -> Optional[str]:
    for engine in ([prefer] if prefer else ["podman", "docker"]):
        if engine and shutil.which(engine):
            return engine
    return None


def run(root: str, image: str = DEFAULT_IMAGE, engine: Optional[str] = None, timeout: int = 120,
        surfaces: Tuple[str, ...] = SURFACES) -> Dict[str, Any]:
    root = os.path.abspath(root)
    result: Dict[str, Any] = {"schema": SCHEMA, "root": root, "image": image, "evidence_tier": "sandbox-observed",
                              "surfaces": [s for s in SURFACES if s in surfaces],
                              "steps": [], "events": [], "dns": [], "canaries": [], "coverage": {}, "limits": [
                                  "absence of an event is not evidence of safety: only the commands listed ran",
                                  "the tracer runs as the same user as the code it watches; deliberate evasion is possible",
                                  "encrypted or transformed sends of a canary are not recognised"]}
    engine = find_engine(engine)
    if not engine:
        raise RuntimeError("no container engine (podman or docker) is installed")
    probe = subprocess.run([engine, "image", "inspect", "--format", "{{.Id}}", image], capture_output=True, text=True)
    if probe.returncode != 0:
        raise RuntimeError("image %s is not present; build it once with: %s build -t %s -f "
                           "templates/detonate.Containerfile templates" % (image, engine, image))
    result["engine"], result["image_id"] = engine, probe.stdout.strip()[:80]
    canaries = make_canaries()
    run_dir = tempfile.mkdtemp(prefix="jh-detonate-")
    try:
        for c in canaries:
            path = os.path.join(run_dir, "home", c["path"][len(HOME) + 1:])
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write(c["text"])
        snap = os.path.join(run_dir, "src")
        try:
            snapshot(root, snap)
        except OSError as exc:
            raise RuntimeError("could not snapshot %s: %s" % (root, exc))
        # plan from the snapshot, so what runs is exactly what was read
        steps, gaps = plan_steps(snap, surfaces)
        if not steps:
            gaps.append("nothing to run was found (package hooks, or commands that run when the repository is opened)")
        os.makedirs(os.path.join(run_dir, "jh"))
        os.makedirs(os.path.join(run_dir, "out"))
        os.chmod(os.path.join(run_dir, "out"), 0o777)
        shutil.copy(os.path.join(os.path.dirname(os.path.abspath(__file__)), "jh_detonate_sink.py"),
                    os.path.join(run_dir, "jh", "sink.py"))
        with open(os.path.join(run_dir, "jh", "resolv.conf"), "w") as fh:
            fh.write("nameserver 127.0.0.1\noptions attempts:1 timeout:1\n")
        with open(os.path.join(run_dir, "jh", "run.sh"), "w") as fh:
            fh.write(inner_script(steps, int(timeout)))
        write_steps(steps, os.path.join(run_dir, "jh"))
        timed_out = False
        if steps:
            try:
                subprocess.run(container_argv(engine, image, run_dir, snap), capture_output=True,
                               timeout=sum(step_limit(s, int(timeout)) + 5 for s in steps) + 60)
            except subprocess.TimeoutExpired:
                timed_out = True
                gaps.append("the run exceeded its time limit")
        out = os.path.join(run_dir, "out")
        values = [(c["id"], v) for c in canaries for v in c["values"]]
        for i, step in enumerate(steps):
            exit_path = os.path.join(out, "step.%d.exit" % i)
            code = open(exit_path).read().strip() if os.path.exists(exit_path) else None
            trace_path = os.path.join(out, "trace.%d" % i)
            traced = os.path.exists(trace_path)
            row = {"name": step["name"], "surface": step["surface"], "source": step["source"],
                   "command": shown(step["script"], values), "exit": code, "traced": traced}
            if step.get("host"):
                row["note"] = "in real use this runs on the host machine, outside any container"
            if step.get("server"):
                row["note"] = "a server runs until stopped; it was stopped after %d seconds" % step_limit(step, int(timeout))
            result["steps"].append(row)
            if code == "124" and not step.get("server"):
                gaps.append("%s hit its time limit" % step["name"])
            if not traced:
                gaps.append("%s left no trace" % step["name"])
                continue
            text = open(trace_path, encoding="utf-8", errors="replace").read()
            result["events"].extend(parse_trace(text, canaries, step["name"]))
        dns_path = os.path.join(out, "dns.log")
        if os.path.exists(dns_path):
            names = sorted({n.strip() for n in open(dns_path, encoding="ascii", errors="replace") if n.strip()})
            result["dns"] = names[:200]
            for name in names[:200]:
                result["events"].append({"verdict": "DENY", "kind": "dns", "detail": name, "pid": "", "process": "",
                                         "step": ""})
        result["timed_out"] = timed_out
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)       # the evidence is kept; the sandbox and canaries are not
    values = [(c["id"], v) for c in canaries for v in c["values"]]
    for e in result["events"]:
        e["detail"], e["process"] = mask(e["detail"], values), mask(e["process"], values)
    result["canaries"] = [{"id": c["id"], "kind": c["kind"], "path": c["path"]} for c in canaries]
    result["coverage"] = {"state": "partial" if gaps else "complete", "gaps": gaps}
    result["counts"] = {v: sum(1 for e in result["events"] if e["verdict"] == v) for v in ("ALERT", "DENY")}
    return result


def render_markdown(r: Dict[str, Any]) -> str:
    out = ["# jankhunt42 detonate", "",
           "Evidence tier: `sandbox-observed`. Image `%s` via %s. Coverage: **%s**." % (
               r["image"], r.get("engine", "?"), r["coverage"]["state"]), ""]
    for gap in r["coverage"]["gaps"]:
        out.append("- coverage gap: %s" % gap)
    for surface, title in (("install", "When it is installed"), ("open", "When it is opened")):
        rows = [s for s in r["steps"] if s.get("surface", "install") == surface]
        if not rows:
            continue
        out += ["", "## %s" % title, ""]
        for s in rows:
            out.append("- **%s** (`%s`): `%s`, exit %s%s%s" % (
                s["name"], s.get("source") or "?", s["command"].replace("`", "'"), s["exit"],
                "" if s["traced"] else " (no trace)", "; %s" % s["note"] if s.get("note") else ""))
    out += ["", "## Audit log", ""]
    if not r["events"]:
        out.append("No network attempts, canary access or persistence attempts were observed in the steps that ran.")
    for e in sorted(r["events"], key=lambda e: (e["verdict"] != "ALERT", e["kind"], e["detail"])):
        who = " by `%s`" % e["process"] if e["process"] else ""
        out.append("- **%s** %s: %s%s%s" % (e["verdict"], e["kind"], e["detail"], who,
                                           " (%s)" % e["step"] if e["step"] else ""))
    out += ["", "## Limits", ""] + ["- %s" % x for x in r["limits"]]
    return "\n".join(out) + "\n"
