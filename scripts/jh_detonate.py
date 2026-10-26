"""detonate: run a repository's own install hooks in a disposable sandbox and report what they try to do.

Opt-in only. jankhunt42 stays stdlib: it orchestrates an external rootless container engine (podman, or docker)
and an operator-built image that holds strace. The repository is copied in read-only, the network is off, the
root filesystem is read-only, every capability is dropped, and resources and time are bounded. Fresh canary
credentials sit in a throwaway HOME. strace, started as the parent of each hook, records file, network and
process activity; a loopback DNS sink records the names looked up.

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
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Tuple

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


def make_canaries() -> List[Dict[str, Any]]:
    out = []
    for kind, rel, template in CANARY_FILES:
        text = template.format(u16=secrets.token_hex(8).upper(), h32=secrets.token_hex(16), h26=secrets.token_hex(13),
                               h16=secrets.token_hex(8))
        values = re.findall(r"[\w/+=-]*JH42CANARY\w+|AKIA[0-9A-F]{16}", text)
        out.append({"id": "canary-%s" % kind, "kind": kind, "path": HOME + "/" + rel, "text": text, "values": values})
    return out


def plan_steps(root: str) -> Tuple[List[Dict[str, str]], List[str]]:
    """The hooks to run, and why coverage is partial before anything runs."""
    steps: List[Dict[str, str]] = []
    gaps: List[str] = []
    pkg = os.path.join(root, "package.json")
    if os.path.isfile(pkg):
        try:
            doc = json.load(open(pkg, encoding="utf-8"))
        except (OSError, ValueError):
            doc = {}
            gaps.append("package.json could not be read")
        scripts = doc.get("scripts") if isinstance(doc.get("scripts"), dict) else {}
        for hook in NPM_HOOKS:
            if isinstance(scripts.get(hook), str):
                steps.append({"name": "npm %s" % hook, "argv": "npm run --if-present %s" % hook})
        if doc.get("dependencies") or doc.get("devDependencies"):
            gaps.append("npm dependencies are not installed (the network is off), so their install hooks did not run")
    if os.path.isfile(os.path.join(root, "setup.py")):
        steps.append({"name": "python setup.py", "argv": "python3 setup.py egg_info --egg-base /tmp"})
    elif os.path.isfile(os.path.join(root, "pyproject.toml")):
        steps.append({"name": "python build backend",
                      "argv": "python3 -m pip wheel --no-deps --no-build-isolation --no-index -w /tmp/wheel ."})
        gaps.append("a pyproject build backend that is not in the image cannot run")
    return steps, gaps


def inner_script(steps: List[Dict[str, str]]) -> str:
    lines = ["set -u", "python3 /jh/sink.py /out/dns.log & sleep 0.3",
             "cp -r /src/. /work/repo 2>/dev/null; cd /work/repo"]
    for i, step in enumerate(steps):
        lines.append("timeout -k 5 %%TIMEOUT%% strace -f -qq -yy -s 256 -e trace=%%network,%%file,%%process,read,write "
                     "-o /out/trace.%d %s >/out/step.%d.log 2>&1; echo $? > /out/step.%d.exit" % (i, step["argv"], i, i))
    return "\n".join(lines) + "\n"


def container_argv(engine: str, image: str, run_dir: str, src: str) -> List[str]:
    z = ",Z" if engine == "podman" else ""
    return [engine, "run", "--rm", "--pull=never", "--network=none", "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", *LIMITS, "--sysctl", "net.ipv4.ip_unprivileged_port_start=0",
            "--tmpfs", "/tmp:rw,size=256m,mode=1777", "--tmpfs", "/work:rw,size=1g,mode=1777",
            "-v", "%s:/src:ro%s" % (src, z), "-v", "%s/home:%s:ro%s" % (run_dir, HOME, z),
            "-v", "%s/jh:/jh:ro%s" % (run_dir, z), "-v", "%s/out:/out:rw%s" % (run_dir, z),
            "-v", "%s/jh/resolv.conf:/etc/resolv.conf:ro%s" % (run_dir, z),
            "-e", "HOME=" + HOME, "-e", "npm_config_cache=/tmp/npm", "-e", "npm_config_update_notifier=false", "-e", "PIP_NO_INDEX=1",
            image, "sh", "/jh/run.sh"]


_LINE_RE = re.compile(r"^(\d+)\s+(\w+)\((.*)$")
_RESUMED_RE = re.compile(r"^(\d+)\s+<\.\.\. (\w+) resumed>.*= (\d+)$")
# the package manager reading its own configuration is expected, not the repository's doing
_OWN_CONFIG = {"canary-npm": re.compile(r"^(?:npm|node\s+\S*/npm(?:-cli\.js)?)\b")}
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


def run(root: str, image: str = DEFAULT_IMAGE, engine: Optional[str] = None, timeout: int = 120) -> Dict[str, Any]:
    root = os.path.abspath(root)
    result: Dict[str, Any] = {"schema": SCHEMA, "root": root, "image": image, "evidence_tier": "sandbox-observed",
                              "steps": [], "events": [], "dns": [], "canaries": [], "coverage": {}, "limits": [
                                  "absence of an event is not evidence of safety: only the hooks listed ran",
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
    steps, gaps = plan_steps(root)
    if not steps:
        gaps.append("no install hooks were found (package.json scripts, setup.py or pyproject.toml)")
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
        os.makedirs(os.path.join(run_dir, "jh"))
        os.makedirs(os.path.join(run_dir, "out"))
        os.chmod(os.path.join(run_dir, "out"), 0o777)
        shutil.copy(os.path.join(os.path.dirname(os.path.abspath(__file__)), "jh_detonate_sink.py"),
                    os.path.join(run_dir, "jh", "sink.py"))
        with open(os.path.join(run_dir, "jh", "resolv.conf"), "w") as fh:
            fh.write("nameserver 127.0.0.1\noptions attempts:1 timeout:1\n")
        with open(os.path.join(run_dir, "jh", "run.sh"), "w") as fh:
            fh.write(inner_script(steps).replace("%TIMEOUT%", str(int(timeout))))
        timed_out = False
        if steps:
            try:
                subprocess.run(container_argv(engine, image, run_dir, snap), capture_output=True,
                               timeout=timeout * max(1, len(steps)) + 60)
            except subprocess.TimeoutExpired:
                timed_out = True
                gaps.append("the run exceeded its time limit")
        out = os.path.join(run_dir, "out")
        for i, step in enumerate(steps):
            exit_path = os.path.join(out, "step.%d.exit" % i)
            code = open(exit_path).read().strip() if os.path.exists(exit_path) else None
            trace_path = os.path.join(out, "trace.%d" % i)
            traced = os.path.exists(trace_path)
            result["steps"].append({"name": step["name"], "command": step["argv"], "exit": code, "traced": traced})
            if code == "124":
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
    out += ["", "## Steps", ""]
    for s in r["steps"]:
        out.append("- `%s`: exit %s%s" % (s["command"], s["exit"], "" if s["traced"] else " (no trace)"))
    out += ["", "## Audit log", ""]
    if not r["events"]:
        out.append("No network attempts, canary access or persistence attempts were observed in the steps that ran.")
    for e in sorted(r["events"], key=lambda e: (e["verdict"] != "ALERT", e["kind"], e["detail"])):
        who = " by `%s`" % e["process"] if e["process"] else ""
        out.append("- **%s** %s: %s%s%s" % (e["verdict"], e["kind"], e["detail"], who,
                                           " (%s)" % e["step"] if e["step"] else ""))
    out += ["", "## Limits", ""] + ["- %s" % x for x in r["limits"]]
    return "\n".join(out) + "\n"
