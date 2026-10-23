#!/usr/bin/env python3
"""Environment and project health checks for jankhunt42."""
from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from jh_core import TOOL, VERSION

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build", "target",
    "out", "coverage", ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", ".tox", ".idea", ".vscode", ".gradle", ".next", ".nuxt",
    ".cache", ".terraform", "bower_components", "Pods", "DerivedData",
}

TOOL_CMDS = [
    ("git", ["--version"]), ("node", ["--version"]), ("npm", ["--version"]),
    ("pnpm", ["--version"]), ("yarn", ["--version"]), ("bun", ["--version"]),
    ("python3", ["--version"]), ("pip3", ["--version"]), ("uv", ["--version"]),
    ("poetry", ["--version"]), ("cargo", ["--version"]), ("rustc", ["--version"]),
    ("go", ["version"]), ("java", ["-version"]), ("mvn", ["-version"]),
    ("gradle", ["--version"]), ("dotnet", ["--version"]), ("gcc", ["--version"]),
    ("clang", ["--version"]), ("make", ["--version"]), ("cmake", ["--version"]),
    ("docker", ["--version"]), ("podman", ["--version"]),
    ("kubectl", ["version", "--client"]), ("helm", ["version", "--short"]),
    ("terraform", ["version"]), ("jq", ["--version"]), ("rg", ["--version"]),
    ("shellcheck", ["--version"]), ("hadolint", ["--version"]),
    ("semgrep", ["--version"]), ("trivy", ["--version"]),
    ("gdb", ["--version"]), ("lldb", ["--version"]), ("strace", ["-V"]),
    ("perf", ["--version"]), ("valgrind", ["--version"]),
    ("py-spy", ["--version"]), ("hyperfine", ["--version"]),
]


@dataclass
class Warning:
    level: str
    text: str


@dataclass
class DoctorResult:
    root: str
    git: Dict[str, object] = field(default_factory=dict)
    manifests: List[str] = field(default_factory=list)
    languages: List[Dict[str, object]] = field(default_factory=list)
    tools: List[Dict[str, str]] = field(default_factory=list)
    system: Dict[str, object] = field(default_factory=dict)
    warnings: List[Warning] = field(default_factory=list)
    files: int = 0
    tests: int = 0


def _run(cmd: Sequence[str], cwd: Optional[str] = None, timeout: float = 2.5) -> Tuple[int, str]:
    try:
        proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                              timeout=timeout, errors="replace")
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, str(exc)
    out = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode, out.strip()


def _first_line(text: str, width: int = 100) -> str:
    for line in text.splitlines():
        line = line.strip()
        if line:
            return line if len(line) <= width else line[: width - 1] + "…"
    return ""


def _tool_rows() -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for name, args in TOOL_CMDS:
        path = shutil.which(name)
        if not path:
            continue
        rc, out = _run([path] + args)
        rows.append({"name": name, "path": path, "version": _first_line(out) or ("exit %d" % rc)})
    return rows


def _git_info(root: str) -> Dict[str, object]:
    rc, out = _run(["git", "-C", root, "rev-parse", "--is-inside-work-tree"])
    if rc != 0 or out.strip() != "true":
        return {}
    info: Dict[str, object] = {}
    _, top = _run(["git", "-C", root, "rev-parse", "--show-toplevel"])
    info["top"] = top.strip()
    _, branch = _run(["git", "-C", root, "branch", "--show-current"])
    info["branch"] = branch.strip() or "(detached)"
    _, head = _run(["git", "-C", root, "log", "-1", "--format=%h|%s|%cr"])
    parts = head.strip().split("|", 2)
    info["head"] = parts[0] if parts else ""
    info["subject"] = parts[1] if len(parts) > 1 else ""
    info["commit_age"] = parts[2] if len(parts) > 2 else ""
    _, count = _run(["git", "-C", root, "rev-list", "--count", "HEAD"])
    info["commits"] = count.strip()
    _, status = _run(["git", "-C", root, "status", "--porcelain=v1"])
    changed = [ln for ln in status.splitlines() if ln.strip()]
    info["changed"] = len(changed)
    info["changed_files"] = changed[:15]
    _, conflicts = _run(["git", "-C", root, "diff", "--name-only", "--diff-filter=U"])
    info["conflicts"] = [ln for ln in conflicts.splitlines() if ln.strip()]
    _, stash = _run(["git", "-C", root, "stash", "list"])
    info["stashes"] = len([ln for ln in stash.splitlines() if ln.strip()])
    _, dirty = _run(["git", "-C", root, "status", "--porcelain", "--untracked-files=no"])
    info["dirty_tracked"] = bool(dirty.strip())
    return info


def _find_manifests(root: str) -> List[str]:
    names = {
        "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
        "bun.lockb", "pyproject.toml", "requirements.txt", "setup.py", "setup.cfg",
        "pipfile", "pipfile.lock", "poetry.lock", "uv.lock", "cargo.toml",
        "cargo.lock", "go.mod", "go.sum", "pom.xml", "build.gradle",
        "build.gradle.kts", "settings.gradle", "composer.json", "gemfile",
        "gemfile.lock", "dockerfile", "docker-compose.yml", "docker-compose.yaml",
        "compose.yml", "compose.yaml", "chart.yaml", "makefile", "cmakelists.txt",
        "pubspec.yaml", "mix.exs", ".gitlab-ci.yml", "azure-pipelines.yml",
        "jenkinsfile",
    }
    found: List[str] = []
    base = Path(root)
    for depth in range(0, 3):
        pattern = "*/" * depth + "*"
        try:
            entries = base.glob(pattern)
        except OSError:
            break
        for p in entries:
            if not p.is_file():
                continue
            if p.name.lower() in names or p.suffix.lower() in (".csproj", ".fsproj", ".vbproj", ".tf"):
                rel = os.path.relpath(str(p), root).replace(os.sep, "/")
                found.append(rel)
    return sorted(set(found))


def _language_stats(root: str, max_files: int = 8000) -> Tuple[List[Dict[str, object]], int, int]:
    counts: Dict[str, int] = {}
    files = 0
    tests = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            files += 1
            if files > max_files:
                break
            ext = os.path.splitext(fn)[1].lower() or "(none)"
            counts[ext] = counts.get(ext, 0) + 1
            low = fn.lower()
            if ("test" in low or "spec" in low) and ext in (".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".cs", ".rb", ".php"):
                tests += 1
        if files > max_files:
            break
    rows = [{"ext": k, "files": v} for k, v in sorted(counts.items(), key=lambda kv: -kv[1])[:15]]
    return rows, files, tests


def _meminfo() -> Dict[str, int]:
    out: Dict[str, int] = {}
    try:
        with open("/proc/meminfo", "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = re.match(r"^(\w+):\s+(\d+)\s+kB", line)
                if m:
                    out[m.group(1)] = int(m.group(2)) * 1024
    except OSError:  # jankhunt42: ignore JH201
        pass
    return out


def _system_info(root: str, deep: bool) -> Dict[str, object]:
    info: Dict[str, object] = {}
    info["os"] = platform.platform()
    try:
        with open("/etc/os-release", "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("PRETTY_NAME="):
                    info["distro"] = line.split("=", 1)[1].strip().strip('"')
                    break
    except OSError:  # jankhunt42: ignore JH201
        pass
    info["kernel"] = platform.release()
    info["python"] = sys.version.split()[0]
    info["cpu_count"] = os.cpu_count()
    try:
        info["loadavg"] = [round(x, 2) for x in os.getloadavg()]
    except OSError:  # jankhunt42: ignore JH201
        pass
    mem = _meminfo()
    if mem:
        info["mem_total_gib"] = round(mem.get("MemTotal", 0) / 1073741824, 2)
        info["mem_available_gib"] = round(mem.get("MemAvailable", 0) / 1073741824, 2)
    try:
        usage = shutil.disk_usage(root)
        info["disk_total_gib"] = round(usage.total / 1073741824, 1)
        info["disk_free_gib"] = round(usage.free / 1073741824, 1)
        info["disk_free_pct"] = round(100.0 * usage.free / usage.total, 1) if usage.total else 0
    except OSError:  # jankhunt42: ignore JH201
        pass
    try:
        with open("/proc/sys/fs/inotify/max_user_watches", "r", encoding="utf-8") as fh:
            info["inotify_watches"] = int(fh.read().strip())
    except (OSError, ValueError):  # jankhunt42: ignore JH201
        pass
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        info["nofile_soft"] = soft
        info["nofile_hard"] = hard
    except (ImportError, OSError, ValueError):  # jankhunt42: ignore JH201
        pass
    proxies = [k for k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY") if os.environ.get(k)]
    if proxies:
        info["proxy_vars"] = proxies
    if os.environ.get("LD_LIBRARY_PATH"):
        info["ld_library_path"] = os.environ["LD_LIBRARY_PATH"]
    if os.environ.get("PYTHONPATH"):
        info["pythonpath"] = os.environ["PYTHONPATH"]

    if deep:
        rc, ss = _run(["ss", "-ltn"], timeout=3)
        if rc == 0:
            info["listening_ports"] = [ln for ln in ss.splitlines()[1:26] if ln.strip()]
        rc, failed = _run(["systemctl", "--failed", "--no-legend"], timeout=3)
        if rc == 0:
            info["failed_units"] = [ln for ln in failed.splitlines()[:10] if ln.strip()]
        rc, dmesg = _run(["dmesg", "--level=err,warn", "-T"], timeout=3)
        if rc == 0:
            info["dmesg_tail"] = [ln for ln in dmesg.splitlines()[-15:] if ln.strip()]
        else:
            info["dmesg"] = "not readable (try sudo dmesg / journalctl -k)"
    return info


def doctor(root: str = ".", deep: bool = False) -> DoctorResult:
    root = os.path.abspath(root)
    result = DoctorResult(root=root)
    result.git = _git_info(root)
    result.manifests = _find_manifests(root)
    result.languages, result.files, result.tests = _language_stats(root)
    result.tools = _tool_rows()
    result.system = _system_info(root, deep)

    names = {os.path.basename(p).lower() for p in result.manifests}
    warns = result.warnings
    if result.git:
        if result.git.get("conflicts"):
            warns.append(Warning("major", "Merge conflicts present in %d file(s)." % len(result.git["conflicts"])))
        if result.git.get("branch") == "(detached)":
            warns.append(Warning("info", "HEAD is detached; commits can be lost unless a branch is created."))
        if result.git.get("dirty_tracked"):
            warns.append(Warning("info", "Tracked files have uncommitted changes; diffs may not explain the running build."))
    if "package.json" in names and not (names & {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb"}):
        warns.append(Warning("info", "package.json has no lockfile; installs are not reproducible."))
    if "package.json" in names and not os.path.isdir(os.path.join(root, "node_modules")):
        warns.append(Warning("info", "node_modules is missing; dependencies are not installed."))
    if os.path.exists(os.path.join(root, ".env")):
        warns.append(Warning("info", ".env is present; ensure it is gitignored and never committed."))
    if names & {"dockerfile"} and not any(t["name"] in ("docker", "podman") for t in result.tools):
        warns.append(Warning("info", "Dockerfile present but no docker/podman CLI found."))
    if "pyproject.toml" in names and not (os.path.isdir(os.path.join(root, ".venv")) or os.path.isdir(os.path.join(root, "venv"))):
        warns.append(Warning("info", "Python project without a local virtualenv; confirm the interpreter is the intended one."))
    free = result.system.get("disk_free_gib")
    pct = result.system.get("disk_free_pct")
    if isinstance(free, (int, float)) and free < 5:
        warns.append(Warning("major", "Only %.1f GiB free disk space." % free))
    elif isinstance(pct, (int, float)) and pct < 10:
        warns.append(Warning("minor", "Disk is %.1f%% free." % pct))
    watches = result.system.get("inotify_watches")
    if isinstance(watches, int) and watches < 524288:
        warns.append(Warning("info", "inotify max_user_watches=%d; large projects may exhaust file watchers." % watches))
    nofile = result.system.get("nofile_soft")
    if isinstance(nofile, int) and nofile < 4096:
        warns.append(Warning("info", "ulimit -n is %d; servers/tests may hit file-descriptor limits." % nofile))
    return result


def doctor_json(result: DoctorResult) -> str:
    data = {
        "tool": TOOL,
        "version": VERSION,
        "command": "doctor",
        "root": result.root,
        "files": result.files,
        "tests": result.tests,
        "git": result.git,
        "manifests": result.manifests,
        "languages": result.languages,
        "tools": result.tools,
        "system": result.system,
        "warnings": [asdict(w) for w in result.warnings],
    }
    return json.dumps(data, indent=2, ensure_ascii=False)


def doctor_markdown(result: DoctorResult) -> str:
    out: List[str] = ["# Project doctor", ""]
    out.append("**Root:** `%s` · **Files:** %d · **Tests:** %d" % (result.root, result.files, result.tests))
    if result.git:
        g = result.git
        out.append("")
        out.append("**Git:** `%s` @ `%s` · %s · %s commits · %d changed · %d stashes"
                   % (g.get("branch", "?"), g.get("head", "?"), g.get("commit_age", ""),
                      g.get("commits", "?"), int(g.get("changed", 0) or 0), int(g.get("stashes", 0) or 0)))
    if result.warnings:
        out.append("")
        out.append("## Warnings")
        for w in result.warnings:
            out.append("- **%s** — %s" % (w.level, w.text))
    out.append("")
    out.append("## Manifests")
    if result.manifests:
        out.append(", ".join("`%s`" % m for m in result.manifests[:40]))
    else:
        out.append("No known manifests detected.")
    out.append("")
    out.append("## Languages")
    out.append("| Extension | Files |")
    out.append("|---|---:|")
    for row in result.languages:
        out.append("| `%s` | %d |" % (row["ext"], row["files"]))
    out.append("")
    out.append("## Toolchain")
    out.append("| Tool | Version | Path |")
    out.append("|---|---|---|")
    for t in result.tools:
        out.append("| %s | %s | `%s` |" % (t["name"], t["version"].replace("|", "\\|"), t["path"]))
    out.append("")
    out.append("## System")
    s = result.system
    keys = [
        ("distro", "Distro"), ("kernel", "Kernel"), ("python", "Python"), ("cpu_count", "CPUs"),
        ("loadavg", "Load"), ("mem_total_gib", "RAM GiB"), ("mem_available_gib", "RAM available GiB"),
        ("disk_total_gib", "Disk GiB"), ("disk_free_gib", "Disk free GiB"), ("disk_free_pct", "Disk free %"),
        ("inotify_watches", "inotify watches"), ("nofile_soft", "ulimit -n"),
    ]
    for key, label in keys:
        if key in s:
            out.append("- **%s:** %s" % (label, s[key]))
    for key in ("proxy_vars", "ld_library_path", "pythonpath"):
        if key in s:
            out.append("- **%s:** `%s`" % (key, s[key]))
    if "listening_ports" in s:
        out.append("")
        out.append("### Listening ports")
        out.append("```text")
        out.extend(str(x) for x in s["listening_ports"])
        out.append("```")
    if "failed_units" in s:
        out.append("")
        out.append("### Failed systemd units")
        out.append("```text")
        out.extend(str(x) for x in s["failed_units"])
        out.append("```")
    if "dmesg_tail" in s:
        out.append("")
        out.append("### Recent kernel warnings")
        out.append("```text")
        out.extend(str(x) for x in s["dmesg_tail"])
        out.append("```")
    elif "dmesg" in s:
        out.append("")
        out.append("Kernel log: %s" % s["dmesg"])
    return "\n".join(out)
