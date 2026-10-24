#!/usr/bin/env python3
"""`jankhunt42 selftest`: self-assurance that does not grade its own homework.

A scanner that scans itself can award itself a perfect score, so the
dogfood steps here are reported but never decide the gate on their own.
The gate rests on independent evidence: an oracle-checked test suite,
a hand-maintained ground truth for the self-map, seeded fixtures,
mutation testing (deliberately broken copies must make tests fail), and a
privacy scan of shipped files and generated artifacts.

Each check reports pass | fail | skip | insufficient-evidence with the
exact command, exit code, and timing. Nothing is installed, fetched, or
sent anywhere; optional checks that need tools which are not present are
reported as `skip` and never counted as passes.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

HERE = os.path.dirname(os.path.realpath(__file__))
ROOT = os.path.dirname(HERE)
TESTS = os.path.join(ROOT, "tests")
CLI = os.path.join(HERE, "jankhunt42")

# (id, description, file, old, new, test pattern). Each mutant must be
# "killed": the named tests must fail against the mutated copy.
MUTANTS = [
    ("M1-permission-comparison", "integrity admits read instead of write/delete/admin", "jh_graph.py",
     'return base if cap in ("write", "delete", "admin") else None',
     'return base if cap in ("read",) else None', "test_graph.py"),
    ("M2-edge-type-filter", "depends-on edges propagate authority", "jh_graph.py",
     'if kind == "depends-on":\n        return None', 'if kind == "depends-on":\n        return base', "test_graph.py"),
    ("M3-redaction-branch", "key=value credential redaction disabled", "jh_graph.py",
     'out = _KV_SECRET_RE.sub(lambda m: m.group(1) + m.group(2) + "<redacted>", out)', 'out = out',
     "test_graph.py"),
    ("M4-unknown-as-safe", "unknown capability treated as no access", "jh_graph.py",
     'if kind in ("connects", "calls"):\n            return min(base, 1)',
     'if kind in ("connects", "calls"):\n            return None', "test_graph.py"),
    ("M5-policy-precedence", "repository config may weaken the effective policy", "jh_policy.py",
     'if ACTION_RANK[v] > ACTION_RANK[eff["actions"][k]]:', 'if True:', "test_passport.py"),
    ("M6-unverified-to-verified", "repository inventory claims become provider-verified", "jh_map.py",
     'verification = "provider-verified" if trusted else "declared"', 'verification = "provider-verified"',
     "test_map.py"),
    ("M7-coverage-floor", "partial coverage no longer forces insufficient-evidence", "jh_policy.py",
     'add("P-COV-001", "insufficient-evidence" if cov_reasons else "pass",',
     'add("P-COV-001", "pass",', "test_passport.py"),
    ("M8-accept-revision-mismatch", "an acceptance record survives a revision change", "jh_passport.py",
     'invalid.append("revision-changed")', 'pass', "test_extensions.py"),
    ("M9-csv-formula-injection", "CSV cells starting with = are no longer neutralized", "jh_map.py",
     'if text[:1] in ("=", "+", "-", "@", "\\t", "\\r"):', 'if False:', "test_extensions.py"),
    ("M10-not-run-counts-as-verified", "a verifier that did not run satisfies the verified-attestation gate",
     "jh_supply.py", 'tool_verified = any(r.get("outcome") == "tool-verified" for r in results)',
     'tool_verified = bool(results)', "test_verify.py"),
    ("M11-token-on-redirect", "the GitHub token is sent to redirect targets", "jh_verify.py",
     'if parts.hostname == API_HOST:', 'if parts.hostname:', "test_verify.py"),
    ("M12-in-repo-verify-plan", "a verification plan inside the repository is trusted", "jh_verify.py",
     'if _inside(path, root):\n        raise PlanError', 'if False:\n        raise PlanError', "test_verify.py"),
]

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@([A-Za-z0-9\-]+\.)+[A-Za-z]{2,}")
_ALLOWED_EMAIL_DOMAINS = ("example.com", "example.org", "example.net", "example.invalid", "users.noreply.github.com")
_SECRET_PATTERNS = [
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----\s*\n\s*[A-Za-z0-9+/=]{40,}")),
    ("aws-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
]
_PASCAL_RE = re.compile("Jank" + "Hunt")


class Check:
    def __init__(self, cid: str, title: str, mandatory: bool = True):
        self.id = cid
        self.title = title
        self.mandatory = mandatory
        self.status = "insufficient-evidence"
        self.detail = ""
        self.commands: List[Dict[str, Any]] = []
        self.data: Dict[str, Any] = {}
        self.seconds = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "title": self.title, "mandatory": self.mandatory, "status": self.status,
                "detail": self.detail, "seconds": round(self.seconds, 2), "commands": self.commands,
                "data": self.data}


def _rel_cmd(cmd: Sequence[str]) -> str:
    out = []
    for c in cmd:
        c = str(c)
        if c.startswith(ROOT):
            c = os.path.relpath(c, ROOT)
        elif c == sys.executable:
            c = "python3"
        elif c.startswith(tempfile.gettempdir()):
            c = "$TMP/" + os.path.basename(c)
        out.append(c)
    return " ".join(out)


def _run(check: Check, cmd: Sequence[str], timeout: int = 900, cwd: Optional[str] = None,
         env: Optional[Dict[str, str]] = None) -> subprocess.CompletedProcess:
    e = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    e.pop("FORCE_COLOR", None)
    if env:
        e.update(env)
    t0 = time.time()
    try:
        proc = subprocess.run(list(cmd), capture_output=True, text=True, timeout=timeout, cwd=cwd or ROOT, env=e)
    except subprocess.TimeoutExpired:
        proc = subprocess.CompletedProcess(list(cmd), 124, "", "timeout after %ds" % timeout)
    check.commands.append({"command": _rel_cmd(cmd), "exit_code": proc.returncode,
                           "seconds": round(time.time() - t0, 2)})
    return proc


def _tail(text: str, n: int = 6) -> str:
    lines = [l for l in (text or "").strip().splitlines() if l.strip()]
    return "\n".join(lines[-n:])


def check_unit_tests() -> Check:
    c = Check("unit-tests", "unittest suite: oracle, metamorphic, adapters, policy, diff, fuzz, snapshots, compat")
    if not os.path.isdir(TESTS):
        c.detail = "tests/ directory not present in this installation"
        return c
    proc = _run(c, [sys.executable, "-m", "unittest", "discover", "-s", TESTS])
    summary = _tail(proc.stderr, 3)
    m = re.search(r"Ran (\d+) tests?", proc.stderr or "")
    skipped = re.search(r"skipped=(\d+)", proc.stderr or "")
    c.data = {"tests": int(m.group(1)) if m else None, "skipped": int(skipped.group(1)) if skipped else 0}
    c.status = "pass" if proc.returncode == 0 else "fail"
    c.detail = summary
    return c


def check_shell_suite() -> Check:
    c = Check("shell-regression", "scripts/selftest.sh end-to-end CLI regression suite")
    bash = shutil.which("bash")
    if not bash:
        c.status, c.detail = "skip", "bash not available on this system"
        c.mandatory = False
        return c
    proc = _run(c, [bash, os.path.join(HERE, "selftest.sh")])
    c.status = "pass" if proc.returncode == 0 else "fail"
    c.detail = _tail(proc.stdout + "\n" + proc.stderr, 2)
    return c


def _json_cli(c: Check, *args: str) -> Optional[Dict[str, Any]]:
    proc = _run(c, [sys.executable, CLI] + list(args))
    try:
        return json.loads(proc.stdout)
    except ValueError:
        c.detail = "invalid JSON from %s: %s" % (" ".join(args[:2]), _tail(proc.stderr, 2))
        return None


def check_self_map() -> Check:
    c = Check("dogfood-map", "self-map vs hand-maintained ground truth (tests/fixtures/self-expected.json)")
    expected_path = os.path.join(TESTS, "fixtures", "self-expected.json")
    if not os.path.exists(expected_path):
        c.detail = "ground-truth fixture missing"
        return c
    with open(expected_path, encoding="utf-8") as fh:
        expected = json.load(fh)
    rep = _json_cli(c, "map", ROOT, "--json", "--no-config")
    if rep is None:
        c.status = "fail"
        return c
    labels = {}
    for n in rep["graph"]["nodes"]:
        labels[n["id"]] = "jankhunt42" if n["kind"] == "application" else n["display_label"]
    got = {(labels[e["source"]], e["kind"], e["capability"], labels[e["target"]]) for e in rep["graph"]["edges"]}
    want = {(e["source"], e["kind"], e["capability"], e["target"]) for e in expected["edges"]}
    fp = sorted(got - want)
    fn = sorted(want - got)
    bad_kinds = sorted({n["kind"] for n in rep["graph"]["nodes"]} & set(expected.get("must_not_contain", [])))
    c.data = {"expected_edges": len(want), "observed_edges": len(got), "true_positives": len(got & want),
              "false_positives": [list(x) for x in fp], "false_negatives": [list(x) for x in fn],
              "forbidden_kinds_present": bad_kinds, "exposure": rep["assessment"]["exposure"]["class"],
              "coverage": rep["coverage"]["status"]}
    c.status = "pass" if not fp and not fn and not bad_kinds else "fail"
    c.detail = "%d/%d expected edges found, %d false positive(s), %d false negative(s)" % (
        len(got & want), len(want), len(fp), len(fn))
    return c


def check_self_scan_and_passport() -> Check:
    c = Check("dogfood-passport", "self-scan and self-passport (reported, never self-approving)", mandatory=False)
    scan = _json_cli(c, "scan", ROOT, "--json")
    pp = _json_cli(c, "passport", ROOT, "--json")
    if scan is None or pp is None:
        c.status = "fail"
        return c
    c.data = {"jank_score": scan["summary"]["jank_score"], "findings": scan["summary"]["counts"],
              "passport_decision": pp["assessment"]["decision"]["result"],
              "passport_reasons": [r["rule"] for r in pp["assessment"]["decision"]["reasons"]],
              "exposure": pp["assessment"]["exposure"]["class"],
              "lifecycle": pp["lifecycle"]["state"], "acceptance": pp["lifecycle"]["acceptance"]["state"]}
    ok = pp["lifecycle"]["acceptance"]["state"] == "not-supplied"
    c.status = "pass" if ok else "fail"
    c.detail = ("self-scan Jank Score %s; self-passport decision %s. A self-issued passport is evidence about "
                "the tool's own inputs, not certification of release readiness." % (
                    c.data["jank_score"], c.data["passport_decision"]))
    return c


def _copy_tree(tmp: str) -> None:
    shutil.copytree(HERE, os.path.join(tmp, "scripts"), ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(TESTS, os.path.join(tmp, "tests"), ignore=shutil.ignore_patterns("__pycache__"))
    if os.path.isdir(os.path.join(ROOT, "templates")):
        shutil.copytree(os.path.join(ROOT, "templates"), os.path.join(tmp, "templates"))


def check_mutants() -> Check:
    c = Check("mutation", "representative mutants must be killed by the test suite")
    if not os.path.isdir(TESTS):
        c.detail = "tests/ directory not present"
        return c
    results = []
    # Control: the unmutated copy must pass the same tests, otherwise a
    # "kill" could just mean the copy itself is broken.
    controls: Dict[str, bool] = {}
    for pattern in sorted({m[5] for m in MUTANTS}):
        tmp = tempfile.mkdtemp(prefix="jh-control-")
        try:
            _copy_tree(tmp)
            proc = _run(c, [sys.executable, "-m", "unittest", "discover", "-s", os.path.join(tmp, "tests"),
                            "-p", pattern], timeout=600, cwd=tmp)
            controls[pattern] = proc.returncode == 0
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    if not all(controls.values()):
        c.status = "fail"
        c.detail = "control (unmutated) copy failed: %s" % ", ".join(p for p, ok in controls.items() if not ok)
        c.data = {"controls": controls}
        return c
    for mid, desc, fname, old, new, pattern in MUTANTS:
        tmp = tempfile.mkdtemp(prefix="jh-mutant-")
        try:
            _copy_tree(tmp)
            path = os.path.join(tmp, "scripts", fname)
            with open(path, encoding="utf-8") as fh:
                src = fh.read()
            if src.count(old) != 1:
                results.append({"id": mid, "description": desc, "status": "invalid",
                                "detail": "mutation anchor not found exactly once (source changed?)"})
                continue
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(src.replace(old, new))
            proc = _run(c, [sys.executable, "-m", "unittest", "discover", "-s", os.path.join(tmp, "tests"),
                            "-p", pattern], timeout=600, cwd=tmp)
            results.append({"id": mid, "description": desc,
                            "status": "killed" if proc.returncode != 0 else "survived", "tests": pattern})
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    killed = sum(1 for r in results if r["status"] == "killed")
    c.data = {"controls": controls, "attempted": len(results), "killed": killed,
              "survived": [r["id"] for r in results if r["status"] == "survived"],
              "invalid": [r["id"] for r in results if r["status"] == "invalid"], "mutants": results}
    c.status = "pass" if killed == len(results) == len(MUTANTS) else "fail"
    c.detail = "%d/%d mutants killed" % (killed, len(MUTANTS))
    return c


def _shipped_files() -> List[str]:
    try:
        out = subprocess.run(["git", "-C", ROOT, "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                             capture_output=True, timeout=30)
        if out.returncode == 0:
            files = [p for p in out.stdout.decode("utf-8", "replace").split("\0") if p]
            return [f for f in files if not f.startswith("docs/") and os.path.isfile(os.path.join(ROOT, f))]
    except (OSError, subprocess.SubprocessError):
        found = []  # no usable git: fall back to walking the tree below
    found = []
    for base, dirs, names in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in (".git", "docs", "__pycache__")]
        found += [os.path.relpath(os.path.join(base, n), ROOT) for n in names]
    return found


def check_privacy() -> Check:
    c = Check("privacy", "shipped files and generated artifacts: no emails, tokens, keys, home paths, or PascalCase name")
    problems: List[str] = []
    home = os.path.expanduser("~")
    for rel in sorted(_shipped_files()):
        if rel.endswith((".png", ".jpg", ".gif", ".ico")):
            continue
        try:
            with open(os.path.join(ROOT, rel), encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        for m in _EMAIL_RE.finditer(text):
            before = text[max(0, m.start() - 80):m.start()].split()[-1:] or [""]
            if "://" in before[0] or text[max(0, m.start() - 3):m.start()].endswith("://"):
                continue  # URL userinfo (user:pass@host) in a test fixture, not an email address
            dom = m.group(0).split("@", 1)[1].lower()
            if not any(dom == d or dom.endswith("." + d) for d in _ALLOWED_EMAIL_DOMAINS) and not m.group(0).startswith("noreply@"):
                if "@" in m.group(0) and not re.match(r"^[\w.\-]+@\d", m.group(0)):
                    problems.append("%s: email-like string %s" % (rel, m.group(0)))
        for name, rx in _SECRET_PATTERNS:
            if rx.search(text):
                problems.append("%s: %s pattern" % (rel, name))
        if _PASCAL_RE.search(text):
            problems.append("%s: PascalCase product name (use 'jankhunt42')" % rel)
        if len(home) > 1 and home in text:
            problems.append("%s: absolute home path" % rel)
    tmp = tempfile.mkdtemp(prefix="jh-privacy-")
    try:
        demo = os.path.join(tmp, "demo-app")
        shutil.copytree(os.path.join(TESTS, "fixtures", "demo-app"), demo)
        for args in (("map", "--json"), ("map", "--html"), ("passport", "--json"), ("passport", "--html"),
                     ("map", "--json", "--redact"), ("passport", "--json", "--redact")):
            proc = _run(c, [sys.executable, CLI, args[0], demo] + list(args[1:]))
            out = proc.stdout
            for needle, what in (("example-only", "fixture password"), (tmp, "absolute temp path"), (home, "home path")):
                if needle and needle in out:
                    problems.append("generated %s leaks %s" % (" ".join(args), what))
            if "--redact" in args:
                for needle in ("ledger-db.prod.internal", "demo-org", "payments-api"):
                    if needle in out:
                        problems.append("redacted %s still shows %s" % (" ".join(args), needle))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    c.data = {"problems": problems[:50], "files_scanned": len(_shipped_files())}
    c.status = "pass" if not problems else "fail"
    c.detail = "%d problem(s)" % len(problems)
    return c


def check_python_matrix() -> Check:
    c = Check("python-matrix", "unit tests on locally cached Python images (docker, --pull never, --network none)",
              mandatory=False)
    docker = shutil.which("docker")
    if not docker:
        c.status, c.detail = "skip", "docker not available; matrix not run (not a pass)"
        return c
    ran = []
    for image in ("python:3.9-slim", "python:3.10-slim", "python:3.11-slim", "python:3.12-slim", "python:3.13-slim",
                  "python:3.14-slim"):
        probe = subprocess.run([docker, "image", "inspect", image], capture_output=True, timeout=60)
        if probe.returncode != 0:
            ran.append({"image": image, "status": "skip", "detail": "image not cached locally; not pulled"})
            continue
        proc = _run(c, [docker, "run", "--rm", "--pull", "never", "--network", "none", "-v", "%s:/src:ro" % ROOT,
                        "-w", "/src", "-e", "PYTHONDONTWRITEBYTECODE=1", image,
                        "python", "-m", "unittest", "discover", "-s", "tests"], timeout=900)
        ran.append({"image": image, "status": "pass" if proc.returncode == 0 else "fail",
                    "detail": _tail(proc.stderr, 2)})
    c.data = {"images": ran}
    statuses = {r["status"] for r in ran}
    c.status = "fail" if "fail" in statuses else ("pass" if "pass" in statuses else "skip")
    c.detail = ", ".join("%s %s" % (r["image"], r["status"]) for r in ran)
    return c


def check_independent_analyzers() -> Check:
    c = Check("independent-analyzers", "independent tools if installed locally (never installed or fetched)",
              mandatory=False)
    results = []
    # Always available: byte-compile every script with the stdlib compiler,
    # into a throwaway directory so no cache lands in the skill directory.
    tmp = tempfile.mkdtemp(prefix="jh-compile-")
    try:
        script = ("import py_compile,sys,os\n"
                  "bad=0\n"
                  "for f in sys.argv[2:]:\n"
                  "    try: py_compile.compile(f, cfile=os.path.join(sys.argv[1], os.path.basename(f)+'.pyc'), doraise=True)\n"
                  "    except py_compile.PyCompileError as e: print(e); bad=1\n"
                  "sys.exit(bad)\n")
        files = sorted(os.path.join(HERE, f) for f in os.listdir(HERE) if f.endswith(".py")) + [CLI]
        proc = _run(c, [sys.executable, "-c", script, tmp] + files)
        results.append({"tool": "py_compile (stdlib)", "status": "pass" if proc.returncode == 0 else "fail"})
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    optional = [
        ("ruff", ["ruff", "check", "--no-cache", "--select", "E9,F63,F7,F82", HERE]),
        ("pyflakes", ["pyflakes", HERE]),
        ("bandit", ["bandit", "-q", "-ll", "-r", HERE]),
        ("shellcheck", ["shellcheck", "-S", "error", os.path.join(HERE, "selftest.sh")]),
    ]
    for name, cmd in optional:
        if not shutil.which(cmd[0]):
            results.append({"tool": name, "status": "skip", "detail": "not installed (not counted as a pass)"})
            continue
        proc = _run(c, cmd, timeout=600)
        results.append({"tool": name, "status": "pass" if proc.returncode == 0 else "fail",
                        "detail": _tail(proc.stdout + proc.stderr, 3)})
    c.data = {"tools": results}
    statuses = [r["status"] for r in results]
    c.status = "fail" if "fail" in statuses else "pass"
    c.detail = ", ".join("%s %s" % (r["tool"], r["status"]) for r in results)
    return c


def gate(checks: Sequence[Check]) -> str:
    if any(c.status == "fail" for c in checks):
        return "fail"
    if any(c.mandatory and c.status != "pass" for c in checks):
        return "insufficient-evidence"
    return "pass"


def run(full: bool) -> Dict[str, Any]:
    from jh_core import VERSION
    checks: List[Check] = []
    steps = [check_unit_tests]
    if full:
        steps += [check_shell_suite, check_self_map, check_self_scan_and_passport, check_mutants,
                  check_privacy, check_independent_analyzers, check_python_matrix]
    for step in steps:
        t0 = time.time()
        c = step()
        c.seconds = time.time() - t0
        checks.append(c)
    rev = None
    try:
        p = subprocess.run(["git", "-C", ROOT, "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10)
        rev = p.stdout.strip() or None if p.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        rev = None  # not a git checkout, or git unavailable: report the revision as unknown
    result = gate(checks)
    return {
        "schema_version": "jankhunt.selftest.v1",
        "tool": "jankhunt42",
        "tool_version": VERSION,
        "source_revision": rev,
        "mode": "full" if full else "quick",
        "gate": result,
        "note": ("the gate rests on independent checks; a perfect self-scan or self-passport is never "
                 "a substitute for them, and this tool creates no release"),
        "checks": [c.to_dict() for c in checks],
        "not_run": [] if full else ["shell-regression", "dogfood-map", "dogfood-passport", "mutation",
                                    "privacy", "independent-analyzers", "python-matrix"],
    }


def markdown(rep: Dict[str, Any]) -> str:
    out = ["# jankhunt42 selftest (%s)" % rep["mode"], "",
           "- Gate: **%s**" % rep["gate"], "- Version: %s; revision: %s" % (rep["tool_version"], rep["source_revision"] or "unknown"),
           "- %s" % rep["note"], "", "| check | status | detail |", "|---|---|---|"]
    for c in rep["checks"]:
        out.append("| %s%s | %s | %s |" % (c["id"], "" if c["mandatory"] else " (optional)", c["status"],
                                          c["detail"].replace("\n", " ").replace("|", "/")[:160]))
    if rep["not_run"]:
        out += ["", "Not run in quick mode (use `--full`): %s" % ", ".join(rep["not_run"])]
    return "\n".join(out)


def main(args: Any) -> int:
    rep = run(bool(getattr(args, "full", False)))
    if getattr(args, "json", False):
        print(json.dumps(rep, indent=2, ensure_ascii=False))
    else:
        print(markdown(rep))
    return 0 if rep["gate"] == "pass" else 1
