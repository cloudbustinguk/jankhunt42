"""The skill is run by AI agents, whose conversation pays again for every byte a command prints on every later turn.
Every command SKILL.md suggests must print a bounded amount: a summary, a short report, or the full report to a file
(--out or a redirect). These tests read every command out of SKILL.md and run the short forms on a large project."""
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from _util import ROOT, run_cli

SKILL = Path(ROOT) / "SKILL.md"
LIMIT = 20000                      # bytes any command the skill lets an agent print may produce (~5,000 tokens)
FULL_FORMATS = ("--json", "--sarif", "--html", "--brief")
# forms that print a short report whatever the repository's size (checked on a large project below)
SHORT = re.compile(r"^jankhunt42 (?:map \.(?: --base \S+)?"
                   r"|passport \.(?: --profile citizen| --base \S+ --md| --emit-sandbox-policy \S+| --fail-on \S+"
                   r"| --compare \S+| --branch-rules \S+)?"
                   r"|scan \. --score|scan \. --prompt|rules --category \S+)$")


def skill_commands():
    text = SKILL.read_text(encoding="utf-8")
    found = [m.group(1) for m in re.finditer(r"`(jankhunt42 [^`]+)`", text)]
    for block in re.findall(r"```sh\n(.*?)```", text, re.S):
        found += [line.split("  #")[0].strip() for line in block.splitlines() if line.startswith("jankhunt42 ")]
    return [c for c in found if c]


def bounded(cmd):
    if "--summary" in cmd or "--out " in cmd or re.search(r"\s>\s*\S", cmd):
        return True
    if any(flag in cmd.split() for flag in FULL_FORMATS):
        return False
    return bool(SHORT.match(cmd))


class EveryCommandIsBounded(unittest.TestCase):
    def test_skill_md_suggests_only_bounded_commands(self):
        cmds = skill_commands()
        self.assertGreater(len(cmds), 20)
        unbounded = [c for c in cmds if not bounded(c)]
        self.assertEqual(unbounded, [], "SKILL.md suggests commands an agent would print in full")

    def test_a_full_format_is_never_printed(self):
        for c in skill_commands():
            if any(flag in c.split() for flag in FULL_FORMATS):
                with self.subTest(command=c):
                    self.assertTrue("--out " in c or re.search(r"\s>\s*\S", c), c)


class ShortFormsStayShort(unittest.TestCase):
    """The short forms on a project with hundreds of findings, agent settings and an MCP config."""

    @classmethod
    def setUpClass(cls):
        cls.root = tempfile.mkdtemp(prefix="jh-skill-bounded-")
        body = ("import os, subprocess, requests\n"
                "API_KEY = 'sk-proj-Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4zAb7cDe0fGh3iJk'\n"
                "def f(x):\n    try:\n        subprocess.run('ls ' + x, shell=True)\n    except:\n        pass\n"
                "    requests.get('https://api.example.invalid/' + x, verify=False)\n    breakpoint()\n")
        for i in range(80):
            p = os.path.join(cls.root, "pkg%02d" % (i // 10), "m%02d.py" % i)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(body * 3)
        os.makedirs(os.path.join(cls.root, ".claude"))
        with open(os.path.join(cls.root, ".claude", "settings.json"), "w") as fh:
            json.dump({"permissions": {"allow": ["Bash", "WebFetch"]}}, fh)
        with open(os.path.join(cls.root, ".mcp.json"), "w") as fh:
            json.dump({"mcpServers": {"fetch": {"command": "npx", "args": ["-y", "server-fetch"]}}}, fh)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root, ignore_errors=True)

    def check(self, *argv):
        proc = run_cli(*argv)
        self.assertIn(proc.returncode, (0, 1), proc.stderr[-300:])
        self.assertLess(len(proc.stdout.encode("utf-8")), LIMIT, " ".join(argv))
        return proc

    def test_the_short_forms_on_a_large_project(self):
        full = json.loads(run_cli("scan", self.root, "--json", "--no-progress").stdout)
        self.assertGreater(full["summary"]["findings"], 500)       # a project whose full report is large
        for argv in (("scan", self.root, "--summary", "--no-progress"),
                     ("scan", self.root, "--category", "agent", "--summary", "--no-progress"),
                     ("scan", self.root, "--score", "--no-progress"),
                     ("scan", self.root, "--prompt", "--no-progress"),
                     ("map", self.root), ("passport", self.root),
                     ("passport", self.root, "--profile", "citizen"),
                     ("passport", self.root, "--emit-sandbox-policy", "claude-code"),
                     ("rules", "--category", "agent")):
            with self.subTest(argv=argv[0:1] + argv[2:]):
                self.check(*argv)

    def test_out_writes_the_full_report_and_prints_only_the_short_one(self):
        out = os.path.join(self.root, ".jankhunt42")
        for cmd in ("map", "passport"):
            with self.subTest(cmd=cmd):
                self.check(cmd, self.root, "--out", os.path.join(out, cmd + ".json"))
                with open(os.path.join(out, cmd + ".json"), encoding="utf-8") as fh:
                    self.assertTrue(json.load(fh).get("schema_version", "").startswith("jankhunt."))

    @unittest.skipUnless(shutil.which("git"), "git unavailable")
    def test_review_summary_on_a_large_change(self):
        repo = tempfile.mkdtemp(prefix="jh-skill-review-")
        self.addCleanup(shutil.rmtree, repo, True)
        git = ["git", "-C", repo, "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid"]
        subprocess.run(["git", "-C", repo, "init", "-q"], check=True)
        Path(repo, "README.md").write_text("x\n")
        subprocess.run(git + ["add", "-A"], check=True)
        subprocess.run(git + ["commit", "-qm", "one"], check=True)
        shutil.copytree(os.path.join(self.root, "pkg00"), os.path.join(repo, "pkg00"))
        subprocess.run(git + ["add", "-A"], check=True)
        subprocess.run(git + ["commit", "-qm", "two"], check=True)
        proc = run_cli("review", repo, "--base", "HEAD^", "--summary")
        self.assertLess(len(proc.stdout.encode("utf-8")), LIMIT)
        self.assertIn("review summary", proc.stdout)


class SummaryEdges(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="jh-summary-edges-")
        self.addCleanup(shutil.rmtree, self.root, True)

    @unittest.skipIf(os.name == "nt", "file names with line breaks")
    def test_line_breaks_in_file_names_keep_the_summary_short(self):
        for i in range(10):
            Path(self.root, "tile%d" % i + "\n" * 54 + ".py").write_text("breakpoint()\n")
        out = run_cli("scan", self.root, "--rule", "JH204", "--summary", "--no-progress").stdout
        self.assertLessEqual(len(out.splitlines()), 60)

    def test_the_summary_states_the_gate_verdict(self):
        Path(self.root, "card.py").write_text("breakpoint()\n")
        fail = run_cli("scan", self.root, "--no-config", "--rule", "JH204", "--fail-on", "minor", "--summary", "--no-progress")
        ok = run_cli("scan", self.root, "--no-config", "--rule", "JH204", "--fail-on", "major", "--summary", "--no-progress")
        self.assertEqual((fail.returncode, ok.returncode), (1, 0))
        self.assertIn("gate (--fail-on minor): FAIL", fail.stdout)
        self.assertIn("gate (--fail-on major): PASS", ok.stdout)

    def test_score_with_out_writes_the_report_and_refuses_summary(self):
        Path(self.root, "chart.py").write_text("breakpoint()\n")
        saved = os.path.join(self.root, "out", "saved.json")
        proc = run_cli("scan", self.root, "--score", "--out", saved, "--rule", "JH204", "--no-progress")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(os.path.isfile(saved))
        refused = run_cli("scan", self.root, "--score", "--summary", "--no-progress")
        self.assertEqual(refused.returncode, 2)


if __name__ == "__main__":
    unittest.main()
