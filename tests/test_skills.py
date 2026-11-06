"""Agent skills (4.12.0): allowed-tools that pre-approves any shell command. Invented skills only."""
import json
import os
import shutil
import tempfile
import unittest

from _util import run_cli
import jh_checks as C

SKILLS = {
    ".claude/skills/deploy/SKILL.md": ("---\nname: deploy\ndescription: Deploy the app\n"
                                       "allowed-tools: Bash Read Grep\n---\n\nDeploy with the script.\n"),
    ".claude/skills/narrow/SKILL.md": ("---\nname: narrow\ndescription: Run the tests\n"
                                       "allowed-tools: Read Bash(git status *) Bash(npm run test:*) "
                                       "Bash(python3 scripts/report.py *)\n---\n"),
    ".agents/skills/report/SKILL.md": ("---\nname: report\ndescription: Build a report\nallowed-tools:\n  - Read\n"
                                       "  - Bash(python3:*)\n---\n"),
    "skills/flow/SKILL.md": "---\nname: flow\ndescription: x\nallowed-tools: [Read, \"Bash(*)\"]\n---\n",
    ".claude/commands/ship.md": "---\ndescription: Ship it\nallowed-tools: Bash(git add:*), Bash\n---\nShip.\n",
    "skills/empty/SKILL.md": "---\nname: empty\ndescription: x\nallowed-tools: []\n---\n",
    "skills/body/SKILL.md": "---\nname: body\ndescription: x\n---\n\nallowed-tools: Bash\n",
    "notes/plan.md": "---\ntitle: plan\nallowed-tools: Bash\n---\n",
    ".github/prompts/release.prompt.md": "---\nmode: agent\nallowed-tools: Bash\n---\nRelease.\n",   # not a skill
    "tests/fixtures/hostile/SKILL.md": "---\nname: hostile\ndescription: x\nallowed-tools: Bash\n---\n",
}


class AllowedTools(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tempfile.mkdtemp()
        for rel, text in SKILLS.items():
            os.makedirs(os.path.join(cls.root, os.path.dirname(rel)), exist_ok=True)
            with open(os.path.join(cls.root, rel), "w") as fh:
                fh.write(text)
        p = run_cli("scan", cls.root, "--json", "--no-config", "--rule", "JH712")
        cls.found = {f["path"]: f for f in json.loads(p.stdout)["findings"]}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root)

    def test_any_shell_command(self):
        f = self.found[".claude/skills/deploy/SKILL.md"]
        self.assertEqual((f["line"], f["severity"], f["confidence"]), (4, "major", "high"))
        self.assertIn("pre-approves any shell command (`Bash`)", f["message"])
        self.assertIn("during the turn that invokes this skill", f["message"])
        self.assertEqual(f["owasp"], ["CD-SEC-07", "ASI02", "ASI05"])

    def test_every_list_form(self):
        self.assertEqual(self.found[".agents/skills/report/SKILL.md"]["line"], 6)            # block list item
        self.assertIn("any command run through python3", self.found[".agents/skills/report/SKILL.md"]["message"])
        self.assertIn("(`Bash(*)`)", self.found["skills/flow/SKILL.md"]["message"])          # flow list
        ship = self.found[".claude/commands/ship.md"]                                        # comma-separated
        self.assertIn("invokes this command", ship["message"])

    def test_quiet_when_narrow_or_not_a_skill(self):
        for rel in (".claude/skills/narrow/SKILL.md", "skills/empty/SKILL.md", "skills/body/SKILL.md",
                    "notes/plan.md", ".github/prompts/release.prompt.md"):
            with self.subTest(rel=rel):
                self.assertNotIn(rel, self.found)

    def test_test_data_is_minor(self):
        f = self.found["tests/fixtures/hostile/SKILL.md"]
        self.assertEqual((f["severity"], f["confidence"]), ("minor", "low"))


class Entries(unittest.TestCase):
    def test_broad_entries(self):
        for entry, want in (("Bash", "any shell command"), ("Bash(*)", "any shell command"),
                            ("Bash(:*)", "any shell command"), ("Bash(sh -c *)", "any command run through sh"),
                            ("Bash(/usr/bin/env *)", "any command run through env"),
                            ("Bash(npx:*)", "any command run through npx"),
                            ("Bash(node*)", "any command run through node")):
            with self.subTest(entry=entry):
                self.assertEqual(C.broad_shell(entry), want)

    def test_narrow_entries(self):
        for entry in ("Read", "Bash(git:*)", "Bash(git status *)", "Bash(npm run test:*)", "Bash(curl:*)",
                      "Bash(python3 scripts/report.py *)", "Bash(python3)", "WebFetch"):
            with self.subTest(entry=entry):
                self.assertIsNone(C.broad_shell(entry))

    def test_tool_lists(self):
        self.assertEqual(C._tool_list("Read Edit Bash(git add *) Bash"), ["Read", "Edit", "Bash(git add *)", "Bash"])
        self.assertEqual(C._tool_list("Bash, Write, Read"), ["Bash", "Write", "Read"])
        self.assertEqual(C._tool_list("['Azure MCP/documentation', \"Bash(git status *)\"]"),
                         ["Azure MCP/documentation", "Bash(git status *)"])
        self.assertEqual(C._tool_list("[Azure MCP/documentation, Read]"), ["Azure MCP/documentation", "Read"])
        self.assertEqual(C._tool_list("[]"), [])

    def test_frontmatter_ends(self):
        lines = ["---", "name: x", "allowed-tools:", "  - Read", "description: y", "- Bash", "---", "allowed-tools: Bash"]
        self.assertEqual(C.allowed_tools(lines), [(4, "Read")])
        self.assertEqual(C.allowed_tools(["name: x", "allowed-tools: Bash"]), [])


if __name__ == "__main__":
    unittest.main()
