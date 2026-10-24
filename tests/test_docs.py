"""Documentation is executable: README samples are generated from the
synthetic fixture, and every jankhunt42 command shown in README.md and
SKILL.md runs against the real CLI (or is skipped for a stated reason)."""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

import _util

UPDATE = os.environ.get("JH_UPDATE_SNAPSHOTS") == "1"
SAMPLE_RE = re.compile(r"(<!-- sample:([\w.-]+) -->\n)(.*?)(<!-- /sample -->)", re.S)
# Commands documented but not executed here, and why.
SKIP = [
    ("--cve", "contacts OSV.dev; the suite is offline"),
    ("--pr", "needs the GitHub CLI and a checked-out pull request"),
    ("selftest", "selftest runs this suite; executing it here would recurse"),
    ("--online", "lets --verify fetch from GitHub; the suite is offline"),
]
GIT_ENV = {"GIT_AUTHOR_NAME": "fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
           "GIT_COMMITTER_NAME": "fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
           "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}


def read(name):
    with open(os.path.join(_util.ROOT, name), encoding="utf-8") as fh:
        return fh.read()


def commands(text):
    """Yield documented jankhunt42 command lines from ```sh blocks."""
    out = []
    for block in re.findall(r"```sh\n(.*?)```", text, re.S):
        block = block.replace("\\\n", " ")
        for line in block.splitlines():
            line = line.strip()
            if line.startswith('python3 "$SKILL_DIR/scripts/jankhunt42"'):
                line = "jankhunt42" + line[len('python3 "$SKILL_DIR/scripts/jankhunt42"'):]
            if line.startswith("jankhunt42 "):
                out.append(re.sub(r"\s+#.*$", "", line))
    return out


class Samples(unittest.TestCase):
    def test_readme_samples_match_generated_snapshots(self):
        text = read("README.md")
        found = SAMPLE_RE.findall(text)
        self.assertEqual({f[1] for f in found}, {"map-100", "passport-100"})

        def body(name):
            with open(os.path.join(_util.HERE, "snapshots", name + ".txt"), encoding="utf-8") as fh:
                return "```text\n" + fh.read().rstrip("\n") + "\n```\n"

        if UPDATE:
            new = SAMPLE_RE.sub(lambda m: m.group(1) + body(m.group(2)) + m.group(4), text)
            with open(os.path.join(_util.ROOT, "README.md"), "w", encoding="utf-8") as fh:
                fh.write(new)
            text = new
        for _, name, content, _ in SAMPLE_RE.findall(text):
            self.assertEqual(content, body(name), "README sample %s is stale (JH_UPDATE_SNAPSHOTS=1)" % name)


@unittest.skipUnless(shutil.which("bash") and shutil.which("git"), "needs bash and git")
class DocumentedCommands(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="jh-docs-")
        cls.repo = os.path.join(cls.tmp, "repo")
        shutil.copytree(os.path.join(_util.FIXTURES, "demo-app"), cls.repo)
        env = dict(os.environ, **GIT_ENV)
        run = lambda *a: subprocess.run(["git", "-C", cls.repo] + list(a), check=True, capture_output=True,
                                        env=env, timeout=60)
        run("init", "-q", "-b", "main")
        run("add", "-A")
        run("commit", "-q", "-m", "base")
        with open(os.path.join(cls.repo, "app", "audit.py"), "w") as fh:
            fh.write('import requests\nrequests.post("https://audit.example.com/v1/events")\n')
        run("add", "-A")
        run("commit", "-q", "-m", "head")
        run("update-ref", "refs/remotes/origin/main", "HEAD~1")
        with open(os.path.join(cls.repo, "app.log"), "w") as fh:
            fh.write("2026-01-01T00:00:00Z ERROR timeout talking to db id=42\n" * 3)
        shutil.copy(os.path.join(_util.ROOT, "templates", "panel-finding.json"), os.path.join(cls.repo, "panel-1.json"))
        with open(os.path.join(cls.repo, "apptrust-evidence.json"), "w") as fh:
            json.dump({"evidence": []}, fh)
        with open(os.path.join(cls.tmp, "inventory.json"), "w") as fh:
            json.dump({"schema_version": "jankhunt.inventory.v1", "assets": [{"match": "ledger-db", "environment": "production"}]}, fh)
        with open(os.path.join(cls.tmp, "scenario.json"), "w") as fh:
            json.dump({"name": "docs", "mutations": [{"op": "block-egress"}]}, fh)
        env2 = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        for name, cmd in (("stored-map.json", "map"), ("old-passport.json", "passport")):
            out = subprocess.run([sys.executable, _util.CLI, cmd, cls.repo, "--json"], capture_output=True, text=True,
                                 env=env2, timeout=300).stdout
            for where in (cls.tmp, cls.repo):
                with open(os.path.join(where, name), "w") as fh:
                    fh.write(out)
        with open(os.path.join(cls.tmp, "acceptance.json"), "w") as fh:
            json.dump({"accepted_by": "docs", "accepted_at": "2026-10-01T00:00:00Z", "decision_accepted": "review"}, fh)
        with open(os.path.join(cls.repo, "scenario.json"), "w") as fh:
            json.dump({"name": "docs", "mutations": [{"op": "revoke", "source": "repo", "target": "ledger"}]}, fh)
        with open(os.path.join(cls.tmp, "verify-plan.json"), "w") as fh:
            json.dump({"schema_version": "jankhunt.verify.v1", "identity": {"repo": "example-org/demo-app"},
                       "subjects": [{"path": "repo/dist/demo-app.tar.gz"}],
                       "tools": {"gh": "./no-such-gh"}}, fh)
        with open(os.path.join(cls.tmp, "policy.json"), "w") as fh:
            json.dump({"schema_version": "jankhunt.policy.v1", "require": {"owner": True}}, fh)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def run_doc(self, source):
        ran, skipped = 0, []
        for cmd in commands(read(source)):
            reason = next((why for token, why in SKIP if re.search(r"(^|\s)%s(\s|$)" % re.escape(token), cmd)), None)
            if reason:
                skipped.append((cmd, reason))
                continue
            cmd = cmd.replace("<ref>", "HEAD~1").replace("<relevant paths>", ".").replace(
                "tests/fixtures/demo-app", ".")
            script = 'jankhunt42() { "%s" "%s" "$@"; }\n%s\n' % (sys.executable, _util.CLI, cmd)
            env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", SKILL_DIR=_util.ROOT, **GIT_ENV)
            proc = subprocess.run(["bash", "-c", script], cwd=self.repo, capture_output=True, text=True,
                                  env=env, timeout=300)
            self.assertIn(proc.returncode, (0, 1), "%s: documented command failed (%d): %s"
                          % (source, proc.returncode, proc.stderr[-400:]))
            self.assertNotIn("Traceback", proc.stderr, cmd)
            ran += 1
        return ran, skipped

    def test_readme_commands_execute(self):
        ran, skipped = self.run_doc("README.md")
        self.assertGreater(ran, 30)
        self.assertTrue(all(r for _, r in skipped))

    def test_skill_commands_execute(self):
        ran, _ = self.run_doc("SKILL.md")
        self.assertGreater(ran, 15)


class SkillContract(unittest.TestCase):
    def test_frontmatter_and_size(self):
        text = read("SKILL.md")
        self.assertLess(len(text.splitlines()), 500)
        front = text.split("---", 2)[1]
        for key in ("name: jankhunt42", "description:", "license: MIT", "compatibility:", 'version: "'):
            self.assertIn(key, front)
        for trigger in ("passport", "blast radius", "data exposure", "connectivity", "deep hunt"):
            self.assertIn(trigger, text.lower())
        self.assertIn("Permission gate", text)

    def test_every_referenced_file_exists(self):
        for name in ("SKILL.md", "README.md"):
            for ref in set(re.findall(r"(references/[\w.-]+\.md|templates/[\w.-]+\.(?:md|json))", read(name))):
                self.assertTrue(os.path.exists(os.path.join(_util.ROOT, ref)), "%s -> %s" % (name, ref))

    def test_versions_agree(self):
        import jh_core
        self.assertIn('version: "%s"' % jh_core.VERSION, read("SKILL.md"))
        self.assertIn("**Version:** %s" % jh_core.VERSION, read("README.md"))
        self.assertIn("## [%s]" % jh_core.VERSION, read("CHANGELOG.md"))

    def test_lowercase_product_name_everywhere(self):
        bad = "Jank" + "Hunt"
        for base, dirs, files in os.walk(_util.ROOT):
            dirs[:] = [d for d in dirs if d not in (".git", "docs", "__pycache__")]
            for f in files:
                if f.endswith((".png", ".jpg")):
                    continue
                with open(os.path.join(base, f), encoding="utf-8", errors="replace") as fh:
                    self.assertNotIn(bad, fh.read(), os.path.join(base, f))


if __name__ == "__main__":
    unittest.main()
