"""Review correctness on small invented repositories (from an audit of 4.22.0)."""
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from _util import run_cli


def git(root, *args):
    subprocess.run(["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
                   check=True, capture_output=True)


@unittest.skipUnless(shutil.which("git"), "git unavailable")
class BeforeTheFirstCommit(unittest.TestCase):
    def test_working_review_reads_edits_made_after_staging(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        git(root, "init", "-q")
        (root / "page.py").write_text("answer = 1\n", encoding="utf-8")
        git(root, "add", "--", "page.py")
        with open(root / "page.py", "a", encoding="utf-8") as fh:
            fh.write("# noqa\n")
        working = run_cli("review", ".", "--min-severity", "info", "--fail-on", "info", "--json", cwd=str(root))
        doc = json.loads(working.stdout)
        self.assertEqual([(f["rule"], f["line"]) for f in doc["findings"]], [("JH306", 2)])
        self.assertEqual(doc["review"]["gate"]["result"], "fail")
        self.assertNotEqual(working.returncode, 0)
        staged = json.loads(run_cli("review", ".", "--staged", "--min-severity", "info", "--json", cwd=str(root)).stdout)
        self.assertEqual(staged["findings"], [])           # the staged copy has only line 1


@unittest.skipUnless(shutil.which("git"), "git unavailable")
class CapsAfterClassification(unittest.TestCase):
    def test_an_unchanged_finding_never_takes_the_slot_of_a_new_one(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        git(root, "init", "-q")
        (root / "app.py").write_text("# noqa\n" + "".join("v%d = %d\n" % (i, i) for i in range(1, 9)), encoding="utf-8")
        git(root, "add", "-A")
        git(root, "commit", "-qm", "base")
        with open(root / "app.py", "a", encoding="utf-8") as fh:
            fh.write("# noqa\n")
        git(root, "commit", "-qam", "add")
        proc = run_cli("review", ".", "--base", "HEAD~1", "--min-severity", "info", "--rule", "JH306", "--fail-on", "info",
                       "--max-per-file-rule", "1", "--json", cwd=str(root))
        doc = json.loads(proc.stdout)
        self.assertEqual([(f["path"], f["line"]) for f in doc["findings"]], [("app.py", 10)])
        self.assertEqual(doc["review"]["gate"]["result"], "fail")
        self.assertEqual(doc["summary"]["capped_findings"], 1)        # the unchanged one, counted


@unittest.skipUnless(shutil.which("git"), "git unavailable")
class RelativePathsAndBaselines(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.top = Path(temp.name)

    def test_a_repository_named_from_its_parent_folder_is_reviewed(self):
        repo = self.top / "one"
        repo.mkdir()
        (repo / "note.py").write_text("# noqa\n", encoding="utf-8")
        git(repo, "init", "-q")
        for cwd, arg in ((self.top, "one"), (repo, "."), (self.top, str(repo))):
            with self.subTest(arg=arg):
                doc = json.loads(run_cli("review", arg, "--min-severity", "info", "--fail-on", "info", "--json",
                                         cwd=str(cwd)).stdout)
                self.assertEqual(doc["summary"]["files_reviewed"], 1)
                self.assertEqual(doc["review"]["gate"]["result"], "fail")

    def test_a_second_copy_on_a_new_line_is_new_despite_the_baseline(self):
        repo = self.top / "r"
        repo.mkdir()
        git(repo, "init", "-q")
        body = "# noqa\n" + "".join("v%d = %d\n" % (i, i) for i in range(1, 9))
        (repo / "app.py").write_text(body, encoding="utf-8")
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "base")
        base = self.top / "base"
        base.mkdir()
        (base / "app.py").write_text(body, encoding="utf-8")
        baseline = self.top / "base.json"
        baseline.write_text(run_cli("scan", str(base), "--no-config", "--min-severity", "info", "--rule", "JH306",
                                    "--json").stdout, encoding="utf-8")
        with open(repo / "app.py", "a", encoding="utf-8") as fh:
            fh.write("# noqa\n")
        git(repo, "commit", "-qam", "add")
        doc = json.loads(run_cli("review", ".", "--base", "HEAD~1", "--rule", "JH306", "--min-severity", "info",
                                 "--fail-on", "info", "--baseline", str(baseline), "--json", cwd=str(repo)).stdout)
        self.assertEqual([(f["line"], f["scope"]) for f in doc["findings"]], [(10, "new")])
        self.assertEqual(doc["review"]["gate"]["result"], "fail")


if __name__ == "__main__":
    unittest.main()
