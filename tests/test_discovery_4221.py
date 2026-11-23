"""Discovery accounting on small, invented projects."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from _util import run_cli


HANDLER = "try:\n    answer = 1\nexcept:\n    raise\n"


class DiscoveryAccounting(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def write(self, rel, text):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def scan(self, *args, output="--json"):
        proc = run_cli("scan", ".", output, "--no-progress", *args, cwd=self.root)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout) if output == "--json" else proc.stdout

    def hits(self, report):
        return [(f["path"], f["line"]) for f in report["findings"]]

    @unittest.skipUnless(shutil.which("git"), "git unavailable")
    def test_ignored_files_are_read_in_both_modes(self):
        self.write(".gitignore", "*.py\n*.map\n")
        for path in ("sample.py", "src/inner.py", "vendor/other.py", "schema.map"):
            self.write(path, HANDLER)
        self.write("large.py", HANDLER * 10)
        args = ("--no-config", "--rule", "JH217", "--max-file-bytes", "100")
        plain = self.scan(*args)
        limited = self.scan(*args, "--max-files", "2")
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        repo = self.scan(*args)
        self.assertEqual(self.hits(repo), self.hits(plain))
        self.assertEqual(sorted(self.hits(repo)), [("sample.py", 3), ("src/inner.py", 3)])
        self.assertEqual(repo["summary"]["files"], plain["summary"]["files"])
        self.assertEqual(repo["set_aside"]["git_ignored_read"],
                         {"count": 2, "paths": ["sample.py", "src/inner.py"]})
        self.assertNotIn("git_ignored_read", plain["set_aside"])
        capped = self.scan(*args, "--max-files", "2")
        self.assertEqual(self.hits(capped), self.hits(limited))
        self.assertEqual(capped["set_aside"]["git_ignored_read"], {"count": 1, "paths": ["sample.py"]})
        section = self.scan(*args, output="--md").split("### Set aside in this run")[1].split("\n## ")[0]
        for word in ("2", "read", "untracked", "`src/inner.py`"):
            self.assertIn(word, section)

    @unittest.skipUnless(shutil.which("git"), "git unavailable")
    def test_ignored_samples_only_include_files_actually_read(self):
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        self.write(".gitignore", "*.txt\n")
        for index in range(23):
            self.write("note%02d.txt" % index, "hello\n")
        self.write("binary.txt", "\x00")
        self.write("tracked.txt", "hello\n")
        subprocess.run(["git", "-C", str(self.root), "add", "-f", "tracked.txt"], check=True)
        ignored = self.scan("--no-config")["set_aside"]["git_ignored_read"]
        self.assertEqual(ignored["count"], 23)
        self.assertEqual(ignored["paths"], ["note%02d.txt" % i for i in range(20)])

class GitIgnoredFindings(unittest.TestCase):
    """A key kept in a git-ignored .env is reported, but as minor and with the reason: it is not committed."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    @unittest.skipUnless(shutil.which("git"), "git unavailable")
    def test_findings_in_git_ignored_files_are_minor_and_say_why(self):
        key = "KEY=sk-proj-" + "Rk8vT2qWm9ZsLp4XbN7cQ3dF5gH1jK6mN0pR" + "\n"
        (self.root / ".gitignore").write_text(".env\n", encoding="utf-8")
        (self.root / ".env").write_text(key, encoding="utf-8")
        (self.root / "shipped.env").write_text(key, encoding="utf-8")
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        proc = run_cli("scan", ".", "--json", "--no-progress", "--rule", "JH101", cwd=self.root)
        doc = json.loads(proc.stdout)
        by_path = {f["path"]: f for f in doc["findings"]}
        self.assertEqual(by_path["shipped.env"]["severity"], "critical")
        self.assertEqual(by_path[".env"]["severity"], "minor")
        self.assertIn("not committed", by_path[".env"]["message"])
        held = json.loads(run_cli("scan", ".", "--json", "--no-progress", "--rule", "JH101", "--min-severity", "major",
                                  cwd=self.root).stdout)
        self.assertEqual([f["path"] for f in held["findings"]], ["shipped.env"])
        self.assertEqual(held["set_aside"]["below_floor"]["minor"], 1)
