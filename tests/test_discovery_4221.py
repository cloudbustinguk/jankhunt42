"""Discovery accounting on small, invented projects."""
import json
import os
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

    def test_excluded_files_are_counted_by_origin(self):
        self.write(".jankhunt42.json", json.dumps({"ignore": ["*.py", "missing-*"]}))
        for name in ("first.py", "src/second.py"):
            self.write(name, HANDLER)
        paths = ["first.py", "src/second.py"]
        sample = {"count": 2, "paths": paths}
        config_sample = dict(sample, source=str(self.root / ".jankhunt42.json"))
        args = ("--rule", "JH217")
        for mode in ("folder", "repository"):
            if mode == "repository":
                if not shutil.which("git"):
                    break
                subprocess.run(["git", "init", "-q", str(self.root)], check=True)
            with self.subTest(mode=mode):
                config = self.scan(*args)
                self.assertEqual(config["summary"]["files"], 1)
                self.assertEqual(config["set_aside"]["files_excluded"], {"config": config_sample})
                cli = self.scan(*args, "--no-config", "--exclude", "*.py", "--exclude", "first*")
                self.assertEqual(cli["set_aside"]["files_excluded"], {"--exclude": sample})
                both = self.scan(*args, "--exclude", "first*")["set_aside"]["files_excluded"]
                self.assertEqual(both["both"], dict(config_sample, count=1, paths=["first.py"]))
                self.assertEqual(both["config"], dict(config_sample, count=1, paths=["src/second.py"]))
                restored = self.scan(*args, "--no-config", "--exclude", "missing-*")
                self.assertNotIn("files_excluded", restored["set_aside"])
                self.assertEqual(self.hits(restored), [(p, 3) for p in paths])
                section = self.scan(*args, "--exclude", "first*", output="--md").split("### Set aside in this run")[1]
                for word in ("1 file", "`first.py`", "`src/second.py`", ".jankhunt42.json", "--exclude", "--no-config"):
                    self.assertIn(word, section)

    def test_excluded_samples_stop_at_twenty(self):
        for index in range(23):
            self.write("src/page%02d.txt" % index, "ink\n")
        self.write("vendor/page00.txt", "ink\n")
        info = self.scan("--no-config", "--exclude", "*.txt")["set_aside"]["files_excluded"]["--exclude"]
        self.assertEqual(info, {"count": 23, "paths": ["src/page%02d.txt" % i for i in range(20)]})

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


class UnreadFilesMakeCoveragePartial(unittest.TestCase):
    """A supported file over the size limit is considered, named, and makes the map partial; the passport's
    coverage floor then holds the release (insufficient evidence) instead of passing."""

    def test_size_limit_on_a_supported_file(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        (root / "a.py").write_text("x = 1\n", encoding="utf-8")
        (root / "b.py").write_text("long_value = 1234567890\n", encoding="utf-8")
        (root / "logo.png").write_bytes(b"\x89PNG" + b"\x00" * 64)
        cov = json.loads(run_cli("map", str(root), "--max-file-bytes", "20", "--json").stdout)["coverage"]
        self.assertEqual((cov["files_considered"], cov["files_read"]), (3, 1))
        self.assertEqual(cov["status"], "partial")
        self.assertTrue(any("b.py" in r for r in cov["partial_reasons"]))
        self.assertFalse(any("logo.png" in r for r in cov["partial_reasons"]))   # not a type the map reads
        doc = json.loads(run_cli("passport", str(root), "--max-file-bytes", "20", "--json").stdout)
        cov_rule = [r for r in doc["assessment"]["decision"]["rules"] if r["rule"] == "P-COV-001"][0]
        self.assertEqual(cov_rule["outcome"], "insufficient-evidence")
        self.assertIn("b.py", cov_rule["message"])


class FilesNotReadAreCounted(unittest.TestCase):
    """An unreadable file or folder, a binary file and an empty file are each counted with the reason; text in
    UTF-16 with a byte-order mark is read like its UTF-8 copy."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.addCleanup(lambda: [os.chmod(p, 0o755) for p in self.root.rglob("*")])

    def scan(self, rel):
        return json.loads(run_cli("scan", str(self.root / rel), "--json", "--no-progress", "--min-severity", "info").stdout)

    def test_reasons(self):
        for rel, data in (("binary/a.bin", b"a\x00b"), ("empty/empty.py", b""),
                          ("utf8/leaf.py", "value = 1  # noqa\n".encode("utf-8")),
                          ("utf16/leaf.py", "value = 1  # noqa\n".encode("utf-16"))):
            (self.root / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.root / rel).write_bytes(data)
        self.assertEqual(self.scan("binary")["set_aside"]["files_not_read"]["binary"]["paths"], ["a.bin"])
        self.assertEqual(self.scan("empty")["set_aside"]["files_not_read"]["empty"]["paths"], ["empty.py"])
        utf8, utf16 = self.scan("utf8"), self.scan("utf16")
        self.assertEqual(utf16["summary"]["files"], 1)
        self.assertEqual([(f["rule"], f["line"]) for f in utf16["findings"]], [(f["rule"], f["line"]) for f in utf8["findings"]])

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root reads every file")
    def test_unreadable_file_and_folder(self):
        (self.root / "u").mkdir()
        (self.root / "u" / "leaf.py").write_text("x = 1\n", encoding="utf-8")
        os.chmod(self.root / "u" / "leaf.py", 0)
        (self.root / "d" / "closed").mkdir(parents=True)
        (self.root / "d" / "closed" / "f.py").write_text("x = 1\n", encoding="utf-8")
        os.chmod(self.root / "d" / "closed", 0)
        self.assertEqual(self.scan("u")["set_aside"]["files_not_read"]["unreadable"]["paths"], ["leaf.py"])
        self.assertEqual(self.scan("d")["set_aside"]["folders_not_read"]["unreadable"]["paths"], ["closed"])


class EvidenceUsesTheSharedFolderRule(unittest.TestCase):
    def test_a_bill_of_materials_in_a_hidden_folder_counts_and_one_in_a_virtualenv_does_not(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        top = Path(temp.name)
        bom = '{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[{"type":"library","name":"chalk","version":"1"}]}\n'
        policy = top / "needed.json"
        policy.write_text('{"require":{"sbom":true}}\n', encoding="utf-8")
        for name, folder, venv in (("hidden", ".records", False), ("virtual", "env", True)):
            (top / name / folder).mkdir(parents=True)
            (top / name / "sheet.py").write_text("hue = 4\n", encoding="utf-8")
            (top / name / folder / "bom.json").write_text(bom, encoding="utf-8")
            if venv:
                (top / name / folder / "pyvenv.cfg").write_text("version = 3.11\n", encoding="utf-8")
        results = {}
        for name in ("hidden", "virtual"):
            doc = json.loads(run_cli("passport", str(top / name), "--no-config", "--policy", str(policy), "--json").stdout)
            results[name] = [r["outcome"] for r in doc["assessment"]["decision"]["rules"] if r["rule"] == "P-EVD-001"][0]
        self.assertEqual(results, {"hidden": "pass", "virtual": "insufficient-evidence"})

