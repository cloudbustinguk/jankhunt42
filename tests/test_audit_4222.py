"""Fixes for findings an audit of 4.22.0 left open for 4.22.2 (invented projects only)."""
import json
import os
import tempfile
import unittest
from pathlib import Path

from _util import run_cli

BARE = "try:\n    value = 1\nexcept:\n    raise\n"


def project(test, files):
    temp = tempfile.TemporaryDirectory()
    test.addCleanup(temp.cleanup)
    root = Path(temp.name)
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8")
    return root


def scan(*args, cwd=None):
    return json.loads(run_cli("scan", *args, "--json", "--no-progress", cwd=cwd).stdout)


class ConfigOfANamedFile(unittest.TestCase):
    def test_the_callers_config_never_governs_a_file_elsewhere(self):
        root = project(self, {"caller/.jankhunt42.json": '{"rules": {"JH217": false}}\n', "target/sample.py": BARE})
        caller = str(root / "caller")
        by_file = scan("../target/sample.py", cwd=caller)
        by_folder = scan("../target", cwd=caller)
        self.assertEqual(by_file["summary"]["counts"], {"major": 1})
        self.assertEqual(by_file["summary"]["counts"], by_folder["summary"]["counts"])

    def test_the_files_own_config_still_applies(self):
        root = project(self, {"target/.jankhunt42.json": '{"rules": {"JH217": false}}\n', "target/sample.py": BARE})
        self.assertEqual(scan(str(root / "target" / "sample.py"))["summary"]["counts"], {})


class UnparsedFilesAreReported(unittest.TestCase):
    def test_a_malformed_config_is_named_and_a_valid_empty_one_is_not(self):
        bad = project(self, {".mcp.json": '{"mcpServers": {\n'})
        good = project(self, {".mcp.json": "{}\n"})
        self.assertEqual(scan(str(bad), "--min-severity", "info")["set_aside"]["files_not_parsed"]["paths"], [".mcp.json"])
        self.assertNotIn("files_not_parsed", scan(str(good), "--min-severity", "info")["set_aside"])


@unittest.skipUnless(__import__("shutil").which("git"), "git unavailable")
class RepositoryBoundariesAndAliases(unittest.TestCase):
    def git(self, root, *args):
        __import__("subprocess").run(["git", "-C", str(root), *args], check=True, capture_output=True)

    def test_a_submodule_or_nested_repository_is_listed(self):
        for shape in ("gitlink", "nested"):
            with self.subTest(shape=shape):
                root = project(self, {"outer.txt": "hello\n", "child/leaf.py": BARE})
                self.git(root, "init", "-q")
                if shape == "gitlink":
                    self.git(root, "update-index", "--add", "--cacheinfo",
                             "160000,1111111111111111111111111111111111111111,child")
                else:
                    self.git(root / "child", "init", "-q")
                doc = scan(str(root), "--min-severity", "info")
                self.assertEqual(doc["set_aside"]["folders_not_read"]["nested repository"]["paths"], ["child"])

    @unittest.skipIf(os.name == "nt", "symbolic links")
    def test_an_alias_never_displaces_the_real_source(self):
        for alias in ("a.txt", "zz.txt"):                     # sorting before and after the source
            with self.subTest(alias=alias):
                root = project(self, {"m.py": BARE})
                os.symlink("m.py", str(root / alias))
                self.git(root, "init", "-q")
                self.assertEqual([f["rule"] for f in scan(str(root))["findings"]], ["JH217"])


class DebugLeftoversAndDirectives(unittest.TestCase):
    def test_the_cap_switch_reveals_every_debug_call_and_each_call_on_a_line_counts(self):
        root = project(self, {"six/sample.py": "breakpoint()\n" * 6, "one/sample.py": "breakpoint(); breakpoint()\n"})
        held = scan(str(root / "six"), "--rule", "JH204", "--max-per-file-rule", "3", "--max-per-rule", "6")
        self.assertEqual((held["summary"]["findings"], held["set_aside"]["capped"]), (3, 3))
        shown = scan(str(root / "six"), "--rule", "JH204", "--max-per-file-rule", "6", "--max-per-rule", "6")
        self.assertEqual([f["line"] for f in shown["findings"]], [1, 2, 3, 4, 5, 6])
        compact = scan(str(root / "one"), "--rule", "JH204")
        self.assertEqual([(f["line"], f["column"]) for f in compact["findings"]], [(1, 1), (1, 15)])

    def test_a_quoted_directive_is_text_and_a_comment_is_a_directive(self):
        root = project(self, {"q/sample.py": 'note = "Example: jankhunt42: ignore JH204"\nbreakpoint()\n',
                              "c/sample.py": "# jankhunt42: ignore JH204\nbreakpoint()\n",
                              "j/settings.json": '{\n  "a": "jankhunt42: ignore JH306"\n}\n'})
        quoted = scan(str(root / "q"))
        self.assertEqual([(f["rule"], f["line"]) for f in quoted["findings"]], [("JH204", 2)])
        self.assertNotIn("inline_ignore", quoted["set_aside"])
        comment = scan(str(root / "c"))
        self.assertEqual((comment["findings"], comment["set_aside"].get("inline_ignore")), ([], 1))


if __name__ == "__main__":
    unittest.main()
