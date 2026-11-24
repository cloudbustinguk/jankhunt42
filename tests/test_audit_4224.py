"""4.22.4: regressions the third audit pass found in the released 4.22.2/4.22.3 code, each with its own case."""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from _util import run_cli

GIT = shutil.which("git")


def scan(*args):
    return json.loads(run_cli("scan", *args, "--json", "--no-progress").stdout)


def git(repo, *args):
    subprocess.run(["git", "-C", repo, "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid"] + list(args),
                   check=True, capture_output=True)


class Base(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="jh-4224-")
        self.addCleanup(shutil.rmtree, self.root, True)

    def path(self, *parts):
        p = os.path.join(self.root, *parts)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        return p


class PhpTemplateText(Base):
    def test_text_after_a_closing_tag_is_not_code(self):
        Path(self.path("card.php")).write_text("<?php // end ?> Manual: var_dump($shade) displays a value.\n")
        Path(self.path("two.php")).write_text("<?php\n$a = 1; ?>\n<p>var_dump($x) shows</p>\n<?php var_dump($a); ?>\n")
        d = scan(self.root, "--no-config", "--rule", "JH204")
        self.assertEqual([(f["path"], f["line"]) for f in d["findings"]], [("two.php", 4)])


class EveryDeclaration(Base):
    def test_eleven_sse_servers_give_eleven_findings(self):
        servers = {"color%02d" % i: {"type": "sse", "url": "https://color%02d.invalid/events" % i} for i in range(1, 12)}
        Path(self.path(".mcp.json")).write_text(json.dumps({"mcpServers": servers}, indent=2) + "\n")
        d = scan(self.root, "--no-config", "--rule", "JH715")
        self.assertEqual(len(d["findings"]), 11)
        self.assertNotIn("capped", d["set_aside"])


class FileWideIgnorePastTheBound(Base):
    def test_a_file_wide_ignore_covers_calls_past_the_safety_bound(self):
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))
        import jh_checks
        n = jh_checks.DEBUG_BOUND + 1
        Path(self.path("card.py")).write_text("# jankhunt42: ignore-file JH204\n" + "breakpoint()\n" * n)
        proc = run_cli("scan", self.root, "--no-config", "--rule", "JH204", "--fail-on", "minor", "--json", "--no-progress")
        d = json.loads(proc.stdout)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(d["summary"]["findings"], 0)
        self.assertEqual(d["set_aside"].get("inline_ignore"), n)
        self.assertNotIn("capped", d["set_aside"])


@unittest.skipUnless(GIT, "git unavailable")
class ReviewScoreReadsEveryChangedLine(Base):
    def test_review_score_counts_all_changed_line_findings(self):
        subprocess.run(["git", "init", "-q", self.root], check=True)
        Path(self.path("draft.py")).write_text("# noqa\n" * 9)
        d = json.loads(run_cli("review", self.root, "--rule", "JH306", "--min-severity", "info", "--json").stdout)
        jank = d["summary"]["jank"]
        self.assertEqual((d["summary"]["findings"], jank["counted_findings"]), (9, 9))
        s = scan(self.root, "--rule", "JH306", "--min-severity", "info")
        self.assertEqual(s["summary"]["jank"]["counted_findings"], 5)      # a scan's score keeps its budget


@unittest.skipIf(os.name == "nt", "backslashes in file names")
class EscapedNames(Base):
    def test_a_rule_file_pattern_matches_the_name_on_disk(self):
        Path(self.path("tile-\\xFF.md")).write_text("pencil\n")
        rules = {"schema_version": "jankhunt.ruleset.v1", "name": "Paper", "rules": [{
            "id": "PAPER01", "title": "Draft note", "message": "Review the note.", "severity": "minor",
            "patterns": ["pencil"], "files": ["tile-\\xFF.md"], "target": "raw", "examples": {"match": ["pencil"]}}]}
        rs = os.path.join(tempfile.mkdtemp(prefix="jh-4224-rs-"), "r.json")
        self.addCleanup(shutil.rmtree, os.path.dirname(rs), True)
        Path(rs).write_text(json.dumps(rules))
        d = scan(self.root, "--no-config", "--ruleset", rs, "--rule", "PAPER01")
        self.assertEqual(len(d["findings"]), 1)

    @unittest.skipUnless(GIT, "git unavailable")
    def test_a_historical_map_applies_a_subfolder_exclusion_under_an_escaped_parent(self):
        sub = os.path.join(self.root, "p-\\xFF")
        Path(self.path("p-\\xFF", "part", "card.py")).write_text("v=1\n")
        subprocess.run(["git", "init", "-q", self.root], check=True)
        git(self.root, "commit", "-q", "--allow-empty", "-m", "one")
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "two")
        for rev in ((), ("--base", "HEAD^")):
            with self.subTest(rev=rev):
                cov = json.loads(run_cli("map", sub, *rev, "--exclude", "part/*.py", "--json").stdout)["coverage"]
                self.assertEqual(cov["inspected_paths"], [])
                self.assertEqual(len(cov["skipped_paths"]), 1)


@unittest.skipIf(os.name == "nt", "symbolic links")
class LinkedFiles(Base):
    def test_an_excluded_target_leaves_its_allowed_link_representing_the_file(self):
        Path(self.path("z.py")).write_text("# noqa\n")
        os.symlink("z.py", self.path("a.py"))
        d = scan(self.root, "--exclude", "z.py", "--min-severity", "info", "--rule", "JH306")
        self.assertEqual([f["path"] for f in d["findings"]], ["a.py"])
        self.assertEqual(d["set_aside"]["files_excluded"]["--exclude"]["paths"], ["z.py"])

    @unittest.skipUnless(GIT, "git unavailable")
    def test_a_git_ignored_link_is_rated_the_same_in_either_order(self):
        for target in ("0.txt", "z.txt"):
            with self.subTest(target=target):
                repo = os.path.join(self.root, target.replace(".", "-"))
                os.makedirs(repo)
                Path(repo, target).write_text("try:\n    n = 1\nexcept:\n    raise\n")
                os.symlink(target, os.path.join(repo, "m.py"))
                Path(repo, ".gitignore").write_text("m.py\n")
                subprocess.run(["git", "init", "-q", repo], check=True)
                git(repo, "add", ".gitignore", target)
                d = scan(repo, "--rule", "JH217")
                self.assertEqual([(f["path"], f["severity"]) for f in d["findings"]], [("m.py", "minor")])
                self.assertEqual(d["set_aside"]["git_ignored_read"]["paths"], ["m.py"])


if __name__ == "__main__":
    unittest.main()
