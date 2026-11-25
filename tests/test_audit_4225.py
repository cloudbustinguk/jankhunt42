"""4.22.5: a link whose target cannot be read never stops a scan (found by the full-corpus run, 1 of 17,529)."""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import json
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

from _util import run_cli

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))
import jh_core  # noqa: E402


@unittest.skipIf(os.name == "nt", "symbolic links")
@unittest.skipUnless(shutil.which("git"), "git unavailable")
class UnreadableLinkTarget(unittest.TestCase):
    """Python 3.9-3.13 raise PermissionError from is_dir() on such a link; 3.14 returns False. The test makes the
    check raise on every version, as a committed link into /root does inside a container."""

    def test_a_committed_link_into_an_unreadable_folder_is_skipped_not_fatal(self):
        root = tempfile.mkdtemp(prefix="jh-4225-")
        self.addCleanup(shutil.rmtree, root, True)
        repo = os.path.join(root, "repo")
        os.makedirs(repo)
        Path(repo, "app.py").write_text("x = 1\n")
        os.symlink("/root/.pub-cache/hosted/plugin-1.0/", os.path.join(repo, "plugin"))
        os.makedirs(os.path.join(repo, "shared"))
        Path(repo, "shared", "lib.py").write_text("y = 2\n")
        os.symlink("shared/lib.py", os.path.join(repo, "inner"))     # inside the folder: reaches the file check
        subprocess.run(["git", "init", "-q", repo], check=True)
        subprocess.run(["git", "-C", repo, "add", "-A"], check=True)
        real_is_dir, real_is_file = pathlib.Path.is_dir, pathlib.Path.is_file

        def raising(real):
            def check(self, *args, **kwargs):
                if self.name in ("plugin", "inner"):
                    raise PermissionError(13, "Permission denied", str(self))
                return real(self, *args, **kwargs)
            return check

        with mock.patch.object(pathlib.Path, "is_dir", raising(real_is_dir)), \
                mock.patch.object(pathlib.Path, "is_file", raising(real_is_file)):
            found = jh_core.discover_files([repo])
        _, files = found                          # (root, files)
        names = sorted(p.name for p in files)
        self.assertIn("app.py", names)
        self.assertIn("lib.py", names)
        self.assertNotIn("plugin", names)
        self.assertNotIn("inner", names)


GIT = shutil.which("git")


def scan(*args):
    return json.loads(run_cli("scan", *args, "--json", "--no-progress").stdout)


def git(repo, *args):
    subprocess.run(["git", "-C", repo, "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid"] + list(args),
                   check=True, capture_output=True)


class Base(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="jh-4225b-")
        self.addCleanup(shutil.rmtree, self.root, True)

    def path(self, *parts):
        p = os.path.join(self.root, *parts)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        return p

    def repo(self, name):
        r = os.path.join(self.root, name)
        os.makedirs(r, exist_ok=True)
        subprocess.run(["git", "init", "-q", r], check=True)
        return r


@unittest.skipIf(os.name == "nt", "backslashes in file names")
class NamesOnDisk(Base):
    """Patterns, ratings, exclusions and links use the name on disk; reports show the escaped form."""

    def test_an_exact_file_pattern_does_not_match_its_neighbour(self):          # B67
        Path(self.path("tile\\\\xFF.md")).write_text("paper\n")
        Path(self.path("tile\\xFF.md")).write_text("pencil\n")
        rs = self.path("..", os.path.basename(self.root) + "-rules.json")
        self.addCleanup(lambda: os.path.exists(rs) and os.remove(rs))
        Path(rs).write_text(json.dumps({"schema_version": "jankhunt.ruleset.v1", "name": "P", "rules": [{
            "id": "PAPER01", "title": "t", "message": "m", "severity": "minor", "patterns": ["pencil"],
            "files": ["tile\\\\xFF.md"], "target": "raw", "examples": {"match": ["pencil"]}}]}))
        self.assertEqual(scan(self.root, "--no-config", "--ruleset", rs, "--rule", "PAPER01")["findings"], [])

    def test_a_pattern_on_the_file_name_matches_a_nested_escaped_name(self):     # W3-113 (basename on disk)
        Path(self.path("sub", "tile-\\xFF.md")).write_text("pencil\n")
        rs = self.path("..", os.path.basename(self.root) + "-rules2.json")
        self.addCleanup(lambda: os.path.exists(rs) and os.remove(rs))
        Path(rs).write_text(json.dumps({"schema_version": "jankhunt.ruleset.v1", "name": "P", "rules": [{
            "id": "PAPER02", "title": "t", "message": "m", "severity": "minor", "patterns": ["pencil"],
            "files": ["tile-\\xFF.md"], "target": "raw", "examples": {"match": ["pencil"]}}]}))
        self.assertEqual(len(scan(self.root, "--no-config", "--ruleset", rs, "--rule", "PAPER02")["findings"]), 1)

    def test_a_config_path_rating_applies_to_an_escaped_name(self):             # B74
        Path(self.path("card-\\xFF.py")).write_text("# noqa\n")
        Path(self.path(".jankhunt42.json")).write_text(json.dumps({"paths": {"card-\\xFF.py": {"severity": {"JH306": "major"}}}}))
        proc = run_cli("scan", self.root, "--rule", "JH306", "--fail-on", "major", "--json", "--no-progress")
        self.assertEqual([f["severity"] for f in json.loads(proc.stdout)["findings"]], ["major"])
        self.assertEqual(proc.returncode, 1)

    def test_the_passport_honours_the_project_ignore_list_for_an_escaped_name(self):   # B86
        Path(self.path("card-\\xFF.py")).write_text("breakpoint()\n")
        Path(self.path(".jankhunt42.json")).write_text(json.dumps({"ignore": ["card-\\xFF.py"]}))
        pp = json.loads(run_cli("passport", self.root, "--json").stdout)
        self.assertEqual(pp["assessment"]["jank"]["score"], 0)
        self.assertEqual(pp["assessment"]["jank"]["findings"], 0)

    def test_sarif_links_decode_to_the_file_on_disk(self):                       # B77
        Path(self.path("tile-\\xFF.py")).write_text("breakpoint()\n")
        sarif = json.loads(run_cli("scan", self.root, "--no-config", "--rule", "JH204", "--sarif", "--no-progress").stdout)
        uris = [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in sarif["runs"][0]["results"]]
        self.assertEqual(len(uris), 1)
        self.assertTrue(os.path.isfile(os.path.join(self.root, urllib.parse.unquote(uris[0]))), uris)

    @unittest.skipUnless(GIT, "git unavailable")
    def test_a_historical_exclusion_removes_only_the_named_file(self):           # B75
        r = self.repo("map")
        git(r, "commit", "-q", "--allow-empty", "-m", "one")
        Path(r, "part").mkdir()
        Path(r, "part", "tile-\\xFF.py").write_text("v=1\n")
        Path(r, "part", "tile-\\\\xFF.py").write_text("v=2\n")
        git(r, "add", "-A")
        git(r, "commit", "-q", "-m", "two")
        for rev in ((), ("--base", "HEAD^")):
            with self.subTest(rev=rev):
                cov = json.loads(run_cli("map", os.path.join(r, "part"), *rev, "--exclude", "tile-\\\\xFF.py", "--json").stdout)["coverage"]
                self.assertEqual((cov["files_inspected"], len(cov["skipped_paths"])), (1, 1))

    @unittest.skipIf(sys.platform == "darwin", "file names that are not UTF-8")
    def test_a_byte_in_the_root_still_gives_json_and_a_summary(self):          # B85
        d = os.path.join(self.root.encode(), b"studio-\xff")
        os.makedirs(d)
        with open(os.path.join(d, b"leaf.py"), "w") as fh:
            fh.write("breakpoint()\n")
        out = os.path.join(self.root, "last.json")
        proc = run_cli("scan", os.fsdecode(d), "--rule", "JH204", "--summary", "--out", out, "--no-progress")
        self.assertEqual(proc.returncode, 0, proc.stderr[-300:])
        self.assertIn("summary:", proc.stdout)
        self.assertTrue(json.load(open(out, encoding="utf-8"))["root"].endswith("studio-\\xFF"))


@unittest.skipIf(os.name == "nt", "symbolic links")
class LinkReplacement(Base):
    @unittest.skipUnless(GIT, "git unavailable")
    def test_an_ignored_target_is_rated_and_listed_as_ignored_in_either_order(self):   # B68
        for n in ("0.py", "z.py"):
            with self.subTest(target=n):
                r = self.repo("inv-" + n[0])
                Path(r, n).write_text("try:\n    n=1\nexcept:\n    raise\n")
                Path(r, ".gitignore").write_text(n + "\n")
                os.symlink(n, os.path.join(r, "m.txt"))
                git(r, "add", ".gitignore", "m.txt")
                d = scan(r, "--no-config", "--rule", "JH217")
                self.assertEqual([(f["path"], f["severity"]) for f in d["findings"]], [(n, "minor")])
                self.assertEqual(d["set_aside"]["git_ignored_read"]["paths"], [n])

    def test_a_generated_target_stays_skipped_in_either_order(self):            # B78
        for n in ("0.generated.py", "z.generated.py"):
            with self.subTest(target=n):
                d = os.path.join(self.root, n + "-dir")
                os.makedirs(d)
                Path(d, n).write_text("breakpoint()\n")
                os.symlink(n, os.path.join(d, "m.py"))
                r = scan(d, "--rule", "JH204")
                self.assertEqual([f["path"] for f in r["findings"]], ["m.py"])
                self.assertEqual(r["set_aside"]["files_by_name"]["generated"]["paths"], [n])


class SafetyBound(Base):
    def bound(self):
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))
        import jh_checks
        return jh_checks.DEBUG_BOUND

    def test_a_line_exemption_covers_calls_past_the_bound(self):                 # B72
        n = self.bound() + 1
        # a header line first: line 1 holds no ignore, so only each call's own line can excuse it
        Path(self.path("card.py")).write_text("# header\n" + "breakpoint()  # jankhunt42: ignore JH204\n" * n)
        proc = run_cli("scan", self.root, "--rule", "JH204", "--max-file-bytes", "9000000", "--fail-on", "minor",
                       "--json", "--no-progress")
        d = json.loads(proc.stdout)
        self.assertEqual((d["summary"]["findings"], d["set_aside"].get("inline_ignore"), d["set_aside"].get("capped", 0)),
                         (0, n, 0))
        self.assertEqual(proc.returncode, 0)

    def test_findings_past_the_bound_keep_their_own_rating(self):                # B80
        n = self.bound() + 1
        Path(self.path("package.json")).write_text(json.dumps({"peerDependencies": {"tint%d" % i: "*" for i in range(n)}}, indent=2))
        proc = run_cli("scan", self.root, "--no-config", "--rule", "JH424", "--min-severity", "minor", "--fail-on", "minor",
                       "--max-file-bytes", "9000000", "--json", "--no-progress")
        d = json.loads(proc.stdout)
        self.assertEqual(d["set_aside"].get("capped", 0), 0)
        self.assertEqual(d["set_aside"]["below_floor"]["info"], n)
        self.assertEqual(proc.returncode, 0)


class McpServers(Base):
    def test_two_servers_on_one_line_are_two_findings(self):                     # B76
        Path(self.path(".mcp.json")).write_text(json.dumps({"mcpServers": {
            "ink": {"type": "sse", "url": "https://ink.invalid/e"}, "paper": {"type": "sse", "url": "https://paper.invalid/e"}}}))
        d = scan(self.root, "--no-config", "--rule", "JH715")
        self.assertEqual(sorted(f["extra"]["server"] for f in d["findings"]), ["ink", "paper"])

    def test_the_scan_reads_servers_past_the_inventory_limit(self):              # B81
        servers = {"tone%d" % i: {"type": "http", "url": "https://tone.invalid/%d" % i} for i in range(200)}
        servers["paper"] = {"type": "sse", "url": "https://paper.invalid/e"}
        Path(self.path(".mcp.json")).write_text(json.dumps({"mcpServers": servers}, indent=2))
        proc = run_cli("scan", self.root, "--no-config", "--rule", "JH715", "--fail-on", "minor", "--json", "--no-progress")
        self.assertEqual([f["extra"]["server"] for f in json.loads(proc.stdout)["findings"]], ["paper"])
        self.assertEqual(proc.returncode, 1)


class PhpTemplateText(Base):
    def test_text_after_a_second_closing_tag_on_the_line_is_not_code(self):       # B71
        Path(self.path("card.php")).write_text("<?php // end ?><?php echo 1; ?> Manual: var_dump($shade).\n")
        Path(self.path("real.php")).write_text("<?php // x ?> text <?php var_dump($a); ?> more\n")
        d = scan(self.root, "--no-config", "--rule", "JH204")
        self.assertEqual([(f["path"], f["line"]) for f in d["findings"]], [("real.php", 1)])


class Output(Base):
    def test_map_and_passport_fail_when_out_cannot_be_written(self):            # B69
        Path(self.path("app.py")).write_text("x = 1\n")
        os.makedirs(self.path("dest", "x"))
        for cmd in ("map", "passport"):
            with self.subTest(cmd=cmd):
                self.assertEqual(run_cli(cmd, self.root, "--out", self.path("dest")).returncode, 2)

    @unittest.skipUnless(GIT, "git unavailable")
    def test_an_output_name_with_line_breaks_keeps_both_summaries_short(self):  # B73
        r = self.repo("card")
        Path(r, "leaf.py").write_text("breakpoint()\n")
        dest = os.path.join(self.root, "dest", "r" + "\n" * 70 + "s.json")
        for cmd in ("scan", "review"):
            with self.subTest(cmd=cmd):
                out = run_cli(cmd, r, "--rule", "JH204", "--fail-on", "minor", "--summary", "--out", dest).stdout
                self.assertLessEqual(len(out.splitlines()), 60)

    def test_the_summary_says_what_it_could_not_read(self):                      # B82
        import zipfile
        with zipfile.ZipFile(self.path("paper.zip"), "w") as z:
            z.writestr("solution.xml", "<paper/>")
            z.writestr("customizations.xml", "<paper/>")
            z.writestr("CanvasApps/art.msapp", "unfinished")
        out = run_cli("scan", self.root, "--summary", "--no-progress").stdout
        self.assertIn("not read: 1 item", out)

    def test_control_characters_in_a_name_are_written_with_two_digits(self):    # W3-108
        if os.name == "nt":
            self.skipTest("line breaks in file names")
        Path(self.path("a\nb.py")).write_text("breakpoint()\n")
        self.assertIn("a\\x0ab.py", run_cli("scan", self.root, "--rule", "JH204", "--summary", "--no-progress").stdout)

    def test_the_summary_lists_ten_findings_and_eight_rules(self):               # W3-132, W3-130
        Path(self.path("calls.py")).write_text("breakpoint()\n" * 12)
        Path(self.path("mixed.py")).write_text(
            "import os, pickle, hashlib, tempfile, subprocess, requests\n"
            "eval(x)\nos.system(c)\npickle.loads(b)\nhashlib.md5(b)\ntempfile.mktemp()\n"
            "subprocess.run(c, shell=True)\nrequests.get(u, verify=False)\n# noqa\n"
            "try:\n    pass\nexcept:\n    pass\n")
        out = run_cli("scan", self.root, "--min-severity", "info", "--summary", "--no-progress").stdout
        listed = out.split("most serious", 1)[1].split("\n")[1:]
        self.assertEqual(len([l for l in listed if l.startswith("  ") and ":" in l and " JH" in l]), 10)
        self.assertIn("more rules", out)

    def test_the_summary_is_cut_at_exactly_sixty_lines(self):                    # W3-105, W3-106
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))
        import jh_render, jh_rules
        result = jh_rules.ScanResult()
        base = len(jh_render.render_summary(result, {}).splitlines())
        held = [("x", "held %d" % i) for i in range(jh_render.SUMMARY_MAX_LINES - base)]   # base + 1 + held = 61
        with mock.patch.object(jh_render, "set_aside_lines", lambda meta: held):
            lines = jh_render.render_summary(result, {}).splitlines()
        self.assertEqual(len(lines), jh_render.SUMMARY_MAX_LINES)
        self.assertTrue(lines[-1].startswith("... summary cut at"))


class ScoreBudget(Base):
    def test_the_score_reads_at_most_two_hundred_findings_per_rule(self):        # W3-102, W3-128
        for i in range(45):
            Path(self.path("m%02d.py" % i)).write_text("# noqa\n" * 5)
        d = scan(self.root, "--no-config", "--rule", "JH306", "--min-severity", "info")
        self.assertEqual(d["summary"]["findings"], 225)
        self.assertEqual(d["summary"]["jank"]["counted_findings"], 200)


class Directives(Base):
    def test_a_file_wide_directive_is_read_within_the_first_twelve_lines(self):  # W3-120
        Path(self.path("card.py")).write_text("# header\n" * 9 + "# jankhunt42: ignore-file JH204\nbreakpoint()\n")
        self.assertEqual(scan(self.root, "--no-config", "--rule", "JH204")["findings"], [])


@unittest.skipUnless(GIT, "git unavailable")
class Review(Base):
    def test_a_folder_named_like_a_marker_does_not_skip_its_parent(self):         # B70
        r = self.repo("fm")
        Path(r, "README.md").write_text("x\n")
        git(r, "add", "-A"); git(r, "commit", "-q", "-m", "one")
        os.makedirs(os.path.join(r, "env", "pyvenv.cfg"))
        Path(r, "env", "pyvenv.cfg", "label.txt").write_text("plain\n")
        Path(r, "env", "card.py").write_text("breakpoint()\n")
        git(r, "add", "-A"); git(r, "commit", "-q", "-m", "two")
        d = json.loads(run_cli("review", r, "--commit", "HEAD", "--rule", "JH204", "--fail-on", "minor", "--json").stdout)
        self.assertEqual([f["path"] for f in d["findings"]], ["env/card.py"])
        self.assertEqual(d["review"]["gate"]["result"], "fail")

    def test_a_repository_name_ending_in_a_space_is_the_one_reviewed(self):      # B83
        a, b = self.repo("canvas "), self.repo("canvas")
        Path(a, "draft.py").write_text("breakpoint()\n")
        Path(b, "clean.py").write_text("x = 1\n")
        d = json.loads(run_cli("review", a, "--rule", "JH204", "--fail-on", "minor", "--json").stdout)
        self.assertEqual(d["review"]["scope"]["reviewed_files"], ["draft.py"])

    def test_a_text_file_marked_binary_still_has_line_changes(self):            # B84
        r = self.repo("bin")
        Path(r, ".gitattributes").write_text("*.py binary\n")
        Path(r, "draft.py").write_text("x = 1\n")
        git(r, "add", "-A"); git(r, "commit", "-q", "-m", "one")
        Path(r, "draft.py").write_text("x = 1\nbreakpoint()\n")
        proc = run_cli("review", r, "--rule", "JH204", "--fail-on", "minor", "--json")
        self.assertEqual(json.loads(proc.stdout)["summary"]["new_findings"], 1)
        self.assertEqual(proc.returncode, 1)

    def test_before_the_first_commit_an_edit_after_staging_changes_the_review(self):   # M793
        r = self.repo("initial")
        Path(r, "page.py").write_text("answer = 1\n")
        git(r, "add", "page.py")
        def ident():
            rv = json.loads(run_cli("review", r, "--min-severity", "info", "--json").stdout)["review"]
            return rv.get("diff_hash") or rv["scope"].get("diff_hash")
        first = ident()
        with open(os.path.join(r, "page.py"), "a") as fh:            # edited after staging, not staged again
            fh.write("# noqa\n")
        self.assertNotEqual(first, ident())

    def test_moving_a_line_between_new_files_changes_the_review_identity(self):  # B79
        r = self.repo("mv")
        def ident():
            rv = json.loads(run_cli("review", r, "--rule", "JH204", "--json").stdout)["review"]
            return rv.get("diff_hash") or rv["scope"].get("diff_hash")
        # no final newlines: joined with one, both states read "a = 1\nbreakpoint()\nb = 2"
        Path(r, "a.py").write_text("a = 1\nbreakpoint()"); Path(r, "b.py").write_text("b = 2")
        first = ident()
        self.assertEqual(first, ident())                          # stable on a repeat
        Path(r, "a.py").write_text("a = 1"); Path(r, "b.py").write_text("breakpoint()\nb = 2")
        self.assertNotEqual(first, ident())


if __name__ == "__main__":
    unittest.main()
