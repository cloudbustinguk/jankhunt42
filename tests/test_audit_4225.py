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

    def test_scan_and_map_count_unreadable_tracked_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            locked = root / "locked"
            locked.mkdir()
            target = locked / "studio.py"
            target.write_text("breakpoint()\n")
            (root / "preview.py").symlink_to("locked/studio.py")
            (root / "note.py").write_text("x = 1\n")
            git(tmp, "init", "-q")
            git(tmp, "add", "note.py", "preview.py")
            for state in ("inaccessible", "missing"):
                if state == "inaccessible":
                    locked.chmod(0)
                else:
                    target.unlink()
                try:
                    if state == "inaccessible" and os.access(target, os.F_OK):
                        continue  # privileged accounts can still read the target
                    with self.subTest(state=state):
                        doc = scan(tmp)
                        self.assertEqual(doc["summary"]["files"], 1)
                        self.assertEqual(doc["set_aside"].get("files_not_read"),
                                         {"unreadable": {"count": 1, "paths": ["preview.py"]}})
                        cov = json.loads(run_cli("map", tmp, "--json").stdout)["coverage"]
                        self.assertEqual((cov["status"], cov["files_considered"], cov["files_inspected"]),
                                         ("partial", 2, 1))
                        self.assertEqual((cov["skipped"], cov["skipped_paths"]), ({"unreadable": 1}, ["preview.py"]))
                finally:
                    locked.chmod(0o700)

    def test_permission_error_resolving_a_link_is_counted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "target").write_text("text")
            link = root / "preview.py"
            link.symlink_to("target")
            resolve = Path.resolve
            def denied(path, *args, **kwargs):
                if path == link:
                    raise PermissionError("permission denied")
                return resolve(path, *args, **kwargs)
            with mock.patch.object(Path, "resolve", denied):
                not_read = {}
                jh_core.discover_files([tmp], not_read=not_read)
            self.assertEqual(not_read.get("unreadable"), ["preview.py"])

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
    def test_explicit_link_uses_its_own_project_config(self):
        project = Path(self.path("selected", ".jankhunt42.json"))
        project.write_text(json.dumps({"rules": {"JH217": {"severity": "minor"}}}))
        target = Path(self.path("source", "z.txt"))
        target.write_text("try:\n    n = 1\nexcept:\n    raise\n")
        link = project.parent / "m.py"
        link.symlink_to(target)
        doc = scan(str(link), "--rule", "JH217")
        self.assertEqual(doc.get("config"), str(project))
        self.assertEqual([f["severity"] for f in doc["findings"]], ["minor"])
        target.unlink()                    # a named link whose target is gone is refused by name, never read as empty
        proc = run_cli("scan", str(link), "--rule", "JH217", "--json", "--no-progress")
        self.assertEqual((proc.returncode, proc.stdout), (2, ""))
        self.assertIn("broken symbolic link", proc.stderr)

    def test_excluding_a_links_target_keeps_the_permitted_name_in_the_passport(self):   # B96
        for target in ("draft.py", "zdraft.py"):                # the target sorts before and after the link
            with self.subTest(target=target):
                folder = Path(self.path(target[0], "x")).parent
                (folder / target).write_text("breakpoint()\n")
                (folder / "active.py").symlink_to(target)
                (folder / ".jankhunt42.json").write_text(json.dumps({"ignore": [target]}))
                doc = scan(str(folder))
                self.assertEqual([(f["rule"], f["path"]) for f in doc["findings"]], [("JH204", "active.py")])
                card = json.loads(run_cli("passport", str(folder), "--json").stdout)
                self.assertEqual((card["scope"]["files_scanned"], card["assessment"]["jank"]["findings"],
                                  card["assessment"]["jank"]["score"]),
                                 (doc["summary"]["files"], 1, doc["summary"]["jank"]["score"]))

    def test_explicit_file_links_select_rules_by_the_requested_name(self):
        folder = Path(self.root, "project")
        folder.mkdir()
        (folder / "z.txt").write_text("try:\n    n = 1\nexcept:\n    raise\n")
        (folder / "m.py").symlink_to("z.txt")
        (folder / "policy.txt").symlink_to("z.txt")
        rules = Path(self.root, "rules.json")
        rules.write_text(json.dumps({"schema_version": "jankhunt.ruleset.v1", "name": "Policy", "rules": [{
            "id": "POLICY01", "title": "Check policy", "message": "Check policy.", "severity": "major",
            "patterns": ["except:"], "files": ["policy.txt"], "target": "raw", "examples": {"match": ["except:"]}}]}))
        typed = ("m.py", "JH217", "major", 3)
        named = ("policy.txt", "POLICY01", "major", 3)
        for paths, count, expected in ((["."], 3, [typed, named]), (["m.py"], 1, [typed]),
                                       (["policy.txt"], 1, [named]), (["z.txt"], 1, []),
                                       (["m.py", "z.txt", "policy.txt"], 3, [typed, named])):
            with self.subTest(paths=paths):
                proc = run_cli("scan", *paths, "--no-config", "--ruleset", str(rules), "--rule", "JH217",
                               "--rule", "POLICY01", "--json", cwd=folder)
                doc = json.loads(proc.stdout)
                self.assertEqual(doc["summary"]["files"], count)
                self.assertCountEqual([(f["path"], f["rule"], f["severity"], f["line"]) for f in doc["findings"]],
                                      expected)

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

    def test_a_dependency_is_read_from_the_manifest_not_from_its_layout(self):   # B89
        doc = {"name": "palette", "description": "latest", "scripts": {"tint": "latest"},
               "dependencies": {"chalkboard": "*", "easel": "latest", "frame": "^1.2.0"},
               "peerDependencies": {"canvas": "*"}}
        expected = [("dependencies", "chalkboard", "minor"), ("dependencies", "easel", "minor"),
                    ("peerDependencies", "canvas", "info")]
        for name, indent, lines in (("flat", None, [1, 1, 1]), ("pretty", 2, [8, 9, 13])):
            with self.subTest(layout=name):
                Path(self.path(name, "package.json")).write_text(json.dumps(doc, indent=indent))
                Path(self.path(name, "package-lock.json")).write_text("{}")
                proc = run_cli("scan", self.path(name, "x")[:-2], "--no-config", "--rule", "JH424", "--min-severity", "info",
                               "--fail-on", "minor", "--json", "--no-progress")
                found = json.loads(proc.stdout)["findings"]
                self.assertEqual(sorted((f["extra"]["section"], f["extra"]["package"], f["severity"]) for f in found),
                                 expected)
                self.assertEqual(sorted(f["line"] for f in found), lines)
                self.assertEqual(proc.returncode, 1)
        Path(self.path("words", "package.json")).write_text('{\n  "name": "palette",\n  "description": "latest"\n}\n')
        proc = run_cli("scan", self.path("words", "x")[:-2], "--no-config", "--rule", "JH424", "--min-severity", "info",
                       "--fail-on", "info", "--json", "--no-progress")
        self.assertEqual((json.loads(proc.stdout)["findings"], proc.returncode), ([], 0))
        # a manifest that is not valid JSON is still read, line by line
        Path(self.path("broken", "package.json")).write_text('{\n  "dependencies": {\n    "chalkboard": "*",\n  }\n}\n')
        d = scan(self.path("broken", "x")[:-2], "--no-config", "--rule", "JH424")
        self.assertEqual([f["line"] for f in d["findings"]], [3])


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

    def test_a_quote_in_the_page_text_does_not_hide_the_block_after_it(self):          # B101
        files = {"prose.php": "<p>Today's shade: <?php var_dump($shade); ?></p>\n",
                 "plain.php": "<p>Current shade: <?php var_dump($shade); ?></p>\n",
                 "printed.php": "<p>Call var_dump($x) here: <?php echo 1; ?> and var_dump($y)</p>\n",
                 # the state carries across lines: page text, a block, a comment closed by its tag, a tag in a string
                 "long.php": "<html>\n<p>it's\n<?php\n// note ?> var_dump($a) <?php var_dump($b);\n"
                             "$s = \"?>\"; var_dump($c);\n?>\nvar_dump($d)\n<?= var_dump($e) ?>\n",
                 # no opening tag anywhere: read as code, as before
                 "bare.php": "$label = 'x';\nvar_dump($label);\n"}
        for name, text in files.items():
            Path(self.path(name)).write_text(text)
        d = scan(self.root, "--rule", "JH204", "--no-config")
        self.assertEqual(sorted((f["path"], f["line"]) for f in d["findings"]),
                         [("bare.php", 2), ("long.php", 4), ("long.php", 5), ("long.php", 8), ("plain.php", 1),
                          ("prose.php", 1)])


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
        # display_path writes the byte (\\x0A); the summary's own filter would write \\x0a: two digits either way
        self.assertIn("a\\x0Ab.py", run_cli("scan", self.root, "--rule", "JH204", "--summary", "--no-progress").stdout)

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
    @unittest.skipIf(os.name == "nt", "symbolic links")
    def test_only_markers_resolving_to_files_skip_source_in_each_view(self):
        r = self.repo("markers")
        expected = []
        for kind in ("file", "linked", "directory", "missing", "loop"):
            env = Path(r, kind, "env")
            env.mkdir(parents=True)
            marker = env / "pyvenv.cfg"
            if kind == "file":
                marker.write_text("home = fixture\n")
            elif kind == "linked":
                (env.parent / "layout").mkdir()
                (env.parent / "layout" / "config").write_text("home = fixture\n")
                (env / "alias").symlink_to("../layout")
                marker.symlink_to("alias/config")
            elif kind == "directory":
                (env / "layout").mkdir()
                (env / "layout" / "detail.txt").write_text("detail\n")
                marker.symlink_to("layout")
            else:
                marker.symlink_to("pyvenv.cfg" if kind == "loop" else "absent")
            (env / "card.py").write_text("breakpoint()\n")
            if kind in ("directory", "missing", "loop"):
                expected.append((kind + "/env/card.py", 1))
        git(r, "add", "-A")
        for mode in ([], ["--staged"], ["--commit", "HEAD"]):
            if mode == ["--staged"]:
                # Neither snapshot should consult the changed working copy.
                Path(r, "linked/layout/config").unlink()
                Path(r, "missing/env/absent").write_text("home = fixture\n")
            if "--commit" in mode:
                git(r, "commit", "-qm", "markers")
            with self.subTest(mode=mode):
                proc = run_cli("review", r, *mode, "--rule", "JH204", "--fail-on", "minor", "--json")
                doc = json.loads(proc.stdout)
                self.assertCountEqual([(f["path"], f["line"]) for f in doc["findings"]], expected)
                skipped = {s["path"]: s["reason"] for s in doc["review"]["scope"]["skipped_files"]}
                for kind in ("file", "linked"):
                    self.assertEqual(skipped[kind + "/env/card.py"], "dependencies")
                self.assertEqual((doc["review"]["gate"]["result"], proc.returncode), ("fail", 1))

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

    def test_only_small_files_that_read_as_text_get_a_text_diff(self):            # review cost with real binaries
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))
        import jh_review
        r = self.repo("mixed")
        Path(r, ".gitattributes").write_text("*.py binary\n*.dat binary\n")
        Path(r, "draft.py").write_text("x = 1\n")
        Path(r, "big.dat").write_bytes(b"a" * 2000000)                # text-like, but over the size limit
        Path(r, "real.bin").write_bytes(bytes(range(256)) * 8)       # NUL bytes: a real binary
        git(r, "add", "-A"); git(r, "commit", "-q", "-m", "one")
        Path(r, "draft.py").write_text("x = 1\nbreakpoint()\n")
        Path(r, "big.dat").write_bytes(b"b" * 2000000)
        Path(r, "real.bin").write_bytes(b"\x00" + bytes(range(255, 0, -1)) * 8)   # NUL first: not a UTF-16 mark
        args = ["diff", "HEAD", "--no-color", "--src-prefix=a/", "--dst-prefix=b/", "--no-ext-diff", "--find-renames"]
        self.assertEqual(jh_review._binary_but_text(r, args, None, False), ["draft.py"])
        patch = jh_review._diff_command(r, "working")[0]
        self.assertIn("+breakpoint()", patch)
        self.assertLess(len(patch), 20000)

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

    @unittest.skipUnless(GIT, "git unavailable")
    def test_a_staged_review_looks_for_the_lockfile_in_the_index(self):           # B99
        r = self.repo("lock")
        Path(r, "package.json").write_text('{"name":"palette","version":"1.0.0"}\n')
        git(r, "add", "package.json")

        def verdict(*mode):
            proc = run_cli("review", r, *mode, "--rule", "JH423", "--min-severity", "info", "--fail-on", "info", "--json")
            doc = json.loads(proc.stdout)
            return [f["rule"] for f in doc["findings"]], doc["review"]["gate"]["result"], proc.returncode
        missing, present = (["JH423"], "fail", 1), ([], "pass", 0)
        self.assertEqual(verdict("--staged"), missing)
        Path(r, "package-lock.json").write_text('{"name":"palette","lockfileVersion":3}\n')
        self.assertEqual(verdict("--staged"), missing)        # on disk only: the index still has no lockfile
        git(r, "add", "package-lock.json")
        self.assertEqual(verdict("--staged"), present)
        os.remove(os.path.join(r, "package-lock.json"))
        self.assertEqual(verdict("--staged"), present)        # gone from disk, still in the index
        git(r, "commit", "-qm", "both")
        Path(r, "package.json").write_text('{"name":"palette","version":"1.0.1"}\n')
        self.assertEqual(verdict(), missing)                  # the working tree is what a working review reads
        git(r, "add", "package.json")
        git(r, "commit", "-qm", "manifest only")
        self.assertEqual(verdict("--commit", "HEAD"), present)   # the commit holds the lockfile the folder lost

    @unittest.skipUnless(GIT, "git unavailable")
    def test_a_changed_line_past_the_safety_bound_still_reaches_the_gate(self):   # B61
        import jh_checks
        n = jh_checks.DEBUG_BOUND + 1
        r = self.repo("bound-change")
        Path(r, "draft.py").write_text("breakpoint()\n" * n + "x = 1\n")
        git(r, "add", "draft.py")
        git(r, "commit", "-qm", "base")

        def review():
            proc = run_cli("review", r, "--rule", "JH204", "--fail-on", "minor", "--max-file-bytes", "9000000", "--json")
            doc = json.loads(proc.stdout)
            return (doc["summary"]["new_findings"], doc["summary"]["capped_findings"],
                    doc["review"]["set_aside"].get("capped", 0), doc["review"]["gate"]["result"], proc.returncode,
                    [f["line"] for f in doc["findings"] if f["line"] > n])
        Path(r, "draft.py").write_text("breakpoint()\n" * n + "x = 2\n")
        # the call past the bound is on an unchanged line: counted in both places, and the change passes
        self.assertEqual(review(), (0, 1, 1, "pass", 0, []))
        Path(r, "draft.py").write_text("breakpoint()\n" * n + "x = 2\nbreakpoint()\n")
        # the added call is past the bound too: it is listed and fails the gate; the unchanged one is still counted
        self.assertEqual(review(), (1, 1, 1, "fail", 1, [n + 2]))


class FifthPass(Base):
    """Fixes from the review pass on the 4.22.5 candidate itself."""

    def test_the_summary_counts_every_unread_item_and_the_report_lists_them(self):   # B87
        import zipfile
        for name, count in (("paint", 26), ("sketch", 25)):
            with zipfile.ZipFile(self.path(name + ".zip"), "w") as z:
                z.writestr("solution.xml", "<paper/>")
                z.writestr("customizations.xml", "<paper/>")
                for i in range(count):
                    z.writestr("CanvasApps/page%02d.msapp" % i, "unfinished")
        out = self.path("..", os.path.basename(self.root) + "-arch.json")
        self.addCleanup(lambda: os.path.exists(out) and os.remove(out))
        summary = run_cli("scan", self.root, "--summary", "--out", out, "--no-progress").stdout
        self.assertIn("not read: 51 items", summary)
        self.assertEqual(len(json.load(open(out))["warnings"]), 51)

    @unittest.skipUnless(GIT, "git unavailable")
    def test_the_review_ignores_the_repository_diff_prefix_setting(self):            # B90
        r = self.repo("pre")
        Path(r, "draft.py").write_text("x = 1\n")
        git(r, "add", "-A"); git(r, "commit", "-q", "-m", "one")
        Path(r, "draft.py").write_text("x = 1\nbreakpoint()\n")
        for setting in ("diff.mnemonicPrefix", "diff.noprefix"):
            with self.subTest(setting=setting):
                git(r, "config", "--unset-all", "diff.mnemonicPrefix") if setting == "diff.noprefix" else None
                git(r, "config", setting, "true")
                proc = run_cli("review", r, "--rule", "JH204", "--fail-on", "minor", "--json")
                d = json.loads(proc.stdout)
                self.assertEqual(d["review"]["scope"]["changed_files"], ["draft.py"])
                self.assertEqual(proc.returncode, 1)

    def test_passport_compare_writes_out(self):                                     # B91
        Path(self.path("card", "leaf.py")).write_text("breakpoint()\n")
        ref = self.path("ref.json")
        Path(ref).write_text(run_cli("passport", self.path("card"), "--json").stdout)
        for extra, name in (((), "live.json"), (("--against", ref), "saved.json")):
            with self.subTest(name=name):
                dest = self.path("reports", name)
                proc = run_cli("passport", self.path("card"), "--compare", ref, *extra, "--out", dest, "--json")
                self.assertEqual(proc.returncode, 0, proc.stderr[-200:])
                self.assertTrue(json.load(open(dest)))

    @unittest.skipIf(os.name == "nt", "file modes and links")
    def test_out_keeps_permissions_and_writes_through_a_link(self):               # B93
        Path(self.path("reg", "leaf.py")).write_text("breakpoint()\n")
        last = self.path("reports", "last.json")
        Path(last).write_text("{}\n")
        os.chmod(last, 0o600)
        run_cli("scan", self.path("reg"), "--summary", "--out", last, "--no-progress")
        self.assertEqual(os.stat(last).st_mode & 0o777, 0o600)
        Path(self.path("reports", "run.json")).write_text('{"previous": true}\n')
        os.symlink("run.json", self.path("reports", "daily.json"))
        run_cli("scan", self.path("reg"), "--summary", "--out", self.path("reports", "daily.json"), "--no-progress")
        self.assertTrue(os.path.islink(self.path("reports", "daily.json")))
        self.assertEqual(json.load(open(self.path("reports", "run.json")))["summary"]["findings"], 1)

    @unittest.skipIf(os.name == "nt", "symbolic links")
    def test_a_generated_link_stays_skipped_when_its_text_target_comes_first(self):  # B94
        for n in ("0.txt", "z.txt"):
            with self.subTest(target=n):
                d = self.path(n + "-dir", n)
                Path(d).write_text("breakpoint()\n")
                os.symlink(n, os.path.join(os.path.dirname(d), "m.generated.py"))
                proc = run_cli("scan", os.path.dirname(d), "--no-config", "--rule", "JH204", "--fail-on", "minor", "--json", "--no-progress")
                r = json.loads(proc.stdout)
                self.assertEqual(r["findings"], [])
                self.assertEqual(r["set_aside"]["files_by_name"]["generated"]["paths"], ["m.generated.py"])
                self.assertEqual(proc.returncode, 0)

    def test_two_more_mcp_checks_report_every_server(self):                         # B100
        for folder, rule, spec in (("cap", "JH705", lambda i: {"command": "npx", "args": ["paper-tone"]}),
                                   ("net", "JH707", lambda i: {"type": "http", "url": "http://tone.invalid/%d" % i})):
            with self.subTest(rule=rule):
                Path(self.path(folder, ".mcp.json")).write_text(json.dumps({"mcpServers": {"tile%d" % i: spec(i) for i in range(11)}}, indent=2))
                self.assertEqual(len(scan(self.path(folder), "--rule", rule)["findings"]), 11)

    @unittest.skipIf(os.name == "nt", "symbolic links")
    def test_a_link_loop_is_set_aside_not_fatal(self):                              # B102 (RuntimeError on 3.12)
        Path(self.path("loop", "note.py")).write_text("x = 1\n")
        os.symlink("studio.py", self.path("loop", "preview.py"))
        os.symlink("preview.py", self.path("loop", "studio.py"))
        real_resolve = pathlib.Path.resolve

        def resolve(self_, *a, **k):
            if self_.name in ("preview.py", "studio.py"):
                raise RuntimeError("Symlink loop from %r" % str(self_))
            return real_resolve(self_, *a, **k)

        with mock.patch.object(pathlib.Path, "resolve", resolve):
            not_read = {}
            _, files = jh_core.discover_files([self.path("loop")], not_read=not_read)
        self.assertEqual([p.name for p in files], ["note.py"])
        self.assertEqual(sorted(not_read["dirs"]["link that cannot be resolved"]), ["preview.py", "studio.py"])

    @unittest.skipIf(sys.platform == "darwin" or os.name == "nt", "file names that are not UTF-8")
    def test_a_byte_named_project_with_a_config_saves_its_scan(self):               # B103
        d = os.path.join(self.root.encode(), b"studio-\xff")
        os.makedirs(d)
        with open(os.path.join(d, b"note.py"), "w") as fh:
            fh.write("breakpoint()\n")
        with open(os.path.join(d, b".jankhunt42.json"), "w") as fh:
            fh.write('{"ignore": ["note.py"]}\n')
        out = os.path.join(self.root, "scan.json")
        proc = run_cli("scan", os.fsdecode(d), "--summary", "--out", out, "--no-progress")
        self.assertEqual(proc.returncode, 0, proc.stderr[-300:])
        self.assertEqual(json.load(open(out, encoding="utf-8"))["command"], "scan")


class PastThePositionLimit(Base):
    """Past the bound, call positions are kept up to a limit; beyond it the calls are still counted (M859)."""

    def test_calls_beyond_the_position_limit_are_counted(self):
        import contextlib, io, runpy
        Path(self.path("card.py")).write_text("breakpoint()\n" * 10)
        scripts = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts")
        sys.path.insert(0, scripts)
        import jh_checks
        out = io.StringIO()
        argv = ["jankhunt42", "scan", self.root, "--no-config", "--rule", "JH204", "--fail-on", "minor", "--json",
                "--no-progress"]
        with mock.patch.object(jh_checks, "DEBUG_BOUND", 3), mock.patch.object(jh_checks, "BOUND_POSITIONS_MAX", 2), \
                mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(out):
            with self.assertRaises(SystemExit) as code:
                runpy.run_path(os.path.join(scripts, "jankhunt42"), run_name="__main__")
        d = json.loads(out.getvalue())
        self.assertEqual(code.exception.code, 1)
        self.assertEqual(len(d["findings"]), 3)
        self.assertEqual(d["set_aside"].get("capped"), 7)          # 2 with their positions, 5 counted beyond them


if __name__ == "__main__":
    unittest.main()
