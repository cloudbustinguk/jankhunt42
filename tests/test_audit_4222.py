"""Fixes for findings an audit of 4.22.0 left open for 4.22.2 (invented projects only)."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from _util import CLI, run_cli

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


class ScopeAndSelection(unittest.TestCase):
    def test_the_floor_counts_only_what_the_selection_could_show_and_the_selection_is_stated(self):
        root = project(self, {"sample.py": "value = 1  # noqa\n"})
        tests_only = scan(str(root), "--category", "tests")
        self.assertNotIn("below_floor", tests_only["set_aside"])
        self.assertEqual(tests_only["set_aside"]["selection"], {"categories": ["tests"]})
        md = run_cli("scan", str(root), "--rule", "JH204", "--md", "--no-progress").stdout
        self.assertIn("reported only rule(s) JH204", md)

    def test_a_site_rule_id_in_an_ignore_comment_takes_effect(self):
        rule = {"id": "ACME-001", "title": "Internal hostname in code", "severity": "major", "category": "security",
                "message": "An internal hostname is written into the code.", "fix": "Read it from configuration.",
                "patterns": [r"\b[a-z0-9-]+\.corp\.acme\.internal\b"], "target": "raw", "files": ["*.py"],
                "examples": {"match": ['host = "db1.corp.acme.internal"'], "no_match": ["see acme.com"]}}
        ops = project(self, {"rs.json": json.dumps({"schema_version": "jankhunt.ruleset.v1", "name": "acme", "rules": [rule]})})
        root = project(self, {"app.py": 'host = "db1.corp.acme.internal"  # jankhunt42: ignore ACME-001\n'})
        held = scan(str(root), "--ruleset", str(ops / "rs.json"))
        self.assertEqual((held["findings"], held["set_aside"].get("inline_ignore")), ([], 1))
        shown = scan(str(root), "--ruleset", str(ops / "rs.json"), "--no-inline-ignore")
        self.assertEqual([f["rule"] for f in shown["findings"]], ["ACME-001"])

    @unittest.skipUnless(__import__("shutil").which("git"), "git unavailable")
    def test_review_names_the_rules_switched_off(self):
        root = project(self, {"sample.py": "value = 1\n"})
        __import__("subprocess").run(["git", "-C", str(root), "init", "-q"], check=True)
        doc = json.loads(run_cli("review", ".", "--ignore-ci", "--json", cwd=str(root)).stdout)
        self.assertIn("JH417", doc["review"]["set_aside"]["ignored_rules"]["rules"])


class FileLimit(unittest.TestCase):
    def test_the_notice_is_true_named_files_count_and_zero_is_refused(self):
        root = project(self, {"one/a.py": "x = 1\n", "two/a.py": "x = 1\n", "two/b.py": "y = 2\n"})
        self.assertNotIn("file_limit", scan(str(root / "one"), "--max-files", "1")["set_aside"])
        self.assertEqual(scan(str(root / "two"), "--max-files", "1")["set_aside"]["file_limit"], 1)
        named = scan(str(root / "two" / "a.py"), str(root / "two" / "b.py"), "--max-files", "1")
        self.assertEqual((named["summary"]["files"], named["set_aside"]["file_limit"]), (1, 1))
        refused = run_cli("scan", str(root / "two"), "--max-files", "0", "--json")
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("must be at least 1", refused.stderr)


class SkippedPathsAreAccurate(unittest.TestCase):
    def test_version_control_folders_are_listed_but_the_repositorys_own_git_is_not(self):
        root = project(self, {"a.py": "x = 1\n", ".hg/x": "1\n", ".svn/x": "1\n", ".git/HEAD": "ref\n"})
        vcs = scan(str(root))["set_aside"]["folders_not_read"]["version control"]
        self.assertEqual((vcs["count"], vcs["paths"]), (2, [".hg", ".svn"]))

    def test_two_named_projects_keep_their_own_paths(self):
        root = project(self, {"m1/build/a.js": "x=1\n", "m2/build/a.js": "x=1\n"})
        for order in (("m1", "m2"), ("m2", "m1")):
            with self.subTest(order=order):
                built = scan(*order, cwd=str(root))["set_aside"]["folders_not_read"]["build output"]
                self.assertEqual(built["paths"], ["m1/build", "m2/build"])


class RulesetFieldsAsWritten(unittest.TestCase):
    def test_a_present_field_of_the_wrong_type_is_refused_and_omitted_or_empty_ones_load(self):
        root = project(self, {"a.py": "x = 1\n"})
        ops = project(self, {})
        base = {"schema_version": "jankhunt.ruleset.v1", "name": "x"}
        for extra, ok in (({"rules": False}, False), ({"ignore": None}, False), ({"severity": ""}, False),
                          ({"rules": [], "ignore": [], "severity": {}}, True), ({}, True)):
            with self.subTest(extra=extra):
                (ops / "rs.json").write_text(json.dumps(dict(base, **extra)), encoding="utf-8")
                proc = run_cli("scan", str(root), "--ruleset", str(ops / "rs.json"), "--json")
                self.assertEqual(proc.returncode == 0, ok, proc.stderr)
                if not ok:
                    self.assertEqual(proc.returncode, 2)
                    self.assertIn(next(iter(extra)), proc.stderr)


class LinksLimitsAndVerifiers(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "symbolic links")
    def test_folder_links_are_listed_never_followed(self):
        root = project(self, {"project/main.py": "x = 1\n", "shared/leaf.py": BARE, "project/lib/a.py": "y = 2\n"})
        os.symlink("../shared", str(root / "project" / "env"))
        os.symlink("lib", str(root / "project" / "alias"))
        aside = scan(str(root / "project"), "--no-config")["set_aside"]["folders_not_read"]
        self.assertEqual(aside["link outside the scanned folder"]["paths"], ["env"])
        self.assertEqual(aside["linked folder (not followed)"]["paths"], ["alias"])

    @unittest.skipUnless(__import__("shutil").which("git"), "git unavailable")
    def test_the_same_files_are_chosen_at_a_limit_with_or_without_git(self):
        chosen = []
        for git in (False, True):
            root = project(self, {"z.py": BARE, "a/one.py": "x = 1\n"})
            if git:
                __import__("subprocess").run(["git", "init", "-q", str(root)], check=True)
            doc = scan(str(root), "--rule", "JH217", "--no-config", "--max-files", "1")
            chosen.append([f["path"] for f in doc["findings"]])
        self.assertEqual(chosen, [["z.py"], ["z.py"]])

    def test_a_stored_hash_gets_verifier_guidance_not_an_exposed_password_alarm(self):
        root = project(self, {"derived.yml": 'password: "$pbkdf2-sha512$310000$c8p78n7pUMln0jzv$JNRBzwAo0ek5qKn50cFzzvE9RXV88h1"\n'})
        f = scan(str(root), "--rule", "JH101", "--min-severity", "info")["findings"][0]
        self.assertEqual(f["severity"], "minor")
        self.assertTrue(f["fix"].startswith("Keep password verifiers out of source"))
        self.assertNotIn("secret", f["tags"])
        prompt = run_cli("scan", str(root), "--rule", "JH101", "--min-severity", "info", "--prompt").stdout
        self.assertNotIn("already been exposed", prompt)


class FileNames(unittest.TestCase):
    @unittest.skipUnless(__import__("shutil").which("git"), "git unavailable")
    def test_review_keeps_every_staged_name_and_lists_a_binary(self):
        root = project(self, {"page.bin": "\x00hello\n", "pêche.py": "# noqa\n", "two words.py": "# noqa\n",
                              'a"q.py': "# noqa\n"})
        sp = __import__("subprocess")
        sp.run(["git", "-C", str(root), "init", "-q"], check=True)
        sp.run(["git", "-C", str(root), "add", "-A"], check=True)
        doc = json.loads(run_cli("review", ".", "--staged", "--min-severity", "info", "--json", cwd=str(root)).stdout)
        scope = doc["review"]["scope"]
        self.assertEqual(scope["changed_files"], ['a"q.py', "page.bin", "pêche.py", "two words.py"])
        self.assertEqual(scope["skipped_files"], [{"path": "page.bin", "reason": "binary or unreadable"}])
        self.assertEqual(sorted(f["path"] for f in doc["findings"]), ['a"q.py', "pêche.py", "two words.py"])

    @unittest.skipIf(os.name == "nt" or sys.platform == "darwin", "file names that are not UTF-8")
    def test_a_name_that_is_not_utf8_is_found_and_every_report_stays_utf8(self):
        sp = __import__("subprocess")
        for git in (False, True) if __import__("shutil").which("git") else (False,):
            root = project(self, {})
            with open(os.path.join(os.fsencode(str(root)), b"caf\xe9.py"), "wb") as fh:
                fh.write(BARE.encode())
            if git:
                sp.run(["git", "-C", str(root), "init", "-q"], check=True)
            for cmd in ("scan", "map", "passport"):
                with self.subTest(git=git, cmd=cmd):
                    argv = [sys.executable, "-I", "-B", str(CLI), cmd, str(root), "--no-config", "--json"]
                    proc = sp.run(argv, capture_output=True, timeout=300)
                    self.assertEqual(proc.returncode in (0, 1), True, proc.stderr[-300:])
                    doc = json.loads(proc.stdout.decode("utf-8"))      # strict UTF-8
                    if cmd == "scan":
                        self.assertEqual([f["path"] for f in doc["findings"] if f["rule"] == "JH217"], ["caf\\xE9.py"])
                    if cmd == "map":
                        self.assertEqual(doc["coverage"]["inspected_paths"], ["caf\\xE9.py"])

    def test_the_map_claims_the_file_limit_only_when_a_file_was_turned_away(self):
        root = project(self, {"a.py": "x = 1\n"})
        doc = json.loads(run_cli("map", str(root), "--no-config", "--json", "--max-files", "1").stdout)
        self.assertNotEqual(doc["coverage"].get("max_files_reached"), True)


class SiteRulesMatchEveryLine(unittest.TestCase):
    def _rules(self, rid, pattern, match):
        rule = {"id": rid, "title": "Spacing", "message": "Spacing.", "fix": "Remove it.", "severity": "major",
                "category": "style", "patterns": [pattern], "target": "raw",
                "examples": {"match": match, "no_match": ["value = 1"]}}
        ops = project(self, {"rs.json": json.dumps({"schema_version": "jankhunt.ruleset.v1", "name": "s", "rules": [rule]})})
        return str(ops / "rs.json")

    def test_a_line_its_example_describes_is_found_and_the_end_of_the_file_is_not_a_line(self):
        root = project(self, {"sample.py": "value = 1\n   \nvalue = 2   \n"})
        trailing = scan(str(root), "--no-config", "--ruleset", self._rules("SPACE01", " +$", ["   ", "value = 2   "]),
                        "--rule", "SPACE01")
        self.assertEqual([f["line"] for f in trailing["findings"]], [2, 3])
        blank = scan(str(root), "--no-config", "--ruleset", self._rules("BLANK01", r"^\s*$", ["   "]), "--rule", "BLANK01")
        self.assertEqual([f["line"] for f in blank["findings"]], [2])


class ReviewPolicyIdentity(unittest.TestCase):
    @unittest.skipUnless(__import__("shutil").which("git"), "git unavailable")
    def test_the_policy_shapes_the_identity_and_the_replay_command_restores_it(self):
        rule = {"id": "STYLE001", "title": "Print call", "message": "A print call.", "fix": "Use logging.",
                "severity": "minor", "category": "style", "patterns": [r"\bprint\("], "target": "code",
                "files": ["*.py"], "examples": {"match": ["print(1)"], "no_match": ["log(1)"]}}
        doc = {"schema_version": "jankhunt.ruleset.v1", "name": "site", "rules": [rule]}
        text_only = dict(doc, rules=[dict(rule, files=["*.txt"])])
        root = project(self, {"config/site.json": json.dumps(doc), "config/text.json": json.dumps(text_only),
                              "project/sample.py": "print('hi')\n"})
        repo = str(root / "project")
        sp = __import__("subprocess")
        sp.run(["git", "-C", repo, "init", "-q"], check=True)
        sp.run(["git", "-C", repo, "add", "-A"], check=True)

        def review(policy):
            return json.loads(run_cli("review", ".", "--rule", "STYLE001", "--ruleset", policy, "--json", cwd=repo).stdout)
        first, narrowed, again = review("../config/site.json"), review("../config/text.json"), review("../config/site.json")
        self.assertNotEqual(first["scan_id"], narrowed["scan_id"])
        self.assertNotEqual(first["review"]["rulepack_hash"], narrowed["review"]["rulepack_hash"])
        self.assertEqual((first["scan_id"], first["review"]["rulepack_hash"]),
                         (again["scan_id"], again["review"]["rulepack_hash"]))
        self.assertEqual([r["name"] for r in first["rulesets"]], ["site"])
        repro = first["findings"][0]["repro"]
        self.assertIn("--ruleset ../config/site.json", repro)
        argv = __import__("shlex").split(repro)[1:]
        replay = json.loads(run_cli(*argv, cwd=repo).stdout)
        self.assertEqual([(f["rule"], f["line"], f["severity"]) for f in replay["findings"]], [("STYLE001", 1, "minor")])


class ReviewCountsIdentityAndScorecard(unittest.TestCase):
    def _repo(self, files):
        root = project(self, files)
        __import__("subprocess").run(["git", "-C", str(root), "init", "-q"], check=True)
        return root

    @unittest.skipUnless(__import__("shutil").which("git"), "git unavailable")
    def test_a_final_newline_adds_no_changed_line(self):
        counts = []
        for end in ("\n", ""):
            root = self._repo({"chip.py": "# noqa\nvalue = 1" + end})
            doc = json.loads(run_cli("review", ".", "--rule", "JH306", "--min-severity", "info", "--json",
                                     cwd=str(root)).stdout)
            counts.append((doc["review"]["scope"]["changed_lines"], doc["review"]["score"]["loc"]))
        self.assertEqual(counts, [(2, 2), (2, 2)])

    @unittest.skipUnless(__import__("shutil").which("git"), "git unavailable")
    def test_an_unrelated_clean_file_keeps_the_sarif_identity_of_an_alert(self):
        ids = []
        for extra in ({}, {"sample.py": "hue = 1\n"}):
            root = self._repo(dict({"sheet.py": "# noqa\n"}, **extra))
            sarif = json.loads(run_cli("review", ".", "--rule", "JH306", "--min-severity", "info", "--sarif",
                                       cwd=str(root)).stdout)
            ids.append([r["partialFingerprints"]["jankhunt42"] for r in sarif["runs"][0]["results"]])
        self.assertEqual(len(ids[0]), 1)
        self.assertEqual(ids[0], ids[1])

    def test_the_scorecard_names_the_policy_that_changed_a_rating(self):
        root = project(self, {"score/sheet.py": BARE,
                              "rating.json": '{"schema_version":"jankhunt.ruleset.v1","name":"studio-rating",'
                                             '"severity":{"JH217":"info"}}\n'})
        args = (str(root / "score"), "--no-config", "--rule", "JH217", "--min-severity", "info",
                "--ruleset", str(root / "rating.json"))
        card = json.loads(run_cli("scan", *args, "--score", "--json").stdout)
        full = scan(*args)
        self.assertEqual([r["name"] for r in card["rulesets"]], ["studio-rating"])
        self.assertEqual(card["rulesets"], full["rulesets"])
        self.assertEqual(card["jank"]["score"], full["summary"]["jank"]["score"])


class RevisionsUseTheSameFolderRule(unittest.TestCase):
    @unittest.skipUnless(__import__("shutil").which("git"), "git unavailable")
    def test_working_and_revision_runs_read_the_same_files(self):
        sp = __import__("subprocess")
        root = project(self, {"app.py": "x = 1\n"})
        git = ["git", "-C", str(root), "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid"]
        sp.run(["git", "-C", str(root), "init", "-q"], check=True)
        sp.run(git + ["add", "-A"], check=True)
        sp.run(git + ["commit", "-qm", "one"], check=True)
        for rel, text in ((".memo/note.py", "# noqa\n"), ("normal/note.py", "# noqa\n"), ("env/note.py", "# noqa\n"),
                          ("env/pyvenv.cfg", "home = /usr\n"), (".obsidian/plugins/palette/main.js", "console.log(1);\n")):
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text, encoding="utf-8")
        sp.run(git + ["add", "-A"], check=True)
        sp.run(git + ["commit", "-qm", "two"], check=True)
        want = [".memo/note.py", "app.py", "normal/note.py"]
        for extra in ((), ("--base", "HEAD^")):
            with self.subTest(extra=extra):
                m = json.loads(run_cli("map", ".", *extra, "--json", cwd=str(root)).stdout)
                self.assertEqual(m["coverage"]["inspected_paths"], want)
        doc = json.loads(run_cli("review", ".", "--base", "HEAD^", "--rule", "JH306", "--rule", "JH204",
                                 "--min-severity", "info", "--json", cwd=str(root)).stdout)
        self.assertEqual(sorted(f["path"] for f in doc["findings"]), [".memo/note.py", "normal/note.py"])
        reasons = {s["path"]: s["reason"] for s in doc["review"]["scope"]["skipped_files"]}
        self.assertEqual(reasons, {".obsidian/plugins/palette/main.js": "installed plugin",
                                   "env/note.py": "dependencies", "env/pyvenv.cfg": "dependencies"})

    @unittest.skipIf(os.name == "nt", "a backslash is a separator on Windows")
    def test_map_evidence_keeps_a_backslash_in_a_file_name(self):
        root = project(self, {"ink/page.py": "shade = 1\n",
                              "ink\\page.py": 'import requests\nrequests.get("https://glaze.invalid/colour")\n'})
        doc = json.loads(run_cli("map", str(root), "--no-config", "--json").stdout)
        ev = doc["evidence"].values() if isinstance(doc["evidence"], dict) else doc["evidence"]
        self.assertEqual([(e["path"], e["line"]) for e in ev if e["adapter"] == "python:http-call"], [("ink\\page.py", 2)])


class EachRevisionItsOwnConfig(unittest.TestCase):
    def _commit(self, root, message):
        sp = __import__("subprocess")
        git = ["git", "-C", str(root), "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid"]
        sp.run(git + ["add", "-A"], check=True)
        sp.run(git + ["commit", "-qm", message], check=True)

    @unittest.skipUnless(__import__("shutil").which("git"), "git unavailable")
    def test_a_working_tree_policy_edit_does_not_change_a_comparison_of_two_commits(self):
        root = project(self, {"app.py": "x = 1\n", ".jankhunt42.json": "{}\n"})
        __import__("subprocess").run(["git", "-C", str(root), "init", "-q"], check=True)
        self._commit(root, "one")
        (root / ".mcp.json").write_text('{"mcpServers":{"fetch":{"command":"npx","args":["-y","@modelcontextprotocol/server-fetch"]}}}\n')
        self._commit(root, "two")

        def row():
            d = json.loads(run_cli("map", ".", "--base", "HEAD^", "--json", cwd=str(root)).stdout)
            return d["coverage"]["inspected_paths"], len(d["delta"]["nodes"]["added"]), len(d["delta"]["edges"]["added"])
        clean = row()
        (root / ".jankhunt42.json").write_text('{"ignore":[".mcp.json"]}\n')
        self.assertEqual(row(), clean)
        self.assertEqual(clean[0], [".mcp.json", "app.py"])

    @unittest.skipUnless(__import__("shutil").which("git"), "git unavailable")
    def test_declarations_follow_the_config_choice_in_both_directions(self):
        root = project(self, {".jankhunt42.json": '{"passport":{"assets":[{"match":"application","sensitivity":"restricted"}]}}\n',
                              "sub/app.py": "value = 1\n"})
        __import__("subprocess").run(["git", "-C", str(root), "init", "-q"], check=True)
        self._commit(root, "one")
        (root / "sub" / "app.py").write_text("value = 2\n")
        self._commit(root, "two")
        got = []
        for argv in ((".", "--no-config"), (".", "--base", "HEAD^", "--no-config"), ("sub",), ("sub", "--base", "HEAD^")):
            d = json.loads(run_cli("map", *argv, "--json", cwd=str(root)).stdout)
            got.append([n.get("sensitivity") for n in d["graph"]["nodes"] if n.get("kind") == "application"])
        self.assertEqual(got, [["unknown"], ["unknown"], ["restricted"], ["restricted"]])


class ALinkWithARole(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "symbolic links")
    def test_a_link_that_makes_a_file_an_agent_command_is_read_there_and_a_plain_alias_is_not(self):
        root = project(self, {"docs/commit.md": "---\nallowed-tools: Bash\n---\nCommit the work.\n", "lib/real.py": BARE})
        (root / ".claude" / "commands").mkdir(parents=True)
        os.symlink("../../docs/commit.md", str(root / ".claude" / "commands" / "commit.md"))
        os.symlink("real.py", str(root / "lib" / "alias.py"))
        doc = scan(str(root), "--no-config", "--min-severity", "info")
        got = sorted((f["rule"], f["path"]) for f in doc["findings"] if f["rule"] in ("JH217", "JH712"))
        self.assertEqual(got, [("JH217", "lib/real.py"), ("JH712", ".claude/commands/commit.md")])
        self.assertEqual(doc["summary"]["files"], 3)


class PhpHashComments(unittest.TestCase):
    def test_a_php_hash_comment_suppresses_and_an_attribute_stays_code(self):
        root = project(self, {"card.php": "<?php\n# jankhunt42: ignore JH204\nvar_dump($shade);\n#[Route(\"/x\")]\n"
                                          "function f() { var_dump(1); }\n"})
        doc = scan(str(root), "--no-config", "--rule", "JH204")
        self.assertEqual([f["line"] for f in doc["findings"]], [5])
        self.assertEqual(doc["set_aside"].get("inline_ignore"), 1)
        import sys as _s
        _s.path.insert(0, str(Path(CLI).parent))
        import jh_core
        code, _, comments = jh_core.sanitize('#[Route("/x")]\n# note\n', "php")
        self.assertTrue(code[0].startswith("#[Route("))
        self.assertEqual(comments[1], "# note")


class CapsKeepTheMostSerious(unittest.TestCase):
    @unittest.skipUnless(__import__("shutil").which("git"), "git unavailable")
    def test_a_major_is_kept_over_earlier_minors_and_the_gate_still_fails(self):
        root = project(self, {"a.py": "breakpoint(); breakpoint()\n", "z.py": "breakpoint()\n",
                              ".jankhunt42.json": '{"paths":{"z.py":{"severity":{"JH204":"major"}}}}\n'})
        __import__("subprocess").run(["git", "init", "-q", str(root)], check=True)
        proc = run_cli("scan", str(root), "--rule", "JH204", "--max-per-rule", "2", "--fail-on", "major", "--json")
        doc = json.loads(proc.stdout)
        self.assertEqual(proc.returncode, 1)
        self.assertEqual([(f["path"], f["severity"]) for f in doc["findings"]], [("z.py", "major"), ("a.py", "minor")])
        self.assertEqual(doc["set_aside"]["capped"], 1)
        one = run_cli("scan", str(root), "--rule", "JH204", "--max-per-rule", "1", "--fail-on", "minor", "--json")
        self.assertEqual(one.returncode, 1)

    def test_a_capped_major_still_fails_the_gate(self):
        root = project(self, {"a.py": "breakpoint()\nbreakpoint()\n", "b.py": "breakpoint()\n",
                              ".jankhunt42.json": '{"paths":{"b.py":{"severity":{"JH204":"major"}}},'
                                                  '"severity":{"JH204":"major"}}\n'})
        proc = run_cli("scan", str(root), "--rule", "JH204", "--max-per-rule", "1", "--fail-on", "major", "--json")
        self.assertEqual(proc.returncode, 1)


class LinkSpellings(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "symbolic links")
    def test_a_link_that_gives_a_language_is_read_and_order_never_decides(self):
        root = project(self, {"b12/z.txt": "try:\n    count = 1\nexcept:\n    raise\n", "a17/b.py": BARE,
                              "rs.json": json.dumps({"schema_version": "jankhunt.ruleset.v1", "name": "c", "rules": [{
                                  "id": "COLOUR01", "title": "Draft colour", "message": "Check.", "fix": "x",
                                  "severity": "minor", "category": "style", "files": ["*.md"], "patterns": ["pencil"],
                                  "target": "raw", "examples": {"match": ["pencil"], "no_match": ["pen"]}}]})})
        os.symlink("z.txt", str(root / "b12" / "a.py"))
        b12 = scan(str(root / "b12"), "--rule", "JH217")
        self.assertEqual([(f["path"], f["line"]) for f in b12["findings"]], [("a.py", 3)])
        os.symlink("b.py", str(root / "a17" / "a.txt"))
        a17 = scan(str(root / "a17"), "--rule", "JH217")
        self.assertEqual(([f["path"] for f in a17["findings"]], a17["summary"]["files"]), (["b.py"], 1))
        for target in ("0.txt", "z.txt"):
            with self.subTest(target=target):
                d = root / ("b22-" + target)
                d.mkdir()
                (d / target).write_text("pencil\n")
                os.symlink(target, str(d / "a.md"))
                os.symlink(target, str(d / "b.md"))
                doc = scan(str(d), "--ruleset", str(root / "rs.json"), "--rule", "COLOUR01")
                self.assertEqual([f["path"] for f in doc["findings"]], ["a.md", "b.md"])


class RevisionRunsOnOddInput(unittest.TestCase):
    def _repo(self):
        root = project(self, {"main.py": "x = 1\n"})
        sp = __import__("subprocess")
        self.git = ["git", "-C", str(root), "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid"]
        sp.run(["git", "-C", str(root), "init", "-q"], check=True)
        sp.run(self.git + ["add", "-A"], check=True)
        sp.run(self.git + ["commit", "-qm", "one"], check=True)
        return root

    def _commit(self):
        sp = __import__("subprocess")
        sp.run(self.git + ["add", "-A"], check=True)
        sp.run(self.git + ["commit", "-qm", "two"], check=True)

    @unittest.skipUnless(__import__("shutil").which("git"), "git unavailable")
    @unittest.skipIf(os.name == "nt" or sys.platform == "darwin", "file names that are not UTF-8")
    def test_a_name_that_is_not_utf8_in_a_revision(self):
        root = self._repo()
        with open(os.path.join(os.fsencode(str(root)), b"item-\xff.py"), "wb") as fh:
            fh.write(b"number = 1\n")
        self._commit()
        for cmd in ("map", "passport"):
            with self.subTest(cmd=cmd):
                proc = __import__("subprocess").run([sys.executable, "-I", "-B", str(CLI), cmd, ".", "--base", "HEAD^", "--json"],
                                                    cwd=str(root), capture_output=True, timeout=300)
                self.assertEqual(proc.returncode, 0, proc.stderr[-300:])
                json.loads(proc.stdout.decode("utf-8"))

    @unittest.skipUnless(__import__("shutil").which("git"), "git unavailable")
    def test_a_committed_config_that_is_not_utf8_is_a_warning(self):
        root = self._repo()
        (root / ".jankhunt42.json").write_bytes(b'{"label":"caf\xe9"}\n')
        self._commit()
        proc = run_cli("map", ".", "--base", "HEAD^", "--json", cwd=str(root))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        doc = json.loads(proc.stdout)
        self.assertEqual(doc["coverage"]["inspected_paths"], ["main.py"])
        self.assertTrue(any("could not parse .jankhunt42.json" in w for w in doc["warnings"]))


class PreTagAuditBatch2(unittest.TestCase):
    @unittest.skipUnless(__import__("shutil").which("git"), "git unavailable")
    def test_an_unstaged_marker_never_changes_a_staged_review(self):
        root = project(self, {"env/draft.py": "# noqa\n"})
        sp = __import__("subprocess")
        sp.run(["git", "-C", str(root), "init", "-q"], check=True)
        sp.run(["git", "-C", str(root), "add", "env/draft.py"], check=True)
        (root / "env" / "pyvenv.cfg").write_text("home = fixture\n")
        doc = json.loads(run_cli("review", ".", "--staged", "--rule", "JH306", "--min-severity", "info", "--json",
                                 cwd=str(root)).stdout)
        self.assertEqual([f["path"] for f in doc["findings"]], ["env/draft.py"])

    def test_raised_limits_reach_every_debug_call_and_the_safety_bound_counts_the_rest(self):
        root = project(self, {"widget.py": "breakpoint()\n" * 1001})
        doc = scan(str(root), "--no-config", "--rule", "JH204", "--max-per-file-rule", "1001", "--max-per-rule", "1001")
        self.assertEqual((doc["summary"]["findings"], doc["findings"][-1]["line"]), (1001, 1001))
        sys.path.insert(0, str(Path(CLI).parent))
        import jh_checks, jh_core, jh_rules
        old = jh_checks.DEBUG_BOUND
        jh_checks.DEBUG_BOUND = 3
        try:
            sf = jh_core.source_from_text("widget.py", str(root / "widget.py"), "breakpoint()\n" * 5)
            res = jh_rules.scan_sources([sf], jh_rules.ScanOptions(rule_ids={"JH204"}, max_per_file_rule=100,
                                                                   max_per_rule=100))
        finally:
            jh_checks.DEBUG_BOUND = old
        self.assertEqual((len(res.findings), res.set_aside.get("capped")), (3, 2))

    @unittest.skipIf(os.name == "nt" or sys.platform == "darwin", "file names that are not UTF-8")
    def test_a_byte_name_and_its_escaped_spelling_stay_two_files(self):
        root = project(self, {"card-\\xFF.py": "# noqa\n"})
        with open(os.path.join(os.fsencode(str(root)), b"card-\xff.py"), "wb") as fh:
            fh.write(b"# noqa\n")
        doc = scan(str(root), "--rule", "JH306", "--min-severity", "info")
        self.assertEqual(sorted(f["path"] for f in doc["findings"]), ["card-\\\\xFF.py", "card-\\xFF.py"])

    @unittest.skipUnless(__import__("shutil").which("git"), "git unavailable")
    @unittest.skipIf(os.name == "nt", "a backslash is a separator on Windows")
    def test_a_backslash_in_an_untracked_name_is_not_a_folder(self):
        root = project(self, {"a\\b.txt": "one\n", "a/b.txt": "two\nthree\n"})
        __import__("subprocess").run(["git", "-C", str(root), "init", "-q"], check=True)
        scope = json.loads(run_cli("review", ".", "--json", cwd=str(root)).stdout)["review"]["scope"]
        self.assertEqual((scope["changed_files"], scope["changed_lines"]), (["a/b.txt", "a\\b.txt"], 3))


class PreTagAuditBatch3(unittest.TestCase):
    @unittest.skipUnless(__import__("shutil").which("git"), "git unavailable")
    def test_review_and_passport_report_a_settings_file_that_could_not_be_parsed(self):
        root = project(self, {".claude/settings.json": '{"theme":\n'})
        __import__("subprocess").run(["git", "-C", str(root), "init", "-q"], check=True)
        want = {"count": 1, "paths": [".claude/settings.json"]}
        self.assertEqual(scan(str(root), "--no-config", "--min-severity", "info")["set_aside"]["files_not_parsed"], want)
        rv = json.loads(run_cli("review", ".", "--min-severity", "info", "--json", cwd=str(root)).stdout)
        self.assertEqual(rv["review"]["set_aside"]["files_not_parsed"], want)
        pp = json.loads(run_cli("passport", str(root), "--no-config", "--json").stdout)
        self.assertEqual(pp["scope"]["set_aside"]["files_not_parsed"], want)

    @unittest.skipUnless(__import__("shutil").which("git"), "git unavailable")
    def test_a_review_sarif_with_no_alerts_says_what_it_held_back(self):
        root = project(self, {"a.py": "x = 1  # noqa\n"})
        __import__("subprocess").run(["git", "-C", str(root), "init", "-q"], check=True)
        run = json.loads(run_cli("review", ".", "--rule", "JH306", "--min-severity", "major", "--sarif",
                                 cwd=str(root)).stdout)["runs"][0]
        self.assertEqual(run["results"], [])
        self.assertEqual(run["properties"]["setAside"]["below_floor"], {"info": 1, "floor": "major"})
        self.assertTrue(run["invocations"][0]["toolExecutionNotifications"])
        self.assertEqual(run["tool"]["driver"]["informationUri"], "https://github.com/cloudbustinguk/jankhunt42")

    @unittest.skipIf(os.name == "nt", "symbolic links")
    def test_a_working_tree_map_records_what_it_skipped(self):
        root = project(self, {"lib/card.py": "n = 1\n", "build/extra.py": "n = 2\n", "yarn.lock": "{}\n"})
        os.symlink("lib", str(root / "alias"))
        cov = json.loads(run_cli("map", str(root), "--json").stdout)["coverage"]
        self.assertEqual(cov["skipped"], {"folder: build output": 1, "folder: linked folder (not followed)": 1,
                                          "lockfile": 1})
        self.assertEqual(sorted(cov["skipped_paths"]), ["alias", "build", "yarn.lock"])


class NoCapByDefault(unittest.TestCase):
    def test_every_finding_reaches_json_unless_a_limit_is_set(self):
        root = project(self, {"w.py": "breakpoint()\n" * 12})
        full = scan(str(root), "--no-config", "--rule", "JH204")
        self.assertEqual((full["summary"]["findings"], full["set_aside"].get("capped")), (12, None))
        limited = scan(str(root), "--no-config", "--rule", "JH204", "--max-per-file-rule", "5")
        self.assertEqual((limited["summary"]["findings"], limited["set_aside"].get("capped")), (5, 7))


class PreTagAuditP2(unittest.TestCase):
    @unittest.skipIf(os.name == "nt" or sys.platform == "darwin", "file names that are not UTF-8")
    def test_an_unread_file_with_a_byte_name_keeps_the_report_utf8(self):
        root = project(self, {})
        open(os.path.join(os.fsencode(str(root)), b"item-\xff.py"), "wb").close()
        proc = __import__("subprocess").run([sys.executable, "-I", "-B", str(CLI), "scan", str(root), "--json",
                                             "--no-progress"], capture_output=True, timeout=300)
        doc = json.loads(proc.stdout.decode("utf-8"))
        self.assertEqual(doc["set_aside"]["files_not_read"]["empty"]["paths"], ["item-\\xFF.py"])

    def test_two_debug_calls_on_one_line_are_two_sarif_alerts(self):
        root = project(self, {"a.py": "breakpoint(); breakpoint()\n", "b.py": "eval(input())\n"})
        run = json.loads(run_cli("scan", str(root), "--sarif", "--no-progress").stdout)["runs"][0]
        ids = {r["partialFingerprints"]["jankhunt42"] for r in run["results"] if r["ruleId"] == "JH204"}
        self.assertEqual(ids, {"JH204:a.py:1:1", "JH204:a.py:1:15"})


class InternationalHostsInSandboxLogs(unittest.TestCase):
    def test_a_unicode_host_in_a_sandbox_log_is_a_named_undeclared_destination(self):
        root = project(self, {"p/a.py": "x = 1\n"})
        log = root / "only.log"
        log.write_text(json.dumps({"class_uid": 4001, "activity_id": 1, "action_id": 1, "disposition_id": 1,
                                   "dst_endpoint": {"hostname": "caf\u00e9-other.example", "port": 443}, "time": 1}) + "\n",
                       encoding="utf-8")
        doc = json.loads(run_cli("passport", str(root / "p"), "--json", "--sandbox-log", str(log)).stdout)
        text = json.dumps(doc)
        self.assertIn("xn--caf-other-d4a.example:443", text)
        self.assertNotIn('"no_destination": 1', text)


class SecondPassBatch1(unittest.TestCase):
    def test_a_php_line_comment_ends_at_the_closing_tag(self):
        root = project(self, {"card.php": "<?php # title ?>Draft<?php var_dump($shade); ?>\n"
                                          "<?php // note ?><b>x</b><?php var_dump(2); ?>\n"})
        doc = scan(str(root), "--no-config", "--rule", "JH204")
        self.assertEqual([(f["line"], f["column"]) for f in doc["findings"]], [(1, 28), (2, 31)])

    @unittest.skipUnless(__import__("shutil").which("git"), "git unavailable")
    def test_a_git_ignored_cap_applies_before_the_limits_and_the_gate(self):
        root = project(self, {".gitignore": "draft.py\n", "draft.py": "breakpoint()\nbreakpoint()\n",
                              ".jankhunt42.json": '{"paths":{"draft.py":{"severity":{"JH204":"major"}}}}\n'})
        sp = __import__("subprocess")
        sp.run(["git", "-C", str(root), "init", "-q"], check=True)
        sp.run(["git", "-C", str(root), "add", ".gitignore", ".jankhunt42.json"], check=True)
        for limit in ("1", "2"):
            with self.subTest(limit=limit):
                proc = run_cli("scan", str(root), "--rule", "JH204", "--max-per-rule", limit, "--fail-on", "major", "--json")
                self.assertEqual(proc.returncode, 0)
                self.assertEqual({f["severity"] for f in json.loads(proc.stdout)["findings"]}, {"minor"})

    def test_overflow_past_a_checks_bound_follows_the_selection(self):
        root = project(self, {"draft.py": "breakpoint()\n" * 5})
        sys.path.insert(0, str(Path(CLI).parent))
        import jh_checks, jh_core, jh_rules
        old = jh_checks.DEBUG_BOUND
        jh_checks.DEBUG_BOUND = 3
        try:
            sf = jh_core.source_from_text("draft.py", str(root / "draft.py"), "breakpoint()\n" * 5)
            other = jh_rules.scan_sources([sf], jh_rules.ScanOptions(categories={"supply-chain"}))
            mine = jh_rules.scan_sources([sf], jh_rules.ScanOptions(rule_ids={"JH204"}))
        finally:
            jh_checks.DEBUG_BOUND = old
        self.assertEqual((other.set_aside.get("capped"), other.capped_worst), (None, None))
        self.assertEqual((len(mine.findings), mine.set_aside.get("capped")), (3, 2))


if __name__ == "__main__":
    unittest.main()
