"""Site rulesets (--ruleset FILE.json, jankhunt.ruleset.v1): site rules on the shipped engine, shipped rules set
aside or re-rated, every rule checked against its own examples, and trust that follows where the file lives."""
import json
import os
import shutil
import tempfile
import unittest

from _util import run_cli

SECRET = "Kq7Lm2" + "Xv9Pz4"
SITE_RULE = {"id": "ACME001", "title": "Internal hostname in code", "severity": "major", "category": "security",
             "message": "An internal hostname is written into the code.", "fix": "Read it from configuration.",
             "patterns": [r"\b[a-z0-9-]+\.corp\.acme\.internal\b"], "target": "raw", "files": ["*.py"],
             "examples": {"match": ['host = "db1.corp.acme.internal"'], "no_match": ["see acme.com"]}}


def ruleset(**over):
    doc = {"schema_version": "jankhunt.ruleset.v1", "name": "acme-site-policy", "rules": [dict(SITE_RULE)]}
    doc.update(over)
    return doc


class Rulesets(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="jh-rs-repo-")
        self.outside = tempfile.mkdtemp(prefix="jh-rs-ops-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.addCleanup(shutil.rmtree, self.outside, True)
        with open(os.path.join(self.root, "app.py"), "w") as fh:
            fh.write('DB_HOST = "db1.corp.acme.internal"\n')
        with open(os.path.join(self.root, "appsettings.json"), "w") as fh:
            json.dump({"ConnectionStrings": {"Db": "Server=sql.corp.internal;User Id=sa;Password=%s;" % SECRET}}, fh)

    def write(self, doc, where=None, name="site.json"):
        path = os.path.join(where or self.outside, name)
        with open(path, "w") as fh:
            fh.write(doc if isinstance(doc, str) else json.dumps(doc))
        return path

    def scan(self, *extra):
        r = run_cli("scan", self.root, "--json", *extra)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)

    def test_a_site_rule_reports_like_a_shipped_one(self):
        path = self.write(ruleset())
        d = self.scan("--ruleset", path)
        self.assertIn(("ACME001", "major", "app.py", 1), [(f["rule"], f["severity"], f["path"], f["line"])
                                                          for f in d["findings"]])
        self.assertEqual(d["rulesets"][0]["rules"], ["ACME001"])
        self.assertTrue(d["rulesets"][0]["trusted"])
        sarif = json.loads(run_cli("scan", self.root, "--sarif", "--ruleset", path).stdout)
        self.assertIn("ACME001", [r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]])
        self.assertEqual(run_cli("scan", self.root, "--fail-on", "major", "--ruleset", path,
                                 "--ignore-rule", "JH101").returncode, 1)          # a site rule gates too
        self.assertEqual(self.scan("--ruleset", path, "--ignore-rule", "acme001")["ignored_rules"], ["ACME001"])

    def test_shipped_rules_set_aside_or_rerated(self):
        d = self.scan("--ruleset", self.write(ruleset(ignore=["JH101"])))
        self.assertNotIn("JH101", [f["rule"] for f in d["findings"]])
        self.assertEqual(d["ignored_rules"], ["JH101"])
        d = self.scan("--ruleset", self.write(ruleset(severity={"JH101": "info"})))
        self.assertEqual({f["severity"] for f in d["findings"] if f["rule"] == "JH101"}, {"info"})

    def test_a_broken_ruleset_is_refused_with_its_reason(self):
        cases = [
            (ruleset(rules=[dict(SITE_RULE, examples={"match": ["nothing here"]})]), "misses its own match example"),
            (ruleset(rules=[dict(SITE_RULE, examples={"match": SITE_RULE["examples"]["match"],
                                                      "no_match": ["db2.corp.acme.internal"]})]),
             "reports its own no_match example"),
            (ruleset(rules=[dict(SITE_RULE, id="JH999")]), "reserved for shipped rules"),
            (ruleset(rules=[dict(SITE_RULE, patterns=["(unclosed"])]), "does not compile"),
            (ruleset(rules=[dict(SITE_RULE, colour="red")]), "unknown keys colour"),
            (ruleset(rules=[SITE_RULE, SITE_RULE]), "already defined"),
            (ruleset(ignore=["JH000"]), "no such rule: JH000"),
            (ruleset(schema_version="v0"), "schema_version must be"),
            (ruleset(rules=[dict(SITE_RULE, title="token " + "ghp_" + "a" * 36)]), "looks like it holds a secret"),
            (ruleset(name="ghp_" + "b" * 36), "looks like it holds a secret"),
            (ruleset(rules=[dict(SITE_RULE, category="glpat-" + "c" * 20)]), "looks like it holds a secret"),
            (ruleset(rules=[dict(SITE_RULE, title="Policy for postgres://app:" + "Hx9" + "Lw2@db.example.invalid/app")]),
             "looks like it holds a secret"),
            (ruleset(rules=[dict(SITE_RULE, title="_https://app:" + "Qv4" + "Tz8@db.example.invalid/app_")]),
             "looks like it holds a secret"),
            (ruleset(rules=[dict(SITE_RULE, message="\u6570\u636e\u5e93https://app:" + "Qv4" + "Tz8@db.example.invalid")]),
             "looks like it holds a secret"),
            (ruleset(rules=[dict(SITE_RULE, category="Not A Category!")]), "category"),
            (ruleset(rules=[dict(SITE_RULE, patterns=["a{1,999999999999999999999}"])]), "does not compile"),
            (ruleset(rules=[dict(SITE_RULE, patterns=["(a+)+$"],
                                 examples={"match": ["aaa"], "no_match": ["a" * 32 + "!"]})]), "take over"),
            ('{"schema_version": "jankhunt.ruleset.v1", "name": "a", "name": "b"}', "duplicate JSON keys"),
        ]
        for doc, why in cases:
            with self.subTest(why=why):
                r = run_cli("scan", self.root, "--ruleset", self.write(doc))
                self.assertEqual(r.returncode, 2)
                self.assertIn(why, r.stderr)
        r = run_cli("scan", self.root, "--ignore-rule", "ACME001")       # a site id needs its ruleset
        self.assertEqual(r.returncode, 2)
        self.assertIn("no such rule: ACME001", r.stderr)

    def test_a_ruleset_that_is_not_a_regular_file_is_refused_at_once(self):
        fifo = os.path.join(self.outside, "policy.fifo")
        os.mkfifo(fifo)
        r = run_cli("scan", self.root, "--json", "--ruleset", fifo)
        self.assertEqual(r.returncode, 2)
        self.assertIn("not a regular file", r.stderr)

    def test_a_runaway_site_rule_is_switched_off_and_the_scan_still_reports(self):
        # the pattern passes its own examples, then meets a line that would take it longer than the universe
        with open(os.path.join(self.root, "slow.py"), "w") as fh:
            fh.write("x = '" + "a" * 40 + "!'\n")
        slow = dict(SITE_RULE, id="SLOW001", patterns=["(a+)+$"], files=["*.py"], target="raw",
                    examples={"match": ["aaa"], "no_match": ["b"]})
        r = run_cli("scan", self.root, "--json", "--ruleset", self.write(ruleset(rules=[slow])))
        self.assertEqual(r.returncode, 0, r.stderr)
        d = json.loads(r.stdout)
        self.assertTrue(any("SLOW001 ran over" in w for w in d["warnings"]), d["warnings"])
        self.assertIn("SLOW001 ran over", r.stderr)

    @unittest.skipUnless(shutil.which("git"), "git is not installed")
    def test_review_also_reports_a_runaway_site_rule(self):
        import subprocess
        env = dict(os.environ, GIT_AUTHOR_NAME="fixture", GIT_AUTHOR_EMAIL="fixture@example.invalid",
                   GIT_COMMITTER_NAME="fixture", GIT_COMMITTER_EMAIL="fixture@example.invalid",
                   GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
        git = lambda *a: subprocess.run(["git", "-C", self.root] + list(a), env=env, check=True,  # noqa: E731
                                        capture_output=True)
        git("init", "-q")
        git("add", "-A")
        git("commit", "-qm", "base")
        with open(os.path.join(self.root, "slow.py"), "w") as fh:
            fh.write("x = '" + "a" * 40 + "!'\n")
        git("add", "-A")
        git("commit", "-qm", "change")
        slow = dict(SITE_RULE, id="SLOW002", patterns=["(a+)+$"], files=["*.py"], target="raw",
                    examples={"match": ["aaa"], "no_match": ["b"]})
        r = run_cli("review", self.root, "--base", "HEAD~1", "--json", "--ruleset", self.write(ruleset(rules=[slow])))
        self.assertIn(r.returncode, (0, 1), r.stderr)
        self.assertTrue(any("SLOW002 ran over" in w for w in json.loads(r.stdout)["warnings"]))
        self.assertIn("SLOW002 ran over", r.stderr)

    def test_the_shipped_example_loads(self):
        example = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "templates",
                               "site-ruleset.example.json")
        self.assertEqual(self.scan("--ruleset", os.path.abspath(example))["rulesets"][0]["rules"], ["SITE001"])

    def test_trust_follows_where_the_file_lives(self):
        # outside the repository: the operator's policy, honoured by the citizen governance scans too.
        # inside it: the repository's own say, like .jankhunt42.toml, which those scans do not take
        def passport(path):
            r = run_cli("passport", self.root, "--profile", "citizen", "--json", "--ruleset", path)
            return json.loads(r.stdout)
        doc = ruleset(ignore=["JH101"])
        outside = passport(self.write(doc))
        inside = passport(self.write(doc, where=self.root, name="jankhunt-site.json"))
        self.assertEqual([r["trusted"] for r in outside["scope"]["rulesets"]], [True])
        self.assertEqual([r["trusted"] for r in inside["scope"]["rulesets"]], [False])
        reasons = lambda p: [r["rule"] for r in p["assessment"]["decision"]["reasons"]]     # noqa: E731
        self.assertNotIn("P-SEC-001", reasons(outside))
        self.assertIn("P-SEC-001", reasons(inside))


if __name__ == "__main__":
    unittest.main()
