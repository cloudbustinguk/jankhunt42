"""--ignore-rule: an operator sets a rule aside for one run (in CI, for a rule the team owns), and every output
says so. The rule's findings are not reported, scored or gated on; an unknown id is refused."""
import json
import os
import shutil
import tempfile
import unittest

from _util import run_cli

WORKFLOW = ("name: ci\non: push\npermissions:\n  contents: read\njobs:\n  t:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - uses: some-vendor/deploy-action@v2\n      - run: echo hi\n")
SECRET = "Kq7Lm2" + "Xv9Pz4"


class IgnoreRule(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tempfile.mkdtemp(prefix="jh-ignore-")
        os.makedirs(os.path.join(cls.root, ".github", "workflows"))
        with open(os.path.join(cls.root, ".github", "workflows", "ci.yml"), "w") as fh:
            fh.write(WORKFLOW)
        with open(os.path.join(cls.root, "appsettings.json"), "w") as fh:
            json.dump({"ConnectionStrings": {"Db": "Server=sql.corp.internal;User Id=sa;Password=%s;" % SECRET}}, fh)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root, True)

    def scan(self, *extra):
        return json.loads(run_cli("scan", self.root, "--json", *extra).stdout)

    def test_scan_drops_the_rule_and_says_so(self):
        before = self.scan()
        self.assertIn("JH417", [f["rule"] for f in before["findings"]])
        self.assertNotIn("ignored_rules", before)
        after = self.scan("--ignore-rule", "jh417")          # any case, as typed
        self.assertNotIn("JH417", [f["rule"] for f in after["findings"]])
        self.assertIn("JH101", [f["rule"] for f in after["findings"]])
        self.assertEqual(after["ignored_rules"], ["JH417"])
        self.assertNotIn("JH417", run_cli("scan", self.root, "--sarif", "--ignore-rule", "JH417").stdout)

    def test_the_gate_no_longer_counts_it(self):
        self.assertEqual(run_cli("scan", self.root, "--fail-on", "major", "--ignore-rule", "JH101").returncode, 1)
        self.assertEqual(run_cli("scan", self.root, "--fail-on", "major", "--ignore-rule", "JH101,JH417").returncode, 0)
        self.assertEqual(run_cli("scan", self.root, "--fail-on", "major", "--ignore-rule", "JH101",
                                 "--ignore-rule", "JH417").returncode, 0)

    def test_an_unknown_rule_is_refused(self):
        r = run_cli("scan", self.root, "--ignore-rule", "JH417,JH471")
        self.assertEqual(r.returncode, 2)
        self.assertIn("no such rule: JH471", r.stderr)

    def test_the_passport_records_it_and_its_governance_scans_honour_it(self):
        # the citizen profile's governance scans ignore repository config, but this is the operator's own flag
        def passport(*extra):
            return json.loads(run_cli("passport", self.root, "--profile", "citizen", "--json", *extra).stdout)
        before = passport()
        self.assertNotIn("ignored_rules", before["scope"])
        self.assertIn("P-SEC-001", [r["rule"] for r in before["assessment"]["decision"]["reasons"]])
        after = passport("--ignore-rule", "JH101")
        self.assertEqual(after["scope"]["ignored_rules"], ["JH101"])
        self.assertNotIn("P-SEC-001", [r["rule"] for r in after["assessment"]["decision"]["reasons"]])
        self.assertNotIn("JH101", [p["rule"] for p in after["governance"]["top_problems"]])
        self.assertIn("JH417", [p["rule"] for p in after["governance"]["top_problems"]])     # not ignored: still there


if __name__ == "__main__":
    unittest.main()
