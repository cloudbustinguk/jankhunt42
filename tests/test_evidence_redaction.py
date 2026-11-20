"""4.21.1: a credential on the same line as a finding never reaches any output, and four small robustness fixes.
Invented hosts and canary values only (assembled at run time so this file holds no secret-shaped literal)."""
import json
import os
import shutil
import tempfile
import unittest

from _util import run_cli
import jh_capabilities
import jh_core

PASS = "canary-" + "Zq9TgW4rLm2Pv8"
KEY = "canary-" + "Hx7Lp3Qw9Rt"
CRED = "canary-" + "Bn5Vc2Xz8Kj"
ONE_LINE = {
    "a/.claude/settings.json": '{"env": {"SSH_PASSPHRASE": "%s"}, "permissions": {"allow": ["Bash(make:*)"]}}\n' % PASS,
    "a/.mcp.json": '{"mcpServers": {"ev": {"type": "sse", "url": "https://mcp.example.com/sse", "headers": '
                   '{"Authorization": "ApiKey %s", "X-Deploy-Credentials": "%s"}}}}\n' % (KEY, CRED),
    "a/package.json": '{"name": "a", "version": "1.0.0"}\n',
}


def write(root, files):
    for rel, text in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)


class NoCredentialInAnyOutput(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tempfile.mkdtemp()
        write(cls.root, ONE_LINE)
        cls.project = os.path.join(cls.root, "a")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root)

    def assert_clean(self, text, what):
        for canary in (PASS, KEY, CRED):
            self.assertNotIn(canary, text, "%s leaked a credential" % what)

    def test_scan_json_and_sarif(self):
        p = run_cli("scan", self.project, "--json", "--min-severity", "info", "--no-progress")
        rules = {f["rule"] for f in json.loads(p.stdout)["findings"]}
        self.assertTrue({"JH703", "JH715", "JH706"} <= rules, rules)       # the findings themselves still appear
        self.assert_clean(p.stdout + p.stderr, "scan --json")
        s = run_cli("scan", self.project, "--sarif", "--min-severity", "info", "--no-progress")
        self.assert_clean(s.stdout + s.stderr, "scan --sarif")

    def test_map_and_passport(self):
        for args in (("map", self.project, "--json"), ("passport", self.project, "--json"),
                     ("passport", self.project, "--json", "--profile", "citizen")):
            p = run_cli(*args)
            self.assert_clean(p.stdout + p.stderr, " ".join(args[:1] + args[2:]))

    def test_new_findings_carry_structural_evidence(self):
        p = run_cli("scan", self.project, "--json", "--min-severity", "info", "--no-progress", "--category", "agent")
        ev = {f["rule"]: f["evidence"] for f in json.loads(p.stdout)["findings"] if f["rule"] in ("JH703", "JH715")}
        self.assertEqual(ev["JH715"], "ev: transport sse")
        self.assertEqual(ev["JH703"], "permissions.allow: Bash(make:*)")


class Redactor(unittest.TestCase):
    def test_prefixed_secret_names_and_any_authorization_scheme(self):
        cases = ['"SSH_PASSPHRASE": "%s"' % PASS, '"Authorization": "ApiKey %s"' % KEY, '"Authorization": "%s"' % KEY,
                 "Authorization: Custom %s" % KEY, 'AWS_CREDENTIALS="%s"' % CRED, '"db_pwd": "%s"' % CRED,
                 '"X-Deploy-Credentials": "%s"' % CRED]
        for text in cases:
            self.assertNotIn("canary-", jh_core.redact_secrets(text), text)

    def test_ordinary_text_is_kept(self):
        for text in ('"type": "sse", "url": "https://mcp.example.com/sse"', '"allow": ["Bash(make:*)"]',
                     '"name": "credentials-helper", "version": "1.0.0"'):
            self.assertEqual(jh_core.redact_secrets(text), text)


class Robustness(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.root)

    def scan(self, *extra):
        p = run_cli("scan", self.root, "--json", "--min-severity", "info", "--no-progress", *extra)
        return p, json.loads(p.stdout)["findings"]

    def test_only_documented_sse_names_are_sse(self):
        write(self.root, {".mcp.json": json.dumps({"mcpServers": {
            "bad": {"type": "not-sse", "url": "https://a.example.com/mcp"},
            "old": {"type": "http+sse", "url": "https://b.example.com/sse"},
            "new": {"type": "http", "url": "https://c.example.com/mcp"}}})})
        _, fs = self.scan("--rule", "JH715")
        self.assertEqual(sorted(f["extra"]["server"] for f in fs), ["old"])

    def test_a_non_list_allow_does_not_stop_the_rule_of_two(self):
        write(self.root, {".mcp.json": json.dumps({"mcpServers": {
            "web": {"command": "uvx", "args": ["mcp-server-fetch==2025.4.7"]},
            "db": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-postgres@0.6.2",
                                               "postgresql://app@crm-db.example.com/crm"]}}}),
                          ".claude/settings.json": json.dumps({"permissions": {"allow": True}})})
        p, fs = self.scan("--rule", "JH714")
        self.assertNotIn("failed", p.stderr.lower())
        self.assertEqual(len(fs), 1)

    def test_malformed_syft_license_is_a_gap_not_a_crash(self):
        write(self.root, {"app.syft.json": json.dumps({
            "artifacts": [{"name": "left-pad", "version": "1.3.0", "purl": "pkg:npm/left-pad@1.3.0",
                           "licenses": [{"value": 42}]}],
            "source": {"type": "file", "name": "app.tar.gz"},
            "descriptor": {"name": "syft", "version": "1.0.0"},
            "schema": {"version": "16.1.0", "url": "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-16.1.0.json"}})})
        p = run_cli("passport", self.root, "--json")
        doc = json.loads(p.stdout)
        self.assertIn("provenance", doc)

    def test_each_license_candidate_is_judged(self):
        import jh_supply
        self.assertEqual(jh_supply._license([{"license": {"name": "NOASSERTION"}}, {"license": {"name": "NONE"}}]), "")
        self.assertEqual(jh_supply._license(["NOASSERTION", "MIT"]), "MIT")

    def test_jh715_is_in_the_control_inventory(self):
        self.assertIn("JH715", jh_capabilities.AGENT_RULES)


if __name__ == "__main__":
    unittest.main()
