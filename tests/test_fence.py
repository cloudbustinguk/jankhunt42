"""passport --emit-sandbox-policy: a least-privilege network fence for an AI
coding agent, in Claude Code, Codex and OpenShell formats. The fence must
leave production out, never guess a host, never let a hostile host name
become a rule, and read back through jankhunt42's own boundary readers as the
same allowlist."""
import json
import os
import unittest

import _util
from _util import run_cli
import jh_egress
import jh_fence

DEMO = os.path.join(_util.FIXTURES, "demo-app")
SAVED = {".claude/settings.json": "claude-code", ".codex/config.toml": "codex", "sandbox/policy.yaml": "openshell"}


class Item:
    def __init__(self, rel, text):
        self.rel, self.text = rel, text


class Emit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.out, cls.err = {}, {}
        for fmt in jh_fence.FORMATS:
            p = run_cli("passport", DEMO, "--emit-sandbox-policy", fmt)
            assert p.returncode == 0, p.stderr
            cls.out[fmt], cls.err[fmt] = p.stdout, p.stderr
        cls.map = json.loads(run_cli("map", DEMO, "--json").stdout)

    def test_valid_and_deterministic(self):
        for fmt in jh_fence.FORMATS:
            self.assertEqual(jh_fence.validate(fmt, self.out[fmt]), [], fmt)
            self.assertEqual(run_cli("passport", DEMO, "--emit-sandbox-policy", fmt).stdout, self.out[fmt], fmt)

    def test_production_is_left_out_and_said_so(self):
        for fmt in jh_fence.FORMATS:
            self.assertIn("api.openai.com", self.out[fmt], fmt)
            self.assertIn("registry.npmjs.org", self.out[fmt], fmt)
            self.assertNotIn("ledger-db.prod.internal", self.out[fmt], fmt)
            self.assertIn("ledger-db.prod.internal: production", self.err[fmt], fmt)
            self.assertIn("could not name the host", self.err[fmt], fmt)

    def test_reads_back_as_the_same_allowlist(self):
        want = {r["host"] for r in jh_fence.plan(self.map, None)["allow"]}
        for rel, fmt in SAVED.items():
            bounds = jh_egress.boundaries([Item(rel, self.out[fmt])])
            self.assertEqual(len(bounds), 1, fmt)
            self.assertLessEqual(want, set(bounds[0]["allow"]), fmt)
            # everything the map reaches outside the fence is something the fence excluded on purpose
            outside = {o["host"] for o in jh_egress.compare(bounds, self.map)["outside"]}
            self.assertEqual(outside, {"ledger-db.prod.internal"}, fmt)

    def test_codex_boundary_with_trailing_comments(self):
        text = ('[features]\nnetwork_proxy = true  # on\n[permissions.p.network.domains]\n'
                '"api.openai.com" = "allow"  # the API\n"x#y.example.com" = "deny" # a hash inside quotes\n')
        bounds = jh_egress.boundaries([Item(".codex/config.toml", text)])
        self.assertEqual(bounds[0]["allow"], ["api.openai.com"])
        self.assertEqual(bounds[0]["deny"], ["x#y.example.com"])

    def test_enforcement_caveats_are_stated(self):
        self.assertIn("strictAllowlist", self.err["claude-code"])
        self.assertIn("network_proxy = true", self.out["codex"])
        self.assertIn("real paths", self.out["openshell"])

    def test_cannot_be_combined_with_another_output(self):
        p = run_cli("passport", DEMO, "--emit-sandbox-policy", "codex", "--json")
        self.assertEqual(p.returncode, 2)


class Hostile(unittest.TestCase):
    BAD = ['evil.com"\n"*" = "allow', "x.com\n      - host: '*'", "*", "*.com", "a b.com", "..", "999.1.1.1",
           "evil.com\"]}", "-lead.example.com", "x" * 300 + ".com"]

    def report(self, hosts):
        nodes = [{"id": "external:%d" % i, "kind": "external", "display_label": "n%d" % i, "trust_domain": "external",
                  "environment": "unknown", "attributes": {"engine": "https", "host": h}} for i, h in enumerate(hosts)]
        return {"graph": {"nodes": nodes, "edges": []}}

    def test_hostile_names_never_become_rules(self):
        rep = self.report(self.BAD + ["api.ok.example.com"])
        for fmt in jh_fence.FORMATS:
            text, notes = jh_fence.emit(fmt, rep, None, "test")
            self.assertEqual(jh_fence.validate(fmt, text), [], fmt)
            self.assertIn("api.ok.example.com", text, fmt)
            for bad in self.BAD:
                self.assertNotIn(bad, text, (fmt, bad))
            self.assertNotIn('"*" = "allow"', text, fmt)
            self.assertNotIn("host: '*'\n", text, fmt)
            self.assertEqual(sum("not a plain host name" in n for n in notes), len(self.BAD), fmt)

    def test_clean_host(self):
        self.assertEqual(jh_fence.clean_host("https://API.Example.com:8443/v1?x=1"), "api.example.com")
        self.assertEqual(jh_fence.clean_host("user@db.example.com"), "db.example.com")
        self.assertEqual(jh_fence.clean_host("*.example.com"), "*.example.com")
        self.assertEqual(jh_fence.clean_host("10.0.0.7"), "10.0.0.7")
        self.assertEqual(jh_fence.clean_host("cache"), "cache")
        for bad in self.BAD:
            self.assertIsNone(jh_fence.clean_host(bad), bad)


if __name__ == "__main__":
    unittest.main()
