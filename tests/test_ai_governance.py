"""AI governance in the passport: the AI-use inventory, P-AI-001 (sensitive
data reachable alongside an external AI service), and the NIST AI RMF /
AIGP orientation crosswalk, which must cover every policy rule and quote
every subcategory it cites."""
import json
import os
import shutil
import tempfile
import unittest

import _util
from _util import run_cli
import jh_frameworks
import jh_passport
import jh_policy


class Crosswalk(unittest.TestCase):
    def test_every_policy_rule_has_a_crosswalk_entry(self):
        self.assertEqual(set(jh_frameworks.RULES), set(jh_policy.RULES))

    def test_every_cited_subcategory_is_quoted(self):
        cited = {sub for table in (jh_frameworks.RULES, jh_frameworks.EVIDENCE)
                 for rmf, _ in table.values() for sub in rmf}
        self.assertEqual(cited - set(jh_frameworks.AI_RMF), set())
        domains = {d for table in (jh_frameworks.RULES, jh_frameworks.EVIDENCE) for _, aigp in table.values()
                   for d in aigp}
        self.assertEqual(domains - set(jh_frameworks.AIGP_DOMAINS), set())

    def test_alignment_lists_triggered_rules_with_their_text(self):
        al = jh_frameworks.alignment(["P-AI-001", "P-CUS-001"])
        self.assertIn("not a conformity assessment", al["note"])
        self.assertEqual(al["triggered"]["P-AI-001"]["nist_ai_rmf"], ["MEASURE 2.10", "MAP 4.1", "GOVERN 6.1",
                                                                     "MANAGE 3.1"])
        self.assertTrue(al["subcategories"]["MEASURE 2.10"].startswith("Privacy risk of the AI system"))
        self.assertTrue(al["subcategories"]["GOVERN 2.1"].startswith("Roles and responsibilities"))


class DemoPassport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="jh-aigov-")
        cls.root = os.path.join(cls.tmp, "demo-app")
        shutil.copytree(os.path.join(_util.FIXTURES, "demo-app"), cls.root)
        cls.std = json.loads(run_cli("passport", cls.root, "--json").stdout)
        cls.cit = json.loads(run_cli("passport", cls.root, "--json", "--profile", "citizen").stdout)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def reasons(self, p):
        return {r["rule"]: r for r in p["assessment"]["decision"]["reasons"]}

    def test_inventory_lists_the_model_service(self):
        ai = self.std["ai"]
        self.assertEqual([(s["label"], s["evidence"], s["reached_by"]) for s in ai["model_services"]],
                         [("openai api.openai.com", "inferred", ["demo-app"])])
        self.assertEqual(ai["human_oversight"], "no approval bypass observed")
        self.assertEqual(sorted(p["sensitivity"] for p in ai["sensitive_data_with_ai"]), ["confidential", "restricted"])
        self.assertTrue(all("_id" not in k for p in ai["sensitive_data_with_ai"] for k in p))

    def test_sensitive_data_and_ai_service_ask_for_review_or_block(self):
        self.assertEqual(self.reasons(self.std)["P-AI-001"]["outcome"], "review")
        self.assertEqual(self.reasons(self.cit)["P-AI-001"]["outcome"], "block")
        self.assertIn("P-AI-001", self.std["alignment"]["triggered"])
        self.assertTrue(any("AI services" in b for b in self.std["governance"]["brief"]))

    def test_redaction_hides_ai_labels(self):
        red = jh_passport.redact(self.std)
        blob = json.dumps({"ai": red["ai"], "decision": red["assessment"]["decision"]})
        for word in ("api.openai.com", "ledger-db", "demo-reports-prod"):
            self.assertNotIn(word, blob)

    def test_views_show_ai_use_and_orientation(self):
        md = run_cli("passport", self.root, "--md").stdout
        self.assertIn("## AI use", md)
        self.assertIn("## Framework orientation (NIST AI RMF, AIGP)", md)
        html = run_cli("passport", self.root, "--html").stdout
        self.assertIn('"alignment"', html)

    def test_no_ai_service_passes(self):
        empty = tempfile.mkdtemp(prefix="jh-noai-")
        try:
            with open(os.path.join(empty, "app.py"), "w") as fh:
                fh.write("import json\n")
            p = json.loads(run_cli("passport", empty, "--json").stdout)
        finally:
            shutil.rmtree(empty, ignore_errors=True)
        self.assertEqual(p["ai"]["model_services"], [])
        self.assertNotIn("P-AI-001", self.reasons(p))


if __name__ == "__main__":
    unittest.main()
