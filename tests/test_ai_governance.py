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


def _map(principals, stores, services):
    """A minimal map report: every principal reaches every store and service."""
    nodes = [{"id": p, "display_label": p, "kind": "application", "attributes": {}, "sensitivity": "unknown"}
             for p in principals]
    nodes += [{"id": s, "display_label": s, "kind": "database", "attributes": {"engine": "postgresql"},
               "sensitivity": "restricted"} for s in stores]
    nodes += [{"id": a, "display_label": a, "kind": "external", "attributes": {"engine": "openai"},
               "sensitivity": "unknown"} for a in services]
    reach = {n: {"tier": 2} for n in list(stores) + list(services)}
    radii = {p: {"impacts": {"confidentiality": dict(reach)}} for p in principals}
    return {"graph": {"nodes": nodes}, "assessment": {"blast_radius": radii}}


class Inventory(unittest.TestCase):
    def test_one_entry_per_store_and_service_with_every_principal(self):
        ai = jh_passport.ai_inventory(_map(["p1", "p2", "p3"], ["ledger"], ["openai"]), [], [], {})
        self.assertEqual([(x["data"], x["ai_service"], x["reached_by"]) for x in ai["sensitive_data_with_ai"]],
                         [("ledger", "openai", ["p1", "p2", "p3"])])

    def test_the_rule_sees_every_pair_not_the_display_cap(self):
        stores = ["store-%02d" % i for i in range(25)]
        ai = jh_passport.ai_inventory(_map(["p%d" % i for i in range(7)], stores, ["openai"]), [], [], {})
        self.assertEqual(len(ai["sensitive_data_with_ai"]), 25)
        eff = jh_policy.merge(None, [], [], None)
        out = jh_policy.evaluate(eff, {"files_scanned": 1, "map_files_inspected": 1,
                                       "ai_sensitive_pairs": ai["sensitive_data_with_ai"]}, {"nodes": [], "edges": []})
        rule = {r["rule"]: r for r in out["rules"]}["P-AI-001"]
        self.assertTrue(rule["message"].startswith("25 confidential or restricted data store(s)"), rule["message"])

    def test_without_a_map_the_rule_says_not_assessed(self):
        eff = jh_policy.merge(None, [], [], None)
        out = jh_policy.evaluate(eff, {"files_scanned": 1}, None)
        rule = {r["rule"]: r for r in out["rules"]}["P-AI-001"]
        self.assertEqual(rule["outcome"], "pass")
        self.assertIn("not assessed", rule["message"])


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
        self.assertEqual(ai["human_oversight"], "no agent tooling observed")      # an SDK call is not an agent
        self.assertEqual(sorted(p["sensitivity"] for p in ai["sensitive_data_with_ai"]), ["confidential", "restricted"])
        self.assertEqual({tuple(p["reached_by"]) for p in ai["sensitive_data_with_ai"]}, {("demo-app",)})
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

    def test_redaction_hides_instruction_file_paths(self):
        repo = tempfile.mkdtemp(prefix="jh-agentfiles-")
        try:
            os.makedirs(os.path.join(repo, ".claude", "agents"))
            with open(os.path.join(repo, ".claude", "agents", "payments-ledger-migrator.md"), "w") as fh:
                fh.write("Migrate the ledger tables carefully.\n")
            with open(os.path.join(repo, "app.py"), "w") as fh:
                fh.write("import json\n")
            p = json.loads(run_cli("passport", repo, "--json").stdout)
            md = run_cli("passport", repo, "--md", "--redact").stdout
        finally:
            shutil.rmtree(repo, ignore_errors=True)
        self.assertEqual(p["ai"]["instruction_files"], [".claude/agents/payments-ledger-migrator.md"])
        self.assertEqual(p["ai"]["human_oversight"], "no approval bypass observed")
        self.assertEqual(jh_passport.redact(p)["ai"]["instruction_files"], ["instruction-file-1"])
        self.assertNotIn("payments-ledger-migrator", md)

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
