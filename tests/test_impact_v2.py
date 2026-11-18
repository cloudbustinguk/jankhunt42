"""jankhunt.exposure.v2 (4.20.0): toxic combinations beside the v1 conditions. K1 open destruction and K2 open
sensitive read (anyone can start the principal), K3 and K4 the Agents Rule of Two. Each is the minimum of its
ingredients' tiers; v1's conditions stay drivers. Invented projects and hosts only."""
import itertools
import json
import os
import shutil
import tempfile
import unittest

from _util import edge, node, run_cli
import jh_graph as G
import jh_n8n


def assess(nodes, edges):
    return G.assess({"nodes": nodes, "edges": edges}, 1)


def principal(entry=None, rule_of_two=None, **kw):
    p = node("p", "workload", **kw)
    if entry:
        p["attributes"]["entry"] = {"level": entry, "trigger": "Intake", "why": "test", "verification": "declared"}
    if rule_of_two:
        p["attributes"]["rule_of_two"] = dict({"untrusted_input": "Fetch server 'web'", "sensitive_data": "db",
                                               "acts": "Fetch server 'web'", "unapproved": []}, **rule_of_two)
    return p


def drivers(result, pid="p"):
    return [(d["level"], d["rule"], d["tier"]) for d in result["blast_radius"][pid]["drivers"]]


def flow(nodes, links, ai=()):
    """A parsed n8n workflow: nodes [(id, name, type, parameters, disabled)], main links [(src, dst)], and AI
    links [(tool or model id, agent id, channel)]."""
    doc = {"name": "Flow", "nodes": [dict({"id": i, "name": n, "type": t, "typeVersion": 2, "parameters": p,
                                           "position": [0, 0]}, **({"disabled": True} if off else {}))
                                      for i, n, t, p, off in nodes], "connections": {}}
    names = {i: n for i, n, *_ in nodes}
    for src, dst in links:
        doc["connections"].setdefault(names[src], {}).setdefault("main", [[]])[0].append(
            {"node": names[dst], "type": "main", "index": 0})
    for src, dst, channel in ai:
        doc["connections"].setdefault(names[src], {}).setdefault(channel, [[]])[0].append(
            {"node": names[dst], "type": channel, "index": 0})
    return jh_n8n.parse("flow.json", json.dumps(doc))[0]


B = "n8n-nodes-base."
L = "@n8n/n8n-nodes-langchain."


class EntryLadder(unittest.TestCase):
    def levels(self, f):
        return {k: v["level"] for k, v in jh_n8n.entry_levels(f).items()}

    def test_triggers(self):
        cases = [((B + "webhook", {}), "anyone"),
                 ((B + "webhook", {"authentication": "headerAuth"}), "signed-in"),
                 ((B + "webhook", {"options": {"ipWhitelist": "10.0.0.1"}}), "signed-in"),
                 ((B + "formTrigger", {}), "anyone"),
                 ((L + "chatTrigger", {"public": True}), "anyone"),
                 ((L + "chatTrigger", {}), "internal"),
                 ((B + "scheduleTrigger", {}), "schedule"),
                 ((B + "gmailTrigger", {}), "anyone"),
                 ((B + "executeWorkflowTrigger", {}), "internal"),
                 ((B + "manualTrigger", {}), "internal")]
        for (typ, params), want in cases:
            with self.subTest(typ=typ, params=params):
                f = flow([("t", "T", typ, params, False), ("w", "Write", B + "postgres", {"operation": "insert"}, False)],
                         [("t", "w")])
                self.assertEqual(self.levels(f), {"t": want, "w": want})

    def test_a_later_step_never_lowers_entry(self):
        """Only the trigger's own declaration lowers entry: a step that seems to check a header proves no
        rejection (a comment, a no-op, or a branch whose both outputs go on)."""
        for code in ("if ($json.headers['x-sig'] !== secret) throw new Error('no')",
                     "// headers throw\nreturn $input.all();"):
            with self.subTest(code=code):
                f = flow([("t", "T", B + "webhook", {}, False), ("c", "Check", B + "code", {"jsCode": code}, False),
                          ("w", "Write", B + "postgres", {"operation": "insert"}, False)], [("t", "c"), ("c", "w")])
                self.assertEqual(self.levels(f)["w"], "anyone")

    def test_disabled_nodes_get_no_entry_but_pass_it_on(self):
        f = flow([("t", "T", B + "webhook", {}, False), ("off", "Off", B + "postgres", {"operation": "insert"}, True),
                  ("w", "Write", B + "postgres", {"operation": "insert"}, False)], [("t", "off"), ("off", "w")])
        got = self.levels(f)
        self.assertNotIn("off", got)                     # a disabled node does not run
        self.assertEqual(got["w"], "anyone")             # n8n passes data through it

    def test_a_disabled_agent_starts_no_tools(self):
        f = flow([("t", "Chat", L + "chatTrigger", {"public": True}, False), ("a", "Agent", L + "agent", {}, True),
                  ("d", "Orders", B + "postgresTool", {"operation": "executeQuery"}, False)],
                 [("t", "a")], ai=[("d", "a", "ai_tool")])
        self.assertEqual(self.levels(f), {"t": "anyone"})

    def test_most_open_trigger_wins_and_disabled_triggers_do_not_count(self):
        f = flow([("s", "Nightly", B + "scheduleTrigger", {}, False), ("t", "Open", B + "webhook", {}, False),
                  ("o", "Off", B + "webhook", {}, True), ("w", "Write", B + "postgres", {"operation": "insert"}, False),
                  ("x", "Other", B + "postgres", {"operation": "insert"}, False)],
                 [("s", "w"), ("t", "w"), ("o", "x")])
        got = self.levels(f)
        self.assertEqual(got["w"], "anyone")
        self.assertNotIn("x", got)                       # only a disabled trigger reaches it: no entry known

    def test_tools_take_the_agent_entry(self):
        f = flow([("t", "Chat", L + "chatTrigger", {"public": True}, False), ("a", "Agent", L + "agent", {}, False),
                  ("d", "Orders", B + "postgresTool", {"operation": "executeQuery"}, False)],
                 [("t", "a")], ai=[("d", "a", "ai_tool")])
        self.assertEqual(self.levels(f), {"t": "anyone", "a": "anyone", "d": "anyone"})


class Combinations(unittest.TestCase):
    def test_k1_open_destruction(self):
        db = node("db", sensitivity="restricted")
        r = assess([principal("anyone"), db], [edge("e", "p", "db", "writes", "write", "declared")])
        self.assertEqual(r["exposure"]["class"], "Critical")
        self.assertEqual(drivers(r)[0], ("Critical", "K1-OPEN-DESTRUCTION", "supported"))
        k1 = r["blast_radius"]["p"]["drivers"][0]
        self.assertEqual([i["name"] for i in k1["ingredients"]], ["entry", "authority"])
        self.assertEqual(k1["ingredients"][0]["via"], "Intake")
        # the same principal without open entry: v1's High only
        for entry in (None, "schedule", "internal", "signed-in"):
            with self.subTest(entry=entry):
                r = assess([principal(entry), node("db", sensitivity="restricted")],
                           [edge("e", "p", "db", "writes", "write", "declared")])
                self.assertEqual(r["exposure"]["class"], "High")
                self.assertNotIn("K1-OPEN-DESTRUCTION", [d[1] for d in drivers(r)])

    def test_entry_of_unknown_or_refuted_evidence_never_fires(self):
        for verification in ("unknown", "refuted", None):
            with self.subTest(verification=verification):
                p = principal("anyone")
                p["attributes"]["entry"]["verification"] = verification
                r = assess([p, node("db", sensitivity="restricted")], [edge("e", "p", "db", "writes", "write", "declared")])
                self.assertEqual(r["exposure"]["class"], "High")
                self.assertNotIn("K1-OPEN-DESTRUCTION", [d[1] for d in drivers(r)])

    def test_k1_takes_the_weakest_tier_and_never_fires_on_unknown(self):
        r = assess([principal("anyone"), node("db", environment="production")],
                   [edge("e", "p", "db", "writes", "write", "inferred")])
        self.assertEqual(drivers(r)[0], ("Critical", "K1-OPEN-DESTRUCTION", "inferred"))
        r = assess([principal("anyone"), node("db", environment="production")],
                   [edge("e", "p", "db", "writes", "write", "unknown")])
        self.assertNotIn("K1-OPEN-DESTRUCTION", [d[1] for d in drivers(r)])

    def test_k1_needs_a_sensitive_or_production_asset(self):
        r = assess([principal("anyone"), node("db")], [edge("e", "p", "db", "writes", "write", "declared")])
        self.assertEqual(r["exposure"]["class"], "Moderate")

    def test_k2_open_sensitive_read(self):
        r = assess([principal("anyone"), node("db", sensitivity="confidential")],
                   [edge("e", "p", "db", "reads", "read", "declared")])
        self.assertEqual(r["exposure"]["class"], "High")
        self.assertIn(("High", "K2-OPEN-READ", "supported"), drivers(r))
        r = assess([principal("signed-in"), node("db", sensitivity="confidential")],
                   [edge("e", "p", "db", "reads", "read", "declared")])
        self.assertEqual(r["exposure"]["class"], "Moderate")         # v1: confidential read alone

    def test_k3_and_k4(self):
        for r2, want, rule, tier in (({"verdict": "K3", "certain": True}, "Critical", "K3-TRIFECTA", "supported"),
                                     ({"verdict": "K3", "certain": False}, "Critical", "K3-TRIFECTA", "inferred"),
                                     ({"verdict": "K4", "certain": True}, "High", "K4-TRIFECTA-SUPERVISED",
                                      "supported")):
            with self.subTest(r2=r2):
                r = assess([principal(rule_of_two=r2, trust_domain="local")], [])
                self.assertEqual(r["exposure"]["class"], want)
                self.assertEqual(drivers(r)[0], (want, rule, tier))
        # a K4 resting on a 'possible' is information only, as in the passport
        r = assess([principal(rule_of_two={"verdict": "K4", "certain": False}, trust_domain="local")], [])
        self.assertEqual(r["exposure"]["class"], "Low")

    def test_model_id(self):
        self.assertEqual(assess([principal()], [])["model"], "jankhunt.exposure.v2")


class Properties(unittest.TestCase):
    SENS = ["unknown", "public", "internal", "confidential", "restricted"]
    CRIT = ["unknown", "low", "medium", "high", "critical"]
    ENTRY = [None, "schedule", "internal", "signed-in", "anyone"]
    CAPS = ["read", "write", "delete", "admin"]
    VERS = ["unknown", "inferred", "observed", "provider-verified"]

    def cls(self, s, c, cap, v, e, r2=None):
        r = assess([principal(self.ENTRY[e], r2), node("db", sensitivity=self.SENS[s], criticality=self.CRIT[c])],
                   [edge("a", "p", "db", "writes" if self.CAPS[cap] != "read" else "reads", self.CAPS[cap],
                         self.VERS[v])])
        return G.EXPOSURE_RANK[r["exposure"]["class"]]

    def test_monotone_in_every_ordinal_including_entry(self):
        for s, c, cap, v, e in itertools.product(range(5), range(5), range(4), range(4), range(5)):
            base = self.cls(s, c, cap, v, e)
            for d in ((1, 0, 0, 0, 0), (0, 1, 0, 0, 0), (0, 0, 1, 0, 0), (0, 0, 0, 1, 0), (0, 0, 0, 0, 1)):
                up = (s + d[0], c + d[1], cap + d[2], v + d[3], e + d[4])
                if up[0] > 4 or up[1] > 4 or up[2] > 3 or up[3] > 3 or up[4] > 4:
                    continue
                self.assertGreaterEqual(self.cls(*up), base, (s, c, cap, v, e, d))

    def test_conservative_extension(self):
        """v2 never falls below v1: the same graph without the v2 ingredients."""
        for s, c, cap, v, e in itertools.product(range(5), range(5), range(4), range(4), range(5)):
            for r2 in (None, {"verdict": "K3", "certain": False}, {"verdict": "K4", "certain": True}):
                self.assertGreaterEqual(self.cls(s, c, cap, v, e, r2), self.cls(s, c, cap, v, 0), (s, c, cap, v, e, r2))

    def test_no_combination_across_principals(self):
        """Open entry on one principal and sensitive authority on another never combine."""
        open_p = principal("anyone")
        writer = node("w", "workload")
        r = assess([open_p, writer, node("db", sensitivity="restricted")],
                   [edge("e", "w", "db", "writes", "write", "declared")])
        self.assertNotIn("K1-OPEN-DESTRUCTION", [d[1] for d in drivers(r, "w")])
        self.assertEqual(r["exposure"]["per_principal"]["p"], "Low")


FLOW = {"name": "Ledger intake", "active": True, "nodes": [
    {"id": "1", "name": "Intake", "type": B + "webhook", "typeVersion": 2,
     "parameters": {"httpMethod": "POST", "path": "intake"}, "position": [0, 0]},
    {"id": "2", "name": "Write ledger", "type": B + "postgres", "typeVersion": 2.5,
     "parameters": {"operation": "insert", "schema": "public", "table": "ledger"},
     "credentials": {"postgres": {"id": "c1", "name": "Ledger DB"}}, "position": [200, 0]}],
    "connections": {"Intake": {"main": [[{"node": "Write ledger", "type": "main", "index": 0}]]}}}


class Map(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tempfile.mkdtemp()
        files = {"flow.json": json.dumps(FLOW, indent=1),
                 ".jankhunt42.json": json.dumps({"passport": {"assets": [
                     {"match": "postgresql", "sensitivity": "restricted", "criticality": "critical"}]}}),
                 "agent/.mcp.json": json.dumps({"mcpServers": {
                     "web": {"command": "uvx", "args": ["mcp-server-fetch"]},
                     "db": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-postgres",
                                                       "postgresql://app@crm.example.com/crm"]}}}),
                 "agent/.claude/settings.json": json.dumps({"permissions": {"allow": ["WebFetch", "mcp__web"]}})}
        for rel, text in files.items():
            os.makedirs(os.path.join(cls.root, os.path.dirname(rel)), exist_ok=True)
            with open(os.path.join(cls.root, rel), "w") as fh:
                fh.write(text)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root)

    def test_map(self):
        p = run_cli("map", self.root, "--json")
        self.assertIn(p.returncode, (0, 1), p.stderr)
        d = json.loads(p.stdout)
        a = d["assessment"]
        self.assertEqual((a["model"], a["exposure"]["class"]), ("jankhunt.exposure.v2", "Critical"))
        rules = {dr["rule"] for br in a["blast_radius"].values() for dr in br["drivers"]}
        self.assertTrue({"K1-OPEN-DESTRUCTION", "K3-TRIFECTA"} <= rules, rules)
        nodes = {n["display_label"]: n for n in d["graph"]["nodes"]}
        self.assertEqual(nodes["Write ledger"]["attributes"]["entry"]["level"], "anyone")
        agent = next(n for n in d["graph"]["nodes"] if n["attributes"].get("platform") == "ai-agent")
        self.assertEqual(agent["attributes"]["rule_of_two"]["verdict"], "K3")
        self.assertTrue(agent["attributes"]["rule_of_two"]["certain"])   # read the settings from the map's files

    def test_citizen_passport_blocks_on_exposure(self):
        p = run_cli("passport", self.root, "--json", "--profile", "citizen")
        self.assertIn(p.returncode, (0, 1), p.stderr)
        rules = {r["rule"]: r for r in json.loads(p.stdout)["assessment"]["decision"]["rules"]}
        self.assertEqual(rules["P-EXP-001"]["outcome"], "block")

    def test_standard_passport_asks_for_an_owner_at_high_exposure(self):
        """The standard profile sets no exposure maximum, but P-OWN-001 asks for an owner from High up, so a
        combination that raises the class can change a standard decision too (documented in the changelog)."""
        p = run_cli("passport", self.root, "--json")
        self.assertIn(p.returncode, (0, 1), p.stderr)
        rules = {r["rule"]: r for r in json.loads(p.stdout)["assessment"]["decision"]["rules"]}
        self.assertEqual(rules["P-OWN-001"]["outcome"], "review")

    def test_shareable_map_withholds_combination_ingredients(self):
        p = run_cli("map", self.root, "--json", "--redact")
        self.assertIn(p.returncode, (0, 1), p.stderr)
        d = json.loads(p.stdout)
        parts = [i for br in d["assessment"]["blast_radius"].values() for dr in br["drivers"]
                 for i in dr.get("ingredients") or []]
        self.assertTrue(parts)
        for i in parts:
            for key in ("via", "sources"):
                if key in i:
                    self.assertEqual(i[key], "withheld from the shareable copy")
        self.assertNotIn("Intake", p.stdout)                 # the trigger's name
        self.assertNotIn("Fetch server 'web'", p.stdout)     # the agent's parts, as the ingredients name them


class KeepStrongest(unittest.TestCase):
    def test_order_independent_for_entry_and_rule_of_two(self):
        import jh_map
        cases = [("entry", jh_map._entry_rank, [{"level": lv} for lv in ("schedule", "internal", "signed-in", "anyone")]),
                 ("rule_of_two", jh_map._rule_of_two_rank,
                  [{"verdict": "K4", "certain": False}, {"verdict": "K4", "certain": True},
                   {"verdict": "K3", "certain": False}, {"verdict": "K3", "certain": True}])]
        for key, rank, weakest_first in cases:
            for order in itertools.permutations(weakest_first):
                with self.subTest(key=key, order=order):
                    attrs = {}
                    for value in order:
                        jh_map.keep_strongest(attrs, key, value, rank)
                    self.assertEqual(attrs[key], weakest_first[-1])


class DuplicateExports(unittest.TestCase):
    """Two exports of one workflow: the strongest evidence counts, whatever the file names."""

    def export(self, link_from):
        doc = json.loads(json.dumps(FLOW))
        doc["id"] = "same-workflow"
        doc["nodes"].append({"id": "3", "name": "Nightly", "type": B + "scheduleTrigger", "typeVersion": 1.2,
                             "parameters": {}, "position": [0, 200]})
        doc["connections"] = {link_from: {"main": [[{"node": "Write ledger", "type": "main", "index": 0}]]}}
        return json.dumps(doc)

    def run_map(self, names):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, True)
        files = {names[0]: self.export("Intake"), names[1]: self.export("Nightly"),
                 ".jankhunt42.json": json.dumps({"passport": {"assets": [
                     {"match": "postgresql", "sensitivity": "restricted", "criticality": "critical"}]}})}
        for rel, text in files.items():
            with open(os.path.join(root, rel), "w") as fh:
                fh.write(text)
        p = run_cli("map", root, "--json")
        self.assertIn(p.returncode, (0, 1), p.stderr)
        d = json.loads(p.stdout)
        writer = next(n for n in d["graph"]["nodes"] if n["display_label"] == "Write ledger")
        return d["assessment"]["exposure"]["class"], writer["attributes"]["entry"]["level"]

    def test_file_order_does_not_decide(self):
        self.assertEqual(self.run_map(("a.json", "z.json")), ("Critical", "anyone"))
        self.assertEqual(self.run_map(("z.json", "a.json")), ("Critical", "anyone"))


if __name__ == "__main__":
    unittest.main()
