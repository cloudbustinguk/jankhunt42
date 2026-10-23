"""Reachability vs the independent oracle, metamorphic properties, exposure
monotonicity, and endpoint sanitizing."""
import copy
import itertools
import json
import random
import unittest

import _util
from _util import edge, node
import oracle
import jh_graph as G

KINDS = ["connects", "authenticates-as", "reads", "writes", "deletes", "administers", "calls",
         "publishes", "exports", "depends-on"]
CAPS = ["none", "read", "write", "delete", "admin", "unknown"]
VERS = ["provider-verified", "observed", "declared", "inferred", "unknown", "refuted"]


def random_graph(rng, n_nodes, n_edges):
    nodes = [node("n%d" % i, rng.choice(["application", "database", "identity", "api", "external"]))
             for i in range(n_nodes)]
    edges = []
    for i in range(n_edges):
        s, t = rng.randrange(n_nodes), rng.randrange(n_nodes)
        if s == t:
            continue
        edges.append(edge("e%03d" % i, "n%d" % s, "n%d" % t, rng.choice(KINDS), rng.choice(CAPS), rng.choice(VERS)))
    return nodes, edges


def prod_tiers(edges, src, impact, depth):
    r, _ = G.reach(edges, src, impact, depth)
    return {k: v["tier"] for k, v in r.items()}, r


class OracleAgreement(unittest.TestCase):
    def check(self, edges, src, depth):
        by_id = {e["id"]: e for e in edges}
        for impact in G.IMPACTS:
            tiers, full = prod_tiers(edges, src, impact, depth)
            expect = oracle.reach(edges, src, impact, depth)
            self.assertEqual(tiers, expect, "impact %s from %s" % (impact, src))
            for nid, info in full.items():
                self.assertTrue(oracle.path_is_valid(by_id, src, nid, info["path"], impact, info["tier"], depth),
                                "bad witness for %s/%s: %s" % (impact, nid, info["path"]))

    def test_seeded_random_small_graphs(self):
        rng = random.Random(4242)
        for _ in range(400):
            nodes, edges = random_graph(rng, rng.randint(2, 7), rng.randint(0, 14))
            for depth in (1, 2, 4):
                self.check(edges, "n0", depth)

    def test_cycles_terminate_and_match(self):
        edges = [edge("a", "p", "x", "writes", "write"), edge("b", "x", "y", "authenticates-as", "unknown"),
                 edge("c", "y", "x", "writes", "write"), edge("d", "y", "p", "connects", "unknown")]
        self.check(edges, "p", 6)

    def test_parallel_edges_best_tier_wins(self):
        edges = [edge("a", "p", "db", "connects", "unknown", "observed"),
                 edge("b", "p", "db", "writes", "write", "provider-verified")]
        tiers, _ = prod_tiers(edges, "p", "integrity", 4)
        self.assertEqual(tiers, {"db": 3})
        self.check(edges, "p", 4)

    def test_read_only_never_integrity(self):
        edges = [edge("a", "p", "db", "reads", "read", "provider-verified")]
        self.assertEqual(prod_tiers(edges, "p", "integrity", 4)[0], {})
        self.assertEqual(prod_tiers(edges, "p", "confidentiality", 4)[0], {"db": 3})

    def test_unknown_capability_is_potential_never_verified(self):
        edges = [edge("a", "p", "db", "connects", "unknown", "provider-verified")]
        for impact in G.IMPACTS:
            self.assertEqual(prod_tiers(edges, "p", impact, 4)[0], {"db": 1})

    def test_depends_on_is_not_authority(self):
        edges = [edge("a", "p", "db", "depends-on", "none", "declared")]
        for impact in G.IMPACTS:
            self.assertEqual(prod_tiers(edges, "p", impact, 4)[0], {})

    def test_multiple_identities_and_shared_target(self):
        edges = [edge("a", "p", "id1", "authenticates-as", "unknown", "declared"),
                 edge("b", "p", "id2", "authenticates-as", "unknown", "inferred"),
                 edge("c", "id1", "db", "writes", "write", "declared"),
                 edge("d", "id2", "db", "administers", "admin", "provider-verified")]
        tiers, full = prod_tiers(edges, "p", "integrity", 4)
        self.assertEqual(tiers["db"], 2)
        self.assertEqual(list(full).count("db"), 1)
        self.check(edges, "p", 4)

    def test_api_proxy_does_not_invent_direct_db_edge(self):
        edges = [edge("a", "p", "api", "calls", "write", "observed"),
                 edge("b", "api", "db", "writes", "write", "declared")]
        _, full = prod_tiers(edges, "p", "integrity", 4)
        self.assertEqual(full["db"]["path"], ["a", "b"])  # transitive witness, no direct edge

    def test_depth_truncation_is_reported(self):
        edges = [edge("e%d" % i, "n%d" % i, "n%d" % (i + 1), "writes", "write") for i in range(6)]
        r, trunc = G.reach(edges, "n0", "integrity", 3)
        self.assertTrue(trunc)
        self.assertEqual(sorted(r), ["n1", "n2", "n3"])
        r, trunc = G.reach(edges, "n0", "integrity", 8)
        self.assertFalse(trunc)


class Metamorphic(unittest.TestCase):
    def setUp(self):
        rng = random.Random(7)
        self.cases = [random_graph(rng, rng.randint(3, 9), rng.randint(2, 18)) for _ in range(120)]

    def test_edge_order_does_not_change_results(self):
        rng = random.Random(11)
        for nodes, edges in self.cases:
            shuffled = edges[:]
            rng.shuffle(shuffled)
            for impact in G.IMPACTS:
                self.assertEqual(G.reach(edges, "n0", impact, 4), G.reach(shuffled, "n0", impact, 4))

    def test_disconnected_node_changes_nothing(self):
        for nodes, edges in self.cases:
            extra = edges + [edge("zz1", "island", "island2", "administers", "admin", "provider-verified")]
            for impact in G.IMPACTS:
                self.assertEqual(G.reach(edges, "n0", impact, 4)[0], G.reach(extra, "n0", impact, 4)[0])

    def test_adding_harmful_edge_never_shrinks_reach(self):
        rng = random.Random(13)
        for nodes, edges in self.cases:
            ids = [n["id"] for n in nodes]
            more = edges + [edge("zz", rng.choice(ids), rng.choice(ids + ["new"]), "administers", "admin", "observed")]
            for impact in G.IMPACTS:
                before = prod_tiers(edges, "n0", impact, 4)[0]
                after = prod_tiers(more, "n0", impact, 4)[0]
                for k, v in before.items():
                    self.assertIn(k, after)
                    self.assertGreaterEqual(after[k], v)

    def test_removing_write_removes_integrity_only(self):
        edges = [edge("r", "p", "db", "reads", "read", "observed"), edge("w", "p", "db", "writes", "write", "observed")]
        without = [e for e in edges if e["id"] != "w"]
        self.assertIn("db", prod_tiers(edges, "p", "integrity", 4)[0])
        self.assertNotIn("db", prod_tiers(without, "p", "integrity", 4)[0])
        self.assertEqual(prod_tiers(edges, "p", "confidentiality", 4)[0], prod_tiers(without, "p", "confidentiality", 4)[0])

    def test_unknown_for_verified_keeps_potential_reach(self):
        for nodes, edges in self.cases:
            weakened = [dict(e, verification="unknown") if e["verification"] == "provider-verified" else e for e in edges]
            for impact in G.IMPACTS:
                before = set(prod_tiers(edges, "n0", impact, 4)[0])
                after = set(prod_tiers(weakened, "n0", impact, 4)[0])
                self.assertEqual(before, after)  # certainty drops; potential reach does not shrink

    def test_duplicate_receipts_do_not_inflate(self):
        g = G.Graph()
        a = g.add_node("application", ["app"], "app", trust_domain="internal")
        d = g.add_node("database", ["pg", "h"], "pg h", trust_domain="internal", environment="production")
        for line in (1, 2, 3, 1, 1):
            ev = g.add_evidence("a.py", line, "t", "conn", "observed")
            g.add_edge(a, d, "writes", "write", "observed", "medium", evidence=ev)
        self.assertEqual(len(g.nodes), 2)
        self.assertEqual(len(g.edges), 1)
        self.assertEqual(len(g.evidence), 3)
        g.finalize()
        graph = {"nodes": g.node_list(), "edges": g.edge_list()}
        one = G.assess(graph, 1)
        self.assertEqual(one["exposure"]["class"], "High")


def assess_one(nodes, edges):
    for e in edges:
        e.setdefault("trust_boundary", {"domain": None, "environment": None})
    return G.assess({"nodes": nodes, "edges": edges}, 1)["exposure"]["class"]


class ExposureMonotonicity(unittest.TestCase):
    SENS = ["unknown", "public", "internal", "confidential", "restricted"]
    CRIT = ["unknown", "low", "medium", "high", "critical"]

    def test_fixture_A_local_sqlite_is_low(self):
        nodes = [node("app", "application"), node("db", "database", trust_domain="local")]
        self.assertEqual(assess_one(nodes, [edge("a", "app", "db", "reads", "read")]), "Low")

    def test_fixture_B_twelve_readonly_internal_not_critical(self):
        nodes = [node("app", "application")] + [node("d%d" % i, sensitivity="internal") for i in range(12)]
        edges = [edge("e%d" % i, "app", "d%d" % i, "reads", "read", "provider-verified") for i in range(12)]
        self.assertEqual(assess_one(nodes, edges), "Moderate")

    def test_fixture_C_verified_admin_on_critical_is_critical(self):
        nodes = [node("app", "application"), node("db", criticality="critical", environment="production")]
        self.assertEqual(assess_one(nodes, [edge("a", "app", "db", "administers", "admin", "provider-verified")]), "Critical")

    def test_privileged_prod_beats_many_readonly(self):
        many = [node("app", "application")] + [node("d%d" % i, sensitivity="internal") for i in range(10)]
        many_e = [edge("e%d" % i, "app", "d%d" % i, "reads", "read") for i in range(10)]
        one = [node("app", "application"), node("db", environment="production")]
        one_e = [edge("a", "app", "db", "writes", "write")]
        self.assertGreater(G.EXPOSURE_RANK[assess_one(one, one_e)], G.EXPOSURE_RANK[assess_one(many, many_e)])

    def test_unknown_is_not_low(self):
        nodes = [node("app", "application"), node("db")]
        self.assertEqual(assess_one(nodes, [edge("a", "app", "db", "connects", "unknown", "inferred")]), "Moderate")

    def test_no_files_is_unknown_not_low(self):
        self.assertEqual(G.assess({"nodes": [], "edges": []}, 0)["exposure"]["class"], "Unknown")

    def test_monotone_in_every_ordinal(self):
        caps = ["read", "write", "delete", "admin"]
        vers = ["inferred", "observed", "provider-verified"]
        for s_i, c_i, cap_i, v_i in itertools.product(range(5), range(5), range(4), range(3)):
            base = assess_one([node("app", "application"),
                               node("db", sensitivity=self.SENS[s_i], criticality=self.CRIT[c_i])],
                              [edge("a", "app", "db", "writes" if caps[cap_i] != "read" else "reads", caps[cap_i], vers[v_i])])
            for ds, dc, dcap, dv in ((1, 0, 0, 0), (0, 1, 0, 0), (0, 0, 1, 0), (0, 0, 0, 1)):
                s2, c2, cap2, v2 = s_i + ds, c_i + dc, cap_i + dcap, v_i + dv
                if s2 > 4 or c2 > 4 or cap2 > 3 or v2 > 2:
                    continue
                up = assess_one([node("app", "application"),
                                 node("db", sensitivity=self.SENS[s2], criticality=self.CRIT[c2])],
                                [edge("a", "app", "db", "writes" if caps[cap2] != "read" else "reads", caps[cap2], vers[v2])])
                self.assertGreaterEqual(G.EXPOSURE_RANK[up], G.EXPOSURE_RANK[base],
                                        (s_i, c_i, cap_i, v_i, ds, dc, dcap, dv, base, up))

    def test_breadth_saturates_and_is_monotone(self):
        vals = [G.breadth_indicator(n) for n in range(0, 40)]
        self.assertEqual(vals[0], 1.0)
        self.assertEqual(vals[1], 1.0)
        self.assertTrue(all(b >= a for a, b in zip(vals, vals[1:])))
        self.assertLessEqual(max(vals), 1.5)


PW = "s3cr3t" + "P4ss"
AWS = "AK" + "IA" + "ABCDEFGHIJKLMNOP"


class Sanitizing(unittest.TestCase):

    def test_url_credentials_query_and_fragment_removed(self):
        raw = "postgres://admin:" + PW + "@db.prod.internal:5432/ledger?sslmode=require&password=x#frag"
        ep = G.parse_endpoint(raw)
        self.assertEqual(ep["host"], "db.prod.internal")
        out = G.sanitize_text(raw)
        self.assertNotIn(PW, out)
        self.assertNotIn("admin", out)
        self.assertNotIn("sslmode", out)

    def test_dotnet_connection_string(self):
        raw = "Server=tcp:sql.prod.example.net,1433;Database=orders;User ID=svc;Password=" + PW + ";"
        ep = G.parse_endpoint(raw)
        self.assertEqual((ep["engine"], ep["host"], ep["path"]), ("sqlserver", "sql.prod.example.net", "orders"))
        self.assertNotIn(PW, G.sanitize_text(raw))
        self.assertNotIn("svc", G.sanitize_text(raw))

    def test_placeholder_host_is_unresolved_not_invented(self):
        for raw in ("postgres://${DB_HOST}:5432/app", "redis://{{ .Values.host }}:6379"):
            ep = G.parse_endpoint(raw)
            self.assertFalse(ep["resolved"])
            self.assertEqual(ep["host"], "")

    def test_misc_secret_shapes(self):
        pk = "RSA " + "PRIVATE KEY"
        text = ("key=-----BEGIN " + pk + "-----\nMIIabc\n-----END " + pk + "----- "
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlc2lnbmF0dXJl "
                + AWS + " someone@corp.example.org token=abc123def")
        out = G.sanitize_text(text, 1000)
        for bad in ("MIIabc", "eyJhbGci", AWS, "someone@", "abc123def"):
            self.assertNotIn(bad, out)

    def test_control_characters_neutralized(self):
        out = G.sanitize_text("x\x1b[31mred\x1b]0;title\x07‮evil")
        self.assertNotIn("\x1b", out)
        self.assertNotIn("‮", out)

    def test_trust_domains(self):
        self.assertEqual(G.trust_domain_for_host("localhost"), "local")
        self.assertEqual(G.trust_domain_for_host("10.1.2.3"), "internal")
        self.assertEqual(G.trust_domain_for_host("db"), "internal")
        self.assertEqual(G.trust_domain_for_host("api.openai.com"), "external")
        self.assertEqual(G.trust_domain_for_host(""), "unknown")


class Pseudonymize(unittest.TestCase):
    def test_no_hosts_or_snippets_survive(self):
        g = G.Graph()
        a = g.add_node("application", ["app"], "secret-project", trust_domain="internal")
        d = g.add_node("database", ["pg", "db.internal.example"], "postgresql db.internal.example",
                       attributes={"engine": "postgresql", "host": "db.internal.example"})
        ev = g.add_evidence("x.py", 3, "t", "connect('db.internal.example')", "observed")
        g.add_edge(a, d, "connects", "unknown", "observed", "medium", evidence=ev)
        g.finalize()
        rep = {"scope": {"root": ".", "name": "secret-project"}, "graph": {"nodes": g.node_list(), "edges": g.edge_list()},
               "evidence": g.evidence_list(), "assessment": G.assess({"nodes": g.node_list(), "edges": g.edge_list()}, 1)}
        out = json.dumps(G.pseudonymize(rep))
        self.assertNotIn("db.internal.example", out)
        self.assertNotIn("secret-project", out)
        self.assertNotIn(d, out)


if __name__ == "__main__":
    unittest.main()
