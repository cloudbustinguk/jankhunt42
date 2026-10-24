"""Resource bounds: large synthetic graphs finish within budget; size caps
truncate explicitly and truncation can never produce a clean pass."""
import random
import time
import unittest

import _util
from _util import edge, node
import jh_graph as G
import jh_map
import jh_policy

BUDGET = 60.0


class Performance(unittest.TestCase):
    def test_ten_thousand_edges(self):
        rng = random.Random(99)
        nodes = [node("app%d" % i, "application") for i in range(20)] + [node("n%d" % i) for i in range(2000)]
        ids = [n["id"] for n in nodes]
        kinds = ["connects", "reads", "writes", "authenticates-as", "calls"]
        edges = [edge("e%05d" % i, rng.choice(ids), rng.choice(ids), rng.choice(kinds),
                      rng.choice(["unknown", "read", "write", "admin"]), "observed") for i in range(10000)]
        t0 = time.time()
        res = G.assess({"nodes": nodes, "edges": edges}, 1, max_depth=4)
        took = time.time() - t0
        self.assertLess(took, BUDGET, "10k-edge assessment took %.1fs" % took)
        self.assertIn(res["exposure"]["class"], G.EXPOSURE_CLASSES)

    def test_credential_radius_with_many_identities(self):
        rng = random.Random(7)
        nodes = ([node("w%d" % i, "workload") for i in range(200)] + [node("id%d" % i, "identity") for i in range(1500)]
                 + [node("d%d" % i) for i in range(2000)])
        edges = [edge("h%05d" % i, "w%d" % rng.randrange(200), "id%d" % rng.randrange(1500), "authenticates-as")
                 for i in range(3000)]
        edges += [edge("g%05d" % i, "id%d" % rng.randrange(1500), "d%d" % rng.randrange(2000),
                       rng.choice(["reads", "writes", "connects"]), rng.choice(["read", "write", "unknown"]))
                  for i in range(9000)]
        t0 = time.time()
        res = G.credential_radius({n["id"]: n for n in nodes}, edges, 4)
        took = time.time() - t0
        self.assertLess(took, BUDGET, "credential radius over 1500 identities took %.1fs" % took)
        self.assertTrue(res["identities"])

    def test_graph_caps_truncate_explicitly(self):
        g = G.Graph()
        old = G.MAX_NODES
        G.MAX_NODES = 50
        try:
            a = g.add_node("application", ["a"], "a")
            for i in range(80):
                g.add_edge(a, g.add_node("database", ["d", i], "d%d" % i), "connects", "unknown", "observed", "low")
        finally:
            G.MAX_NODES = old
        self.assertEqual(len(g.nodes), 50)
        self.assertTrue(g.truncated)

    def test_truncated_map_is_never_clean(self):
        old = G.MAX_EDGES
        G.MAX_EDGES = 3
        try:
            files = {"s%d.py" % i: 'import requests\nrequests.get("https://h%d.example.com")\n' % i for i in range(10)}
            col = jh_map.Collected(items=[jh_map.Item(k, v) for k, v in files.items()], considered=10)
            rep = jh_map.build_report(col, "/x", "t", "t", None)
        finally:
            G.MAX_EDGES = old
        self.assertTrue(rep["truncation"]["truncated"])
        self.assertEqual(rep["coverage"]["status"], "partial")
        facts = {"files_scanned": 10, "map_files_inspected": 10, "map_status": rep["coverage"]["status"],
                 "map_partial_reasons": rep["coverage"]["partial_reasons"], "truncated": True,
                 "exposure": rep["assessment"]["exposure"]["class"], "owner_state": "observed"}
        self.assertEqual(jh_policy.evaluate(jh_policy.merge(None, None, []), facts, rep["graph"])["result"],
                         "insufficient-evidence")


if __name__ == "__main__":
    unittest.main()
