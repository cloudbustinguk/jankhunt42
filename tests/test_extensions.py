"""2.1.0 extensions: path strength (oracle-checked), Mermaid/CSV export,
OpenAPI enrichment, code-to-workload bindings, what-if, drift, passport
acceptance records, and passport comparison."""
import csv
import io
import json
import os
import random
import re
import shutil
import subprocess
import tempfile
import unittest

import _util
from _util import edge, node, run_cli
import oracle
import jh_explorer
import jh_graph as G
import jh_map
import jh_passport

GIT_ENV = {"GIT_AUTHOR_NAME": "fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
           "GIT_COMMITTER_NAME": "fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
           "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
KINDS = ["connects", "authenticates-as", "reads", "writes", "deletes", "administers", "calls", "exports", "depends-on"]
CAPS = ["read", "write", "delete", "admin", "unknown"]
VERS = ["provider-verified", "observed", "declared", "inferred", "unknown", "refuted"]


def build(files, decl=None, inventory=None, trusted=False):
    col = jh_map.Collected(items=[jh_map.Item(k, v) for k, v in files.items()], considered=len(files))
    return jh_map.build_report(col, "/x", "app", "t", None, decl, inventory, trusted, "inv.json")


class Strength(unittest.TestCase):
    def test_matches_oracle_on_seeded_graphs(self):
        rng = random.Random(31337)
        for _ in range(300):
            n = rng.randint(2, 7)
            edges = []
            for i in range(rng.randint(0, 14)):
                s, t = rng.randrange(n), rng.randrange(n)
                if s == t:
                    continue
                e = edge("e%02d" % i, "n%d" % s, "n%d" % t, rng.choice(KINDS), rng.choice(CAPS), rng.choice(VERS))
                if rng.random() < 0.8:
                    e["attenuation"] = rng.choice([0.0, 0.1, 0.25, 0.5, 0.9, 1.0])
                edges.append(e)
            by_id = {e["id"]: e for e in edges}
            for impact in G.IMPACTS:
                for depth in (1, 3):
                    got = G.strongest(edges, "n0", impact, depth)
                    want = oracle.strongest(edges, "n0", impact, depth)
                    self.assertEqual(set(got), set(want))
                    for nid, info in got.items():
                        self.assertAlmostEqual(info["strength"], want[nid], places=5)
                        prod, cur, seen = 1.0, "n0", {"n0"}
                        for eid in info["path"]:
                            e = by_id[eid]
                            self.assertEqual(e["source"], cur)
                            self.assertNotIn(e["target"], seen)
                            prod *= float(e.get("attenuation", 1.0))
                            cur = e["target"]
                            seen.add(cur)
                        self.assertEqual(cur, nid)
                        self.assertLessEqual(len(info["path"]), depth)
                        self.assertAlmostEqual(prod, info["strength"], places=5)

    def test_edge_cases(self):
        edges = [dict(edge("a", "p", "x", "writes", "write"), attenuation=0.0),
                 dict(edge("b", "p", "y", "writes", "write"), attenuation=1.0)]
        got = G.strongest(edges, "p", "integrity", 4)
        self.assertNotIn("x", got)               # a = 0 excludes the edge
        self.assertEqual(got["y"]["strength"], 1.0)

    def test_strength_never_changes_the_exposure_class(self):
        nodes = [node("app", "application"), node("db", environment="production")]
        base = [edge("e", "app", "db", "writes", "write", "provider-verified")]
        weighted = [dict(base[0], attenuation=0.01)]
        for e in base + weighted:
            e.setdefault("trust_boundary", {"domain": None, "environment": None})
        a = G.assess({"nodes": nodes, "edges": base}, 1)
        b = G.assess({"nodes": nodes, "edges": weighted}, 1)
        self.assertEqual(a["exposure"], b["exposure"])
        self.assertIn("strength", b["blast_radius"]["app"]["impacts"]["integrity"]["db"])
        self.assertNotIn("strength", a["blast_radius"]["app"]["impacts"]["integrity"]["db"])

    def test_attenuation_only_from_trusted_inventory(self):
        files = {"a.py": 'import psycopg\npsycopg.connect("postgresql://pg.example/x")\n'}
        inv = {"grants": [{"principal": "app", "target": "pg.example", "capability": "write",
                           "verification": "provider-verified", "attenuation": 0.4}]}
        trusted = build(files, inventory=inv, trusted=True)
        untrusted = build(files, inventory=inv, trusted=False)
        self.assertTrue(any(e.get("attenuation") == 0.4 for e in trusted["graph"]["edges"]))
        self.assertFalse(any("attenuation" in e for e in untrusted["graph"]["edges"]))
        self.assertTrue(any("attenuation ignored" in w for w in untrusted["warnings"]))


HOSTILE = 'x"]; click n1 call evil() %%\n<b>|pipe|</b> [x] {y} =cmd|\' /c calc\'!A0'


class Exports(unittest.TestCase):
    def report(self):
        y = ("kind: Deployment\napiVersion: apps/v1\nmetadata:\n  name: %s\n  namespace: n\n" % json.dumps(HOSTILE))
        return build({"k.yaml": y, "a.py": 'import requests\nrequests.get("https://api.example.com/x?token=s3cr3tvalue")\n'})

    def test_mermaid_is_well_formed_and_inert(self):
        text = jh_explorer.render_mermaid(self.report())
        lines = text.split("\n")
        self.assertEqual(lines[2], "flowchart LR")
        for line in lines[3:]:
            self.assertRegex(line, r'^(  n\d+\["[^"\[\]|<>{}()`]*"\]|  n\d+ -(?:->|\.->)\|"[^"|]*"\| n\d+|  classDef \w+ [\w:#,\-. ]+|  class [n\d,]+ \w+|%% .*)$')
        # Hostile text may appear only inside a quoted label: no line is a click/style/link statement.
        self.assertFalse([l for l in lines if re.match(r"\s*(click|style|linkStyle|call|href)\b", l)])
        self.assertNotIn("s3cr3tvalue", text)
        self.assertEqual(text, jh_explorer.render_mermaid(self.report()))

    def test_mermaid_truncation_and_dashed_edges(self):
        files = {"s%d.py" % i: "import redis\n" for i in range(3)}
        files.update({"h%d.py" % i: 'import requests\nrequests.get("https://h%d.example.com")\n' % i for i in range(10)})
        text = jh_explorer.render_mermaid(build(files), max_nodes=4)
        self.assertIn("%% truncated:", text)
        self.assertIn("-.->", jh_explorer.render_mermaid(build({"a.py": "import redis\n"})))

    def test_csv_round_trip_and_formula_injection(self):
        nodes_csv, edges_csv = jh_map.render_csv(self.report())
        rows = list(csv.DictReader(io.StringIO(nodes_csv)))
        self.assertTrue(rows)
        for r in rows:
            for v in r.values():
                self.assertFalse(v[:1] in ("=", "+", "-", "@"), v)
        erows = list(csv.DictReader(io.StringIO(edges_csv)))
        self.assertEqual({"id", "source", "target", "kind", "capability", "verification", "evidence_tier",
                          "confidence", "trust_boundary", "evidence"}, set(erows[0]))
        self.assertNotIn("s3cr3tvalue", nodes_csv + edges_csv)

    def test_formula_cells_are_neutralized(self):
        rep = {"graph": {"nodes": [dict(node("n1", "external"), display_label=lbl) for lbl in
                                   ('=HYPERLINK("http://x","y")', "+1", "-2", "@SUM(A1)")][:1] +
                                  [dict(node("n%d" % i, "external"), display_label=lbl) for i, lbl in
                                   enumerate(("+1", "-2", "@SUM(A1)", "\t=1"), 2)],
                         "edges": []}, "evidence": []}
        nodes_csv, _ = jh_map.render_csv(rep)
        labels = [r["label"] for r in csv.DictReader(io.StringIO(nodes_csv))]
        self.assertEqual(len(labels), 5)
        for lbl in labels:
            self.assertEqual(lbl[0], "'", lbl)

    def test_cli_formats_and_redaction(self):
        tmp = tempfile.mkdtemp(prefix="jh-exp-")
        try:
            root = os.path.join(tmp, "demo")
            shutil.copytree(os.path.join(_util.FIXTURES, "demo-app"), root)
            r = run_cli("map", root, "--mermaid", "--redact")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn("ledger-db", r.stdout)
            out = os.path.join(tmp, "csv")
            r = run_cli("map", root, "--csv", out)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue(os.path.exists(os.path.join(out, "edges.csv")))
            self.assertEqual(run_cli("map", root, "--mermaid", "--json").returncode, 2)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


SPEC = ("openapi: 3.0.0\ninfo:\n  title: t\n  version: '1'\nservers:\n  - url: https://payments.vendor.example.com/v2\n"
        "  - url: '{scheme}://templated'\npaths:\n  /charges:\n    get: {}\n    post: {}\n  /refunds/{id}:\n    delete: {}\n")


class OpenAPI(unittest.TestCase):
    def test_upstream_spec_enriches_without_edges(self):
        files = {"clients/vendor.yaml": SPEC,
                 "pay.py": 'import requests\nrequests.get("https://payments.vendor.example.com/v2/charges")\n'}
        with_spec = build(files)
        without = build({k: v for k, v in files.items() if k != "clients/vendor.yaml"})
        self.assertEqual(len(with_spec["graph"]["edges"]), len(without["graph"]["edges"]))
        node = [n for n in with_spec["graph"]["nodes"] if n["attributes"].get("host") == "payments.vendor.example.com"][0]
        self.assertIn("POST /charges", node["attributes"]["openapi_operations"])
        self.assertEqual(with_spec["coverage"]["by_adapter"]["openapi"], 1)

    def test_own_spec_is_exposed_by_the_application(self):
        rep = build({"openapi.yaml": SPEC})
        app = [n for n in rep["graph"]["nodes"] if n["kind"] == "application"][0]
        self.assertIn("DELETE /refunds/{id}", app["attributes"]["exposes"])
        self.assertEqual(rep["graph"]["edges"], [])

    def test_json_spec_and_malformed_spec(self):
        rep = build({"api/openapi.json": json.dumps({"openapi": "3.1.0", "paths": {"/x": {"get": {}}}})})
        self.assertIn("GET /x", [n for n in rep["graph"]["nodes"] if n["kind"] == "application"][0]["attributes"]["exposes"])
        bad = build({"openapi.json": '{"openapi": "3.0.0", "paths": {'})
        self.assertEqual(bad["coverage"]["parse_failures"][0]["path"], "openapi.json")


class Bindings(unittest.TestCase):
    K8S = ("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api\n  namespace: prod\nspec:\n  template:\n"
           "    spec:\n      serviceAccountName: api-sa\n")
    RBAC = ("kind: Role\napiVersion: rbac.authorization.k8s.io/v1\nmetadata:\n  name: r\n  namespace: prod\nrules:\n"
            "  - resources: [\"secrets\"]\n    verbs: [\"get\"]\n---\nkind: RoleBinding\napiVersion: rbac.authorization.k8s.io/v1\n"
            "metadata:\n  name: b\n  namespace: prod\nsubjects:\n  - kind: ServiceAccount\n    name: api-sa\n    namespace: prod\n"
            "roleRef:\n  kind: Role\n  name: r\n")

    def test_binding_inherits_identity_and_clears_unknown(self):
        files = {"k8s/d.yaml": self.K8S, "k8s/rbac.yaml": self.RBAC, "a.py": "import redis\n"}
        unbound = build(files)
        bound = build(files, decl={"bindings": [{"workload": "Deployment prod/api"}]})
        app = [n["id"] for n in bound["graph"]["nodes"] if n["kind"] == "application"][0]
        sec = [n["id"] for n in bound["graph"]["nodes"] if "secrets" in n["display_label"]][0]
        self.assertNotIn(sec, unbound["assessment"]["blast_radius"][app]["impacts"]["confidentiality"])
        self.assertIn(sec, bound["assessment"]["blast_radius"][app]["impacts"]["confidentiality"])
        self.assertIn("code-to-workload-binding", [u["id"] for u in unbound["unknowns"]])
        self.assertNotIn("code-to-workload-binding", [u["id"] for u in bound["unknowns"]])

    def test_unmatched_binding_warns(self):
        rep = build({"a.py": "import redis\n"}, decl={"bindings": [{"workload": "nope"}]})
        self.assertTrue(any("binding matched no workload" in w for w in rep["warnings"]))


class WhatIf(unittest.TestCase):
    def setUp(self):
        self.rep = build({".env": "DATABASE_URL=postgres://ledger.prod.internal/l\n",
                          "a.py": 'import psycopg\nimport os\nc = psycopg.connect(os.environ["DATABASE_URL"])\n'
                                  'c.execute("DELETE FROM t")\nimport requests\nrequests.post("https://x.example.com/up")\n'},
                         decl={"assets": [{"match": "ledger.prod", "sensitivity": "restricted"}]})

    def run_w(self, *mutations):
        return jh_map.run_whatif(self.rep, {"name": "t", "mutations": list(mutations)}, 4)

    def test_revoke_never_increases_integrity_reach(self):
        w = self.run_w({"op": "revoke", "source": "app", "target": "ledger.prod"})
        self.assertEqual(w["mutations"][0]["matched"], 1)
        self.assertFalse([n for n in w["delta"]["newly_reachable"] if n["impact"] == "integrity"])

    def test_add_edge_never_shrinks_and_is_hypothetical(self):
        w = self.run_w({"op": "add-edge", "source": "app", "target": "x.example.com", "kind": "exports", "capability": "write"})
        self.assertFalse(w["delta"]["edges"]["removed"])
        self.assertTrue(w["delta"]["edges"]["added"])

    def test_block_egress_removes_external_edges(self):
        w = self.run_w({"op": "block-egress"})
        self.assertTrue(w["delta"]["edges"]["removed"])
        self.assertIn("internal->external", w["delta"]["trust_boundaries"]["removed"])

    def test_invalid_op_and_unmatched(self):
        with self.assertRaises(ValueError):
            self.run_w({"op": "rm -rf /"})
        w = self.run_w({"op": "remove-node", "match": "nothing-matches-this"})
        self.assertEqual(len(w["unmatched"]), 1)

    def test_original_report_is_not_mutated(self):
        before = json.dumps(self.rep, sort_keys=True)
        self.run_w({"op": "remove-node", "match": "ledger"}, {"op": "set-capability", "source": "app", "target": "x.example", "to": "admin"})
        self.assertEqual(before, json.dumps(self.rep, sort_keys=True))


class Drift(unittest.TestCase):
    def test_drift_against_stored_map(self):
        tmp = tempfile.mkdtemp(prefix="jh-drift-")
        try:
            root = os.path.join(tmp, "demo")
            shutil.copytree(os.path.join(_util.FIXTURES, "demo-app"), root)
            stored = os.path.join(tmp, "stored.json")
            with open(stored, "w") as fh:
                fh.write(run_cli("map", root, "--json").stdout)
            with open(os.path.join(root, "app", "new.py"), "w") as fh:
                fh.write('import requests\nrequests.post("https://new.example.com/x")\n')
            d = json.loads(run_cli("map", root, "--drift", stored, "--json").stdout)["delta"]
            self.assertEqual(d["kind"], "snapshot-drift")
            self.assertTrue(d["edges"]["added"])
            self.assertIn("not observed runtime drift", d["note"])
            self.assertEqual(run_cli("map", root, "--drift", stored, "--base", "HEAD").returncode, 2)
            with open(stored, "w") as fh:
                json.dump({"schema_version": "something-else"}, fh)
            self.assertEqual(run_cli("map", root, "--drift", stored).returncode, 2)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


def git(root, *args):
    subprocess.run(["git", "-C", root] + list(args), check=True, capture_output=True,
                   env=dict(os.environ, **GIT_ENV), timeout=60)


@unittest.skipUnless(shutil.which("git"), "git not installed")
class Acceptance(unittest.TestCase):
    """The four lifecycle fixtures from the passport spec, plus abuse cases."""
    DIGEST_A = "sha256:" + "a" * 64

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="jh-acc-")
        self.root = os.path.join(self.tmp, "repo")
        shutil.copytree(os.path.join(_util.FIXTURES, "demo-app"), self.root)
        os.makedirs(os.path.join(self.root, "attest"))
        stmt = {"_type": "https://in-toto.io/Statement/v1", "subject": [{"name": "app.tgz", "digest": {"sha256": "a" * 64}}],
                "predicateType": "https://slsa.dev/provenance/v1", "predicate": {}}
        with open(os.path.join(self.root, "attest", "provenance.intoto.json"), "w") as fh:
            json.dump(stmt, fh)
        git(self.root, "init", "-q", "-b", "main")
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "x")
        self.pp = json.loads(run_cli("passport", self.root, "--json").stdout)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def record(self, path=None, **over):
        rec = {"accepted_by": "release-manager", "accepted_at": "2026-10-01T00:00:00Z", "expires": "2099-01-01T00:00:00Z",
               "subject_revision": self.pp["source_revision"], "policy_hash": self.pp["assessment"]["decision"]["policy"]["hash"],
               "decision_accepted": self.pp["assessment"]["decision"]["result"], "artifact_digest": self.DIGEST_A}
        rec.update(over)
        path = path or os.path.join(self.tmp, "acceptance.json")
        with open(path, "w") as fh:
            json.dump(rec, fh)
        return path

    def accept(self, path):
        return json.loads(run_cli("passport", self.root, "--json", "--acceptance", path).stdout)["lifecycle"]

    def test_assessed_without_acceptance(self):
        self.assertEqual(self.pp["lifecycle"]["state"], "assessed")
        self.assertEqual(self.pp["lifecycle"]["acceptance"]["state"], "not-supplied")

    def test_accepted_for_digest_a(self):
        lc = self.accept(self.record())
        self.assertEqual((lc["state"], lc["acceptance"]["state"]), ("accepted", "declared-by-operator"))
        self.assertIn("not verified", lc["acceptance"]["note"])

    def test_digest_b_invalidates(self):
        lc = self.accept(self.record(artifact_digest="sha256:" + "b" * 64))
        self.assertEqual(lc["state"], "assessed")
        self.assertEqual(lc["acceptance"]["state"], "invalidated")
        self.assertIn("digest-changed", lc["acceptance"]["reasons"])

    def test_revision_policy_decision_expiry_invalidate(self):
        for over, reason in (({"subject_revision": "0" * 40}, "revision-changed"), ({"policy_hash": "x"}, "policy-changed"),
                             ({"decision_accepted": "pass"}, "decision-changed"),
                             ({"expires": "2001-01-01T00:00:00Z"}, "expired")):
            lc = self.accept(self.record(**over))
            self.assertEqual(lc["acceptance"]["state"], "invalidated", over)
            self.assertTrue(any(r.startswith(reason) for r in lc["acceptance"]["reasons"]), (over, lc))

    def test_repository_controlled_record_is_rejected(self):
        lc = self.accept(self.record(path=os.path.join(self.root, "acceptance.json")))
        self.assertEqual(lc["acceptance"]["state"], "rejected")
        self.assertNotEqual(lc["state"], "accepted")

    def test_insufficient_evidence_cannot_be_accepted(self):
        empty = os.path.join(self.tmp, "empty")
        os.makedirs(empty)
        git(empty, "init", "-q", "-b", "main")
        git(empty, "commit", "-q", "--allow-empty", "-m", "e")
        pp = json.loads(run_cli("passport", empty, "--json").stdout)
        rec = os.path.join(self.tmp, "acc2.json")
        with open(rec, "w") as fh:
            json.dump({"accepted_by": "x", "accepted_at": "2026-10-01T00:00:00Z", "subject_revision": pp["source_revision"],
                       "policy_hash": pp["assessment"]["decision"]["policy"]["hash"],
                       "decision_accepted": "insufficient-evidence"}, fh)
        lc = json.loads(run_cli("passport", empty, "--json", "--acceptance", rec).stdout)["lifecycle"]
        self.assertEqual(lc["acceptance"]["state"], "rejected")
        self.assertEqual(lc["state"], "draft")

    def test_dirty_tree_invalidates(self):
        path = self.record()
        with open(os.path.join(self.root, "app", "x.py"), "w") as fh:
            fh.write("x = 1\n")
        lc = self.accept(path)
        self.assertIn("working-tree-dirty", lc["acceptance"]["reasons"])

    def test_redacted_acceptance_hides_the_acceptor(self):
        out = run_cli("passport", self.root, "--json", "--redact", "--acceptance", self.record()).stdout
        self.assertNotIn("release-manager", out)


class Compare(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="jh-cmp-")
        self.root = os.path.join(self.tmp, "demo")
        shutil.copytree(os.path.join(_util.FIXTURES, "demo-app"), self.root)
        self.old = os.path.join(self.tmp, "old.json")
        with open(self.old, "w") as fh:
            fh.write(run_cli("passport", self.root, "--json").stdout)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_identical_is_clean(self):
        d = json.loads(run_cli("passport", "--compare", self.old, "--against", self.old, "--json").stdout)
        self.assertFalse(d["regressed"])
        self.assertEqual(d["old"]["integrity"], "consistent")

    def test_lost_owner_is_a_regression(self):
        os.remove(os.path.join(self.root, "CODEOWNERS"))
        d = json.loads(run_cli("passport", self.root, "--compare", self.old, "--json").stdout)
        self.assertTrue(d["regressed"])
        self.assertIn("@demo-org/payments-team", d["owners"]["removed"])
        self.assertIn("ownership", d["evidence_areas"])

    def test_edited_document_fails_integrity(self):
        doc = _util.read_json(self.old)
        doc["assessment"]["decision"]["result"] = "pass"
        edited = os.path.join(self.tmp, "edited.json")
        _util.write_json(edited, doc)
        d = json.loads(run_cli("passport", "--compare", self.old, "--against", edited, "--json").stdout)
        self.assertEqual(d["new"]["integrity"], "mismatch")

    def test_wrong_schema_is_usage_error(self):
        bad = os.path.join(self.tmp, "bad.json")
        _util.write_json(bad, {"schema_version": "jankhunt.map.v1"})
        self.assertEqual(run_cli("passport", "--compare", bad, "--against", self.old).returncode, 2)
        self.assertEqual(run_cli("passport", "--against", self.old).returncode, 2)


if __name__ == "__main__":
    unittest.main()
