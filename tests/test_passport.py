"""Software passport and policy: unknown stays unknown, no approval claims,
precedence (repository config can only tighten), hard floors, schemas."""
import copy
import json
import os
import shutil
import tempfile
import unittest

import _util
from _util import edge, node, run_cli
import jh_policy as P


def facts(**kw):
    base = {"files_scanned": 10, "map_files_inspected": 5, "map_status": "complete-for-supported-types",
            "truncated": False, "exposure": "Moderate", "owner_state": "observed", "jank_policy": "pass",
            "blocker_leads": 0, "supply": {"sbom": 0, "attestations": 0, "verified_attestations": 0}}
    base.update(kw)
    return base


def graph(nodes=(), edges=()):
    return {"nodes": list(nodes), "edges": list(edges)}


def decide(policy=None, g=None, **kw):
    pol = P.merge(policy, None, [])
    return P.evaluate(pol, facts(**kw), g if g is not None else graph())


class PolicyRules(unittest.TestCase):
    def test_clean_case_passes(self):
        self.assertEqual(decide()["result"], "pass")

    def test_no_files_is_insufficient_never_pass(self):
        self.assertEqual(decide(files_scanned=0)["result"], "insufficient-evidence")
        self.assertEqual(P.evaluate(P.merge(None, None, []), facts(), None)["result"], "insufficient-evidence")

    def test_truncation_and_partial_are_insufficient(self):
        self.assertEqual(decide(truncated=True)["result"], "insufficient-evidence")
        self.assertEqual(decide(map_status="partial", map_partial_reasons=["x"])["result"], "insufficient-evidence")

    def test_coverage_floor_cannot_be_disabled(self):
        off = {"actions": {k: "off" for k in P.DEFAULT_POLICY["actions"]}}
        self.assertEqual(decide(off, files_scanned=0)["result"], "insufficient-evidence")

    def test_owner_rules(self):
        self.assertEqual(decide(owner_state="unknown", exposure="Low")["result"], "pass")
        self.assertEqual(decide(owner_state="unknown", exposure="High")["result"], "review")
        self.assertEqual(decide({"require": {"owner": True}}, owner_state="unknown", exposure="Low")["result"],
                         "insufficient-evidence")
        self.assertEqual(decide({"require": {"owner": True}}, owner_state="declared")["result"], "pass")

    def test_verified_sensitive_export_blocks_even_if_turned_off(self):
        g = graph([node("app", "application"), node("x", "external", trust_domain="external")],
                  [dict(edge("e", "app", "x", "exports", "write", "provider-verified"), data_sensitivity="restricted")])
        self.assertEqual(decide({"actions": {"P-DAT-001": "off"}}, g=g)["result"], "block")
        static = graph(g["nodes"], [dict(g["edges"][0], verification="declared")])
        self.assertEqual(decide(g=static)["result"], "review")

    def test_static_authority_leads_never_block(self):
        g = graph([node("app", "application"), node("db", environment="production")],
                  [edge("e", "app", "db", "deletes", "delete", "observed")])
        self.assertEqual(decide({"actions": {"P-DAT-002": "block"}}, g=g)["result"], "review")
        gv = graph(g["nodes"], [edge("e", "app", "db", "deletes", "delete", "provider-verified")])
        self.assertEqual(decide({"actions": {"P-DAT-002": "block"}}, g=gv)["result"], "block")
        self.assertEqual(decide(g=gv)["result"], "review")

    def test_unknown_privilege_on_critical_needs_review(self):
        g = graph([node("app", "application"), node("db", criticality="critical")],
                  [edge("e", "app", "db", "connects", "unknown", "inferred")])
        self.assertEqual(decide(g=g)["result"], "review")

    def test_required_supply_evidence(self):
        pol = {"require": {"sbom": True, "verified_attestation": True}}
        self.assertEqual(decide(pol)["result"], "insufficient-evidence")
        ok = decide(pol, supply={"sbom": 1, "attestations": 1, "verified_attestations": 1})
        self.assertEqual(ok["result"], "pass")

    def test_jank_policy_and_max_exposure(self):
        self.assertEqual(decide(jank_policy="fail")["result"], "review")
        self.assertEqual(decide(blocker_leads=2)["result"], "review")
        self.assertEqual(decide({"max_exposure": "Low"}, exposure="High")["result"], "review")
        self.assertEqual(decide({"max_exposure": "Low"}, exposure="Unknown")["result"], "insufficient-evidence")

    def test_order_block_beats_insufficient_beats_review(self):
        g = graph([node("app", "application"), node("x", "external", trust_domain="external")],
                  [dict(edge("e", "app", "x", "exports", "write", "provider-verified"), data_sensitivity="confidential")])
        self.assertEqual(decide(g=g, files_scanned=0, jank_policy="fail")["result"], "block")
        self.assertEqual(decide(files_scanned=0, jank_policy="fail")["result"], "insufficient-evidence")

    def test_every_reason_is_explained(self):
        d = decide(jank_policy="fail", owner_state="unknown", exposure="High")
        for r in d["reasons"]:
            self.assertTrue(r["rule"] in P.RULES and r["message"])
        self.assertEqual(len(d["rules"]), len(P.RULES))


class Precedence(unittest.TestCase):
    def test_repository_cannot_weaken_operator(self):
        warns = []
        eff = P.merge({"actions": {"P-JNK-001": "block"}, "require": {"owner": True}, "max_exposure": "Moderate"},
                      {"actions": {"P-JNK-001": "off"}, "require": {"owner": False}, "max_exposure": "Critical"}, warns)
        self.assertEqual(eff["actions"]["P-JNK-001"], "block")
        self.assertTrue(eff["require"]["owner"])
        self.assertEqual(eff["max_exposure"], "Moderate")
        self.assertEqual(len(warns), 3)

    def test_repository_cannot_weaken_defaults(self):
        eff = P.merge(None, {"actions": {"P-DAT-002": "off"}}, [])
        self.assertEqual(eff["actions"]["P-DAT-002"], "review")

    def test_repository_can_tighten(self):
        eff = P.merge(None, {"actions": {"P-JNK-001": "block"}, "require": {"sbom": True}, "max_exposure": "Low"}, [])
        self.assertEqual((eff["actions"]["P-JNK-001"], eff["require"]["sbom"], eff["max_exposure"]), ("block", True, "Low"))

    def test_operator_may_relax_defaults(self):
        eff = P.merge({"actions": {"P-JNK-001": "off"}}, None, [])
        self.assertEqual(eff["actions"]["P-JNK-001"], "off")

    def test_invalid_entries_ignored_with_warning(self):
        warns = []
        eff = P.merge({"actions": {"P-JNK-001": "nuke", "X": "block"}, "max_exposure": "Huge"}, None, warns)
        self.assertEqual(eff, P.merge(None, None, []))
        self.assertEqual(len(warns), 3)

    def test_enforcement_is_opt_in(self):
        self.assertFalse(P.fails("block", None))
        self.assertTrue(P.fails("block", "block"))
        self.assertFalse(P.fails("review", "block"))
        self.assertTrue(P.fails("insufficient-evidence", "review"))


class CliPassport(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="jh-pp-")
        self.root = os.path.join(self.tmp, "demo")
        shutil.copytree(os.path.join(_util.FIXTURES, "demo-app"), self.root)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def pp(self, *args):
        r = run_cli("passport", self.root, "--json", *args, env={"SOURCE_DATE_EPOCH": "1700000000"})
        return r, (json.loads(r.stdout) if r.stdout.strip().startswith("{") else None)

    def test_demo_passport_shape_and_honesty(self):
        r, p = self.pp()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(p["schema_version"], "jankhunt.passport.v1")
        self.assertIn(p["assessment"]["decision"]["result"], P.OUTCOMES)
        self.assertEqual(p["lifecycle"]["acceptance"]["state"], "not-supplied")
        self.assertNotIn("accepted", p["lifecycle"]["state"])
        self.assertEqual(p["ownership"]["state"], "observed")
        self.assertEqual(p["operations"]["runbook"]["state"], "not-observed")
        self.assertIn("not proof of absence", p["operations"]["runbook"]["note"])
        self.assertIsNone(p["source_revision"])
        text = json.dumps(p).lower()
        for word in ("certified", "approved", "compliant", "signature verified"):
            self.assertNotIn(word, text)
        self.assertNotIn("example-only", json.dumps(p))  # fixture password never leaves

    def test_without_owner_unknown_stays_unknown(self):
        os.remove(os.path.join(self.root, "CODEOWNERS"))
        _, p = self.pp()
        self.assertEqual(p["ownership"]["state"], "unknown")
        self.assertIn("P-OWN-001", [x["rule"] for x in p["assessment"]["decision"]["reasons"]])

    def test_declared_owner(self):
        os.remove(os.path.join(self.root, "CODEOWNERS"))
        cfg = _util.read_json(os.path.join(self.root, ".jankhunt42.json"))
        cfg["passport"]["owners"] = ["team-ledger"]
        _util.write_json(os.path.join(self.root, ".jankhunt42.json"), cfg)
        _, p = self.pp()
        self.assertEqual(p["ownership"]["state"], "declared")

    def test_provenance_and_digest_are_exporter_reported(self):
        stmt = {"_type": "https://in-toto.io/Statement/v1",
                "subject": [{"name": "app.tar.gz", "digest": {"sha256": "ab" * 32}}],
                "predicateType": "https://slsa.dev/provenance/v1", "predicate": {}}
        os.makedirs(os.path.join(self.root, "attest"))
        _util.write_json(os.path.join(self.root, "attest", "provenance.intoto.json"), stmt)
        _, p = self.pp()
        self.assertEqual(p["provenance"]["state"], "observed")
        d = p["subject"]["artifact_digests"][0]
        self.assertIn("not verified by jankhunt42", d["verification"])

    def test_policy_inside_repo_is_tighten_only(self):
        pol = {"actions": {"P-DAT-002": "off", "P-JNK-001": "off"}}
        path = os.path.join(self.root, "policy.json")
        _util.write_json(path, pol)
        _, inside = self.pp("--policy", path)
        self.assertIn("P-DAT-002", [x["rule"] for x in inside["assessment"]["decision"]["reasons"]])
        outside = os.path.join(self.tmp, "operator.json")
        _util.write_json(outside, pol)
        _, op = self.pp("--policy", outside)
        self.assertNotIn("P-JNK-001", [x["rule"] for x in op["assessment"]["decision"]["reasons"]])
        self.assertEqual(op["assessment"]["decision"]["policy"]["sources"][1]["kind"], "operator-supplied")

    def test_fail_on_exit_codes(self):
        r, p = self.pp("--fail-on", "review")
        self.assertEqual(r.returncode, 1 if p["assessment"]["decision"]["result"] != "pass" else 0)
        r, _ = self.pp("--fail-on", "block")
        self.assertEqual(r.returncode, 0)

    def test_empty_repo_is_insufficient(self):
        empty = os.path.join(self.tmp, "empty")
        os.makedirs(empty)
        r = run_cli("passport", empty, "--json")
        p = json.loads(r.stdout)
        self.assertEqual(p["assessment"]["decision"]["result"], "insufficient-evidence")
        self.assertEqual(p["lifecycle"]["state"], "draft")
        self.assertEqual(p["assessment"]["exposure"]["class"], "Unknown")

    def test_redacted_passport(self):
        r, p = self.pp("--redact")
        out = json.dumps(p)
        for leak in ("demo-org", "ledger-db.prod.internal", "demo-app"):
            self.assertNotIn(leak, out)

    def test_html_and_markdown(self):
        r = run_cli("passport", self.root, "--html")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("default-src 'none'", r.stdout)
        md = run_cli("passport", self.root)
        self.assertTrue(md.stdout.startswith("# Software passport"))

    def test_identical_evidence_identical_exposure_regardless_of_origin(self):
        """Code-origin declarations (human, AI-assisted, citizen) never change the assessment."""
        _, a = self.pp()
        with open(os.path.join(self.root, "AUTHORS.md"), "w") as fh:
            fh.write("Generated with an AI assistant by a citizen developer.\n")
        _, b = self.pp()
        self.assertEqual(a["assessment"]["exposure"], b["assessment"]["exposure"])
        self.assertEqual(a["assessment"]["decision"]["result"], b["assessment"]["decision"]["result"])


class Schemas(unittest.TestCase):
    """Minimal structural validation against the shipped JSON Schemas
    (required keys and enums), without a third-party validator."""

    def check(self, schema, data, where="$"):
        t = schema.get("type")
        if t == "object":
            self.assertIsInstance(data, dict, where)
            for k in schema.get("required", []):
                self.assertIn(k, data, "%s.%s missing" % (where, k))
            for k, sub in schema.get("properties", {}).items():
                if k in data and data[k] is not None:
                    self.check(sub, data[k], "%s.%s" % (where, k))
        elif t == "array":
            self.assertIsInstance(data, list, where)
            for i, item in enumerate(data[:50]):
                self.check(schema.get("items", {}), item, "%s[%d]" % (where, i))
        if "enum" in schema:
            self.assertIn(data, schema["enum"], where)

    def test_map_and_passport_match_schemas(self):
        tmp = tempfile.mkdtemp(prefix="jh-sch-")
        try:
            root = os.path.join(tmp, "demo")
            shutil.copytree(os.path.join(_util.FIXTURES, "demo-app"), root)
            for cmd, name in (("map", "map.schema.json"), ("passport", "passport.schema.json")):
                schema = _util.read_json(os.path.join(_util.ROOT, "templates", name))
                data = json.loads(run_cli(cmd, root, "--json").stdout)
                self.check(schema, data)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
