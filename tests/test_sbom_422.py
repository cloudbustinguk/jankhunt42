"""SBOM quality regressions, using invented documents and local references only."""
import copy
import json
import unittest

import _util
import jh_supply


def parse(doc):
    text = doc if isinstance(doc, str) else json.dumps(doc)
    return jh_supply.parse_sbom("/fixture/ledger", "ledger", text)


def samples(alg, digest):
    records = [{"alg": a, "value": v} for a, v in zip(alg, digest)]
    yield {"spdxVersion": "SPDX-2.3", "packages": [{"name": "quay", "checksums": [
        {"algorithm": r["alg"], "checksumValue": r["value"]} for r in records]}]}
    yield "SPDXVersion: SPDX-2.3\nPackageName: quay\n" + "\n".join(
        "PackageChecksum: %s: %s" % (r["alg"], r["value"]) for r in records)
    yield {"@graph": [{"type": "software_Package", "name": "quay", "verifiedUsing": [
        {"type": "Hash", "algorithm": r["alg"], "hashValue": r["value"]} for r in records]}]}
    yield {"bomFormat": "CycloneDX", "components": [{"name": "quay", "hashes": [
        {"alg": r["alg"], "content": r["value"]} for r in records]}]}
    yield ('<bom xmlns="urn:cyclonedx"><components><component><name>quay</name><hashes>' +
           ''.join('<hash alg="%s">%s</hash>' % (r["alg"], r["value"]) for r in records) +
           '</hashes></component></components></bom>')
    yield {"descriptor": {"name": "ledger"}, "artifacts": [{"name": "quay", "metadata": {"digests": [
        {"algorithm": r["alg"], "value": r["value"]} for r in records]}}]}


class HashEvidence(unittest.TestCase):
    def test_algorithm_and_digest_belong_to_the_same_record(self):
        for alg, val, missing in [(["SHA256", ""], ["", "bd"], ["algorithm", "value"]),
                                  (["SHA256"], [""], ["value"]), ([""], ["ac"], ["algorithm"]),
                                  (["SHA256"], ["bd"], [])]:
            for doc in samples(alg, val):
                parsed = parse(doc)
                with self.subTest(fmt=parsed["format"], missing=missing):
                    quality = parsed["quality"]
                    self.assertEqual(quality["components"]["with_hash"], int(not missing))
                    for half in missing:
                        self.assertTrue(any(m.startswith("hash " + half) for m in quality["missing"]))


class InventoryCoverage(unittest.TestCase):
    def test_nameless_components_remain_in_quality(self):
        for doc in samples(["sha256"], ["fe"]):
            if isinstance(doc, str):
                doc = doc.replace("PackageName: quay", "PackageName: ").replace("<name>quay</name>", "")
            else:
                for key in ("packages", "@graph", "artifacts", "components"):
                    if key in doc:
                        del doc[key][0]["name"]
            sbom = parse(doc)
            self.assertEqual(sbom["packages"], [])
            self.assertEqual(sbom["quality"]["components"]["total"], 1, sbom["format"])
            self.assertIn("component name for 1 of 1 components", sbom["quality"]["missing"])

    def test_quality_beyond_display_cap(self):
        from unittest.mock import patch
        component = {"name": "quay", "version": "2", "supplier": {"name": "port"}, "purl": "pkg:npm/quay@2",
                     "licenses": [{"license": {"id": "MIT"}}], "hashes": [{"alg": "SHA256", "content": "fe"}]}
        doc = {"bomFormat": "CycloneDX", "components": [component, dict(component, version="")],
               "metadata": {"timestamp": "2026-07-02", "authors": [{"name": "crew"}], "tools": [{"name": "ledger"}],
                            "lifecycles": [{"phase": "build"}]}, "dependencies": [{"ref": "a", "dependsOn": ["b"]}]}
        with patch.object(jh_supply, "MAX_PACKAGES", 1):
            sbom = parse(doc)
        self.assertEqual(sbom["package_count"], 1)
        self.assertIn("version for 1 of 2 components", sbom["quality"]["missing"])
        self.assertEqual(sbom["quality"]["minimum_elements"], "partial")
        self.assertTrue(sbom["warnings"])


class DocumentMetadata(unittest.TestCase):
    def test_author_and_named_tool_have_independent_evidence(self):
        def fields(doc):
            result = parse(doc)["quality"]["document"]
            return result["author"], result["tool"]
        base = {"bomFormat": "CycloneDX", "metadata": {"supplier": {"name": "quay"}, "tools": [{"name": "ledger"}]}}
        self.assertEqual(fields(base), (False, True))
        base["metadata"].update(authors=[{"name": "crew"}], tools=[{"id": "opaque"}])
        self.assertEqual(fields(base), (True, False))
        xml = ('<bom xmlns="urn:cyclonedx"><metadata><supplier><name>crew</name></supplier><tools><tool>'
               '<name>ledger</name></tool></tools></metadata></bom>')
        self.assertEqual(fields(xml), (False, True))
        self.assertEqual(fields({"descriptor": {"version": "2"}, "artifacts": []}), (False, False))
        self.assertEqual(fields({"spdxVersion": "SPDX-2.3", "creationInfo": {"creators": ["Tool: ", "Person: "]}}),
                         (False, False))
        doc = {"@graph": [{"type": "software_Sbom", "creationInfo": "_:meta"},
                          {"type": "CreationInfo", "@id": "_:meta", "createdUsing": ["urn:tool"]},
                          {"type": "Tool", "@id": "urn:tool"}]}
        self.assertEqual(fields(doc), (False, False))
        doc["@graph"][-1]["name"] = "ledger"
        self.assertEqual(fields(doc), (False, True))

    def test_document_selects_its_own_creation_info(self):
        author = {"type": "Person", "@id": "_:p", "name": "keeper"}
        meta = {"type": "CreationInfo", "@id": "_:this", "createdBy": [{"@id": "_:p"}], "created": "2026-10-03"}
        unrelated = {"type": "CreationInfo", "@id": "_:other", "created": "2025-10-03"}
        for ref in ("_:this", {"@id": "_:this"}, dict(meta, **{"@id": "_:inline"})):
            document = {"type": "software_Sbom", "creationInfo": ref}
            for nodes in ([unrelated, author, meta, document], [document, meta, author, unrelated]):
                sbom = parse({"@graph": nodes})
                self.assertEqual(sbom["created"], meta["created"])
                self.assertTrue(sbom["quality"]["document"]["author"])
        sbom = parse({"@graph": [unrelated, {"type": "software_Sbom", "creationInfo": "_:absent"}]})
        self.assertFalse(sbom["quality"]["document"]["timestamp"])

    def test_hash_and_licence_references_resolve_locally(self):
        pkg = {"type": "software_Package", "name": "quay", "@id": "_:pkg", "verifiedUsing": [{"@id": "_:h"}]}
        checksum = {"type": "Hash", "@id": "_:h", "algorithm": "sha256", "hashValue": "bc"}
        rel = {"type": "Relationship", "relationshipType": "hasDeclaredLicense", "from": "_:pkg"}
        for ref in ("https://spdx.org/licenses/MIT", {"@id": "http://spdx.org/licenses/MIT"}, "_:lic"):
            nodes = [pkg, dict(rel, to=[ref]), {"@id": "_:lic", "simplelicensing_licenseExpression": "MIT"}, checksum]
            sbom = parse({"@graph": nodes})
            self.assertEqual((sbom["packages"][0]["license"], sbom["quality"]["components"]["with_hash"]), ("MIT", 1))
        sbom = parse({"@graph": [pkg, dict(rel, to=["https://invalid.example/licenses/MIT"])]})
        self.assertEqual((sbom["packages"][0]["license"], sbom["quality"]["components"]["with_hash"]), ("", 0))


class ComponentIdentity(unittest.TestCase):
    def test_producer_fields_and_swhid(self):
        sid = "swh:1:rev:" + "bc" * 20
        for doc in [
            {"spdxVersion": "SPDX-2.3", "packages": [{"name": "quay", "originator": "Organization: crew",
             "externalRefs": [{"referenceType": "swhid", "referenceLocator": sid}]}]},
            "SPDXVersion: SPDX-2.3\nPackageName: quay\nPackageOriginator: Organization: crew\nExternalRef: PERSISTENT-ID swhid " + sid,
            {"@graph": [{"type": "software_Package", "name": "quay", "originatedBy": "_:crew",
                         "externalIdentifier": [{"externalIdentifierType": "swhid", "identifier": sid}]},
                        {"type": "Organization", "@id": "_:crew", "name": "crew"}]},
            {"bomFormat": "CycloneDX", "components": [{"name": "quay", "authors": [{"name": "crew"}],
                                                       "externalReferences": [{"url": sid}]}]},
            ('<bom xmlns="urn:cyclonedx"><components><component><name>quay</name><authors><author><name>crew</name>'
             '</author></authors><externalReferences><reference><url>' + sid +
             '</url></reference></externalReferences></component></components></bom>'),
        ]:
            sbom = parse(doc)
            c = sbom["quality"]["components"]
            self.assertEqual((c["with_producer"], c["with_identifier"]), (1, 1), sbom["format"])
            self.assertEqual(sbom["packages"][0]["swhid"], sid)
            self.assertFalse(any(m.startswith("component producer") for m in sbom["quality"]["missing"]))
        doc = {"artifacts": [{"name": "quay", "metadata": {"maintainer": {"name": "crew"}}}], "descriptor": {}}
        c = parse(doc)["quality"]["components"]
        self.assertEqual((c["with_producer"], c["with_supplier"]), (1, 0))


class QualityGate(unittest.TestCase):
    def test_full_missing_list_reaches_passport_and_supply(self):
        import jh_passport
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            doc = {"spdxVersion": "SPDX-2.3", "packages": [{}]}
            Path(tmp, "quay.spdx.json").write_text(json.dumps(doc))
            report = jh_supply.inspect(tmp, requirements={"sbom_minimum": True}, discover=True)
            missing = report["sboms"][0]["quality"]["missing"]
            self.assertGreater(len(missing), 6)
            self.assertEqual(report["summary"]["sbom_missing"], missing)
            self.assertEqual(jh_passport.provenance(report, [])["sbom_missing"], missing)
            for gap in missing:
                self.assertIn(gap, report["gate"]["reasons"][0])

    def test_spdx2_structural_gap_in_policy_reason(self):
        import tempfile
        from pathlib import Path
        import jh_policy
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, "project")
            root.mkdir()
            Path(root, "quay.spdx").write_text("SPDXVersion: SPDX-2.3\nPackageName: quay\n")
            policy = Path(tmp, "policy.json")
            policy.write_text(json.dumps({"schema_version": jh_policy.POLICY_SCHEMA, "require": {"sbom_minimum": True}}))
            result = _util.run_cli("passport", str(root), "--json", "--policy", str(policy))
            reasons = json.loads(result.stdout)["assessment"]["decision"]["reasons"]
            evd, = [r for r in reasons if r["rule"] == "P-EVD-001"]
            self.assertIn("generation context (SPDX 2 has no field for it)", evd["message"])

    def test_pre_421_verdict_is_ineligible_on_recomputation(self):
        legacy = {"path": "prior.spdx.json", "quality": {"basis": "NTIA minimum elements (2021)",
                  "minimum_elements": "met", "missing": [], "cisa_2025_draft_missing": ["generation context"]}}
        report = {"sboms": [legacy], "attestations": [], "warnings": [], "jfrog": [],
                  "requirements": {"sbom_minimum": True}}
        self.assertEqual(jh_supply.summarize(report)["gate"]["result"], "fail")
        for docs in ([], [legacy]):
            best = jh_supply.best_sbom_quality(docs)
            self.assertEqual(best["cisa_2025_draft_missing"], [])
            self.assertEqual(best["not_counted"], list(jh_supply.NOT_COUNTED))
        fresh = parse({"spdxVersion": "SPDX-2.3", "packages": [{"name": "pier"}]})
        self.assertEqual(jh_supply.best_sbom_quality([legacy, fresh])["path"], fresh["path"])
