"""SBOM minimum-elements quality across every supported format (SPDX 2.3
JSON and tag-value, SPDX 3.0.1 JSON-LD, CycloneDX JSON and XML), the
SPDX 3.0.1 property names, the --require-sbom-minimum gate, and the
passport's require.sbom_minimum policy."""
import json
import os
import shutil
import tempfile
import unittest

import _util
from _util import run_cli
import jh_policy
import jh_supply

SPDX2_FULL = {
    "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": "app",
    "documentNamespace": "https://example.invalid/spdx/app", "documentDescribes": ["SPDXRef-app"],
    "creationInfo": {"created": "2026-10-01T00:00:00Z",
                     "creators": ["Tool: example-sbom-1.0", "Organization: Example Org"]},
    "packages": [
        {"name": "app", "SPDXID": "SPDXRef-app", "versionInfo": "1.0.0", "supplier": "Organization: Example Org",
         "licenseConcluded": "MIT", "checksums": [{"algorithm": "SHA256", "checksumValue": "ab" * 32}],
         "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                           "referenceLocator": "pkg:pypi/app@1.0.0"}]},
        {"name": "requests", "SPDXID": "SPDXRef-req", "versionInfo": "2.32.3", "supplier": "Organization: PSF",
         "licenseConcluded": "Apache-2.0", "checksums": [{"algorithm": "SHA256", "checksumValue": "cd" * 32}],
         "externalRefs": [{"referenceCategory": "SECURITY", "referenceType": "cpe23Type",
                           "referenceLocator": "cpe:2.3:a:python:requests:2.32.3:*:*:*:*:*:*:*"}]},
    ],
    "relationships": [
        {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-app"},
        {"spdxElementId": "SPDXRef-app", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-req"},
    ],
}

SPDX3 = {
    "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
    "@graph": [
        {"type": "CreationInfo", "@id": "_:ci", "specVersion": "3.0.1", "created": "2026-10-01T00:00:00Z",
         "createdBy": ["urn:example:org"], "createdUsing": ["urn:example:tool"]},
        {"type": "Organization", "spdxId": "urn:example:org", "name": "Example Org", "creationInfo": "_:ci"},
        {"type": "Tool", "spdxId": "urn:example:tool", "name": "example-sbom", "creationInfo": "_:ci"},
        {"type": "software_Sbom", "spdxId": "urn:example:sbom", "creationInfo": "_:ci", "name": "app sbom",
         "software_sbomType": ["build"], "rootElement": ["urn:example:app"]},
        {"type": "software_Package", "spdxId": "urn:example:app", "creationInfo": "_:ci", "name": "app",
         "software_packageVersion": "1.0.0", "software_packageUrl": "pkg:npm/app@1.0.0",
         "suppliedBy": "urn:example:org",
         "verifiedUsing": [{"type": "Hash", "algorithm": "sha256", "hashValue": "ef" * 32}]},
        {"type": "software_Package", "spdxId": "urn:example:left-pad", "creationInfo": "_:ci", "name": "left-pad",
         "software_packageVersion": "1.3.0", "suppliedBy": "urn:example:org",
         "externalIdentifier": [{"type": "ExternalIdentifier", "externalIdentifierType": "cpe23",
                                 "identifier": "cpe:2.3:a:left-pad:left-pad:1.3.0:*:*:*:*:*:*:*"}],
         "verifiedUsing": [{"type": "Hash", "algorithm": "sha256", "hashValue": "12" * 32}]},
        {"type": "simplelicensing_LicenseExpression", "spdxId": "urn:example:lic-mit", "creationInfo": "_:ci",
         "simplelicensing_licenseExpression": "MIT"},
        {"type": "Relationship", "spdxId": "urn:example:r1", "creationInfo": "_:ci", "from": "urn:example:app",
         "to": ["urn:example:left-pad"], "relationshipType": "dependsOn"},
        {"type": "Relationship", "spdxId": "urn:example:r2", "creationInfo": "_:ci", "from": "urn:example:app",
         "to": ["urn:example:lic-mit"], "relationshipType": "hasConcludedLicense"},
        {"type": "Relationship", "spdxId": "urn:example:r3", "creationInfo": "_:ci", "from": "urn:example:left-pad",
         "to": ["urn:example:lic-mit"], "relationshipType": "hasDeclaredLicense"},
    ],
}

CDX_JSON = {
    "bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
    "metadata": {"timestamp": "2026-10-01T00:00:00Z", "lifecycles": [{"phase": "build"}],
                 "tools": {"components": [{"type": "application", "name": "example-sbom"}]},
                 "authors": [{"name": "Example Org"}],
                 "component": {"name": "app", "version": "1.0.0", "supplier": {"name": "Example Org"},
                               "purl": "pkg:npm/app@1.0.0"}},
    "components": [
        {"bom-ref": "pkg:npm/express@4.21.1", "name": "express", "version": "4.21.1", "group": "web",
         "supplier": {"name": "OpenJS Foundation"}, "purl": "pkg:npm/express@4.21.1",
         "hashes": [{"alg": "SHA-256", "content": "34" * 32}], "licenses": [{"license": {"id": "MIT"}}]},
        {"bom-ref": "pkg:npm/qs@6.13.0", "name": "qs", "version": "6.13.0", "group": "web",
         "purl": "pkg:npm/qs@6.13.0"},
    ],
    "dependencies": [{"ref": "pkg:npm/express@4.21.1", "dependsOn": ["pkg:npm/qs@6.13.0"]},
                     {"ref": "pkg:npm/qs@6.13.0", "dependsOn": []}],
}

CDX_XML = """<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1">
  <metadata>
    <timestamp>2026-10-01T00:00:00Z</timestamp>
    <lifecycles><lifecycle><phase>build</phase></lifecycle></lifecycles>
    <tools><components><component type="application"><name>example-sbom</name></component></components></tools>
    <authors><author><name>Example Org</name></author></authors>
    <component type="application" bom-ref="app-ref">
      <supplier><name>Example Org</name></supplier>
      <name>app</name><version>1.0.0</version><purl>pkg:maven/org.example/app@1.0.0</purl>
    </component>
  </metadata>
  <components>
    <component type="library" bom-ref="pkg:maven/org.example/lib@2.0.0">
      <supplier><name>Example Org</name></supplier>
      <name>lib</name><version>2.0.0</version>
      <hashes><hash alg="SHA-256">5656565656565656565656565656565656565656565656565656565656565656</hash></hashes>
      <licenses><license><id>Apache-2.0</id></license></licenses>
      <purl>pkg:maven/org.example/lib@2.0.0</purl>
    </component>
  </components>
  <dependencies><dependency ref="app-ref"><dependency ref="pkg:maven/org.example/lib@2.0.0"/></dependency></dependencies>
</bom>
"""

TAG_VALUE = """SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
DocumentName: tag-app
DocumentNamespace: https://example.invalid/spdx/tag-app
Creator: Tool: example-sbom-1.0
Creator: Organization: Example Org
Created: 2026-10-01T00:00:00Z
Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-app

PackageName: app
SPDXID: SPDXRef-app
PackageVersion: 1.0.0
PackageSupplier: Organization: Example Org
PackageDownloadLocation: https://example.invalid/app-1.0.0.tar.gz
PackageChecksum: SHA256: 7878787878787878787878787878787878787878787878787878787878787878
PackageLicenseConcluded: MIT
ExternalRef: PACKAGE-MANAGER purl pkg:pypi/app@1.0.0
Relationship: SPDXRef-app DEPENDS_ON SPDXRef-DOCUMENT
"""


def parse(name, text):
    return jh_supply.parse_sbom("/x/" + name, name, text)


class Formats(unittest.TestCase):
    def test_spdx2_complete_meets_the_minimum(self):
        q = parse("app.spdx.json", json.dumps(SPDX2_FULL))["quality"]
        self.assertEqual((q["minimum_elements"], q["missing"]), ("met", []))
        self.assertEqual(q["cisa_2025_draft_missing"], ["generation context"])   # SPDX 2 cannot state it
        self.assertEqual(q["components"]["with_identifier"], 2)                   # purl or CPE

    def test_spdx2_gaps_are_named(self):
        doc = json.loads(json.dumps(SPDX2_FULL))
        doc["packages"][1]["supplier"] = "NOASSERTION"
        doc["relationships"] = doc["relationships"][:1]
        doc["creationInfo"]["creators"] = []
        q = parse("app.spdx.json", json.dumps(doc))["quality"]
        self.assertEqual(q["minimum_elements"], "partial")
        self.assertEqual(q["missing"], ["supplier for 1 of 2 components", "dependency relationships",
                                        "author of the SBOM data"])

    def test_spdx3_jsonld_uses_the_301_property_names(self):
        sbom = parse("app.spdx3.json", json.dumps(SPDX3))
        pkgs = {p["name"]: p for p in sbom["packages"]}
        self.assertEqual((pkgs["app"]["version"], pkgs["app"]["purl"], pkgs["app"]["license"]),
                         ("1.0.0", "pkg:npm/app@1.0.0", "MIT"))
        self.assertEqual((pkgs["left-pad"]["supplier"], pkgs["left-pad"]["license"]), ("Example Org", "MIT"))
        self.assertTrue(pkgs["left-pad"]["cpe"].startswith("cpe:2.3:"))
        self.assertEqual(sbom["spec_version"], "SPDX-3.0.1")
        q = sbom["quality"]
        self.assertEqual((q["minimum_elements"], q["cisa_2025_draft_missing"]), ("met", []))

    def test_cyclonedx_json_supplier_is_not_the_group(self):
        sbom = parse("bom.cdx.json", json.dumps(CDX_JSON))
        pkgs = {p["name"]: p for p in sbom["packages"]}
        self.assertEqual(pkgs["qs"]["supplier"], "")                              # group "web" is a namespace
        q = sbom["quality"]
        self.assertEqual(q["missing"], ["supplier for 1 of 3 components"])
        self.assertEqual(q["document"], {"timestamp": True, "author": True, "tool": True,
                                         "dependency_relationships": True, "primary_component": True,
                                         "generation_context": True})

    def test_cyclonedx_xml(self):
        sbom = parse("bom.xml", CDX_XML)
        self.assertEqual([p["name"] for p in sbom["packages"]], ["app", "lib"])  # primary yes, tool component no
        self.assertEqual(sbom["packages"][1]["hashes"], ["SHA-256"])
        self.assertEqual(sbom["quality"]["minimum_elements"], "met")

    def test_spdx_tag_value(self):
        sbom = parse("app.spdx", TAG_VALUE)
        pkg = sbom["packages"][0]
        self.assertEqual((pkg["purl"], pkg["hashes"]), ("pkg:pypi/app@1.0.0", ["SHA256"]))   # not the download URL
        self.assertEqual(sbom["quality"]["minimum_elements"], "met")

    def test_spdx2_noassertion_does_not_hide_a_declared_licence(self):
        doc = json.loads(json.dumps(SPDX2_FULL))
        doc["packages"][0]["licenseConcluded"] = "NOASSERTION"
        doc["packages"][0]["licenseDeclared"] = "BSD-3-Clause"
        sbom = parse("app.spdx.json", json.dumps(doc))
        self.assertEqual(sbom["packages"][0]["license"], "BSD-3-Clause")
        self.assertEqual(sbom["quality"]["components"]["with_license"], 2)

    def test_cyclonedx_xml_walks_like_json(self):
        xml = CDX_XML.replace(
            "<purl>pkg:maven/org.example/lib@2.0.0</purl>",
            "<purl>pkg:maven/org.example/lib@2.0.0</purl>"
            "<pedigree><ancestors><component type=\"library\"><name>upstream-lib</name><version>1.9.0</version>"
            "</component></ancestors></pedigree>").replace(
            "<name>app</name><version>1.0.0</version><purl>pkg:maven/org.example/app@1.0.0</purl>",
            "<name>app</name><version>1.0.0</version><purl>pkg:maven/org.example/app@1.0.0</purl>"
            "<components><component type=\"library\"><name>app-core</name><version>1.0.0</version></component>"
            "</components>")
        names = [p["name"] for p in parse("bom.xml", xml)["packages"]]
        self.assertEqual(names, ["app", "app-core", "lib"])        # nested primary yes, pedigree history no

    def test_no_components_is_not_met(self):
        q = parse("empty.cdx.json", json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6"}))["quality"]
        self.assertEqual(q["minimum_elements"], "not-met")


class Gates(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="jh-sbom-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, name, doc):
        with open(os.path.join(self.tmp, name), "w") as fh:
            fh.write(doc if isinstance(doc, str) else json.dumps(doc))

    def test_require_sbom_minimum(self):
        self.write("bom.cdx.json", CDX_JSON)
        partial = run_cli("supply-chain", self.tmp, "--json", "--require-sbom-minimum")
        self.assertEqual(partial.returncode, 1)
        report = json.loads(partial.stdout)
        self.assertEqual(report["summary"]["sbom_minimum_elements"], "partial")
        self.assertIn("no SBOM meets the NTIA minimum elements", report["gate"]["reasons"][0])
        self.write("app.spdx.json", SPDX2_FULL)
        met = run_cli("supply-chain", self.tmp, "--json", "--require-sbom-minimum")
        self.assertEqual(met.returncode, 0, met.stdout[-400:])
        md = run_cli("supply-chain", self.tmp, "--md").stdout
        self.assertIn("| Minimum elements |", md)
        self.assertIn("supplier for 1 of 3 components", md)

    def test_passport_policy_requires_the_minimum(self):
        self.write("bom.cdx.json", CDX_JSON)
        with open(os.path.join(self.tmp, "app.py"), "w") as fh:
            fh.write("import json\n")
        policy = os.path.join(tempfile.mkdtemp(prefix="jh-pol-"), "policy.json")
        with open(policy, "w") as fh:
            json.dump({"schema_version": jh_policy.POLICY_SCHEMA, "require": {"sbom_minimum": True}}, fh)
        try:
            p = json.loads(run_cli("passport", self.tmp, "--json", "--policy", policy).stdout)
        finally:
            shutil.rmtree(os.path.dirname(policy))
        self.assertEqual(p["provenance"]["sbom_minimum_elements"], "partial")
        evd = {r["rule"]: r for r in p["assessment"]["decision"]["reasons"]}.get("P-EVD-001")
        self.assertIn("NTIA minimum elements", evd["message"])


if __name__ == "__main__":
    unittest.main()
