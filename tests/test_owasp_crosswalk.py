"""4.19.0: the passport's own rules map onto the OWASP Citizen Development Top 10, so every one of its ten risks is
reachable from some rule (CD-SEC-09 Asset Management Failures only from the passport rules)."""
import json
import os
import subprocess
import sys
import unittest

import _util  # noqa: F401
import jh_frameworks as F
import jh_policy as P

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JH = os.path.join(ROOT, "scripts", "jankhunt42")
DEMO = os.path.join(ROOT, "tests", "fixtures", "demo-app")


class Crosswalk(unittest.TestCase):
    def test_every_citizen_risk_is_reachable(self):
        reachable = {rid for ids in list(F.OWASP_RULES.values()) + list(F.OWASP_PASSPORT_RULES.values()) for rid in ids}
        for n in range(1, 11):
            self.assertIn("CD-SEC-%02d" % n, reachable)
        scanner = {rid for ids in F.OWASP_RULES.values() for rid in ids}
        self.assertNotIn("CD-SEC-09", scanner)          # only the governance rules can see asset management

    def test_mapping_names_real_rules_and_risks(self):
        for rule, ids in F.OWASP_PASSPORT_RULES.items():
            self.assertIn(rule, P.RULES, rule)
            for rid in ids:
                self.assertIn(rid, F.OWASP_RISKS, (rule, rid))

    def test_only_failing_reasons_count(self):
        reasons = [{"rule": "P-OWN-001", "outcome": "block"}, {"rule": "P-CHG-001", "outcome": "pass"},
                   {"rule": "P-JNK-001", "outcome": "review"}, {"rule": "P-DAT-003", "outcome": "insufficient-evidence"}]
        got = F.owasp_counts([], reasons)["decision_risks"]
        self.assertEqual(got, [{"id": "CD-SEC-09", "title": "Asset Management Failures", "rules": ["P-DAT-003", "P-OWN-001"]}])
        self.assertEqual(F.owasp_counts([])["decision_risks"], [])

    def test_passport_reports_governance_risks(self):
        js = json.loads(subprocess.run([sys.executable, "-I", "-B", JH, "passport", DEMO, "--profile", "citizen", "--json"],
                                       capture_output=True, text=True, timeout=120).stdout)
        risks = {r["id"]: r["rules"] for r in js["assessment"]["owasp"]["decision_risks"]}
        self.assertIn("P-CUS-001", risks.get("CD-SEC-09", []))
        md = subprocess.run([sys.executable, "-I", "-B", JH, "passport", DEMO, "--profile", "citizen", "--md"],
                            capture_output=True, text=True, timeout=120).stdout
        self.assertIn("- Governance risks by OWASP category: ", md)
        self.assertIn("CD-SEC-09 Asset Management Failures (", md)


if __name__ == "__main__":
    unittest.main()
