"""4.19.0: the uncertainty bands on the Jank Score and the exposure class (reporting only; no score changes)."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

import _util  # noqa: F401  (puts scripts/ on the path)
import jh_graph as G
import jh_score as S
from jh_core import Finding

JH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts", "jankhunt42")


def f(severity, confidence, category="security", rule="JH103"):
    return Finding(rule=rule, title="t", severity=severity, category=category, path="a.py", line=1,
                   confidence=confidence)


def drv(level, tier):
    return {"level": level, "tier": tier, "rule": "X", "node": "n", "impact": "integrity", "path": [], "why": ""}


class ScoreBand(unittest.TestCase):
    def test_low_end_counts_only_high_confidence(self):
        r = S.compute([f("critical", "medium")], 10000)
        self.assertEqual(r.band, (0, r.score))
        self.assertGreater(r.score, 0)
        self.assertEqual(r.to_dict()["band"], [0, r.score])
        self.assertIn("high-confidence", r.to_dict()["band_basis"])

    def test_a_sure_score_is_a_point(self):
        r = S.compute([f("critical", "high"), f("minor", "high", "tests", "JH501")], 2000)
        self.assertEqual(r.band, (r.score, r.score))
        for d in r.dimensions.values():
            self.assertEqual(d.to_dict()["band"], [d.score, d.score])

    def test_the_band_never_changes_the_score(self):
        cases = ([], [f("major", "low")], [f("critical", "medium"), f("blocker", "high", "reliability", "JH201")],
                 [f("minor", "medium", "tests", "JH501")] * 30)
        for items in cases:
            with self.subTest(n=len(items)):
                a, b = S.compute(items, 3000), S.compute(items, 3000, band=False)
                self.assertEqual((a.score, a.grade, a.policy), (b.score, b.grade, b.policy))
                self.assertIsNone(b.band)
                self.assertLessEqual(a.band[0], a.band[1])
                self.assertEqual(a.band[1], a.score)

    def test_markdown_and_terminal_show_a_wide_band_only(self):
        wide = S.scorecard_markdown(S.compute([f("critical", "medium")], 10000))
        point = S.scorecard_markdown(S.compute([f("critical", "high")], 10000))
        self.assertIn("Band **0–", wide)
        self.assertNotIn("Band **", point)


class ExposureBand(unittest.TestCase):
    def test_low_end_uses_verified_and_supported_drivers_only(self):
        self.assertEqual(G.class_low([drv("High", "inferred"), drv("Moderate", "supported")]), "Moderate")
        self.assertEqual(G.class_low([drv("Critical", "verified"), drv("High", "inferred")]), "Critical")
        self.assertEqual(G.class_low([drv("High", "inferred"), drv("High", "unknown")]), "Low")
        self.assertEqual(G.class_low([]), "Low")

    def test_monotone_in_evidence(self):
        weak = [drv("High", "inferred"), drv("Moderate", "inferred")]
        for i in range(len(weak)):
            stronger = [dict(d) for d in weak]
            stronger[i]["tier"] = "supported"
            self.assertGreaterEqual(G.EXPOSURE_RANK[G.class_low(stronger)], G.EXPOSURE_RANK[G.class_low(weak)])

    def test_assessment_carries_the_band(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "app.py"), "w") as fh:
                fh.write("import os\nimport psycopg2\nconn = psycopg2.connect(os.environ['DATABASE_URL'])\n"
                         "conn.cursor().execute('DELETE FROM customers WHERE id = %s', (1,))\n")
            out = subprocess.run([sys.executable, "-I", "-B", JH, "map", d, "--json"], capture_output=True,
                                 text=True, timeout=120)
            exp = json.loads(out.stdout)["assessment"]["exposure"]
            lo, hi = exp["class_band"]
            self.assertEqual(hi, exp["class"])
            self.assertLessEqual(G.EXPOSURE_RANK[lo], G.EXPOSURE_RANK[hi])
            self.assertIn("verified or supported", exp["band_basis"])


class PassportBand(unittest.TestCase):
    def test_passport_states_a_wide_score_band(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "app.py"), "w") as fh:
                fh.write("import requests, subprocess\n"
                         "def sync(order_id):\n    requests.post('https://api.example.com/v1/orders', json={})\n"
                         "def run(cmd):\n    subprocess.call(cmd, shell=True)\n")
            md = subprocess.run([sys.executable, "-I", "-B", JH, "passport", d, "--md"], capture_output=True,
                                text=True, timeout=120).stdout
            self.assertRegex(md, r"Technical Jank Score: \*\*\d+/100\*\* grade \w \(\w+\); band 0-\d+ "
                                 r"\(high-confidence findings alone score 0\)")
            js = json.loads(subprocess.run([sys.executable, "-I", "-B", JH, "passport", d, "--profile", "citizen",
                                            "--json"], capture_output=True, text=True, timeout=120).stdout)
            self.assertEqual(js["assessment"]["jank"]["band"][0], 0)
            self.assertTrue(any("less certain leads" in line for line in js["governance"]["brief"]))


if __name__ == "__main__":
    unittest.main()
