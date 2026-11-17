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
    def test_low_end_leaves_out_only_low_confidence(self):
        # a small codebase, so density (not one finding's severity floor) sets the score
        weak = S.compute([f("major", "high"), f("critical", "low", rule="JH112")], 250)
        sure = S.compute([f("major", "high")], 250, band=False)
        self.assertEqual(weak.band, (sure.score, weak.score))
        self.assertLess(weak.band[0], weak.band[1])
        self.assertEqual(weak.to_dict()["band"], [sure.score, weak.score])
        self.assertIn("low-confidence", weak.to_dict()["band_basis"])

    def test_medium_confidence_leads_stay_in_the_low_end(self):
        # medium is the ordinary confidence of a lead; a band that dropped it fell to 0 on 4% of real repositories
        for items in ([f("critical", "medium")], [f("major", "medium"), f("major", "high", rule="JH104")]):
            with self.subTest(n=len(items)):
                r = S.compute(items, 10000)
                self.assertEqual(r.band, (r.score, r.score))
                self.assertGreater(r.score, 0)

    def test_the_band_never_changes_the_score(self):
        cases = ([], [f("major", "low")], [f("critical", "medium"), f("blocker", "high", "reliability", "JH201")],
                 [f("minor", "medium", "tests", "JH501")] * 30, [f("critical", "low"), f("minor", "high")])
        for items in cases:
            with self.subTest(n=len(items)):
                a, b = S.compute(items, 3000), S.compute(items, 3000, band=False)
                self.assertEqual((a.score, a.grade, a.policy), (b.score, b.grade, b.policy))
                self.assertIsNone(b.band)
                self.assertLessEqual(a.band[0], a.band[1])
                self.assertEqual(a.band[1], a.score)

    def test_markdown_shows_a_wide_band_only(self):
        wide = S.scorecard_markdown(S.compute([f("critical", "low")], 10000))
        point = S.scorecard_markdown(S.compute([f("critical", "medium")], 10000))
        self.assertIn("Band **0–", wide)
        self.assertIn("still count", wide)
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
    APP = ("import random, subprocess\n"
           "def reset_token():\n    token = str(random.random())\n    return token\n"
           "def run(cmd):\n    subprocess.call(cmd, shell=True)\n")

    def test_passport_states_a_wide_score_band_for_reviewers(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "app.py"), "w") as fh:
                fh.write(self.APP)
            md = subprocess.run([sys.executable, "-I", "-B", JH, "passport", d, "--md"], capture_output=True,
                                text=True, timeout=120).stdout
            self.assertRegex(md, r"Technical Jank Score: \*\*\d+/100\*\* grade \w \(\w+\); band \d+-\d+ "
                                 r"\(without low-confidence findings it scores \d+\)")

    def test_citizen_brief_never_reassures_with_numbers(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "app.py"), "w") as fh:
                fh.write(self.APP)
            js = json.loads(subprocess.run([sys.executable, "-I", "-B", JH, "passport", d, "--profile", "citizen",
                                            "--json"], capture_output=True, text=True, timeout=120).stdout)
            lo, hi = js["assessment"]["jank"]["band"]
            self.assertLess(lo, hi)
            line = [l for l in js["governance"]["brief"] if "weak signals" in l]
            self.assertEqual(len(line), 1)
            self.assertIn("still counts until a person checks it", line[0])
            self.assertNotRegex(line[0], r"\d")
            for l in js["governance"]["brief"]:
                self.assertNotRegex(l, r"(?i)puts it at (Low|Moderate|High)|certain ones alone")


if __name__ == "__main__":
    unittest.main()
