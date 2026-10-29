"""Backward compatibility: existing commands keep their machine contracts.

Cross-version comparison runs against the previous local release tag when
it exists (`git archive`, read-only, no fetch). Without it the test is
skipped with an explicit reason, never reported as a pass."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

import _util
from _util import run_cli

PREVIOUS = os.environ.get("JH_PREVIOUS_TAG", "v1.1.0")
# Rules added since 1.1.0 (documented in CHANGELOG 2.3.0). Every older rule
# must stay identical; only these ids may be new.
ADDED_RULES = {"JH131", "JH132", "JH133", "JH134", "JH427", "JH428", "JH429", "JH430", "JH431",
               "JH701", "JH702", "JH703", "JH704", "JH705", "JH706", "JH707", "JH708",
               "JH432", "JH709", "JH710", "JH711"}
# Top-level JSON keys added since 1.1.0 (additive; 2.7.1 lists minified bundles).
ADDED_KEYS = {"minified"}


def strip_volatile(obj):
    if isinstance(obj, dict):
        return {k: strip_volatile(v) for k, v in obj.items()
                if k not in ("version", "elapsed_seconds", "root", "generated_at", "elapsed")}
    if isinstance(obj, list):
        return [strip_volatile(v) for v in obj]
    return obj


class CurrentContracts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="jh-compat-")
        self.root = os.path.join(self.tmp, "demo-app")
        shutil.copytree(os.path.join(_util.FIXTURES, "demo-app"), self.root)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_scan_json_keys(self):
        d = json.loads(run_cli("scan", self.root, "--json").stdout)
        for k in ("tool", "version", "command", "root", "summary", "warnings", "config", "cross_file_duplicates",
                  "calibration", "findings"):
            self.assertIn(k, d)
        self.assertEqual(d["command"], "scan")

    def test_sarif_shape(self):
        d = json.loads(run_cli("scan", self.root, "--sarif").stdout)
        self.assertEqual(d["version"], "2.1.0")
        self.assertEqual(d["runs"][0]["tool"]["driver"]["name"], "jankhunt42")

    def test_scan_does_not_compute_passport(self):
        d = json.loads(run_cli("scan", self.root, "--json").stdout)
        self.assertNotIn("passport", d)
        self.assertNotIn("assessment", d)


@unittest.skipUnless(shutil.which("git"), "git not installed")
class CrossVersion(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="jh-xver-")
        ok = subprocess.run(["git", "-C", _util.ROOT, "rev-parse", "--verify", "--quiet", PREVIOUS + "^{commit}"],
                            capture_output=True, timeout=30).returncode == 0
        cls.old = None
        if ok:
            arch = subprocess.run(["git", "-C", _util.ROOT, "archive", PREVIOUS, "scripts"], capture_output=True,
                                  timeout=60)
            if arch.returncode == 0:
                subprocess.run(["tar", "-x", "-C", cls.tmp], input=arch.stdout, check=True, timeout=60)
                cls.old = os.path.join(cls.tmp, "scripts", "jankhunt42")
        cls.root = os.path.join(cls.tmp, "demo-app")
        shutil.copytree(os.path.join(_util.FIXTURES, "demo-app"), cls.root)
        # Documented 2.1.0 rule change (JH104 no longer flags parameterized
        # %s placeholders): the file that exercises it is compared separately
        # in test_documented_jh104_change, so everything else stays strict.
        shutil.move(os.path.join(cls.root, "app", "ledger.py"), os.path.join(cls.tmp, "ledger.py"))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_documented_jh104_change(self):
        probe = os.path.join(self.tmp, "jh104")
        os.makedirs(probe, exist_ok=True)
        shutil.copy(os.path.join(self.tmp, "ledger.py"), os.path.join(probe, "ledger.py"))
        with open(os.path.join(probe, "bad.py"), "w") as fh:
            # jankhunt42: ignore JH104 (writes a deliberately vulnerable probe file)
            fh.write('def f(c, n):\n    return c.execute("SELECT * FROM t WHERE n = \'%s\'" % n)\n')
        old = json.loads(self.run_old("scan", probe, "--json", "--rule", "JH104").stdout)
        new = json.loads(run_cli("scan", probe, "--json", "--rule", "JH104").stdout)
        old_hits = sorted((f["path"], f["line"]) for f in old["findings"])
        new_hits = sorted((f["path"], f["line"]) for f in new["findings"])
        self.assertIn(("ledger.py", 11), old_hits)      # 1.1.0 false positive on a placeholder
        self.assertNotIn(("ledger.py", 11), new_hits)   # fixed
        self.assertIn(("bad.py", 2), new_hits)          # real % formatting still flagged
        self.assertEqual(set(new_hits) - set(old_hits), set())  # the change only removes findings

    def run_old(self, *args):
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        return subprocess.run([sys.executable, self.old] + list(args), capture_output=True, text=True, env=env, timeout=300)

    def setUp(self):
        if not self.old:
            self.skipTest("previous release %s not available locally (not fetched)" % PREVIOUS)

    def test_scan_score_rules_sarif_identical(self):
        # the previous release says `score`; since 4.1.0 that is `scan --score`
        for args, new_args in ((("scan", self.root, "--json"),) * 2,
                               (("score", self.root, "--json"), ("scan", self.root, "--score", "--json")),
                               (("rules", "--json"),) * 2, (("scan", self.root, "--sarif"),) * 2):
            old = json.loads(self.run_old(*args).stdout)
            new = json.loads(run_cli(*new_args).stdout)
            if args == ("rules", "--json"):
                self.assertEqual({r["id"] for r in new} - {r["id"] for r in old}, ADDED_RULES)
                new = [r for r in new if r["id"] not in ADDED_RULES]
            if isinstance(new, dict):
                new = {k: v for k, v in new.items() if k not in ADDED_KEYS - set(old)}
            self.assertEqual(strip_volatile(old), strip_volatile(new), args)

    def test_markdown_scan_identical_modulo_version(self):
        # The only intentional human-output change in 2.0: the product name is
        # written in lowercase (documented in CHANGELOG and README migration notes).
        old = self.run_old("scan", self.root, "--md").stdout.replace("Jank" + "Hunt42", "jankhunt42")
        new = run_cli("scan", self.root, "--md").stdout
        drop = lambda t: [l for l in t.splitlines() if "elapsed" not in l and " in " not in l and "v1." not in l
                          and "v2." not in l and "Scan time" not in l and "Minified bundles" not in l]
        self.assertEqual(drop(old), drop(new))


if __name__ == "__main__":
    unittest.main()
