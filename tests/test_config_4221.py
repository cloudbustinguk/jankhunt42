"""Configured ratings apply before the floor and the caps; invalid settings are reported and ignored (invented
projects, JSON configs so every supported Python reads them)."""
import json
import tempfile
import unittest
from pathlib import Path

from _util import run_cli

BARE = "try:\n    value = 1\nexcept:\n    raise\n"


class ConfiguredRatings(unittest.TestCase):
    def project(self, files):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        for rel, text in files.items():
            (root / rel).write_text(text, encoding="utf-8")
        return root

    def scan(self, root, *args):
        proc = run_cli("scan", str(root), "--json", "--no-progress", *args)
        return proc, json.loads(proc.stdout)

    def test_a_promotion_shows_at_the_default_floor_and_a_demotion_counts_below_a_higher_one(self):
        promoted = self.project({"sample.py": "value = 1  # noqa\n",
                                 ".jankhunt42.json": '{"rules": {"JH306": {"severity": "major"}}}\n'})
        self.assertEqual(self.scan(promoted)[1]["summary"]["counts"], {"major": 1})
        demoted = self.project({"sample.py": BARE, ".jankhunt42.json": '{"rules": {"JH217": {"severity": "minor"}}}\n'})
        _, doc = self.scan(demoted, "--min-severity", "major")
        self.assertEqual(doc["findings"], [])
        self.assertEqual(doc["set_aside"]["below_floor"]["minor"], 1)

    def test_a_finding_the_config_sets_aside_never_takes_the_only_slot(self):
        root = self.project({"a.py": BARE, "b.py": BARE,
                             ".jankhunt42.json": '{"paths": {"a.py": {"ignore": ["JH217"]}}}\n'})
        _, doc = self.scan(root, "--max-per-rule", "1")
        self.assertEqual([f["path"] for f in doc["findings"]], ["b.py"])
        self.assertEqual(doc["config_suppressed"], 1)

    def test_a_misspelled_severity_is_reported_and_cannot_pass_the_gate(self):
        root = self.project({"sample.py": BARE, ".jankhunt42.json": '{"rules": {"JH217": {"severity": "majo"}}}\n'})
        proc, doc = self.scan(root, "--fail-on", "major")
        self.assertEqual(doc["summary"]["counts"], {"major": 1})
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("unknown severity", proc.stderr)

    def test_a_wrongly_typed_ignore_is_reported_and_the_scan_continues(self):
        root = self.project({"sample.py": BARE, ".jankhunt42.json": '{"ignore": true}\n'})
        proc, doc = self.scan(root)
        self.assertEqual(doc["summary"]["counts"], {"major": 1})
        self.assertIn("expected a string or a list of strings", proc.stderr)


if __name__ == "__main__":
    unittest.main()
