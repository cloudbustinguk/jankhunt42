"""`map --base`: graph delta from committed git objects only."""
import json
import os
import shutil
import subprocess
import tempfile
import unittest

import _util
from _util import run_cli

GIT_ENV = {"GIT_AUTHOR_NAME": "fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
           "GIT_COMMITTER_NAME": "fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
           "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}


def git(root, *args):
    env = dict(os.environ, **GIT_ENV)
    subprocess.run(["git", "-C", root] + list(args), check=True, capture_output=True, env=env, timeout=60)


def write(root, rel, text):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(text)


@unittest.skipUnless(shutil.which("git"), "git not installed")
class BaseDiff(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="jh-diff-")
        git(self.root, "init", "-q", "-b", "main")
        write(self.root, "app/db.py", 'import psycopg\nc = psycopg.connect("postgresql://ledger.prod.internal/ledger")\n'
                                      'c.execute("SELECT a FROM t")\n')
        write(self.root, ".jankhunt42.json", json.dumps({"passport": {"assets": [
            {"match": "ledger.prod", "sensitivity": "restricted", "criticality": "critical"}]}}))
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "base")
        write(self.root, "app/db.py", 'import psycopg\nc = psycopg.connect("postgresql://ledger.prod.internal/ledger")\n'
                                      'c.execute("SELECT a FROM t")\nc.execute("DELETE FROM t")\n')
        write(self.root, "app/ai.py", 'import requests\nrequests.post("https://api.vendor.example.com/v1/x")\n')
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "head")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def delta(self, *extra):
        r = run_cli("map", self.root, "--base", "HEAD~1", "--json", *extra)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)

    def test_reports_escalation_new_reach_and_boundaries(self):
        rep = self.delta()
        d = rep["delta"]
        self.assertTrue(d["edges"]["added"])
        self.assertEqual(len(d["permission_escalations"]), 1)
        self.assertIn("delete", d["permission_escalations"][0]["after"])
        self.assertTrue(any(n["impact"] == "integrity" and n["sensitive"] for n in d["newly_reachable_sensitive"]))
        self.assertIn("internal->external", d["trust_boundaries"]["added"])
        self.assertTrue(rep["source_revision"])
        self.assertTrue(rep["scope"]["snapshot"].startswith("git:"))

    def test_dirty_tree_never_contaminates(self):
        clean = self.delta()
        write(self.root, "app/evil.py", 'import pymongo\npymongo.MongoClient("mongodb://dirty.example/x")\n')
        with open(os.path.join(self.root, "app/db.py"), "a") as fh:
            fh.write('c.execute("GRANT ALL ON t TO x")\n')
        dirty = self.delta()
        self.assertNotIn("dirty.example", json.dumps(dirty["graph"]))
        self.assertNotIn("administers", json.dumps(dirty["graph"]))
        self.assertEqual(clean["graph"], dirty["graph"])
        self.assertEqual(clean["delta"], dirty["delta"])
        self.assertTrue(any("working-tree changes are ignored" in w for w in dirty["warnings"]))

    def test_declarations_come_from_the_revision(self):
        write(self.root, ".jankhunt42.json", json.dumps({"passport": {"assets": [{"match": "ledger.prod", "sensitivity": "public"}]}}))
        rep = self.delta()
        node = [n for n in rep["graph"]["nodes"] if "ledger.prod" in n["display_label"]][0]
        self.assertEqual(node["sensitivity"], "restricted")

    def test_same_revision_is_empty_delta(self):
        r = run_cli("map", self.root, "--base", "HEAD", "--json")
        d = json.loads(r.stdout)["delta"]
        self.assertEqual((d["nodes"]["added"], d["edges"]["added"], d["edges"]["removed"]), ([], [], []))
        self.assertFalse(d["exposure"]["changed"])

    def test_removal_is_reported(self):
        os.remove(os.path.join(self.root, "app/ai.py"))
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "drop ai")
        r = run_cli("map", self.root, "--base", "HEAD~1", "--json")
        d = json.loads(r.stdout)["delta"]
        self.assertTrue(d["edges"]["removed"])
        self.assertEqual({x["state"] for x in d["edges"]["removed"]}, {"removed"})
        self.assertIn("internal->external", d["trust_boundaries"]["removed"])

    def test_bad_ref_is_usage_error(self):
        r = run_cli("map", self.root, "--base", "no-such-ref")
        self.assertEqual(r.returncode, 2)
        self.assertIn("map --base", r.stderr)

    def test_markdown_and_html_show_delta(self):
        md = run_cli("map", self.root, "--base", "HEAD~1").stdout
        self.assertIn("## Graph delta", md)
        html = run_cli("map", self.root, "--base", "HEAD~1", "--html").stdout
        self.assertIn('"delta"', html)


if __name__ == "__main__":
    unittest.main()
