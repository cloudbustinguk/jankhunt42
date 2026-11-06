"""P-ENV-001 (4.15.0): where non-production meets production. A development configuration that points at a
production asset, a production one that depends on a non-production system, or components in different known
environments. Unknown environments never count; test code is left out. Invented projects and hosts only."""
import json
import os
import shutil
import tempfile
import unittest

from _util import run_cli
import jh_passport as P
import jh_policy

FILES = {
    "app.py": "import os\nimport psycopg2\n\nconn = psycopg2.connect(os.environ['DATABASE_URL'])\n",
    ".env.local": "DATABASE_URL=postgresql://app:pw@ledger-db.prod.example.com:5432/ledger\n",
    ".env.production": "DATABASE_URL=postgresql://app@orders-db.staging.example.com:5432/orders\n",
    "appsettings.Development.json": '{\n  "ConnectionStrings": {\n    "Main": "Server=sql-prod.example.com;Database=crm;'
                                    'User Id=app;Password=x"\n  }\n}\n',
    "tests/test_db.py": "import psycopg2\npsycopg2.connect('postgresql://u@ledger-db.prod.example.com/x')\n",
}


def node(nid, env, kind="database", label=None, domain="internal"):
    return {"id": nid, "kind": kind, "display_label": label or nid, "environment": env, "trust_domain": domain}


def edge(eid, source, target, refs, env=None, verification="declared"):
    return {"id": eid, "source": source, "target": target, "evidence_refs": refs, "verification": verification,
            "trust_boundary": {"domain": None, "environment": env}}


class ConfigEnvironment(unittest.TestCase):
    def test_names_and_folders(self):
        for path, want in ((".env.development", "non-production"), (".env.local", "non-production"),
                           (".env.production", "production"), (".env.example", "unknown"),
                           ("appsettings.Development.json", "non-production"), ("appsettings.json", "unknown"),
                           ("docker-compose.dev.yml", "non-production"), ("k8s/prod/deploy.yaml", "production"),
                           ("deploy/staging/values.yaml", "non-production"), ("dev-portal/settings.yaml", "unknown"),
                           ("live_chat.json", "unknown"), ("app/ledger.py", "unknown"), ("", "unknown"),
                           ("dev_server.py", "unknown"), ("scripts/rt-live-test.mjs", "unknown"),
                           ("config/live-test.json", "unknown"), ("infra/dev/main.tf", "non-production"),
                           ("values-staging.yaml", "non-production"), (".env", "unknown")):
            with self.subTest(path=path):
                self.assertEqual(P.config_environment(path), want)


class Crossings(unittest.TestCase):
    REPORT = {
        "graph": {
            "nodes": [node("app", "unknown", "application", "app"), node("wl-dev", "non-production", "workload", "worker"),
                      node("db-prod", "production"), node("db-stg", "non-production"), node("db-unk", "unknown"),
                      node("db-prod2", "production"), node("local-prod", "production", domain="local"),
                      node("saas-prod", "production", "external", domain="external"),
                      node("pay-sandbox", "non-production", "external", domain="external")],
            "edges": [edge("e1", "app", "db-prod", ["v1", "v2"]),                       # .env.local -> prod
                      edge("e2", "app", "db-stg", ["v3"]),                              # .env.production -> staging
                      edge("e3", "wl-dev", "db-prod2", ["v4"], env="non-production->production"),
                      edge("e4", "app", "db-unk", ["v1"]),                              # unknown target: never
                      edge("e5", "app", "db-prod", ["v5"]),                             # test code: left out
                      edge("e6", "app", "db-prod", ["v6"]),                             # prod config -> prod: fine
                      edge("e7", "app", "db-prod", ["v7"], verification="refuted"),
                      edge("e8", "app", "local-prod", ["v1"]),                          # a local service: never
                      edge("e9", "app", "saas-prod", ["v1"]),                           # dev -> a SaaS's prod API: fine
                      edge("e10", "app", "pay-sandbox", ["v3"])],                       # prod -> a payment sandbox
        },
        "evidence": [{"id": "v1", "path": ".env.local", "line": 1}, {"id": "v2", "path": "app.py", "line": 4},
                     {"id": "v3", "path": ".env.production", "line": 1}, {"id": "v4", "path": "k8s/worker.yaml", "line": 9},
                     {"id": "v5", "path": "tests/fixtures/.env.local", "line": 2}, {"id": "v6", "path": "k8s/prod/app.yaml", "line": 3},
                     {"id": "v7", "path": ".env.development", "line": 1}],
    }

    @staticmethod
    def facts(rows):
        return {"environment_crossings": rows, "files_scanned": 1, "map_files_inspected": 1}

    def test_both_directions_and_what_never_counts(self):
        got = [(c["edge"], c["direction"], c["path"]) for c in P.environment_crossings(self.REPORT)]
        self.assertEqual(got, [("e1", "non-production->production", ".env.local"),
                               ("e3", "non-production->production", "k8s/worker.yaml"),
                               ("e2", "production->non-production", ".env.production"),
                               ("e10", "production->non-production", ".env.production")])
        self.assertEqual(P.environment_crossings(None), [])

    def test_policy_outcomes(self):
        crossings = P.environment_crossings(self.REPORT)
        for profile, verification, want in (("standard", "declared", "review"), ("citizen", "declared", "block"),
                                            ("standard", "provider-verified", "review"),
                                            ("citizen", "provider-verified", "block")):
            with self.subTest(profile=profile, verification=verification):
                rows = [dict(c, verification=verification) for c in crossings]
                eff = jh_policy.merge(None, [], [], None if profile == "standard" else profile)
                rule = next(r for r in jh_policy.evaluate(eff, self.facts(rows), None)["rules"]
                            if r["rule"] == "P-ENV-001")
                self.assertEqual(rule["outcome"], want)
        rule = next(r for r in jh_policy.evaluate(jh_policy.merge(None, [], [], None), self.facts([]), None)["rules"]
                    if r["rule"] == "P-ENV-001")
        self.assertEqual(rule["outcome"], "pass")


class Project(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tempfile.mkdtemp()
        for rel, text in FILES.items():
            os.makedirs(os.path.join(cls.root, os.path.dirname(rel)), exist_ok=True)
            with open(os.path.join(cls.root, rel), "w") as fh:
                fh.write(text)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root)

    def passport(self, *args):
        p = run_cli("passport", self.root, *args)
        self.assertIn(p.returncode, (0, 1), p.stderr)
        return p.stdout

    def test_crossings_in_the_passport(self):
        p = json.loads(self.passport("--json"))
        rows = p["environment_crossings"]["rows"]
        self.assertEqual([(r["direction"], r["path"], r["target"]) for r in rows], [
            ("non-production->production", ".env.local", "postgresql ledger-db.prod.example.com"),
            ("non-production->production", "appsettings.Development.json", "sqlserver sql-prod.example.com"),
            ("production->non-production", ".env.production", "postgresql orders-db.staging.example.com")])
        rule = next(r for r in p["assessment"]["decision"]["rules"] if r["rule"] == "P-ENV-001")
        self.assertEqual(rule["outcome"], "review")
        self.assertIn("3 declared or observed crossing(s)", rule["message"])

    def test_citizen_profile_blocks(self):
        p = json.loads(self.passport("--json", "--profile", "citizen"))
        self.assertEqual(next(r for r in p["assessment"]["decision"]["rules"] if r["rule"] == "P-ENV-001")["outcome"],
                         "block")

    def test_markdown_and_redaction(self):
        md = self.passport("--md")
        self.assertIn("## Where non-production meets production", md)
        self.assertIn("Non-production reaches production: non-production configuration .env.local reaches", md)
        html = self.passport("--html")
        self.assertIn('"environment_crossings": {"count": 3', html)
        self.assertIn("EC=P.environment_crossings", html)
        red = self.passport("--json", "--redact")
        for secret in ("ledger-db.prod.example.com", "orders-db.staging", ".env.local"):
            with self.subTest(secret=secret):
                self.assertNotIn(secret, red)

    def test_a_project_with_no_crossing_passes(self):
        root = tempfile.mkdtemp()
        try:
            with open(os.path.join(root, ".env.local"), "w") as fh:
                fh.write("DATABASE_URL=postgresql://app@orders-db.staging.example.com:5432/orders\n")
            with open(os.path.join(root, "app.py"), "w") as fh:
                fh.write(FILES["app.py"])
            p = json.loads(run_cli("passport", root, "--json").stdout)
            self.assertEqual(p["environment_crossings"]["count"], 0)
            self.assertEqual(next(r for r in p["assessment"]["decision"]["rules"]
                                  if r["rule"] == "P-ENV-001")["outcome"], "pass")
        finally:
            shutil.rmtree(root)


if __name__ == "__main__":
    unittest.main()
