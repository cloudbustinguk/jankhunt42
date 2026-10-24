"""Precision fixes found by running the scanner and the map on public
repositories: placeholder secrets, safe settings flagged as risky, test
detection outside Python, SQL-looking text, and files the map could not
read. Every fixture here is synthetic; token-shaped values are assembled at
run time so this file never holds one."""
import json
import os
import shutil
import tempfile
import unittest

import _util
from _util import run_cli
import jh_yaml

RANDOM = "Tq9Lm2" + "Xw7Rb4" + "Nc8Vz3Kd"                     # 20 characters, no runs or words
GH_TOKEN = "ghp_" + "Wq7Lz2Xm9Rt4Nb8Vc3Kd6Hj1Fs5Gp0Ya2Ue4Ti"
PEM_KEY = "-----BEGIN " + "PRIVATE KEY-----\nMIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA\n-----END " + "PRIVATE KEY-----\n"
PEM_CERT = "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUQ2Y4cGx1eS1jZXJ0aWZpY2F0ZQ==\n-----END CERTIFICATE-----\n"


def write(root, rel, text):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


class Scanner(unittest.TestCase):
    FILES = {
        # JH101: references, generated runs and descriptive fixtures are not secrets
        "app/settings.py": ("TOKEN_REF = {'token': 'env(APP_AUTH_SECRET)'}\n"
                            "password = \"{{ password }}\"\n"
                            "api_key = \"sk-" + "abcdefghijklmnopqrstuvwxyz123456\"\n"
                            "client_token = \"managed-cloud-api-key\"\n"),
        "app/labels.rs": ("let token = \"Bearer Token Env Var\";\n"
                          ".detail(\"env var sk-" + "proj-SYNTHETIC_CREDENTIAL is not set\");\n"),
        "app/real.py": "api_key = \"%s\"\nGITHUB = \"%s\"\n" % (RANDOM, GH_TOKEN),
        "core/src/session_tests.rs": "let secret = \"%s\";\n" % RANDOM,
        "tests/test_client.py": "api_key = \"%s\"\nGITHUB = \"%s\"\n" % (RANDOM, GH_TOKEN),
        # JH401: registry settings, localhost URLs, placeholders and certificates are not credentials
        "web/.npmrc": "registry=\"https://registry.npmjs.org/\"\n",
        "pkg/.npmrc": "//registry.npmjs.org/:_authToken=" + RANDOM + "\n",
        "front/.env": "VITE_API_URL=http://localhost:8000\n",
        "back/.env": "APP_ENV=development\nSECRET_KEY=changethis\nDATABASE_URL=postgresql://app:changethis@db/app\n",
        "real/.env": "SECRET_" + "KEY=" + RANDOM + "\n",
        "certs/ca.pem": PEM_CERT,
        "certs/server.pem": PEM_KEY,
        # JH414: dropping ALL is the hardened setting
        "deploy/hardened.yaml": ("apiVersion: v1\nkind: Pod\nmetadata:\n  name: a\nspec:\n  containers:\n"
                                 "  - name: a\n    image: a\n    securityContext:\n      capabilities:\n"
                                 "        drop:\n        - ALL\n  - name: b\n    image: b\n"),
        "deploy/risky.yaml": ("apiVersion: v1\nkind: Pod\nmetadata:\n  name: b\nspec:\n  containers:\n"
                              "  - name: a\n    image: a\n    securityContext:\n      capabilities:\n"
                              "        add:\n        - NET_ADMIN\n        drop: [ALL]\n"),
        # JH502: Rust and JS tests that assert through helpers, `?`, or macros
        "tests/skew_test.rs": ("#[tokio::test(flavor = \"multi_thread\")]\n"
                               "async fn helper_asserts() -> Result<()> {\n    let pair = binaries()?;\n"
                               "    assert_version_skew(&pair).await\n}\n\n"
                               "#[test]\nfn macro_asserts() {\n    assert_eq!(1 + 1, 2);\n}\n\n"
                               "#[test]\n#[should_panic]\nfn panics() {\n    explode();\n}\n\n"
                               "#[test]\nfn checks_nothing() {\n    let _ = compute();\n}\n\n"
                               "#[tokio::test]\nasync fn delegates() -> Result<()> {\n    run_scenario(Case::A).await\n}\n\n"
                               "#[test]\nfn only_setup() -> Result<()> {\n    setup();\n    Ok(())\n}\n"),
        "tests/conftest.py": "import pytest\n\n\n" + "@pytest.fixture\ndef test_repository(tmp_path):\n    return tmp_path\n",
        "tests/logging.test.ts": "it(\"logs\", () => {\n  console.log(\"value\", x)\n  expect(x).toBe(1)\n})\n",
        "tests/login.spec.ts": ("test(\"inputs are editable\", async ({ page }) => {\n  await page.goto(\"/login\")\n"
                                "  await verifyInput(page, \"email\")\n})\n\n"
                                "test(\"does nothing\", async ({ page }) => {\n  await page.goto(\"/\")\n})\n"),
        "tests/match.test.mjs": "if (/automated/.test(name)) {\n  rename(name)\n}\n",
        "docs/testing/SKILL.md": "Put the comment above the test (or above its describe block).\n",
        # JH104: SQL-looking text that is not dynamic SQL, and two that are
        "db/static.py": ("q1 = \"UPDATE writes SET value = value + 1 WHERE id = 1\"\n"
                         "q2 = \"COALESCE((SELECT MAX(n) FROM items WHERE thread = ?), -1) + 1\"\n"
                         "msg = f\"Update {path} so its build flag matches\"\n"
                         "gql = \"query(\" + args + \")\" + body\n"
                         "url = appendRawQuery(base + path, raw)\n"
                         "rows = sqlx.query(\"UPDATE writes SET value = value + 1 WHERE id = 1\")\n"),
        # split so this file's own scan does not see dynamic SQL
        "db/dynamic.py": ("rows = cursor.exe" + "cute(\"SEL" + "ECT * FROM users WHERE id = \" + user_id)\n"
                          "sql = f\"SELECT * FROM {table} WHERE id = 1\"\n"
                          "rows = db.qu" + "ery(base_sql + where)\n"),
        # JH105: verify=False on a non-HTTP function is that function's own flag
        "ops/publish.py": ("published = publish_assets(endpoint, version, assets, verify=False)\n"
                           "resp = requests.get(url, verify=False)\n"
                           "resp2 = session.post(\n    url,\n    json=body,\n    verify=False,\n)\n"),
        # JH112: other languages' "random" identifiers are not Python's random module
        "core/oauth.rs": "let generation = digest(random.secret().as_bytes());\n",
        "core/tokens.py": "import random\ntoken = ''.join(random.choice(ALPHABET) for _ in range(32))\n",
        # JH119/JH120: extraction filters and zipfile's own sanitizing
        "tools/extract.py": ("import tarfile, zipfile, shutil\n"
                             "tarfile.open(p).extractall(dest, filter=\"data\")\n"
                             "tarfile.open(p).extractall(dest)\n"
                             "zipfile.ZipFile(p).extractall(dest)\n"
                             "shutil.unpack_archive(p, dest)\n"),
        # JH102: a constant string is not data turned into code
        "tests/test_api.py": "ns = {}\nexec(\"from mypkg import *\", ns)\n",
        "app/plugin.py": "def run(code):\n    exec(code)\n",
        # JH204: console.log in CLI scripts and migrations is the output, not a leftover
        "scripts/report.mjs": "console.log(report)\n",
        "lib/db/migrate.ts": "console.log(\"Running migrations...\")\n",
        "src/app.ts": "export function handler() {\n  console.log(\"debug\", state)\n}\n",
        "core/e2e.rs": "let script = r#\"console.log(fib(10));\"#;\n",
    }

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="jh-precision-")
        for rel, text in cls.FILES.items():
            write(cls.tmp, rel, text)
        out = run_cli("scan", cls.tmp, "--json", "--min-severity", "info", "--no-progress").stdout
        cls.findings = json.loads(out)["findings"]

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def hits(self, rule, path):
        return [f for f in self.findings if f["rule"] == rule and f["path"] == path]

    def lines(self, rule, path):
        return sorted(f["line"] for f in self.hits(rule, path))

    def test_secrets(self):
        self.assertEqual(self.hits("JH101", "app/settings.py"), [])
        self.assertEqual(self.hits("JH101", "app/labels.rs"), [])
        self.assertEqual([(f["severity"], f["confidence"]) for f in self.hits("JH101", "core/src/session_tests.rs")],
                         [("minor", "low")])
        self.assertEqual([(f["line"], f["severity"]) for f in self.hits("JH101", "app/real.py")],
                         [(1, "critical"), (2, "critical")])
        # in test code a generic assignment is probably a fixture; a provider token is not
        self.assertEqual(sorted((f["line"], f["severity"], f["confidence"]) for f in self.hits("JH101", "tests/test_client.py")),
                         [(1, "minor", "low"), (2, "critical", "high")])

    def test_secret_files(self):
        for path in ("web/.npmrc", "front/.env", "back/.env", "certs/ca.pem"):
            self.assertEqual(self.hits("JH401", path), [], path)
        for path in ("pkg/.npmrc", "real/.env", "certs/server.pem"):
            self.assertEqual(len(self.hits("JH401", path)), 1, path)

    def test_capabilities(self):
        self.assertEqual(self.hits("JH414", "deploy/hardened.yaml"), [])
        self.assertEqual(self.lines("JH414", "deploy/risky.yaml"), [12])

    def test_tests_without_assertions(self):
        self.assertEqual([f["message"] for f in self.hits("JH502", "tests/skew_test.rs")],
                         ["Test 'checks_nothing' contains no assertion.", "Test 'only_setup' contains no assertion."])
        self.assertEqual(self.hits("JH502", "tests/conftest.py"), [])
        self.assertEqual(self.lines("JH502", "tests/login.spec.ts"), [6])
        self.assertEqual(self.hits("JH502", "tests/match.test.mjs"), [])
        self.assertEqual(self.hits("JH502", "docs/testing/SKILL.md"), [])

    def test_dynamic_sql(self):
        self.assertEqual(self.hits("JH104", "db/static.py"), [])
        self.assertEqual(self.lines("JH104", "db/dynamic.py"), [1, 2, 3])

    def test_tls_verification(self):
        self.assertEqual(self.lines("JH105", "ops/publish.py"), [2, 6])

    def test_random(self):
        self.assertEqual(self.hits("JH112", "core/oauth.rs"), [])
        self.assertEqual(self.lines("JH112", "core/tokens.py"), [2])

    def test_archives(self):
        self.assertEqual(self.lines("JH119", "tools/extract.py"), [3])
        self.assertEqual(self.lines("JH120", "tools/extract.py"), [5])

    def test_exec(self):
        self.assertEqual(self.hits("JH102", "tests/test_api.py"), [])
        self.assertEqual(self.lines("JH102", "app/plugin.py"), [2])

    def test_debug_output(self):
        for path in ("scripts/report.mjs", "lib/db/migrate.ts", "core/e2e.rs", "tests/logging.test.ts"):
            self.assertEqual(self.hits("JH204", path), [], path)
        self.assertEqual(self.lines("JH204", "src/app.ts"), [2])


class YamlReader(unittest.TestCase):
    def test_flow_sequence_over_several_lines(self):
        docs = jh_yaml.load_all("jobs:\n  done:\n    needs:\n      [\n        build, # first\n        test,\n      ]\n"
                                "    steps:\n      - run: |\n          if [ -f x ]; then\n            echo [\n          fi\n")
        self.assertEqual(docs[0]["jobs"]["done"]["needs"], ["build", "test"])
        self.assertEqual(docs[0]["jobs"]["done"]["steps"][0]["run"], "if [ -f x ]; then\necho [\nfi")

    def test_a_scalar_document(self):
        self.assertEqual(jh_yaml.load_all("Initial Commit\n"), ["Initial Commit"])

    def test_unterminated_flow_collection_is_an_error(self):
        with self.assertRaises(jh_yaml.YamlError):
            jh_yaml.load_all("needs: [a,\n  b\n")


class MapCoverage(unittest.TestCase):
    FILES = {
        ".github/workflows/ci.yml": ("on: push\npermissions:\n  contents: read\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
                                     "    steps:\n      - run: make\n  report:\n    needs:\n      [\n        build,\n      ]\n"
                                     "    runs-on: ubuntu-latest\n    steps:\n      - run: echo done\n"),
        "notes/image.yaml": "Initial Commit\n",
        "src/Api/appsettings.json": "\ufeff" + json.dumps({"ConnectionStrings": {"db": "Host=db.internal;Database=app"}}),
        "src/Host/appsettings.json": "{\n  \"Logging\": {\"LogLevel\": {\"Default\": \"Information\"}},\n"
                                     "  \"ConnectionStrings\": {\n    //\"db\": \"Host=localhost\"\n  },\n}\n",
        "chart/Chart.yaml": "apiVersion: v2\nname: app\nversion: 0.1.0\n",
        "chart/templates/deployment.yaml": ("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n"
                                            "  name: {{ .Release.Name }}\n{{- if .Values.enabled }}\nspec: {}\n{{- end }}\n"),
        "web/lib/providers.ts": "import { customProvider, gateway } from \"ai\";\nexport const m = gateway.languageModel(id);\n",
        "web/lib/grok.ts": "import { xai } from \"@ai-sdk/xai\";\n",
        "svc/Program.cs": "var builder = WebApplication.CreateBuilder(args);\nbuilder.AddAzureOpenAIClient(\"openai\");\n",
        "agent/chain.py": "from langchain_openai import ChatOpenAI\nllm = ChatOpenAI()\n",
    }

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="jh-mapcov-")
        for rel, text in cls.FILES.items():
            write(cls.tmp, rel, text)
        cls.map = json.loads(run_cli("map", cls.tmp, "--json").stdout)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_no_parse_failures(self):
        cov = self.map["coverage"]
        self.assertEqual(cov.get("parse_failures", []), [])
        self.assertEqual(cov["status"], "complete-for-supported-types")

    def test_templates_are_an_explicit_unknown(self):
        u = {x["id"]: x for x in self.map["unknowns"]}
        self.assertEqual(u["unrendered-templates"]["count"], 1)

    def test_ai_services_are_recognised(self):
        engines = {n["attributes"].get("engine") for n in self.map["graph"]["nodes"]}
        for engine in ("vercel-ai-gateway", "xai", "azure-openai", "openai"):
            self.assertIn(engine, engines)


if __name__ == "__main__":
    unittest.main()
