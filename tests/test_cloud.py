"""Data platforms and cloud identity: cloud service hosts, JDBC, Go/Rust/JVM
code, Spark and Unity Catalog, notebooks, Azure credentials, Azure
Terraform (managed identities, role assignments, Key Vault policies), the
credential blast radius, and name-based sensitivity hints."""
import json
import unittest

import _util  # noqa: F401  (puts scripts/ on sys.path)
import jh_checks
import jh_core
import jh_graph as G
import jh_map
import jh_rules


def build(files):
    col = jh_map.Collected(items=[jh_map.Item(k, v) for k, v in files.items()], considered=len(files))
    return jh_map.build_report(col, "/nonexistent", "app", "test", None)


def node(rep, needle):
    found = [n for n in rep["graph"]["nodes"] if needle in n["display_label"]]
    return found[0] if found else None


def caps(rep, src_needle, dst_needle):
    by = {n["id"]: n["display_label"] for n in rep["graph"]["nodes"]}
    return sorted(e["capability"] for e in rep["graph"]["edges"]
                  if src_needle in by[e["source"]] and dst_needle in by[e["target"]])


def cred(rep, needle):
    for r in rep["assessment"]["credential_blast_radius"]["identities"]:
        if needle in r["label"]:
            return r
    return None


class Hosts(unittest.TestCase):
    def test_cloud_service_families(self):
        cases = {
            "sql-prod.database.windows.net": ("database", "sqlserver"),
            "pg.postgres.database.azure.com": ("database", "postgresql"),
            "acct.blob.core.windows.net": ("storage", "azure-blob"),
            "acct.dfs.core.windows.net": ("storage", "azure-blob"),
            "kv-prod.vault.azure.net": ("storage", "azure-keyvault"),
            "adb-1.2.azuredatabricks.net": ("database", "databricks"),
            "x.openai.azure.com": ("external", "azure-openai"),
            "org-acct.snowflakecomputing.com": ("database", "snowflake"),
            "db.abc.eu-west-1.rds.amazonaws.com": ("database", "sql"),
            "cluster0.abcde.mongodb.net": ("database", "mongodb"),
        }
        for host, fam in cases.items():
            self.assertEqual(G.hosted_family(host), fam, host)
        self.assertIsNone(G.hosted_family("windows.net.example.com"))
        self.assertIsNone(G.hosted_family("example.com"))

    def test_jdbc_properties_are_not_part_of_the_host(self):
        ep = G.parse_endpoint("jdbc:sqlserver://sql-prod.database.windows.net:1433;databaseName=ledger;encrypt=true")
        self.assertEqual((ep["kind"], ep["engine"], ep["host"]), ("database", "sqlserver", "sql-prod.database.windows.net"))
        ep = G.parse_endpoint("jdbc:databricks://adb-1.2.azuredatabricks.net:443/default;httpPath=/sql/1.0/x")
        self.assertEqual((ep["engine"], ep["host"], ep["path"]), ("databricks", "adb-1.2.azuredatabricks.net", "default"))

    def test_bare_cloud_host_in_code_is_a_node(self):
        rep = build({"app/q.py": 'from databricks import sql\n'
                                 'c = sql.connect(server_hostname="adb-77.1.azuredatabricks.net", http_path="/x")\n'})
        n = node(rep, "adb-77.1.azuredatabricks.net")
        self.assertIsNotNone(n)
        self.assertEqual(n["attributes"]["engine"], "databricks")

    def test_cloud_host_in_a_comment_is_ignored(self):
        rep = build({"app/q.py": "# see sql-prod.database.windows.net for details\nx = 1\n"})
        self.assertIsNone(node(rep, "database.windows.net"))


class Languages(unittest.TestCase):
    def test_go_imports_env_and_manifest(self):
        rep = build({
            "svc/main.go": 'package main\n\nimport (\n\t"os"\n\t"github.com/jackc/pgx/v5"\n)\n\n'
                           'func main() { _, _ = pgx.Connect(nil, os.Getenv("DATABASE_URL")) }\n',
            "svc/go.mod": "module x\n\nrequire github.com/jackc/pgx/v5 v5.6.0\n",
            ".env": "DATABASE_URL=postgres://u@db.internal:5432/orders\n",
        })
        self.assertIn("go", rep["coverage"]["by_adapter"])
        self.assertIsNotNone(node(rep, "db.internal"))
        only = build({"svc/main.go": 'package main\n\nimport (\n\t"github.com/jackc/pgx/v5"\n)\n'})
        self.assertEqual([ev["adapter"] for ev in only["evidence"]], ["go:import"])
        self.assertIsNotNone(node(only, "postgresql (unresolved target)"))

    def test_rust_and_java(self):
        rep = build({
            "src/db.rs": "use sqlx::PgPool;\nfn main() { let _ = std::env::var(\"DATABASE_URL\"); }\n",
            "src/Repo.java": 'class Repo { String u = "jdbc:sqlserver://sql-prod.database.windows.net:1433;databaseName=ledger"; }\n',
        })
        self.assertIn("rust", rep["coverage"]["by_adapter"])
        self.assertIn("jvm", rep["coverage"]["by_adapter"])
        n = node(rep, "sql-prod.database.windows.net")
        self.assertEqual(n["attributes"]["engine"], "sqlserver")
        self.assertEqual(n["environment"], "production")

    def test_unsupported_language_still_reports_none(self):
        rep = build({"Main.hs": "main = pure ()\n"})
        self.assertEqual(rep["coverage"]["status"], "none")


class Spark(unittest.TestCase):
    def test_unity_catalog_reads_writes_and_overwrite(self):
        rep = build({"jobs/etl.py": (
            'from pyspark.sql import SparkSession\n'
            'from prod_finance.utils.helpers import tidy\n'
            'df = spark.read.table("prod_finance.payroll.salaries")\n'
            'df.write.mode("append").saveAsTable("dev_sandbox.tmp.copy")\n'
            'df.write.mode("overwrite").saveAsTable("prod_finance.reporting.summary")\n'
            'spark.sql("DELETE FROM dev_sandbox.tmp.scratch WHERE x = 1")\n')})
        self.assertEqual(caps(rep, "app", "catalog prod_finance"), ["delete", "read"])
        self.assertEqual(caps(rep, "app", "catalog dev_sandbox"), ["delete", "write"])
        self.assertEqual(node(rep, "catalog prod_finance")["environment"], "production")
        self.assertEqual(node(rep, "catalog prod_finance")["attributes"]["sensitivity_hint"], ["finance"])
        self.assertIsNone(node(rep, "catalog utils"))

    def test_fstring_names_resolve_through_assignments(self):
        rep = build({
            "nb/00_config.py": 'catalog = "sales_prod"\nbronze = f"{catalog}.bronze"\n',
            "nb/01_load.py": 'import pyspark\ndf.write.saveAsTable(f"{bronze}.orders")\n',
            "nb/02_local.py": 'import pyspark\ncat = "hr_dev"\nspark.table(f"{cat}.people.staff")\n',
            "nb/03_ambiguous.py": 'import pyspark\nspark.table(f"{region}.x.y")\n',
            "nb/04_r1.py": 'region = "eu"\n', "nb/05_r2.py": 'region = "us"\n',
        })
        self.assertEqual(caps(rep, "app", "catalog sales_prod"), ["write"])
        self.assertEqual(node(rep, "catalog sales_prod")["environment"], "production")
        self.assertEqual(caps(rep, "app", "catalog hr_dev"), ["read"])
        self.assertEqual(caps(rep, "app", "catalog (unresolved target: region)"), ["read"])

    def test_sql_verbs_per_reference(self):
        rep = build({"jobs/gold.py": (
            'spark.sql("""\nCREATE OR REPLACE TABLE gold_c.mart.dim AS\nSELECT * FROM silver_c.core.orders\n""")\n'
            'spark.sql("MERGE INTO merge_c.s.t USING src_c.s.u ON t.id = u.id")\n'
            'spark.sql("DESCRIBE TABLE desc_c.s.t")\n')})
        self.assertEqual(caps(rep, "app", "catalog gold_c"), ["delete"])
        self.assertEqual(caps(rep, "app", "catalog silver_c"), ["read"])
        self.assertEqual(caps(rep, "app", "catalog merge_c"), ["write"])
        self.assertEqual(caps(rep, "app", "catalog src_c"), ["read"])
        self.assertIsNone(node(rep, "catalog desc_c"))

    def test_sql_server_three_part_names_are_not_catalogs(self):
        rep = build({"app/report.py": 'import pyodbc\ncur.execute("SELECT * FROM finance.dbo.invoices")\n'})
        self.assertIsNone(node(rep, "databricks catalog"))

    def test_databricks_source_notebook_sql_cells(self):
        rep = build({"nb/job.py": ("# Databricks notebook source\nx = 1\n\n# COMMAND ----------\n\n"
                                   "# MAGIC %sql\n# MAGIC INSERT INTO ops_c.s.audit\n# MAGIC SELECT * FROM raw_c.s.events\n\n"
                                   "# COMMAND ----------\n\n# MAGIC %md\n# MAGIC FROM docs_c.s.t\n")})
        self.assertEqual(caps(rep, "app", "catalog ops_c"), ["write"])
        self.assertEqual(caps(rep, "app", "catalog raw_c"), ["read"])
        self.assertIsNone(node(rep, "catalog docs_c"))
        ev = [e for e in rep["evidence"] if "ops_c" in e["snippet"]]
        self.assertEqual(ev[0]["line"], 7)

    def test_python_import_is_not_a_table(self):
        rep = build({"jobs/a.py": "from prod.utils.helpers import tidy\n"})
        self.assertIsNone(node(rep, "databricks catalog"))

    def test_databricks_secret_is_an_identity(self):
        rep = build({"jobs/a.py": 'pw = dbutils.secrets.get(scope="kv-prod", key="sql-password")\n'})
        n = node(rep, "databricks secret kv-prod/sql-password")
        self.assertEqual(n["kind"], "identity")
        self.assertEqual(n["environment"], "production")

    def test_notebook_cells_and_sql_magic(self):
        nb = {"cells": [
            {"cell_type": "code", "source": ['df = spark.table("main.sales.orders")\n']},
            {"cell_type": "markdown", "source": ['spark.table("ignored.in.markdown")']},
            {"cell_type": "code", "source": "%sql\nTRUNCATE TABLE main.sales.staging\n"},
            {"cell_type": "code", "source": ["%pip install x\n", "!ls\n"]}], "nbformat": 4}
        rep = build({"nb/orders.ipynb": json.dumps(nb)})
        self.assertEqual(caps(rep, "app", "catalog main"), ["delete", "read"])
        self.assertIsNone(node(rep, "catalog ignored"))

    def test_malformed_notebook_is_a_parse_failure(self):
        rep = build({"nb/bad.ipynb": "{not json", "app/a.py": "import redis\n"})
        self.assertEqual([p["path"] for p in rep["coverage"]["parse_failures"]], ["nb/bad.ipynb"])
        self.assertEqual(rep["coverage"]["status"], "partial")


class AzureCode(unittest.TestCase):
    def test_credentials_and_key_vault_operations(self):
        rep = build({"app/main.py": (
            "from azure.identity import DefaultAzureCredential\n"
            "from azure.keyvault.secrets import SecretClient\n"
            "kv = SecretClient(vault_url=\"https://kv-prod.vault.azure.net/\", credential=DefaultAzureCredential())\n"
            "kv.get_secret(\"db\")\n")})
        ident = node(rep, "azure identity (DefaultAzureCredential)")
        self.assertTrue(ident["attributes"]["secretless"])
        self.assertIn("read", caps(rep, "app", "kv-prod.vault.azure.net"))

    def test_dotnet_go_and_java_credentials(self):
        rep = build({"src/Program.cs": "var c = new ClientSecretCredential(tenant, id, secret);\n"})
        ident = node(rep, "azure identity (ClientSecretCredential)")
        self.assertFalse(ident["attributes"]["secretless"])
        rep = build({"svc/main.go": "package main\nfunc main() { c, _ := azidentity.NewDefaultAzureCredential(nil); _ = c }\n",
                     "src/App.java": "class App { Object c = new ManagedIdentityCredentialBuilder().build(); }\n"})
        self.assertIsNotNone(node(rep, "azure identity (DefaultAzureCredential)"))
        self.assertIsNotNone(node(rep, "azure identity (ManagedIdentityCredential)"))


TF = '''data "azurerm_client_config" "current" {}

data "azurerm_key_vault" "shared" {
  name = "kv-shared-prod"
}

resource "azurerm_user_assigned_identity" "etl" {
  name = "id-etl-prod"
}

resource "azurerm_storage_account" "lake" {
  name = "stlake"
}

resource "azurerm_linux_function_app" "ingest" {
  name = "func-ingest-prod"
  identity {
    type         = "SystemAssigned, UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.etl.id]
  }
}

resource "azurerm_linux_web_app" "portal" {
  name = "app-portal-prod"
  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.etl.id]
  }
}

resource "azurerm_role_assignment" "blob" {
  scope                = azurerm_storage_account.lake.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_linux_function_app.ingest.identity[0].principal_id
}

resource "azurerm_role_assignment" "owner" {
  scope              = "/subscriptions/${data.azurerm_client_config.current.subscription_id}"
  role_definition_id = "/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
  principal_id       = azurerm_user_assigned_identity.etl.principal_id
}

resource "azurerm_key_vault_access_policy" "etl" {
  key_vault_id       = data.azurerm_key_vault.shared.id
  object_id          = azurerm_user_assigned_identity.etl.principal_id
  secret_permissions = ["Get", "List", "Set"]
}
'''


class AzureTerraform(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rep = build({"infra/main.tf": TF})

    def test_role_capability_mapping(self):
        for role, cap in (("Owner", "admin"), ("Contributor", "admin"), ("User Access Administrator", "admin"),
                          ("Storage Blob Data Owner", "admin"), ("Storage Blob Data Contributor", "write"),
                          ("Azure Service Bus Data Sender", "write"), ("Key Vault Secrets User", "read"),
                          ("Reader", "read"), ("Storage Blob Data Reader", "read"), ("My Custom Role", "unknown")):
            self.assertEqual(jh_map.azure_role_capability(role), cap, role)

    def test_managed_identities_and_grants(self):
        rep = self.rep
        self.assertEqual(node(rep, "linux function app func-ingest-prod")["kind"], "workload")
        self.assertEqual(caps(rep, "managed identity of func-ingest-prod", "azure-blob stlake"), ["write"])
        self.assertEqual(caps(rep, "managed identity id-etl-prod", "azure subscription"), ["admin"])
        self.assertEqual(caps(rep, "managed identity id-etl-prod", "azure-keyvault kv-shared-prod"), ["read", "write"])
        self.assertEqual(caps(rep, "func-ingest-prod", "managed identity id-etl-prod"), ["unknown"])
        kv = node(rep, "azure-keyvault kv-shared-prod")
        self.assertEqual(kv["sensitivity"], "restricted")
        self.assertTrue(kv["attributes"].get("existing"))

    def test_exposure_reaches_through_the_identity(self):
        self.assertIn(self.rep["assessment"]["exposure"]["class"], ("High", "Critical"))

    def test_credential_blast_radius(self):
        r = cred(self.rep, "managed identity id-etl-prod")
        self.assertEqual(len(r["holders"]), 2)
        self.assertEqual(sorted(r["flags"]), ["broad-scope", "secret-store-pivot", "shared"])
        self.assertTrue(r["secretless"])
        ids = [x["identity"] for x in self.rep["assessment"]["credential_blast_radius"]["identities"]]
        self.assertEqual(ids[0], r["identity"])          # most mutating authority first
        self.assertIn("secret-store-pivot", [u["id"] for u in self.rep["unknowns"]])

    def test_credential_radius_does_not_change_exposure(self):
        graph = self.rep["graph"]
        a = G.assess(graph, 1)
        self.assertEqual(a["exposure"], self.rep["assessment"]["exposure"])
        stripped = {"nodes": graph["nodes"], "edges": [e for e in graph["edges"]]}
        self.assertEqual(G.assess(stripped, 1)["credential_blast_radius"], a["credential_blast_radius"])

    def test_redacted_copy_hides_identity_names(self):
        shared = json.dumps(G.pseudonymize(self.rep))
        for name in ("id-etl-prod", "func-ingest", "kv-shared", "stlake"):
            self.assertNotIn(name, shared)

    def test_deterministic(self):
        again = build({"infra/main.tf": TF})
        self.assertEqual(again["scan_id"], self.rep["scan_id"])


class TerraformReading(unittest.TestCase):
    def test_multiline_lists_comments_and_identity_references(self):
        rep = build({"infra/main.tf": '''resource "azurerm_key_vault" "kv" {
  name = "kv-app-prod" # the shared vault
}

resource "azurerm_databricks_access_connector" "uc" {
  name = "ac-lake"
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_storage_account" "lake" {
  name = "stlake"
}

resource "azurerm_role_assignment" "uc_lake" {
  scope                = azurerm_storage_account.lake.id # lake account
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_databricks_access_connector.uc.identity[0].principal_id
}

resource "azurerm_role_assignment" "fn" {
  scope                = azurerm_key_vault.kv.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azapi_resource.fn.identity[0].principal_id
}

resource "azurerm_key_vault_access_policy" "ops" {
  key_vault_id = azurerm_key_vault.kv.id
  object_id    = var.ops_object_id
  secret_permissions = [
    "Get",
    "List", // reads
    "Delete",
  ]
}
'''})
        self.assertEqual(node(rep, "azure-keyvault kv-app-prod")["display_label"], "azure-keyvault kv-app-prod")
        self.assertEqual(caps(rep, "managed identity of ac-lake", "azure-blob stlake"), ["write"])
        self.assertEqual(caps(rep, "databricks access connector ac-lake", "managed identity of ac-lake"), ["unknown"])
        self.assertEqual(caps(rep, "managed identity of azapi_resource.fn", "azure-keyvault kv-app-prod"), ["read"])
        self.assertEqual(caps(rep, "azure principal var.ops_object_id", "azure-keyvault kv-app-prod"), ["delete", "read"])
        self.assertIsNone(node(rep, "azure scope"))
        self.assertNotIn("broad-scope", cred(rep, "managed identity of ac-lake")["flags"])

    def test_unresolved_scope_is_not_broad(self):
        rep = build({"infra/m.tf": 'resource "azurerm_role_assignment" "a" {\n  scope = var.container_id\n'
                                   '  role_definition_name = "Storage Blob Data Contributor"\n  principal_id = var.p\n}\n'
                                   'resource "azurerm_role_assignment" "b" {\n'
                                   '  scope = "/providers/Microsoft.Management/managementGroups/root"\n'
                                   '  role_definition_name = "Reader"\n  principal_id = var.q\n}\n'})
        self.assertEqual(cred(rep, "var.p")["flags"], ["holder-not-visible"])
        self.assertIn("broad-scope", cred(rep, "var.q")["flags"])
        self.assertEqual(node(rep, "azure management group")["criticality"], "critical")


class SensitivityHints(unittest.TestCase):
    def test_words(self):
        self.assertEqual(G.sensitivity_hints("payroll_db"), ["payroll"])
        self.assertEqual(G.sensitivity_hints("hr-records", "patients"), ["hr", "patient"])
        for benign in ("chrome", "syntax", "cardinal", "throughput", "orders"):
            self.assertEqual(G.sensitivity_hints(benign), [], benign)

    def test_hint_never_sets_sensitivity(self):
        rep = build({".env": "DATABASE_URL=postgres://u@payroll-db.internal:5432/payroll\n",
                     "app/a.py": "import os\nos.environ['DATABASE_URL']\n"})
        n = node(rep, "payroll-db.internal")
        self.assertEqual(n["attributes"]["sensitivity_hint"], ["payroll"])
        self.assertEqual(n["sensitivity"], "unknown")
        self.assertIn("sensitive-by-name", [u["id"] for u in rep["unknowns"]])


class PublicDataStore(unittest.TestCase):
    def scan(self, rel, text):
        sf = jh_core.source_from_text(rel, "/nonexistent/" + rel, text)
        rule = next(r for r in jh_rules.RULES if r.id == "JH134")
        return jh_checks.public_data_store(sf, rule)

    def test_firewall_open_to_the_internet(self):
        out = self.scan("infra/sql.tf", 'resource "azurerm_mssql_firewall_rule" "all" {\n'
                                         '  start_ip_address = "0.0.0.0"\n  end_ip_address   = "255.255.255.255"\n}\n')
        self.assertEqual([(f.line, f.severity) for f in out], [(3, "major")])

    def test_publicly_accessible_instance(self):
        out = self.scan("infra/rds.tf", 'resource "aws_db_instance" "db" {\n  publicly_accessible = true\n}\n')
        self.assertEqual([f.line for f in out], [2])

    def test_private_is_quiet(self):
        out = self.scan("infra/rds.tf", 'resource "aws_db_instance" "db" {\n  publicly_accessible = false\n}\n')
        self.assertEqual(out, [])


if __name__ == "__main__":
    unittest.main()
