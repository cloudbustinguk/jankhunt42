"""2.3.0 citizen-developer governance: the MCP config parser, the agent
blast radius in the map, the citizen policy profile (custodian, tests/CI,
classification, public exposure, agent guardrails, unverified authority),
the plain-language brief, custodian-bound acceptance, and redaction."""
import json
import os
import shutil
import tempfile
import unittest

import _util
from _util import edge, node, run_cli
import jh_agent
import jh_core
import jh_views
import jh_explorer
import jh_graph as G
import jh_map
import jh_passport
import jh_policy

PG = "postgresql://report_ro:${PGPASS}@crm-db.prod.internal:5432/crm"
MCP = json.dumps({"mcpServers": {
    "postgres": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-postgres", PG]},
    "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github@2025.4.8"],
               "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "${env:GITHUB_PAT}"}},
    "docs": {"url": "https://mcp.docs.example.com/mcp"},
    "off": {"command": "npx", "args": ["-y", "off-mcp"], "disabled": True}}}, indent=2)


def build(files, decl=None):
    col = jh_map.Collected(items=[jh_map.Item(k, v) for k, v in files.items()], considered=len(files))
    return jh_map.build_report(col, "/x", "app", "t", None, decl)


class McpParsing(unittest.TestCase):
    def test_jsonc_comments_and_trailing_commas(self):
        text = '// c\n{"mcpServers": {"a": {"command": "uvx", "args": ["x", "/* not a comment */",],},},}\n'
        servers = jh_agent.mcp_servers(".vscode/mcp.json", text.replace("mcpServers", "servers"))
        self.assertEqual([(s.name, s.args) for s in servers], [("a", ["x", "/* not a comment */"])])

    def test_codex_toml_subset(self):
        text = ('model = "o3"\n[mcp_servers.docs]\ncommand = "npx"\nargs = [\n  "-y",\n  "docs-mcp@1.2.3",\n]\n'
                'env = { LOG = "info" }\n[mcp_servers."remote one"]\nurl = "https://mcp.example.com/mcp"\n'
                'bearer_token_env_var = "REMOTE_TOKEN"\n[mcp_servers.docs.env]\nAPI_KEY = "${KEY}"\n[profile]\nx = 1\n')
        s = {x.name: x for x in jh_agent.mcp_servers(".codex/config.toml", text)}
        self.assertEqual(s["docs"].args, ["-y", "docs-mcp@1.2.3"])
        self.assertEqual(s["docs"].env, {"LOG": "info", "API_KEY": "${KEY}"})
        self.assertEqual((s["remote one"].transport, s["remote one"].token_env), ("http", "REMOTE_TOKEN"))
        self.assertEqual(jh_agent.credential_literals(s["docs"]), [])

    def test_opencode_and_vscode_shapes(self):
        oc = jh_agent.mcp_servers("opencode.json", json.dumps({"mcp": {"x": {
            "type": "local", "command": ["npx", "-y", "@acme/mcp"], "environment": {"T": "{env:T}"}}}}))
        self.assertEqual((oc[0].command, oc[0].args), ("npx", ["-y", "@acme/mcp"]))
        vs = jh_agent.mcp_servers(".vscode/mcp.json", json.dumps({"servers": {"gh": {"type": "http", "url": "https://x.example"}}}))
        self.assertEqual(vs[0].transport, "http")
        self.assertEqual(jh_agent.mcp_servers("other.json", '{"servers": {}}'), [])
        self.assertEqual(jh_agent.mcp_servers("mcp.json", "[1, 2]"), [])        # valid JSON, not a client config
        with self.assertRaises(ValueError):
            jh_agent.mcp_servers(".mcp.json", "{not json")

    def test_launch_sources(self):
        L = jh_agent.launch_source
        self.assertFalse(L("npx", ["-y", "@scope/pkg"])["pinned"])
        self.assertFalse(L("npx", ["-y", "pkg@latest"])["pinned"])
        self.assertFalse(L("npx", ["-y", "pkg@^1.2.0"])["pinned"])
        self.assertTrue(L("npx", ["-y", "@scope/pkg@1.2.3"])["pinned"])
        self.assertEqual(L("npx", ["-y", "@scope/pkg@1.2.3"])["package"], "@scope/pkg")
        self.assertTrue(L("cmd", ["/c", "npx", "-y", "pkg@2.0.0"])["pinned"])
        self.assertTrue(L("uvx", ["mcp-server-time==2025.9.25"])["pinned"])
        self.assertFalse(L("uv", ["tool", "run", "mcp-server-git"])["pinned"])
        self.assertFalse(L("docker", ["run", "-i", "--rm", "-e", "TOKEN", "ghcr.io/x/y"])["pinned"])
        port = L("docker", ["run", "-i", "--rm", "-p", "8080:80", "ghcr.io/x/mcp"])      # -p is --publish here
        self.assertEqual((port["package"], port["pinned"]), ("ghcr.io/x/mcp", False))
        self.assertFalse(L("docker", ["run", "ghcr.io/x/y:latest"])["pinned"])
        self.assertTrue(L("docker", ["run", "ghcr.io/x/y@sha256:" + "a" * 64])["pinned"])
        self.assertIsNone(L("node", ["build/index.js"]))
        self.assertIsNone(L("python", ["-m", "server"]))

    def test_credentials_and_transport(self):
        s = jh_agent.McpServer("x", 1, "stdio", command="npx", args=["--token", "abcdef123456789", "--api-key=${K}"],
                               env={"API_KEY": "<your key>", "SECRET": "s3cr3t-value-123", "LOG": "debug"},
                               headers={"Authorization": "Bearer ${input:t}"})
        self.assertEqual(jh_agent.credential_literals(s), [("env", "SECRET"), ("arg", "--token")])
        self.assertEqual(jh_agent.credential_names(s), ["API_KEY", "Authorization", "SECRET"])
        self.assertTrue(jh_agent.plaintext_remote("http://mcp.example.com/mcp"))
        self.assertFalse(jh_agent.plaintext_remote("http://127.0.0.1:8000/mcp"))
        self.assertFalse(jh_agent.plaintext_remote("https://mcp.example.com"))


class AgentBlastRadius(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rep = build({".cursor/mcp.json": MCP, "app/main.py": "import json\n"})
        cls.nodes = {n["id"]: n for n in cls.rep["graph"]["nodes"]}
        cls.label = {n["id"]: n["display_label"] for n in cls.rep["graph"]["nodes"]}

    def edges(self, src_contains):
        return sorted((self.label[e["target"]], e["kind"], e["capability"], e["verification"])
                      for e in self.rep["graph"]["edges"] if src_contains in self.label[e["source"]])

    def test_agent_principal_and_servers(self):
        agent = self.edges("AI agent (cursor")
        self.assertEqual([e[0] for e in agent], ["MCP server docs (remote, mcp.docs.example.com)",
                                                 "MCP server github (local)", "MCP server postgres (local)"])
        self.assertTrue(all(e[1:] == ("calls", "unknown", "declared") for e in agent))
        self.assertFalse(any("off" in lbl for lbl in self.label.values()))

    def test_placeholder_password_keeps_the_real_host(self):
        self.assertEqual(self.edges("MCP server postgres"), [
            ("postgresql crm-db.prod.internal", "connects", "unknown", "declared")])
        self.assertEqual(G.parse_endpoint(PG)["host"], "crm-db.prod.internal")

    def test_credentials_by_name_only(self):
        self.assertEqual(self.edges("MCP server github"), [
            ("credential GITHUB_PERSONAL_ACCESS_TOKEN (MCP github)", "authenticates-as", "unknown", "declared")])
        self.assertNotIn("GITHUB_PAT}", json.dumps(self.rep))

    def test_production_reach_through_the_agent_is_high(self):
        self.assertEqual(self.rep["assessment"]["exposure"]["class"], "High")
        ids = {u["id"] for u in self.rep["unknowns"]}
        self.assertIn("agent-tool-capability", ids)
        self.assertNotIn("code-to-workload-binding", ids)

    def test_remote_servers_get_their_own_nodes(self):
        mcp = json.dumps({"mcpServers": {"a": {"url": "https://api.github.com/mcp/a"},
                                         "b": {"url": "https://api.github.com/mcp/b"}}})
        rep = build({".mcp.json": mcp, "app/gh.py": 'import requests\nrequests.get("https://api.github.com/repos")\n'})
        labels = sorted(n["display_label"] for n in rep["graph"]["nodes"])
        self.assertIn("MCP server a (remote, api.github.com)", labels)
        self.assertIn("MCP server b (remote, api.github.com)", labels)
        app_targets = [n for n in rep["graph"]["nodes"] if "api.github.com" in n["display_label"]
                       and not n["display_label"].startswith("MCP server")]
        self.assertTrue(app_targets and not any(n["attributes"].get("mcp_server") for n in app_targets))

    def test_config_files_that_also_define_servers_keep_their_adapter(self):
        appsettings = json.dumps({"ConnectionStrings": {"Ledger": "Server=ledger-sql.prod.internal;Database=ledger;"},
                                  "mcpServers": {"fs": {"command": "npx", "args": ["-y", "fs-mcp@1.0.0"]}}})
        rep = build({"appsettings.json": appsettings, "src/app.cs": 'var c = Configuration["ConnectionStrings:Ledger"];\n'})
        labels = {n["display_label"] for n in rep["graph"]["nodes"]}
        self.assertIn("MCP server fs (local)", labels)
        self.assertTrue(any("ledger-sql.prod.internal" in l for l in labels), labels)
        self.assertEqual(rep["coverage"]["parse_failures"], [])

    def test_deeply_nested_settings_never_crash_the_map(self):
        deep = '{"mcpServers": {}, "x": ' + "[" * 200000 + "]" * 200000 + "}"   # beyond every version's limit
        rep = build({".claude/settings.json": deep, "app/main.py": "import json\n"})
        self.assertTrue(rep["coverage"]["parse_failures"] or any("could not be read" in w for w in rep["warnings"]))

    def test_shareable_map_withholds_warnings(self):
        rep = build({".mcp.json": MCP, "k8s/rb.yaml": "apiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\n"
                     "metadata:\n  name: secret-rb\nroleRef:\n  kind: Role\n  name: missing-role\nsubjects: []\n"})
        self.assertTrue(rep["warnings"])
        shared = G.pseudonymize(rep)
        self.assertNotIn("missing-role", json.dumps(shared["warnings"]))

    def test_malformed_config_is_a_coverage_gap(self):
        rep = build({".mcp.json": "{broken", "app/main.py": "import json\n"})
        self.assertEqual([f["path"] for f in rep["coverage"]["parse_failures"]], [".mcp.json"])

    def test_hosted_data_services_are_databases(self):
        self.assertEqual(G.parse_endpoint("https://abcd.supabase.co/rest/v1")["kind"], "database")
        rep = build({"web/db.ts": 'import { createClient } from "@supabase/supabase-js";\n',
                     "web/sheet.py": "import gspread\n"})
        kinds = sorted((n["kind"], n["attributes"].get("engine")) for n in rep["graph"]["nodes"] if n["kind"] != "application")
        self.assertIn(("database", "supabase"), kinds)
        self.assertIn(("database", "google-sheets"), kinds)


class Profile(unittest.TestCase):
    def test_citizen_preset(self):
        eff = jh_policy.merge(None, None, [], "citizen")
        self.assertEqual(eff["profile"], "citizen")
        self.assertTrue(all(eff["require"][k] for k in ("owner", "custodian", "tests", "ci", "classification")))
        self.assertEqual(eff["max_exposure"], "Moderate")
        self.assertEqual(eff["static_leads"], "block")
        self.assertEqual(eff["actions"]["P-DAT-002"], "block")

    def test_repository_opts_in_but_never_out(self):
        warns = []
        eff = jh_policy.merge(None, {"profile": "citizen"}, warns)
        self.assertEqual(eff["profile"], "citizen")
        eff = jh_policy.merge({"profile": "citizen"}, {"profile": "standard", "static_leads": "review"}, warns)
        self.assertEqual((eff["profile"], eff["static_leads"]), ("citizen", "block"))
        self.assertTrue(any("cannot leave the citizen profile" in w for w in warns))

    def test_ordinary_operator_settings_cannot_weaken_the_profile(self):
        warns = []
        eff = jh_policy.merge({"actions": {"P-DAT-002": "review"}, "require": {"tests": False},
                               "max_exposure": "High"}, None, warns, "citizen")
        self.assertEqual((eff["actions"]["P-DAT-002"], eff["require"]["tests"], eff["max_exposure"]),
                         ("block", True, "Moderate"))
        self.assertEqual(sum("profile_exceptions" in w for w in warns), 3)

    def test_repository_tightening_survives_operator_exceptions(self):
        op = {"profile": "citizen", "profile_exceptions": {"require.tests": False}}
        warns = []
        eff = jh_policy.merge(op, [{"require": {"tests": True}}, {"max_exposure": "Low"}], warns)
        self.assertEqual((eff["require"]["tests"], eff["max_exposure"]), (True, "Low"))
        self.assertFalse(any("ignored profile_exceptions" in w for w in warns))
        empty = []
        jh_policy.merge({"profile_exceptions": {}}, None, empty, "citizen")
        self.assertEqual(empty, [])

    def test_custodian_rule_can_be_turned_off_by_the_operator(self):
        eff = jh_policy.merge({"profile": "citizen", "profile_exceptions": {"P-CUS-001": "off"}}, None, [])
        facts = {"files_scanned": 1, "map_files_inspected": 1, "exposure": "Low", "owner_state": "observed",
                 "declared_custodians": ["me"], "operations": {"tests": "observed", "ci": "observed"}}
        out = jh_policy.evaluate(eff, facts, {"nodes": [], "edges": []})
        self.assertEqual([r["outcome"] for r in out["rules"] if r["rule"] == "P-CUS-001"], ["pass"])

    def test_exceptions_cover_requirements_and_ceilings(self):
        warns = []
        op = {"profile": "citizen", "profile_exceptions": {"require.tests": False, "max_exposure": "High"}}
        eff = jh_policy.merge(op, None, warns)
        self.assertEqual((eff["require"]["tests"], eff["max_exposure"]), (False, "High"))
        self.assertEqual(len([w for w in warns if "operator exception" in w]), 2)
        bad = []
        jh_policy.merge({"profile_exceptions": {"require.tests": True}}, None, bad, "citizen")
        self.assertTrue(any("ignored profile_exceptions" in w for w in bad))

    def test_operator_exceptions_relax_and_repository_retightens(self):
        warns = []
        op = {"profile": "citizen", "profile_exceptions": {"P-OPS-001": "review"}, "custodians": ["@platform"]}
        eff = jh_policy.merge(op, None, warns)
        self.assertEqual((eff["actions"]["P-OPS-001"], eff["custodians"]), ("review", ["@platform"]))
        self.assertEqual(eff["profile_exceptions"], {"P-OPS-001": "review"})
        self.assertTrue(any("operator exception" in w for w in warns))
        again = jh_policy.merge(eff, {"max_exposure": "Low"}, [])            # re-merge keeps the exception
        self.assertEqual(again["actions"]["P-OPS-001"], "review")
        eff = jh_policy.merge(op, {"profile": "citizen", "actions": {"P-OPS-001": "block"}}, [])
        self.assertEqual(eff["actions"]["P-OPS-001"], "block")
        warns = []
        eff = jh_policy.merge(None, {"profile": "citizen", "profile_exceptions": {"P-OPS-001": "off"}}, warns)
        self.assertEqual(eff["actions"]["P-OPS-001"], "block")
        self.assertIn("repository policy cannot grant profile_exceptions; ignored", warns)

    def test_standard_profile_is_unchanged_without_new_evidence(self):
        eff = jh_policy.merge(None, None, [])
        facts = {"files_scanned": 3, "map_files_inspected": 2, "exposure": "Low", "owner_state": "observed",
                 "operations": {"tests": "not-observed", "ci": "not-observed"}}
        out = jh_policy.evaluate(eff, facts, {"nodes": [], "edges": []})
        self.assertEqual(out["result"], "pass")
        self.assertEqual(len(out["rules"]), len(jh_policy.RULES))


class CitizenRules(unittest.TestCase):
    def setUp(self):
        self.eff = jh_policy.merge({"custodians": ["@eng-lead"]}, None, [], "citizen")
        self.facts = {"files_scanned": 3, "map_files_inspected": 2, "exposure": "Moderate", "owner_state": "observed",
                      "declared_custodians": ["@eng-lead"], "operations": {"tests": "observed", "ci": "observed"},
                      "jank_policy": "pass",
                      "change_control": {"state": "provider-verified", "severe": [], "weak": [], "unknown": []}}
        self.graph = {"nodes": [node("app", "application"),
                                node("db", environment="production", sensitivity="internal")],
                      "edges": [edge("e1", "app", "db", "connects", "unknown", "declared")]}

    def outcomes(self, facts=None, graph=None, eff=None):
        out = jh_policy.evaluate(eff or self.eff, facts or self.facts, graph or self.graph)
        return out["result"], {r["rule"]: r["outcome"] for r in out["reasons"]}

    def test_unverified_production_authority_blocks(self):
        result, reasons = self.outcomes()
        self.assertEqual((result, reasons), ("block", {"P-DAT-002": "block"}))
        std = jh_policy.merge(None, None, [])
        self.assertEqual(self.outcomes(eff=std)[1], {"P-DAT-002": "review"})

    def test_custodian(self):
        bare = jh_policy.merge(None, None, [], "citizen")                       # no operator custodians
        facts = dict(self.facts, declared_custodians=[])
        self.assertEqual(self.outcomes(facts, eff=bare)[1].get("P-CUS-001"), "block")
        self.assertEqual(self.outcomes(eff=bare)[1].get("P-CUS-001"), "block")   # a repository declaration does not count
        op = jh_policy.merge({"custodians": ["@platform"]}, None, [], "citizen")
        out = jh_policy.evaluate(op, facts, self.graph)
        cus = [r for r in out["rules"] if r["rule"] == "P-CUS-001"][0]
        self.assertEqual(cus["outcome"], "pass")
        self.assertIn("operator policy", cus["message"])

    def test_declared_tests_are_not_enough(self):
        facts = dict(self.facts, operations={"tests": "declared", "ci": "observed"})
        self.assertEqual(self.outcomes(facts)[1].get("P-OPS-001"), "block")

    def test_unclassified_store_is_insufficient_evidence(self):
        graph = {"nodes": [node("app", "application"), node("db")], "edges": []}
        self.assertEqual(self.outcomes(graph=graph)[1], {"P-DAT-003": "insufficient-evidence"})

    def test_public_exposure_and_agent_leads(self):
        lead = {"rule": "JH132", "path": ".env", "line": 3, "severity": "critical", "title": "x"}
        facts = dict(self.facts, exposure_findings=[lead], agent_findings=[dict(lead, rule="JH703")])
        graph = {"nodes": [node("app", "application")], "edges": []}
        result, reasons = self.outcomes(facts, graph)
        self.assertEqual(reasons, {"P-SEC-001": "block", "P-AGT-001": "block"})
        std = jh_policy.merge(None, None, [])
        self.assertEqual(self.outcomes(facts, graph, std)[1], {"P-SEC-001": "review", "P-AGT-001": "review"})

    def test_exposure_above_moderate_blocks(self):
        facts = dict(self.facts, exposure="High")
        graph = {"nodes": [node("app", "application")], "edges": []}
        self.assertEqual(self.outcomes(facts, graph)[1], {"P-EXP-001": "block"})


class CitizenPassport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="jh-citizen-")
        cls.app = os.path.join(cls.tmp, "app")
        files = {
            ".cursor/mcp.json": MCP,
            "app/main.py": "import json\n\n\ndef handler(event):\n    return json.dumps(event)\n",
            "tests/test_main.py": "from app.main import handler\n\n\ndef test_handler():\n    assert handler({}) == '{}'\n",
            "CODEOWNERS": "* @demo-org/builders\n",
        }
        for rel, text in files.items():
            path = os.path.join(cls.app, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write(text)
        out = run_cli("passport", cls.app, "--profile", "citizen", "--json").stdout
        cls.p = json.loads(out)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_blocks_with_a_plain_language_brief(self):
        gov = self.p["governance"]
        self.assertEqual(self.p["assessment"]["decision"]["result"], "block")
        self.assertEqual(gov["profile"], "citizen")
        self.assertTrue(gov["brief"][0].startswith("Not ready to ship"))
        self.assertIn("- No engineer is named as its custodian, so nobody with engineering responsibility answers for it.",
                      gov["brief"])
        self.assertTrue(any("reaching postgresql crm-db.prod.internal" in b for b in gov["brief"]))
        self.assertEqual(sorted(s["name"] for s in gov["agent"]["servers"]), ["docs", "github", "postgres"])

    def test_views_show_the_brief_only_for_citizen(self):
        md = run_cli("passport", self.app, "--profile", "citizen", "--md").stdout
        self.assertIn("## In plain terms (citizen-developer profile)", md)
        std = run_cli("passport", self.app, "--md").stdout
        self.assertNotIn("In plain terms", std)
        html = run_cli("passport", self.app, "--profile", "citizen", "--html").stdout
        self.assertIn('"profile": "citizen"', html)

    def test_redaction_hides_agent_tooling_custodians_and_rule_details(self):
        red = jh_passport.redact(self.p)
        blob = json.dumps(red["governance"])
        for secret_ish in ("postgres", "GITHUB_PERSONAL_ACCESS_TOKEN", "crm-db", "mcp.json"):
            self.assertNotIn(secret_ish, blob)
        decision = json.dumps(red["assessment"]["decision"])
        self.assertNotIn("crm-db", decision)                  # P-DAT-003 quoted the host
        self.assertNotIn(".cursor/mcp.json", decision)        # P-AGT-001 quoted the path
        self.assertIn("(details redacted)", decision)

    def test_acceptance_must_come_from_a_named_custodian(self):
        p = json.loads(json.dumps(self.p))
        p["governance"].update(custodians=["@eng-lead"], custodian_source="operator-policy")
        p["assessment"]["decision"]["result"] = "pass"
        p["source_revision"] = "abc123"
        record = {"accepted_at": "2026-10-01T00:00:00Z", "decision_accepted": "pass", "subject_revision": "abc123",
                  "policy_hash": p["assessment"]["decision"]["policy"]["hash"]}
        ok = jh_passport.apply_acceptance(json.loads(json.dumps(p)), dict(record, accepted_by="@eng-lead"), True, "a.json")
        self.assertEqual(ok["lifecycle"]["acceptance"]["state"], "declared-by-operator")
        bad = jh_passport.apply_acceptance(json.loads(json.dumps(p)), dict(record, accepted_by="@builder"), True, "a.json")
        self.assertEqual(bad["lifecycle"]["acceptance"]["state"], "rejected")
        reason = "accepted_by is not a custodian named by the operator policy (citizen profile)"
        self.assertIn(reason, bad["lifecycle"]["acceptance"]["reasons"])
        p["governance"]["custodian_source"] = "repository"     # the author could have named themselves
        mine = jh_passport.apply_acceptance(json.loads(json.dumps(p)), dict(record, accepted_by="@eng-lead"), True, "a.json")
        self.assertEqual(mine["lifecycle"]["acceptance"]["state"], "rejected")

    def test_repository_can_declare_the_profile_and_custodian(self):
        cfg = os.path.join(self.app, ".jankhunt42.json")
        with open(cfg, "w") as fh:
            json.dump({"passport": {"profile": "citizen", "custodians": ["@eng-lead"]}}, fh)
        try:
            p = json.loads(run_cli("passport", self.app, "--json").stdout)
        finally:
            os.remove(cfg)
        self.assertEqual(p["governance"]["profile"], "citizen")
        self.assertEqual((p["governance"]["custodians"], p["governance"]["custodian_source"]), (["@eng-lead"], "repository"))
        cus = {r["rule"]: r for r in p["assessment"]["decision"]["reasons"]}.get("P-CUS-001")
        self.assertEqual(cus["outcome"], "block")             # recorded, but it does not satisfy the rule
        self.assertIn("declared only in the repository", cus["message"])

    def test_repository_cannot_suppress_governance_leads(self):
        cfg = os.path.join(self.app, ".jankhunt42.json")
        vs = os.path.join(self.app, ".vscode", "settings.json")
        os.makedirs(os.path.dirname(vs), exist_ok=True)
        with open(vs, "w") as fh:
            fh.write('{\n  "chat.tools.autoApprove": true\n}\n')
        with open(cfg, "w") as fh:
            json.dump({"rules": {"JH703": {"enabled": False}, "JH705": {"enabled": False}}}, fh)
        try:
            cit = json.loads(run_cli("passport", self.app, "--profile", "citizen", "--json").stdout)
            std = json.loads(run_cli("passport", self.app, "--json").stdout)
        finally:
            os.remove(cfg)
            shutil.rmtree(os.path.dirname(vs))
        self.assertEqual(sorted({l["rule"] for l in cit["governance"]["agent_leads"]}), ["JH703", "JH705"])
        self.assertEqual({r["rule"]: r["outcome"] for r in cit["assessment"]["decision"]["reasons"]}["P-AGT-001"], "block")
        self.assertEqual(std["governance"]["agent_leads"], [])        # the standard profile honours repository tuning
        self.assertEqual(std["governance"]["repository_suppressed_leads"], 2)
        self.assertTrue(any("does not honour" in w for w in cit["warnings"]))

    def test_suppressed_count_is_exact_beyond_display_caps(self):
        servers = {"s%d" % i: {"command": "npx", "args": ["-y", "pkg-%d" % i]} for i in range(7)}
        text = json.dumps({"mcpServers": servers}, indent=2)
        text = text.replace('    "s3": {', '    // jankhunt42: ignore JH705 (reviewed)\n    "s3": {')
        path = os.path.join(self.app, ".mcp.json")
        with open(path, "w") as fh:
            fh.write(text)
        try:
            std = json.loads(run_cli("passport", self.app, "--json").stdout)
            cit = json.loads(run_cli("passport", self.app, "--profile", "citizen", "--json").stdout)
        finally:
            os.remove(path)
        self.assertEqual(std["governance"]["repository_suppressed_leads"], 1)
        self.assertEqual(len([l for l in std["governance"]["agent_leads"] if l["path"] == ".mcp.json"]), 6)
        self.assertEqual(len([l for l in cit["governance"]["agent_leads"] if l["path"] == ".mcp.json"]), 7)

    def test_repository_tightening_adds_leads_under_citizen(self):
        cfg = os.path.join(self.app, ".jankhunt42.json")
        cs = os.path.join(self.app, ".claude", "settings.json")
        os.makedirs(os.path.dirname(cs), exist_ok=True)
        with open(cs, "w") as fh:
            json.dump({"env": {"HTTPS_PROXY": "http://proxy.example.com:3128"}}, fh)
        with open(cfg, "w") as fh:
            json.dump({"rules": {"JH704": {"severity": "major"}}}, fh)
        try:
            cit = json.loads(run_cli("passport", self.app, "--profile", "citizen", "--json").stdout)
        finally:
            os.remove(cfg)
            shutil.rmtree(os.path.dirname(cs))
        self.assertIn("JH704", {l["rule"] for l in cit["governance"]["agent_leads"]})

    def test_repository_ignore_globs_cannot_hide_governance_leads(self):
        cfg = os.path.join(self.app, ".jankhunt42.json")
        env = os.path.join(self.app, "web", ".env.production")
        os.makedirs(os.path.dirname(env), exist_ok=True)
        with open(env, "w") as fh:
            fh.write("NEXT_PUBLIC_" + "OPENAI_API_KEY=\n")
        with open(cfg, "w") as fh:
            json.dump({"ignore": ["web/**"]}, fh)
        try:
            std = json.loads(run_cli("passport", self.app, "--json").stdout)
            cit = json.loads(run_cli("passport", self.app, "--profile", "citizen", "--json").stdout)
            capped = json.loads(run_cli("passport", self.app, "--profile", "citizen", "--json", "--max-files", "2").stdout)
        finally:
            os.remove(cfg)
            shutil.rmtree(os.path.dirname(env))
        self.assertNotIn("web/.env.production", {l["path"] for l in std["governance"]["public_exposure_leads"]})
        self.assertIn("web/.env.production", {l["path"] for l in cit["governance"]["public_exposure_leads"]})
        self.assertIn("web/.env.production", {row["path"] for row in
                      cit["governance"]["agent_policy_evidence"]["finding_context"]})
        self.assertTrue(any("reached --max-files" in w for w in capped["warnings"]))
        self.assertEqual({r["rule"]: r["outcome"] for r in capped["assessment"]["decision"]["reasons"]}["P-COV-001"],
                         "insufficient-evidence")

    def test_shareable_passport_withholds_warnings(self):
        p = json.loads(json.dumps(self.p))
        p["warnings"] = ["binding matched no workload: payments-prod.internal.example"]
        red = jh_passport.redact(p)
        self.assertNotIn("payments-prod", json.dumps(red["warnings"]))


class CitizenPolicyEvidence(unittest.TestCase):
    def test_candidates_are_proximity_only_and_never_claim_history(self):
        items = [jh_map.Item(path, "PRIVATE POLICY CONTENT") for path in (
            "AGENTS.md", "web/CLAUDE.md", "web/AGENTS.override.md", "web2/CLAUDE.md",
            "web/.claude/settings.json", "other/.codex/config.toml", "notes/foo.claude/settings.json")]
        findings = [jh_core.Finding("JH132", "lead", "major", "security", "web/app.py", 4),
                    jh_core.Finding("JH101", "lead", "critical", "security", "web2/app.py", 2)]
        evidence = jh_passport.agent_policy_evidence(items, findings)
        rows = {row["path"]: row for row in evidence["finding_context"]}
        self.assertEqual(rows["web/app.py"]["candidate_instruction_files"],
                         ["AGENTS.md", "web/AGENTS.override.md", "web/CLAUDE.md"])
        self.assertEqual(rows["web/app.py"]["candidate_configuration_files"], ["web/.claude/settings.json"])
        self.assertEqual(rows["web2/app.py"]["candidate_instruction_files"], ["AGENTS.md", "web2/CLAUDE.md"])
        self.assertEqual(rows["web2/app.py"]["candidate_configuration_files"], [])
        duplicate = jh_passport.agent_policy_evidence(items, findings + findings)
        self.assertEqual(len(duplicate["finding_context"]), 2)
        for field in ("agent_identity", "policy_loaded", "managed_policy", "causal_link"):
            self.assertEqual(evidence[field], "unknown")
        self.assertNotIn("PRIVATE POLICY CONTENT", json.dumps(evidence))
        self.assertNotIn("notes/foo.claude/settings.json", evidence["configuration_files"])

    def test_hostile_names_are_safe_in_terminal_and_html(self):
        with tempfile.TemporaryDirectory(prefix="jh-policy-html-") as root:
            report = json.loads(run_cli("passport", root, "--profile", "citizen", "--json").stdout)
        context = jh_passport.agent_policy_evidence(
            [jh_map.Item("<img src=x onerror=alert(1)>/AGENTS.md", "")],
            [jh_core.Finding("JH101", "lead", "major", "security",
                             "<img src=x onerror=alert(1)>/a.py", 1)])
        report["governance"]["agent_policy_evidence"] = context
        html = jh_explorer.render_passport(report)
        self.assertNotIn("<img src=x onerror=alert(1)>", html)
        self.assertNotIn("\x1b", jh_views.passport_tty(report, color=False))

    def test_empty_and_bounded_evidence_stays_unknown(self):
        evidence = jh_passport.agent_policy_evidence([], [])
        self.assertEqual(evidence["instruction_files"], [])
        self.assertEqual(evidence["causal_link"], "unknown")
        items = [jh_map.Item("d%03d/AGENTS.md" % i, "") for i in range(201)]
        findings = [jh_core.Finding("JH101", "lead", "major", "security", "d%03d/a.py" % i, 1)
                    for i in range(51)]
        bounded = jh_passport.agent_policy_evidence(items, findings)
        self.assertTrue(bounded["sources_truncated"])
        self.assertTrue(bounded["findings_truncated"])
        self.assertEqual(len(bounded["finding_context"]), 50)
        self.assertIn("omitted by report limits", bounded["note"])
        nested = [jh_map.Item("/".join(["x"] * i + ["AGENTS.md"]), "") for i in range(22)]
        deep = jh_core.Finding("JH101", "lead", "major", "security", "/".join(["x"] * 22 + ["a.py"]), 1)
        limited = jh_passport.agent_policy_evidence(nested, [deep])
        self.assertTrue(limited["finding_context"][0]["candidates_truncated"])
        self.assertEqual(len(limited["finding_context"][0]["candidate_instruction_files"]), 20)
        self.assertIn("omitted by report limits", limited["note"])

    def test_citizen_cli_views_and_share_redaction(self):
        with tempfile.TemporaryDirectory(prefix="jh-policy-evidence-") as root:
            os.makedirs(os.path.join(root, "web", ".claude"))
            for rel, content in (("AGENTS.md", "TOP-SECRET-POLICY-TEXT"),
                                 ("web/CLAUDE.md", "TOP-SECRET-POLICY-TEXT"),
                                 ("web/AGENTS.override.md", "TOP-SECRET-POLICY-TEXT"),
                                 ("web/.claude/settings.json", "{}"),
                                 ("web/.env.production", "NEXT_PUBLIC_" + "OPENAI_API_KEY=\n")):
                with open(os.path.join(root, rel), "w") as fh:
                    fh.write(content)
            result = run_cli("passport", root, "--profile", "citizen", "--json")
            report = json.loads(result.stdout)
            context = report["governance"]["agent_policy_evidence"]
            row = next(row for row in context["finding_context"] if row["path"] == "web/.env.production")
            self.assertIn("web/CLAUDE.md", row["candidate_instruction_files"])
            self.assertIn("web/AGENTS.override.md", row["candidate_instruction_files"])
            self.assertIn("web/.claude/settings.json", row["candidate_configuration_files"])
            self.assertNotIn("TOP-SECRET-POLICY-TEXT", result.stdout)
            self.assertIn("Agent policy context", jh_passport.markdown(report))
            self.assertIn("agent policy context", jh_views.passport_tty(report, color=False))
            self.assertIn("agent policy context", jh_explorer.render_passport(report))
            share = jh_passport.redact(report)
            payload = json.dumps(share["governance"]["agent_policy_evidence"])
            self.assertNotIn("web/", payload)
            self.assertNotIn("AGENTS.md", payload)
            self.assertIn("instruction-file-", payload)



if __name__ == "__main__":
    unittest.main()
