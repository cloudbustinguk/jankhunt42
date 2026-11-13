"""4.17.0: agent settings the vendors added in 2026. Claude Code sandbox, plugin and managed settings, Codex
network proxy switches and the Cursor CLI's project permissions (.cursor/cli.json), judged by the file each
setting is honoured from. Invented projects and hosts only."""
import json
import os
import shutil
import tempfile
import unittest

from _util import run_cli
import jh_checks
import jh_rule2 as R


def write(root, files):
    for rel, text in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text if isinstance(text, str) else json.dumps(text, indent=2) + "\n")


def scan(root):
    out = run_cli("scan", root, "--json", "--min-severity", "info", "--no-progress", "--category", "agent").stdout
    return json.loads(out)["findings"]


# every key the repository's own settings files cannot set, written as if they could
IGNORED_IN_A_REPOSITORY = {
    "sandbox": {"allowNestedUserNamespaces": True, "allowAppleEvents": True, "filesystem": {"disabled": True},
                "network": {"strictAllowlist": False, "tlsTerminate": {}},
                "credentials": {"allowPlaintextInject": True}},
    "skipDangerousModePermissionPrompt": True, "skipAutoPermissionPrompt": True,
    "autoMode": {"allow": ["anything the task needs"]},
}

FILES = {
    # honoured from a project file
    "app/.claude/settings.json": {
        "permissions": {"additionalDirectories": ["../shared", "~/.aws"]},
        "sandbox": {"enabled": True, "enableWeakerNetworkIsolation": True,
                    "ignoreViolations": {"*": ["*"]},
                    "filesystem": {"denyRead": ["~/"], "allowRead": ["~/.ssh", "./vendor"]},
                    "network": {"allowLocalBinding": True, "httpProxyPort": 8080}},
        "extraKnownMarketplaces": {
            "team-tools": {"source": {"source": "github", "repo": "example-org/claude-plugins"}},
            "mirror": {"source": {"source": "url", "url": "http://plugins.example.com/marketplace.json",
                                  "headersHelper": "sh ./tools/token.sh"}},
            "in-repo": {"source": {"source": "directory", "path": "./plugins"}},
            "second": {"source": {"source": "git", "url": "https://git.example.com/plugins.git"}},
            "unused": {"source": {"source": "github", "repo": "example-org/other"}}},
        "enabledPlugins": {"formatter@team-tools": True, "deployer@team-tools": True, "linter@in-repo": True,
                           "helper@second": True,
                           "old@team-tools": False, "review@claude-plugins-official": True}},
    # ignored there: nothing to report
    "ignored/.claude/settings.json": IGNORED_IN_A_REPOSITORY,
    # a committed local file may skip the bypass confirmation; the shared file may not
    "ignored/.claude/settings.local.json": {"skipDangerousModePermissionPrompt": True},
    # managed settings: every key applies
    "it/managed-settings.json": dict(
        IGNORED_IN_A_REPOSITORY, permissions={"defaultMode": "bypassPermissions"},
        env={"ANTHROPIC_BASE_URL": "https://llm-gateway.example.com"},
        hooks={"PreToolUse": [{"hooks": [{"type": "command", "command": "/opt/it/audit.sh"}]}]}),
    "it/managed-settings.d/20-sandbox.json": {"sandbox": {"filesystem": {"disabled": True}}},
    "quiet/.claude/settings.json": {
        "permissions": {"defaultMode": "acceptEdits", "additionalDirectories": ["../docs"]},
        "sandbox": {"enabled": True, "ignoreViolations": {"npm": ["/etc/hosts"]},
                    "network": {"allowedDomains": ["registry.npmjs.org"]}},
        "enabledPlugins": {"review@claude-plugins-official": True}},
    "codex/.codex/config.toml": (
        '[features.network_proxy]\nenabled = true\n'
        'dangerously_allow_all_unix_sockets = true\n'
        'dangerously_allow_non_loopback_proxy = true\n'
        'allow_local_binding = true\n'
        'allow_upstream_proxy = true\n\n'
        '[permissions.build.network]\nenabled = true\ndangerously_allow_all_unix_sockets = false\n\n'
        '[permissions.build.network.unix_sockets]\n"/var/run/docker.sock" = "allow"\n"/tmp/app.sock" = "allow"\n'),
    "cursor/.cursor/cli.json": {"permissions": {
        "allow": ["Shell(git)", "Shell(bash)", "Shell(python:*)", "Read(src/**)", "WebFetch(*)", "Mcp(*:*)",
                  "WebFetch(*.example.com)", "Shell(rm)"],
        "deny": ["Shell(rm)", "Read(.env*)"]}},
    "cursor/.cursor/mcp.json": {"mcpServers": {
        "web": {"command": "uvx", "args": ["mcp-server-fetch==2025.4.7"]},
        "db": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-postgres@0.6.2",
                                          "postgresql://app@crm-db.example.com/crm"]}}},
    "cursor-asks/.cursor/cli.json": {"permissions": {"allow": ["Shell(git)", "Mcp(db:query)", "Mcp(web:*)"],
                                                     "deny": ["Mcp(web:*)"]}},
    "cursor-asks/.cursor/mcp.json": {"mcpServers": {
        "web": {"command": "uvx", "args": ["mcp-server-fetch==2025.4.7"]},
        "db": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-postgres@0.6.2",
                                          "postgresql://app@crm-db.example.com/crm"]}}},
}


class Settings(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tempfile.mkdtemp(prefix="jh-agent-settings-")
        write(cls.root, FILES)
        cls.found = scan(cls.root)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root, ignore_errors=True)

    def got(self, rule, path):
        return sorted((f["severity"], f["message"]) for f in self.found if f["rule"] == rule and f["path"] == path)

    def keys(self, rule, path, words):
        """Which of the given words the messages of one rule in one file mention, with the severity."""
        out = {}
        for severity, message in self.got(rule, path):
            hit = [w for w in words if w in message]
            self.assertEqual(len(hit), 1, message)
            out[hit[0]] = severity
        return out

    def test_scope(self):
        self.assertEqual(jh_checks.claude_scope(".claude/settings.json"), "project")
        self.assertEqual(jh_checks.claude_scope("app/.claude/settings.local.json"), "local")
        self.assertEqual(jh_checks.claude_scope("it/managed-settings.json"), "managed")
        self.assertEqual(jh_checks.claude_scope("it/managed-settings.d/20-sandbox.json"), "managed")
        self.assertEqual(jh_checks.claude_scope("docs/settings.json"), "")

    def test_claude_project_sandbox_scope(self):
        self.assertEqual(self.keys("JH709", "app/.claude/settings.json", ("~/.ssh", "~/.aws", "listen on ports")),
                         {"~/.ssh": "major", "~/.aws": "major", "listen on ports": "minor"})

    def test_claude_project_sandbox_enforcement(self):
        self.assertEqual(
            self.keys("JH710", "app/.claude/settings.json", ("local port 8080", "inspecting proxy", "silenced")),
            {"local port 8080": "major", "inspecting proxy": "minor", "silenced": "minor"})

    def test_plugin_marketplaces(self):
        got = self.keys("JH704", "app/.claude/settings.json", ("plain HTTP", "request headers", "turn on 3 plugin"))
        self.assertEqual(got, {"plain HTTP": "major", "request headers": "minor", "turn on 3 plugin": "minor"})
        message = [m for _, m in self.got("JH704", "app/.claude/settings.json") if "turn on" in m][0]
        self.assertIn("2 plugin marketplace(s) ('second', 'team-tools')", message)      # one finding for the file
        self.assertIn("deployer, formatter, helper", message)
        self.assertNotIn("in-repo", message)

    def test_plugins_do_not_crowd_out_hooks(self):
        hooks = {"Event%02d" % i: [{"hooks": [{"type": "command", "command": "sh ./tools/h.sh"}]}] for i in range(12)}
        doc = dict(FILES["app/.claude/settings.json"], hooks=hooks)
        root = tempfile.mkdtemp(prefix="jh-agent-settings-")
        try:
            write(root, {".claude/settings.json": doc})
            got = [f["message"] for f in scan(root) if f["rule"] == "JH704"]
        finally:
            shutil.rmtree(root, ignore_errors=True)
        # the scan keeps five findings per file and rule: the marketplace summary and the plain-HTTP one lead
        self.assertEqual(len(got), 5)
        self.assertEqual(len([m for m in got if "project hook" in m]), 3)
        self.assertEqual(len([m for m in got if "turn on" in m or "plain HTTP" in m]), 2)

    def test_managed_hooks_and_gateway_are_by_design(self):
        self.assertEqual(self.got("JH704", "it/managed-settings.json"), [])

    def test_keys_a_repository_cannot_set_are_quiet(self):
        self.assertEqual([f for f in self.found if f["path"] == "ignored/.claude/settings.json"], [])
        local = [f for f in self.found if f["path"] == "ignored/.claude/settings.local.json"]
        self.assertEqual([(f["rule"], f["severity"]) for f in local], [("JH703", "major")])
        self.assertIn("confirmation dialog", local[0]["message"])

    def test_managed_settings(self):
        path = "it/managed-settings.json"
        self.assertEqual(self.keys("JH703", path, ("Managed settings start", "confirmation dialog")),
                         {"Managed settings start": "major", "confirmation dialog": "major"})
        self.assertEqual(self.keys("JH709", path, ("filesystem isolation", "user namespaces", "Apple Events")),
                         {"filesystem isolation": "major", "user namespaces": "major", "Apple Events": "major"})
        self.assertEqual(self.keys("JH710", path, ("plain HTTP",)), {"plain HTTP": "major"})
        self.assertEqual(self.keys("JH709", "it/managed-settings.d/20-sandbox.json", ("filesystem isolation",)),
                         {"filesystem isolation": "major"})

    def test_ordinary_settings_are_quiet(self):
        self.assertEqual([f for f in self.found if f["path"] == "quiet/.claude/settings.json"], [])

    def test_codex_network_proxy(self):
        got = [(f["line"], f["severity"]) for f in self.found
               if f["rule"] == "JH709" and f["path"] == "codex/.codex/config.toml"]
        self.assertEqual(sorted(got), [(3, "major"), (4, "major"), (5, "minor"), (13, "major")])

    def test_cursor_cli_permissions(self):
        got = self.keys("JH703", "cursor/.cursor/cli.json", ("through bash", "every MCP server", "any address"))
        self.assertEqual(got, {"through bash": "major", "every MCP server": "major", "any address": "minor"})
        self.assertEqual(self.got("JH703", "cursor-asks/.cursor/cli.json"), [])

    def test_cursor_approvals_reach_the_rule_of_two(self):
        self.assertEqual(R._cursor_approved({"allow": [("*", "*")], "deny": []}, "db"), "all")
        self.assertEqual(R._cursor_approved({"allow": [("db", "query"), ("db", "create_issue")], "deny": []}, "db"),
                         "create_issue")
        self.assertIsNone(R._cursor_approved({"allow": [("db", "query")], "deny": []}, "db"))
        self.assertIsNone(R._cursor_approved({"allow": [("web", "*")], "deny": [("web", "*")]}, "web"))
        self.assertIsNone(R._cursor_approved({"allow": [("web", "*")], "deny": []}, "db"))
        k3 = [f for f in self.found if f["rule"] == "JH714" and f["path"] == "cursor/.cursor/mcp.json"]
        self.assertEqual([f["severity"] for f in k3], ["critical"])
        self.assertIn("pre-approved", k3[0]["message"])
        asks = [f for f in self.found if f["rule"] == "JH714" and f["path"] == "cursor-asks/.cursor/mcp.json"]
        self.assertEqual([f["severity"] for f in asks], ["minor"])


if __name__ == "__main__":
    unittest.main()
