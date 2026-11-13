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

CANARY = "ghp_" + "Ab3Cd4Ef5Gh6Ij7Kl8Mn9Op0Qr1St2Uv3Wx4"      # invented, assembled so this file holds no token
AWS_CANARY = "AKIA" + "B2C3D4E5F6G7H8J9"
LOWER_CANARY = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"
PG_FETCH = {"mcpServers": {
    "web": {"command": "uvx", "args": ["mcp-server-fetch==2025.4.7"]},
    "db": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-postgres@0.6.2",
                                      "postgresql://app@crm-db.example.com/crm"]}}}


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
                    "ignoreViolations": {"*": ["*", "/"]},      # literal substrings: not "everything"
                    "filesystem": {"denyRead": ["~/"], "allowRead": ["~/.ssh", "./vendor"]},
                    "network": {"allowLocalBinding": True, "httpProxyPort": 8080}},
        "extraKnownMarketplaces": {
            "team-tools": {"source": {"source": "github", "repo": "example-org/claude-plugins"}},
            # Claude Code skips a helper unless the catalog is a url source over https
            "mirror": {"source": {"source": "url", "url": "http://plugins.example.com/marketplace.json",
                                  "headersHelper": "sh ./tools/skipped.sh"}},
            "catalog": {"source": {"source": "url", "url": "https://plugins.example.com/marketplace.json",
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
        "allow": ["Shell(git)", "Shell(node:--version)", "Shell(bash)", "Shell(python:*)", "Read(src/**)", "WebFetch(*)", "Mcp(*:*)",
                  "WebFetch(*.example.com)", "Shell(rm)"],
        "deny": ["Shell(rm)", "Read(.env*)"]}},
    "cursor/.cursor/mcp.json": PG_FETCH,
    # nothing that acts is pre-approved: every acting step asks
    "cursor-asks/.cursor/cli.json": {"permissions": {"allow": ["Shell(git)", "Mcp(db:query)"]}},
    "cursor-asks/.cursor/mcp.json": PG_FETCH,
    # the fetch server is denied whole, or its one tool is: no untrusted input and no way out is left
    "cursor-denied/.cursor/cli.json": {"permissions": {"allow": ["Mcp(web:*)"], "deny": ["Mcp(web:*)"]}},
    "cursor-denied/.cursor/mcp.json": PG_FETCH,
    "cursor-tool-denied/.cursor/cli.json": {"permissions": {"allow": ["Mcp(web:*)"], "deny": ["Mcp(web:fetch)"]}},
    "cursor-tool-denied/.cursor/mcp.json": PG_FETCH,
    # arguments narrow an entry, and a deny for the whole command covers it
    "cursor-narrow/.cursor/cli.json": {"permissions": {
        "allow": ["Shell(python:--version)", "Shell(bash)", "Mcp(*:*)", "WebFetch(*)"],
        "deny": ["Shell(*)", "Mcp(*:*)", "WebFetch(*)"]}},
    # names a repository chooses reach the report redacted
    "secret/.cursor/cli.json": {"permissions": {"allow": ["Shell(bash:*)", "Shell(sh:echo %s)" % CANARY,
                                                          "Mcp(*:*)", "Mcp(%s:*)" % CANARY]}},
    "secret2/.cursor/cli.json": {"permissions": {"allow": ["Shell(%s)" % CANARY, "Shell(*:%s)" % CANARY]}},
    "secret/.claude/settings.json": {
        "extraKnownMarketplaces": {
            CANARY: {"source": {"source": "url", "url": "http://plugins.example.com/m.json"}},
            "team": {"source": {"source": "github", "repo": "example-org/plugins"}}},
        "enabledPlugins": {CANARY + "@team": True, "x@" + CANARY: True}},
    # paths, hosts, sockets and profile names a repository writes reach a message redacted, before shortening
    "secret3/.claude/settings.json": {
        "permissions": {"additionalDirectories": ["~/.aws/" + AWS_CANARY]},
        "sandbox": {"filesystem": {"denyRead": ["~/"], "allowRead": ["~/.ssh/" + AWS_CANARY],
                                   "allowWrite": ["~/.ssh/" + AWS_CANARY]},
                    "excludedCommands": ["bash *"],
                    "network": {"allowUnixSockets": ["/" + CANARY + "/docker.sock"],
                                "allowedDomains": ["*." + LOWER_CANARY + ".github.io"]}}},
    "secret3/.codex/config.toml": ('[permissions.%s.network]\nmode = "full"\n\n'
                                   '[features.network_proxy.domains]\n"*.%s.github.io" = "allow"\n'
                                   % (CANARY, LOWER_CANARY)),
    # only the tables Codex reads count; a quoted key with dots in it is one key, not a table path
    "codex-other/.codex/config.toml": (
        '[unrelated.network]\ndangerously_allow_all_unix_sockets = true\n\n'
        '[unrelated.network.unix_sockets]\n"/var/run/docker.sock" = "allow"\n\n'
        '[unrelated.network.domains]\n"*" = "allow"\n\n'
        '["features.network_proxy"]\ndangerously_allow_all_unix_sockets = true\n\n'
        '[permissions."demo.network"]\ndangerously_allow_all_unix_sockets = true\nmode = "full"\n\n'
        '["features.network_proxy.unix_sockets"]\n"/var/run/docker.sock" = "allow"\n\n'
        '["features.network_proxy.domains"]\n"*" = "allow"\n'),
    # the desktop app's table belongs to requirements.toml and is not a command sandbox setting
    "codex-app/.codex/config.toml": ('[application.network.domains]\n"*" = "allow"\n\n'
                                     '[application.network]\ndangerously_allow_all_unix_sockets = true\n'),
    # a header the reader cannot follow ends the table before it; text inside a string is not a setting
    "codex-array/.codex/config.toml": '[features.network_proxy]\n[[unrelated]]\ndangerously_allow_all_unix_sockets = true\n',
    "codex-bracket/.codex/config.toml": ('[features.network_proxy]\n["unrelated]table"]\n'
                                         'dangerously_allow_all_unix_sockets = true\n'),
    "codex-string/.codex/config.toml": ('[features.network_proxy]\nnote = """\n'
                                        'dangerously_allow_all_unix_sockets = true\n"""\n'
                                        "other = \'\'\'\nallow_local_binding = true\n\'\'\'\n"),
    "codex-after-string/.codex/config.toml": ('[features.network_proxy]\nnote = """\ntext\n"""\n'
                                              'dangerously_allow_all_unix_sockets = true\n'),
    # a token as a job name, a Copilot Studio agent name and a policy name, placed where a length cap falls in it
    "secret4/.github/workflows/ci.yml": ("on: push\npermissions: write-all\njobs:\n  " + CANARY +
                                         ":\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n"),
    "secret4/src/bots/cr123_helpdesk/bot.xml": (
        '<bot schemaname="cr123_helpdesk">\n<authenticationmode>1</authenticationmode>\n'
        '<name>' + "x" * 64 + " " + CANARY + '</name>\n</bot>'),
    "secret4/supabase/migrations/001_notes.sql": (
        'create table public.notes(id int);\ncreate policy "' + "x" * 44 + " " + CANARY +
        '" on public.notes using ((auth.jwt() -> \'user_metadata\' ->> \'role\') = \'admin\');\n'),
    "secret4/.claude/settings.json": {"hooks": {"SessionStart": [{"hooks": [
        {"type": "command", "command": "echo " + "x" * 140 + " " + CANARY}]}]}},
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
            self.keys("JH710", "app/.claude/settings.json", ("local port 8080", "inspecting proxy")),
            {"local port 8080": "major", "inspecting proxy": "minor"})

    def test_plugin_marketplaces(self):
        got = self.keys("JH704", "app/.claude/settings.json", ("plain HTTP", "request headers", "turn on 3 plugin"))
        self.assertEqual(got, {"plain HTTP": "major", "request headers": "minor", "turn on 3 plugin": "minor"})
        message = [m for _, m in self.got("JH704", "app/.claude/settings.json") if "turn on" in m][0]
        self.assertIn("2 plugin marketplace(s) ('second', 'team-tools')", message)      # one finding for the file
        self.assertIn("deployer, formatter, helper", message)
        self.assertNotIn("in-repo", message)
        helpers = [f["evidence"] for f in self.found if "request headers" in f["message"]]
        self.assertEqual(helpers, ["sh ./tools/token.sh"])       # the helper of the plain-HTTP catalog never runs

    def test_plugins_do_not_crowd_out_hooks(self):
        hooks = {"Event%02d" % i: [{"hooks": [{"type": "command", "command": "sh ./tools/h.sh"}]}] for i in range(12)}
        doc = dict(FILES["app/.claude/settings.json"], hooks=hooks)
        root = tempfile.mkdtemp(prefix="jh-agent-settings-")
        try:
            write(root, {".claude/settings.json": doc})
            got = [f["message"] for f in scan(root) if f["rule"] == "JH704"]
        finally:
            shutil.rmtree(root, ignore_errors=True)
        # the scan keeps five findings per file and rule: the major leads, then what 4.16.0 reported
        self.assertEqual(len(got), 5)
        self.assertEqual(len([m for m in got if "plain HTTP" in m]), 1)
        self.assertEqual(len([m for m in got if "project hook" in m]), 4)

    def test_a_marketplace_never_displaces_a_major(self):
        """Four hooks and a rerouted API filled the cap in 4.16.0; a marketplace must not push the major out."""
        doc = {"hooks": {e: [{"hooks": [{"type": "command", "command": "echo ok"}]}]
                         for e in ("SessionStart", "PreToolUse", "PostToolUse", "Stop")},
               "extraKnownMarketplaces": {"team": {"source": {"source": "github", "repo": "example-org/plugins"}}},
               "enabledPlugins": {"formatter@team": True},
               "env": {"ANTHROPIC_BASE_URL": "https://gateway.example.com"}}
        root = tempfile.mkdtemp(prefix="jh-agent-settings-")
        try:
            write(root, {".claude/settings.json": doc})
            got = [(f["severity"], f["message"]) for f in scan(root) if f["rule"] == "JH704"]
            gate = run_cli("scan", root, "--json", "--no-progress", "--category", "agent", "--fail-on", "major")
        finally:
            shutil.rmtree(root, ignore_errors=True)
        self.assertEqual([s for s, _ in got], ["major"] + ["minor"] * 4)
        self.assertIn("ANTHROPIC_BASE_URL", got[0][1])
        self.assertEqual(gate.returncode, 1)

    def test_every_plain_http_marketplace_is_reported(self):
        doc = {"extraKnownMarketplaces": {"m%d" % i: {"source": {"source": "url", "url": "http://p%d.example.com/m.json" % i}}
                                          for i in range(4)}}
        root = tempfile.mkdtemp(prefix="jh-agent-settings-")
        try:
            write(root, {".claude/settings.json": doc})
            out = run_cli("scan", root, "--json", "--no-progress", "--category", "agent", "--max-per-file-rule", "100")
        finally:
            shutil.rmtree(root, ignore_errors=True)
        self.assertEqual(len([f for f in json.loads(out.stdout)["findings"] if f["rule"] == "JH704"]), 4)

    def test_no_secret_reaches_any_output(self):
        root = os.path.join(self.root, "secret")
        for sub in ("secret", "secret2", "secret3", "secret4"):
            for fmt in ("--json", "--md", "--sarif", "--html", "--prompt"):
                out = run_cli("scan", os.path.join(self.root, sub), fmt, "--no-progress", "--min-severity", "info")
                for canary in (CANARY, AWS_CANARY, LOWER_CANARY):
                    # not the token, and not its first characters where a length cap fell inside it
                    self.assertNotIn(canary, out.stdout, (sub, fmt))
                    self.assertNotIn(canary[:12], out.stdout, (sub, fmt))
        found = run_cli("scan", os.path.join(self.root, "secret4"), "--json", "--no-progress", "--min-severity", "info")
        rules = {f["rule"] for f in json.loads(found.stdout)["findings"]}
        self.assertLessEqual({"JH432", "JH148", "JH154", "JH704"}, rules)     # the findings are still made
        # the findings those canaries sit in are still made: six from the settings file, two from Codex's
        self.assertEqual(len(self.got("JH709", "secret3/.claude/settings.json")), 5)      # the scan's cap of five
        self.assertEqual(len(self.got("JH709", "secret3/.codex/config.toml")), 2)
        rules = {f["rule"] for f in self.found if f["path"].startswith("secret/")}
        self.assertLessEqual({"JH703", "JH704"}, rules)       # the findings are still made
        self.assertTrue(os.path.isdir(root))

    def test_project_bypass_mode_is_a_note_not_a_lead(self):
        root = tempfile.mkdtemp(prefix="jh-agent-settings-")
        try:
            write(root, {".claude/settings.json": {"permissions": {"defaultMode": "bypassPermissions"}}})
            got = [(f["rule"], f["severity"]) for f in scan(root)]
        finally:
            shutil.rmtree(root, ignore_errors=True)
        self.assertEqual(got, [("JH703", "minor")])

    def test_codex_keys_in_other_tables_are_quiet(self):
        self.assertEqual([f for f in self.found if f["path"] == "codex-other/.codex/config.toml"], [])
        self.assertEqual(jh_checks._toml_table('permissions."demo.network"').count("."), 1)
        for project in ("codex-app", "codex-array", "codex-bracket", "codex-string"):
            self.assertEqual([f for f in self.found if f["path"].startswith(project + "/")], [], project)
        after = self.got("JH709", "codex-after-string/.codex/config.toml")     # the string closed: a real setting
        self.assertEqual([s for s, _ in after], ["major"])

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
        self.assertEqual(self.got("JH703", "cursor-narrow/.cursor/cli.json"), [])

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
        for project in ("cursor-denied", "cursor-tool-denied"):
            self.assertEqual([f for f in self.found if f["rule"] == "JH714" and f["path"].startswith(project)], [],
                             project)


if __name__ == "__main__":
    unittest.main()
