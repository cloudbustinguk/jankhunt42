"""4.21.0: a pre-approved runner (awk, sed, make, an interpreter) is any command (JH703, JH712, the Cursor CLI and
the Rule of Two); an MCP server on the deprecated SSE transport (JH715). Invented projects and hosts only."""
import json
import os
import shutil
import tempfile
import unittest

from _util import run_cli
from test_diff import git
import jh_agent


def write(root, files):
    for rel, text in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text if isinstance(text, str) else json.dumps(text, indent=2) + "\n")


def settings(allow=(), deny=()):
    return {"permissions": {"allow": list(allow), "deny": list(deny)}}


def servers(**defs):
    return {"mcpServers": defs}


FETCH = {"command": "uvx", "args": ["mcp-server-fetch==2025.4.7"]}
PG = {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-postgres@0.6.2",
                                 "postgresql://app@crm-db.example.com/crm"]}

PROJECTS = {
    # JH703: runner grants in Claude Code settings
    "awk/.claude/settings.json": settings(["Read", "Bash(awk:*)"]),
    "make/.claude/settings.local.json": settings(["Bash(make:*)"]),
    "python/.claude/settings.json": settings(["Bash(python3 -c *)"]),
    "narrow/.claude/settings.json": settings(["Bash(ls:*)", "Bash(python3 scripts/report.py)", "Bash(make test)"]),
    "denied/.claude/settings.json": settings(["Bash(awk:*)"], deny=["Bash(awk:*)"]),
    "shelldeny/.claude/settings.json": settings(["Bash(node:*)"], deny=["Bash"]),
    "both/.claude/settings.json": settings(["Bash", "Bash(python:*)"]),
    # the Cursor CLI
    "cursor/.cursor/cli.json": {"permissions": {"allow": ["Shell(make:*)"]}},
    "cursorargs/.cursor/cli.json": {"permissions": {"allow": ["Shell(make:test)"]}},
    # JH715, and remote servers configured by URL alone
    "sse/.mcp.json": servers(events={"type": "sse", "url": "https://mcp.example.com/sse",
                                     "headers": {"Authorization": "Bearer ${MCP_TOKEN}"}}),
    "streamable/.mcp.json": servers(api={"type": "streamable-http", "url": "https://mcp.example.com/mcp",
                                         "headers": {"Authorization": "Bearer ${MCP_TOKEN}"}}),
    "noauth/.cursor/mcp.json": servers(docs={"url": "https://mcp.example.org/mcp"}),
    "tokenenv/.codex/config.toml": '[mcp_servers.docs]\nurl = "https://mcp.example.org/mcp"\n'
                                   'bearer_token_env_var = "DOCS_TOKEN"\n',
    "local/.mcp.json": servers(dev={"type": "http", "url": "http://localhost:8931/mcp"},
                               dev6={"type": "http", "url": "https://127.0.0.1:8932/mcp"}),
    "plain/.mcp.json": servers(old={"type": "http", "url": "http://mcp.example.net/mcp"}),
    "stdio/.mcp.json": servers(web=FETCH),
}


class RunnersAndTransport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tempfile.mkdtemp()
        write(cls.root, PROJECTS)
        p = run_cli("scan", cls.root, "--json", "--min-severity", "info", "--no-progress", "--category", "agent")
        assert p.returncode in (0, 1), p.stderr
        cls.found = {}
        for f in json.loads(p.stdout)["findings"]:
            cls.found.setdefault(f["path"].split("/")[0], []).append(f)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root)

    def rules(self, project, rule):
        return [f for f in self.found.get(project, []) if f["rule"] == rule]

    def test_broad_shell(self):
        for entry, want in (("Bash(awk:*)", "any command run through awk"),
                            ("Bash(sed -e *)", "any command run through sed"),
                            ("Bash(/usr/bin/make:*)", "any command run through make"),
                            ("Bash", "any shell command"), ("Bash(ls:*)", None), ("Bash(make test)", None),
                            ("Bash(python --version)", None), ("Bash(awkward:*)", None)):
            self.assertEqual(jh_agent.broad_shell(entry), want, entry)

    def test_claude_runner_grants(self):
        for project, runner in (("awk", "awk"), ("make", "make"), ("python", "python3")):
            got = self.rules(project, "JH703")
            self.assertEqual(len(got), 1, project)
            self.assertEqual(got[0]["severity"], "major")
            self.assertIn("Any command run through %s is pre-approved" % runner, got[0]["message"])
        for project in ("narrow", "denied", "shelldeny"):
            self.assertEqual(self.rules(project, "JH703"), [], project)
        # an unrestricted entry is reported once, not again for the runner beside it
        both = self.rules("both", "JH703")
        self.assertEqual(len(both), 1)
        self.assertIn("Unrestricted shell access", both[0]["message"])

    def test_cursor_runner_grants(self):
        got = self.rules("cursor", "JH703")
        self.assertEqual(len(got), 1)
        self.assertIn("any command run through make", got[0]["message"])
        self.assertEqual(self.rules("cursorargs", "JH703"), [])

    def test_sse_transport(self):
        got = self.rules("sse", "JH715")
        self.assertEqual([(f["severity"], f["extra"]["server"]) for f in got], [("minor", "events")])
        self.assertIn("2026-07-28", got[0]["message"])
        for project in ("streamable", "noauth", "local", "plain", "stdio"):
            self.assertEqual(self.rules(project, "JH715"), [], project)

    @unittest.skipUnless(shutil.which("git"), "git unavailable")
    def test_review_gates_the_transport_edit(self):
        with tempfile.TemporaryDirectory() as root:
            git(root, "init", "-q")
            definition = servers(paper={"type": "http", "url": "https://paper.invalid/events"})
            write(root, {".mcp.json": definition})
            git(root, "add", ".mcp.json")
            git(root, "commit", "-qm", "Initial transport")
            definition["mcpServers"]["paper"]["type"] = "sse"
            write(root, {".mcp.json": definition})
            args = [".", "--rule", "JH715", "--fail-on", "minor", "--json"]
            for command in ("scan", "review"):
                with self.subTest(command=command):
                    result = run_cli(command, *args, cwd=root)
                    report = json.loads(result.stdout)
                    self.assertEqual([(f["line"], f["evidence"]) for f in report["findings"]],
                                     [(4, "paper: transport sse")])
                    self.assertEqual(result.returncode, 1)
                    if command == "review":
                        self.assertEqual(report["review"]["gate"]["result"], "fail")
            git(root, "commit", "-qam", "Use SSE")
            definition["mcpServers"]["album"] = definition["mcpServers"].pop("paper")
            write(root, {".mcp.json": definition})
            result = run_cli("review", *args, cwd=root)
            report = json.loads(result.stdout)
            self.assertEqual((result.returncode, report["review"]["gate"]["result"]), (0, "pass"))
            self.assertEqual(report["findings"], [])
            self.assertEqual([f["line"] for f in report["review"]["contextual"]], [4])

    def test_transport_alias_and_implicit_url_locations(self):
        cases = [(".mcp.json", '"type": "",\n"transport":\n"http+sse",\n"url": "https://paper.invalid"', 5),
                 (".gemini/settings.json", '"headers": {},\n"url": "https://paper.invalid"', 4)]
        for path, properties, expected in cases:
            with self.subTest(path=path), tempfile.TemporaryDirectory() as root:
                write(root, {path: '{"mcpServers": {\n"paper": {\n' + properties + '}}}'})
                result = run_cli("scan", root, "--rule", "JH715", "--json")
                self.assertEqual([f["line"] for f in json.loads(result.stdout)["findings"]], [expected])

    def test_remote_server_by_url_alone_is_quiet(self):
        # Under the MCP authorization specification the client signs in (OAuth) when it connects, and public
        # documentation servers need no sign-in, so a remote https server configured by URL alone is the expected
        # form. An offline scan cannot tell it from an open server; a rule that tried fired on 231 of 3,769
        # corpus repositories, nearly all OAuth or public servers, and was not shipped.
        for project in ("noauth", "tokenenv", "streamable", "local", "stdio"):
            self.assertEqual(self.found.get(project, []), [], project)
        self.assertEqual([f["rule"] for f in self.found.get("plain", [])], ["JH707"])


class RunnerInTheRuleOfTwo(unittest.TestCase):
    """A pre-approved runner is a way to act [C] that runs without asking, like an unrestricted shell."""

    def verdict(self, allow, deny=()):
        root = tempfile.mkdtemp()
        try:
            write(root, {".mcp.json": servers(web=FETCH, db=PG), ".claude/settings.json": settings(allow, deny)})
            p = run_cli("scan", root, "--rule", "JH714", "--min-severity", "info", "--json")
            assert p.returncode in (0, 1), p.stderr
            return [(f["extra"]["verdict"], f["severity"]) for f in json.loads(p.stdout)["findings"]]
        finally:
            shutil.rmtree(root)

    def test_runner_is_unsupervised_action(self):
        self.assertEqual(self.verdict(["Read"]), [("K4", "minor")])
        self.assertEqual([v for v, _ in self.verdict(["Read", "Bash(python:*)"])], ["K3"])
        self.assertEqual(self.verdict(["Read", "Bash(python3 scripts/report.py)"]), [("K4", "minor")])
        self.assertEqual(self.verdict(["Read", "Bash(python:*)"], deny=["Bash"]), [("K4", "minor")])


if __name__ == "__main__":
    unittest.main()


class GeminiTransport(unittest.TestCase):
    def test_native_transport_keys_are_independent_of_url_path(self):
        for path in ("events", "sse"):
            url = "https://ledger.example.org/" + path
            for fields, expected in [({"url": url}, "sse"), ({"httpUrl": url}, "http"),
                                      ({"url": url, "httpUrl": url + "2"}, "http")]:
                doc = json.dumps(servers(relay=fields))
                server, = jh_agent.mcp_servers(".gemini/settings.json", doc)
                self.assertEqual((server.transport, server.url), (expected, fields.get("httpUrl", url)))
                control, = jh_agent.mcp_servers(".mcp.json", doc)
                self.assertEqual(control.transport, "http")
