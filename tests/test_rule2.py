"""JH714 and P-AGT-002 (4.16.0): the Agents Rule of Two. One agent configuration that grants untrusted input [A],
sensitive data [B] and a way to act [C], judged by whether the steps that act ask a person first. Invented projects,
hosts and tokens only."""
import json
import os
import shutil
import tempfile
import unittest

from _util import run_cli
import jh_agent
import jh_passport as P
import jh_policy
import jh_rule2 as R

FETCH = '"web": {"command": "uvx", "args": ["mcp-server-fetch"]}'
PG = '"db": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-postgres", ' \
     '"postgresql://app@crm-db.example.com/crm"]}'
GH = '"github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github@2025.4.8"%s], ' \
     '"env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_PAT}"}%s}'


def mcp(*servers, key="mcpServers"):
    return '{"%s": {\n  %s}}\n' % (key, ",\n  ".join(servers))


def settings(mode="acceptEdits", allow=(), deny=(), **extra):
    doc = {"permissions": {"defaultMode": mode, "allow": list(allow), "deny": list(deny)}}
    doc.update(extra)
    return json.dumps(doc, indent=1) + "\n"


def flow(tools, gate=(), trigger=("Chat", "@n8n/n8n-nodes-langchain.chatTrigger", {"public": True}), agent_off=False):
    """An n8n export: a trigger feeding an AI Agent; tools [(name, type, parameters)] plug into the agent, or into a
    Slack review node when their name is in gate."""
    nodes = [{"id": "t", "name": trigger[0], "type": trigger[1], "typeVersion": 1, "parameters": trigger[2],
              "position": [0, 0]},
             dict({"id": "a", "name": "Helpdesk agent", "type": "@n8n/n8n-nodes-langchain.agent", "typeVersion": 1.7,
                   "parameters": {}, "position": [200, 0]}, **({"disabled": True} if agent_off else {}))]
    conns = {trigger[0]: {"main": [[{"node": "Helpdesk agent", "type": "main", "index": 0}]]}}
    if gate:
        nodes.append({"id": "g", "name": "Review", "type": "n8n-nodes-base.slackHitlTool", "typeVersion": 1,
                      "parameters": {}, "position": [300, 200]})
        conns["Review"] = {"ai_tool": [[{"node": "Helpdesk agent", "type": "ai_tool", "index": 0}]]}
    for i, (name, typ, params) in enumerate(tools):
        nodes.append({"id": "n%d" % i, "name": name, "type": typ, "typeVersion": 2, "parameters": params,
                      "position": [400, 100 * i]})
        target = "Review" if name in gate else "Helpdesk agent"
        conns[name] = {"ai_tool": [[{"node": target, "type": "ai_tool", "index": 0}]]}
    return json.dumps({"name": "Helpdesk", "nodes": nodes, "connections": conns}, indent=1) + "\n"


SLACK = '"chat": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-slack"]}'
PGTOOL = ("Orders", "n8n-nodes-base.postgresTool", {"operation": "executeQuery"})
MAIL = ("Mail", "n8n-nodes-base.sendEmailTool", {})

PROJECTS = {
    # Claude Code: bypassPermissions; the fetch server is the first part that acts (line 2)
    "bypass/.mcp.json": mcp(FETCH, PG), "bypass/.claude/settings.json": settings("bypassPermissions"),
    # every acting step asks: no bypass, nothing pre-approved
    "asks/.mcp.json": mcp(FETCH, PG), "asks/.claude/settings.json": settings(allow=["Read"]),
    # WebFetch for one site is not a way out; the fetch server still asks
    "onesite/.mcp.json": mcp(FETCH, PG),
    "onesite/.claude/settings.json": settings(allow=["WebFetch(domain:docs.example.com)"]),
    # WebFetch for any address runs without asking
    "anysite/.mcp.json": mcp(PG), "anysite/.claude/settings.json": settings(allow=["WebFetch"]),
    # deny wins over bypass: the fetch server, WebFetch and the shell are all denied
    "denied/.mcp.json": mcp(FETCH, PG),
    "denied/.claude/settings.json": settings("bypassPermissions", deny=["mcp__web", "WebFetch", "Bash"]),
    # a project server switched off
    "switched/.mcp.json": mcp(FETCH, PG),
    "switched/.claude/settings.json": settings(allow=["mcp__web"], disabledMcpjsonServers=["web"]),
    # one GitHub server, one acting tool pre-approved: all three, possible rather than certain
    "github/.cursor/mcp.json": mcp(GH % ("", ', "alwaysAllow": ["create_issue"]')),
    # read-only GitHub: no way to act
    "readonly/.cursor/mcp.json": mcp(GH % (', "--read-only"', ', "alwaysAllow": ["*"]')),
    # only reading tools pre-approved: the acting ones still ask
    "readtools/.cursor/mcp.json": mcp(GH % ("", ', "alwaysAllow": ["get_issue", "list_pull_requests"]')),
    # VS Code: every tool call auto-approved
    "vscode/.vscode/mcp.json": mcp('"chat": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-slack"]}',
                                   key="servers"),
    "vscode/.vscode/settings.json": '{"chat.tools.autoApprove": true}\n',
    # a home-folder filesystem server and the fetch server, both pre-approved
    "home/.cursor/mcp.json": mcp('"files": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", '
                                 '"~"], "autoApprove": ["write_file"]}', FETCH),
    "project/.cursor/mcp.json": mcp('"files": {"command": "npx", "args": ["-y", '
                                    '"@modelcontextprotocol/server-filesystem", "./docs"], "autoApprove": ["write_file"]}',
                                    FETCH.replace("]}", '], "autoApprove": ["fetch"]}')),
    # every acting tool of the Slack server denied: no way to act left; one of them still allowed: K3
    "slackdeny/.mcp.json": mcp(SLACK, PG),
    "slackdeny/.claude/settings.json": settings("bypassPermissions", deny=["Bash", "WebFetch", "mcp__chat__slack_post_message",
                                                                        "mcp__chat__slack_reply_to_thread",
                                                                        "mcp__chat__slack_add_reaction"]),
    "slackpart/.mcp.json": mcp(SLACK, PG),
    "slackpart/.claude/settings.json": settings("bypassPermissions", deny=["Bash", "WebFetch",
                                                                        "mcp__chat__slack_post_message"]),
    # an unknown server counts for nothing
    "unknown/.cursor/mcp.json": mcp('"crm": {"command": "npx", "args": ["-y", "acme-crm-mcp@1.0.0"], '
                                    '"autoApprove": ["*"]}', FETCH),
    # n8n
    "n8n-open/workflow.json": flow([PGTOOL, MAIL]),
    "n8n-reviewed/workflow.json": flow([PGTOOL, MAIL], gate=("Orders", "Mail")),
    "n8n-half/workflow.json": flow([PGTOOL, MAIL], gate=("Orders",)),
    "n8n-schedule/workflow.json": flow([PGTOOL, MAIL], trigger=("Nightly", "n8n-nodes-base.scheduleTrigger", {})),
    "n8n-fixedurl/workflow.json": flow([PGTOOL, ("Status", "n8n-nodes-base.httpRequestTool",
                                                 {"url": "https://status.example.com/api", "method": "GET"})],
                                       trigger=("Nightly", "n8n-nodes-base.scheduleTrigger", {})),
    "n8n-anyurl/workflow.json": flow([("Lookup", "n8n-nodes-base.postgresTool", {"operation": "select"}),
                                      ("Web", "n8n-nodes-base.httpRequestTool",
                                       {"url": "={{ $fromAI('url') }}", "method": "GET"})],
                                     trigger=("Nightly", "n8n-nodes-base.scheduleTrigger", {})),
    "n8n-off/workflow.json": flow([PGTOOL, MAIL], agent_off=True),
    # a Slack tool left at its default operation (post a message) only acts; reading a channel brings the rest
    "n8n-post/workflow.json": flow([("Post", "n8n-nodes-base.slackTool", {"channel": "#tips"}),
                                    ("Wiki", "@n8n/n8n-nodes-langchain.toolWikipedia", {})]),
    "n8n-history/workflow.json": flow([("Post", "n8n-nodes-base.slackTool", {"channel": "#tips"}),
                                       ("History", "n8n-nodes-base.slackTool",
                                        {"resource": "channel", "operation": "history"})]),
}


def write(root, files):
    for rel, text in files.items():
        os.makedirs(os.path.join(root, os.path.dirname(rel)), exist_ok=True)
        with open(os.path.join(root, rel), "w") as fh:
            fh.write(text)


class Table(unittest.TestCase):
    def server(self, command="npx", args=(), env=None, url="", headers=None):
        return jh_agent.McpServer(name="s", line=1, transport="stdio", command=command, args=list(args),
                                  env=env or {}, url=url, headers=headers or {})

    def test_capabilities(self):
        cap = R.server_capability
        gh = cap(self.server(args=["-y", "@modelcontextprotocol/server-github"]))
        self.assertEqual((gh["A"], gh["B"], gh["C"]), (R.POSSIBLE, R.POSSIBLE, R.YES))
        for s in (self.server(args=["-y", "@modelcontextprotocol/server-github", "--read-only"]),
                  self.server(args=["@modelcontextprotocol/server-github"], env={"GITHUB_READ_ONLY": "1"}),
                  self.server(command="", url="https://api.githubcopilot.com/mcp/readonly"),
                  self.server(command="", url="https://api.githubcopilot.com/mcp/",
                              headers={"X-MCP-Readonly": "true"})):
            with self.subTest(s=s):
                self.assertEqual(cap(s)["C"], "")
        self.assertEqual(cap(self.server(command="", url="https://api.githubcopilot.com/mcp/"))["C"], R.YES)
        fetch = cap(self.server("uvx", ["mcp-server-fetch"]))
        self.assertEqual((fetch["A"], fetch["B"], fetch["C"]), (R.YES, "", R.YES))
        fs = lambda *d: cap(self.server(args=["-y", "@modelcontextprotocol/server-filesystem"] + list(d)))["B"]
        self.assertEqual([fs("./project"), fs("${workspaceFolder}"), fs("~"), fs("/home/dev"), fs("/srv/data"),
                          fs("./project", "/Users/dev/.ssh"), fs("/")],
                         ["", "", R.YES, R.YES, R.POSSIBLE, R.YES, R.YES])
        self.assertIsNone(cap(self.server(args=["-y", "acme-crm-mcp"])))
        self.assertEqual(cap(self.server(args=["-y", "@modelcontextprotocol/server-postgres"]))["C"], "")

    def test_acting_tools(self):
        self.assertEqual([R.acting_tool(n) for n in ("create_pull_request", "fetch", "postMessage", "mcp__x__push_files",
                                                     "get_issue", "query", "read_file", "list_repos", "search_code")],
                         [True] * 4 + [False] * 5)

    def test_approvals(self):
        # Claude Code: a bare name is a built-in tool (WebFetch), never an MCP tool
        self.assertIsNone(R._approved(["WebFetch", "Read"], "web", False))
        self.assertEqual(R._approved(["mcp__web"], "web", False), "all")
        self.assertEqual(R._approved(["mcp__web__*"], "web", False), "all")
        self.assertEqual(R._approved(["mcp__web__fetch"], "web", False), "fetch")
        self.assertIsNone(R._approved(["mcp__other__create_issue", "mcp__web__get"], "web", False))
        self.assertIsNone(R._approved(["*"], "web", False))
        # a client's per-server list: bare tool names
        self.assertEqual(R._approved(["read_file", "write_file"], "files", True), "write_file")
        self.assertIsNone(R._approved(["read_file"], "files", True))
        self.assertEqual(R._approved(["*"], "files", True), "all")

    def test_assess(self):
        part = lambda a, b, c, sup=True: {"source": "x", "A": a, "B": b, "C": c, "supervised": sup, "why": ""}
        self.assertEqual(R.assess([part(R.YES, "", "", False), part("", R.YES, R.YES)])["verdict"], "K4")
        v = R.assess([part(R.YES, "", ""), part("", R.YES, ""), part("", "", R.YES, False)])
        self.assertEqual((v["verdict"], v["certain"]), ("K3", True))
        v = R.assess([part(R.POSSIBLE, R.YES, R.YES, False)])
        self.assertEqual((v["verdict"], v["certain"]), ("K3", False))
        self.assertEqual(R.assess([part(R.YES, R.YES, "", False)])["verdict"], "none")
        self.assertEqual(R.assess([])["verdict"], "none")


class Scan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tempfile.mkdtemp()
        write(cls.root, PROJECTS)
        p = run_cli("scan", cls.root, "--rule", "JH714", "--min-severity", "info", "--json")
        assert p.returncode in (0, 1), p.stderr
        cls.found = {}
        for f in json.loads(p.stdout)["findings"]:
            cls.found.setdefault(f["path"].split("/")[0], []).append(f)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root)

    def verdict(self, project):
        fs = self.found.get(project, [])
        return [(f["extra"]["verdict"], f["severity"], f["line"]) for f in fs]

    @staticmethod
    def agent_line(project):
        """The line of the AI Agent node in an n8n fixture."""
        text = PROJECTS[project + "/workflow.json"]
        return text[:text.index('"id": "a"')].count("\n") + 1

    def test_verdicts(self):
        want = {"bypass": [("K3", "critical", 2)], "asks": [("K4", "minor", 2)], "onesite": [("K4", "minor", 2)],
                "anysite": [("K3", "critical", 1)], "denied": [], "switched": [],
                "github": [("K3", "major", 2)], "readonly": [], "readtools": [("K4", "info", 2)],
                "vscode": [("K3", "critical", 2)], "home": [("K3", "critical", 2)], "project": [],
                "unknown": [], "n8n-open": [("K3", "critical", "agent")], "n8n-reviewed": [("K4", "minor", "agent")],
                "n8n-half": [("K3", "critical", "agent")], "n8n-schedule": [], "n8n-fixedurl": [],
                # an address the model picks is untrusted input and a way out at once
                "n8n-anyurl": [("K3", "critical", "agent")], "n8n-off": [],
                "slackdeny": [], "slackpart": [("K3", "critical", 2)], "n8n-post": [],
                "n8n-history": [("K3", "critical", "agent")]}
        for project, expected in want.items():
            with self.subTest(project=project):
                expected = [(v, sev, self.agent_line(project) if line == "agent" else line) for v, sev, line in expected]
                self.assertEqual(self.verdict(project), expected)

    def test_messages(self):
        bypass = self.found["bypass"][0]
        self.assertIn("nothing approves its actions: Fetch server 'web' (permissions are bypassed)", bypass["message"])
        self.assertIn("Sensitive data: Claude Code shell, PostgreSQL server 'db'.", bypass["message"])
        self.assertEqual(bypass["extra"]["sensitive_data"], "Claude Code shell, PostgreSQL server 'db'")
        self.assertEqual(bypass["extra"]["unapproved"][0], "Fetch server 'web' (permissions are bypassed)")
        github = self.found["github"][0]
        self.assertIn("'create_issue' is pre-approved", github["message"])
        self.assertIn("Possible rather than certain: untrusted input and sensitive data", github["message"])
        self.assertFalse(github["extra"]["certain"])
        half = self.found["n8n-half"][0]
        self.assertIn("The n8n AI Agent 'Helpdesk agent'", half["message"])
        self.assertIn("Send Email tool 'Mail' (n8n runs an agent's tools without asking)", half["message"])
        self.assertNotIn("Postgres tool 'Orders' (", half["message"])        # behind the review node
        self.assertIn("every tool that acts asks a person first", self.found["asks"][0]["message"])
        self.assertIn("anysite", self.found)
        self.assertIn("Claude Code WebFetch (WebFetch is pre-approved for any address)",
                      self.found["anysite"][0]["message"])

    def test_settings_outside_the_project_are_ignored(self):
        root = tempfile.mkdtemp()
        try:
            write(root, {"outside/settings.json": settings("bypassPermissions"), "proj/.mcp.json": mcp(FETCH, PG)})
            os.makedirs(os.path.join(root, "proj", ".claude"))
            os.symlink(os.path.join(root, "outside", "settings.json"), os.path.join(root, "proj", ".claude",
                                                                                     "settings.json"))
            p = run_cli("scan", os.path.join(root, "proj"), "--rule", "JH714", "--json")
            self.assertEqual([f["extra"]["verdict"] for f in json.loads(p.stdout)["findings"]], ["K4"])
        finally:
            shutil.rmtree(root)


class Passport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tempfile.mkdtemp()
        write(cls.root, {k.split("/", 1)[1]: v for k, v in PROJECTS.items() if k.startswith("bypass/")})
        cls.asks = tempfile.mkdtemp()
        write(cls.asks, {k.split("/", 1)[1]: v for k, v in PROJECTS.items() if k.startswith("asks/")})
        cls.github = tempfile.mkdtemp()
        write(cls.github, {k.split("/", 1)[1]: v for k, v in PROJECTS.items() if k.startswith("readtools/")})

    @classmethod
    def tearDownClass(cls):
        for d in (cls.root, cls.asks, cls.github):
            shutil.rmtree(d)

    def passport(self, root, *args):
        p = run_cli("passport", root, "--json", *args)
        self.assertIn(p.returncode, (0, 1), p.stderr)
        doc = json.loads(p.stdout)
        return doc, {r["rule"]: r for r in doc["assessment"]["decision"]["rules"]}

    def test_k3(self):
        doc, rules = self.passport(self.root)
        self.assertEqual(rules["P-AGT-002"]["outcome"], "review")
        self.assertIn("1 agent(s) hold untrusted input, sensitive data and a way to act with nothing approving",
                      rules["P-AGT-002"]["message"])
        self.assertNotIn("JH714", rules["P-AGT-001"]["message"])                 # counted once, by P-AGT-002
        self.assertEqual([(r["verdict"], r["path"], r["line"]) for r in doc["agent_rule_of_two"]["rows"]],
                         [("K3", ".mcp.json", 2)])
        doc, rules = self.passport(self.root, "--profile", "citizen")
        self.assertEqual(rules["P-AGT-002"]["outcome"], "block")
        self.assertIn("reads text anyone can write, reaches private data", "\n".join(doc["governance"]["brief"]))

    def test_k4_is_review_at_most(self):
        _, rules = self.passport(self.asks, "--profile", "citizen")
        self.assertEqual(rules["P-AGT-002"]["outcome"], "review")
        self.assertIn("every acting step asks a person first", rules["P-AGT-002"]["message"])

    def test_uncertain_k4_is_information_only(self):
        doc, rules = self.passport(self.github, "--profile", "citizen")
        self.assertEqual(rules["P-AGT-002"]["outcome"], "pass")
        self.assertEqual(doc["agent_rule_of_two"]["count"], 0)

    def test_jh714_is_not_an_agent_guardrail_lead(self):
        from jh_core import Finding
        f = Finding(rule="JH714", title="t", severity="critical", category="agent", path=".mcp.json", line=2,
                    extra={"verdict": "K3", "certain": True, "agent": ".mcp.json"})
        self.assertEqual(P.governance_leads([f]), ([], []))
        self.assertEqual([r["verdict"] for r in P.rule_of_two_leads([f])], ["K3"])

    def test_html(self):
        p = run_cli("passport", self.root, "--html")
        self.assertIn('"agent_rule_of_two": {"count": 1', p.stdout)
        self.assertIn("R2=P.agent_rule_of_two", p.stdout)

    def test_policy(self):
        eff = jh_policy.merge(None, [], [], None)
        row = {"rule": "JH714", "path": ".mcp.json", "line": 2, "verdict": "K4", "certain": True, "agent": ".mcp.json"}
        for action, want in (("off", "pass"), ("review", "review"), ("block", "review"),
                             ("insufficient-evidence", "review")):
            with self.subTest(action=action):
                eff["actions"]["P-AGT-002"] = action
                rules = {r["rule"]: r for r in jh_policy.evaluate(eff, {"rule_of_two": [row]}, None)["rules"]}
                self.assertEqual(rules["P-AGT-002"]["outcome"], want)
        eff["actions"]["P-AGT-002"] = "block"
        rules = {r["rule"]: r for r in jh_policy.evaluate(eff, {"rule_of_two": [dict(row, verdict="K3")]}, None)["rules"]}
        self.assertEqual(rules["P-AGT-002"]["outcome"], "block")
        rules = {r["rule"]: r for r in jh_policy.evaluate(eff, {}, None)["rules"]}
        self.assertEqual(rules["P-AGT-002"]["outcome"], "pass")

    def test_plain_words_and_frameworks(self):
        self.assertIn("P-AGT-002", P._PLAIN)
        import jh_frameworks
        self.assertIn("P-AGT-002", jh_frameworks.RULES)
        self.assertEqual(jh_frameworks.owasp("JH714"), ["CD-SEC-04", "CD-SEC-07", "ASI01", "ASI02"])


if __name__ == "__main__":
    unittest.main()
