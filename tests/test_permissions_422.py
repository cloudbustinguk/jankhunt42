"""Effective grants in invented, scan-local agent configurations."""
import json
import unittest

import _util
import jh_agent
import jh_rule2
from jh_core import source_from_text
from jh_rules import scan_sources, ScanOptions
from test_runners_and_mcp_transport import FETCH, PG


def scan(files, *rules):
    sources = [source_from_text(p, "/fixture/" + p, t if isinstance(t, str) else json.dumps(t, indent=2))
               for p, t in files.items()]
    return scan_sources(sources, ScanOptions(rule_ids=set(rules))).findings


class RunnerRecognition(unittest.TestCase):
    def test_shared_runner_recognition(self):
        for prefix, why in [
            ('"/opt/coral kit/PYTHON3.13" -c', 'any command run through python3.13'),
            ('env REGION=bay ruby3.2 -e', 'any command run through ruby3.2'),
            ('REGION=bay node -e', 'any command run through node'),
            ('npm exec', 'package binaries'), ('pnpm dlx', 'package binaries'),
            ('pipx run', 'package binaries'), ('yarn run', "project's own scripts"),
        ]:
            entry = 'Bash(' + prefix + ':*  ) '
            with self.subTest(prefix=prefix):
                self.assertIn(why, jh_agent.broad_shell(entry))
                docs = {'.claude/settings.json': {'permissions': {'allow': [entry]}},
                        'skills/relay/SKILL.md': '---\nallowed-tools: ' + entry + '\n---\n'}
                got = scan(docs, "JH703", "JH712")
                self.assertEqual({f.rule for f in got}, {"JH703", "JH712"})
                for f in got:
                    self.assertIn(why.lower(), f.message.lower())
                parts = jh_rule2.mcp_agent('.mcp.json', json.dumps({'mcpServers': {'web': FETCH, 'db': PG}}),
                                           read=lambda p: json.dumps(docs[p]) if p in docs else None)
                self.assertEqual(parts['verdict'], 'K3')
        for cmd in ('python3 -e', 'ruby -c', 'make -c', 'python ledger.py', 'npm run ledger'):
            self.assertIsNone(jh_agent.broad_shell('Bash(' + cmd + ':*)'), cmd)
        hit, = scan({'.cursor/cli.json': {'permissions': {'allow': ['Shell(Python3.12)']}}}, 'JH703')
        self.assertIn('python3.12', hit.message)


class EffectiveGrants(unittest.TestCase):
    def test_scope_precedence_and_word_boundaries(self):
        for allow, other, key, effective in [
            ("Bash(python:*)", "Bash(python *)", "deny", False),
            ("Bash(python -c *)", " Bash(python:*) ", "deny", False),
            ("Bash(python3:*)", "Bash(python*)", "deny", False),
            ("Bash(python3:*)", "Bash(python:*)", "deny", True),
            ("Bash(python:*)", "Bash(python --version)", "ask", True),
            ("Bash", "Bash(*)", "deny", False),
            ("Bash(make:*)", "Bash", "ask", False),
            ("Bash(make:*)", "*", "deny", False),
        ]:
            with self.subTest(allow=allow, other=other):
                doc = {"permissions": {"allow": [allow], key: [other]}}
                got = scan({".claude/settings.json": doc}, "JH703")
                self.assertEqual(bool(got), effective)
                agent = jh_rule2.mcp_agent(".mcp.json", json.dumps({"mcpServers": {"web": FETCH, "db": PG}}),
                                           read=lambda p: json.dumps(doc) if p.endswith("/settings.json") else None)
                self.assertEqual((agent or {}).get("verdict"), "K3" if effective else None if other == "*" else "K4")
        docs = {".cursor/cli.json": {"permissions": {"allow": ["Shell(make:*)"], "deny": ["Shell(ma*)"]}}}
        self.assertEqual(scan(docs, "JH703"), [])
        settings = jh_agent.claude_scopes([(".claude/settings.json", '{"permissions":{"deny":["Bash"],"ask":["*"]}}')])
        self.assertEqual(jh_agent.settings_for(".mcp.json", settings).decision(jh_agent.permission("Bash")), "deny")

    def test_cross_file_grants_and_scope_isolation(self):
        grant = {"permissions": {"allow": ["Bash(make:*)"]}}
        files = {"harbor/.claude/settings.json": grant, "ridge/.claude/settings.json": grant,
                 "harbor/.claude/settings.local.json": {"permissions": {"deny": ["Bash(*)"]}},
                 "harbor/.mcp.json": {"mcpServers": {"web": FETCH, "db": PG}},
                 "ridge/.mcp.json": {"mcpServers": {"web": FETCH, "db": PG}}}
        hits = scan(files, "JH703", "JH714")
        self.assertEqual([f.path for f in hits if f.rule == "JH703"], ["ridge/.claude/settings.json"])
        self.assertEqual({f.path: f.extra["verdict"] for f in hits if f.rule == "JH714"},
                         {"harbor/.mcp.json": "K4", "ridge/.mcp.json": "K3"})

    def test_skill_respects_only_covering_project_restrictions(self):
        for path in ("quay/.claude/skills/board/SKILL.md", "quay/.claude/commands/board.md", "quay/skills/board/SKILL.md"):
            files = {path: '---\nallowed-tools: Bash(make:*)\n---\n',
                     'quay/.claude/settings.local.json': {'permissions': {'deny': ['Bash']}}}
            self.assertEqual(scan(files, "JH712"), [])
            files['quay/.claude/settings.local.json']['permissions']['deny'] = ['Bash(make preview)']
            hit, = scan(files, "JH712")
            self.assertEqual((hit.path, hit.line), (path, 2))

    def test_bypass_never_dilutes_explicit_grant(self):
        for mode in ("default", "bypassPermissions"):
            files = {".mcp.json": {"mcpServers": {"web": FETCH, "db": PG}},
                     ".claude/settings.json": {"permissions": {"defaultMode": mode, "allow": ["Bash(make:*)"]}}}
            f, = scan(files, "JH714")
            self.assertEqual((f.extra["verdict"], f.severity, f.confidence), ("K3", "critical", "high"))
            self.assertTrue(any("through make" in why for why in f.extra["unapproved"]))
            self.assertNotIn("Only bypassPermissions", f.message)

    def test_user_and_managed_pairs_in_scan_and_snapshot(self):
        import jh_map
        grant = {"permissions": {"allow": ["Bash(make:*)"]}}
        for config, setting in (("home/.claude.json", "home/.claude/settings.json"),
                                ("etc/coral/managed-mcp.json", "etc/coral/managed-settings.json"),
                                ("etc/coral/managed-mcp.json", "etc/coral/managed-settings.d/tools.json")):
            docs = {config: {"mcpServers": {"web": FETCH, "db": PG}}, setting: grant}
            f, = scan(docs, "JH714")
            self.assertEqual((f.path, f.extra["verdict"]), (config, "K3"))
            items = [jh_map.Item(p, json.dumps(value)) for p, value in docs.items()]
            graph, _, _ = jh_map.build_graph(items, "coral", "fixture")
            verdicts = [n["attributes"]["rule_of_two"]["verdict"] for n in graph.nodes.values()
                        if "rule_of_two" in n["attributes"]]
            self.assertEqual(verdicts, ["K3"])

    def test_each_grant_retains_its_declaration(self):
        path = "pier/.claude/settings.local.json"
        doc = '''{
  "note": "Bash(make:*)",
  "permissions": {
    "allow": [
      "Bash(make:*)",
      "Bash(node:*)",
      "WebFetch",
      "mcp__db"
    ]
  }
}'''
        files = {path: doc, "pier/.claude/settings.json": {"permissions": {"allow": True}},
                 "pier/.mcp.json": {"mcpServers": {"web": FETCH, "db": PG}}}
        hits = scan(files, "JH703", "JH714")
        self.assertEqual([(f.path, f.line) for f in hits if f.rule == "JH703"], [(path, 5), (path, 6)])
        verdict, = [f for f in hits if f.rule == "JH714"]
        self.assertEqual({(g["file"], g["line"]) for g in verdict.extra["grants"]}, {(path, n) for n in range(5, 9)})
        self.assertIn("permissions.allow", verdict.extra["coverage_gaps"][0])
        hit, = scan({".cursor/cli.json": doc.replace("Bash(make:*)", "Shell(make:*)")}, "JH703")
        self.assertEqual(hit.line, 5)


class NestedClaudeProjects(unittest.TestCase):
    def test_local_names_and_capabilities_stay_in_their_project(self):
        import jh_map
        doc = {"projects": {
            "/invented/pier": {"mcpServers": {"relay": FETCH}},
            "/invented/cove": {"mcpServers": {"relay": PG}},
            "/invented/bay": {"mcpServers": {"relay": {"type": "sse", "url": "https://bay.example.org/events"}}}}}
        text = json.dumps(doc, indent=2)
        servers = jh_agent.mcp_servers(".claude.json", text)
        self.assertEqual([s.project for s in servers], list(doc["projects"]))
        self.assertEqual([s.line for s in servers], [i for i, l in enumerate(text.splitlines(), 1) if '"relay":' in l])
        hit, = scan({".claude.json": text}, "JH714", "JH715")
        self.assertEqual((hit.rule, hit.extra["project"], hit.line), ("JH715", "/invented/bay", servers[-1].line))
        graph, _, _ = jh_map.build_graph([jh_map.Item(".claude.json", text)], "pier", "fixture")
        agents = [n["attributes"] for n in graph.nodes.values() if n["attributes"].get("platform") == "ai-agent"]
        self.assertEqual({a["project"] for a in agents}, set(doc["projects"]))
        self.assertFalse(any("rule_of_two" in a for a in agents))


class UnanchoredAllowGlobs(unittest.TestCase):
    """Claude Code skips an unanchored allow glob ("*", "B*", "mcp__*"); a glob counts only after mcp__<server>__."""

    def test_unanchored_allow_globs_approve_nothing(self):
        for entry in ("*", "B*", "mcp__*", "Bas*"):
            with self.subTest(entry=entry):
                docs = {'.claude/settings.json': {'permissions': {'allow': [entry]}}}
                self.assertEqual(scan(docs, "JH703"), [])
                parts = jh_rule2.mcp_agent('.mcp.json', json.dumps({'mcpServers': {'web': FETCH, 'db': PG}}),
                                           read=lambda p: json.dumps(docs[p]) if p in docs else None)
                self.assertNotEqual(parts['verdict'], 'K3')

    def test_an_anchored_mcp_glob_still_approves_and_bypass_still_counts(self):
        anchored = {'.claude/settings.json': {'permissions': {'allow': ['mcp__web__*', 'mcp__db__*', 'WebFetch']}}}
        parts = jh_rule2.mcp_agent('.mcp.json', json.dumps({'mcpServers': {'web': FETCH, 'db': PG}}),
                                   read=lambda p: json.dumps(anchored[p]) if p in anchored else None)
        self.assertEqual(parts['verdict'], 'K3')
        bypass = {'.claude/settings.json': {'permissions': {'defaultMode': 'bypassPermissions'}}}
        self.assertEqual({f.rule for f in scan(bypass, "JH703")}, {"JH703"})

