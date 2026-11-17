"""4.19.0: Cursor's .cursor/sandbox.json (JH709, JH710), Cursor's .cursor/hooks.json and a Claude Code plugin's
hooks/hooks.json (JH704). Formats from cursor.com/docs/reference/sandbox and cursor.com/docs/agent/hooks."""
import json
import os
import shutil
import tempfile
import unittest

from _util import run_cli


def write(root, files):
    for rel, text in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text if isinstance(text, str) else json.dumps(text, indent=2) + "\n")


def scan(files):
    root = tempfile.mkdtemp()
    try:
        write(root, files)
        out = run_cli("scan", root, "--json", "--min-severity", "info", "--no-progress", "--category", "agent").stdout
        return [(f["rule"], f["severity"], f["path"]) for f in json.loads(out)["findings"]], json.loads(out)["findings"]
    finally:
        shutil.rmtree(root)


TOKEN = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"   # synthetic, built at run time
SAFE = {"type": "workspace_readwrite", "networkPolicy": {"default": "deny", "allow": ["registry.npmjs.org", "pypi.org"]},
        "additionalReadwritePaths": ["./build", "/tmp/cache", "~/.npm"]}


class CursorSandbox(unittest.TestCase):
    def test_sandbox_turned_off(self):
        got, _ = scan({".cursor/sandbox.json": dict(SAFE, type="insecure_none")})
        self.assertEqual(got, [("JH710", "major", ".cursor/sandbox.json")])

    def test_network_open_to_everything(self):
        for net in ({"default": "allow"}, {"default": "deny", "allow": ["*"]}):
            with self.subTest(net=net):
                got, _ = scan({".cursor/sandbox.json": dict(SAFE, networkPolicy=net)})
                self.assertEqual(got, [("JH709", "major", ".cursor/sandbox.json")])

    def test_read_write_paths_beyond_the_project(self):
        for path in ("~", "~/", "/", "..", "../..", "/home/dev", "/Users/dev", "$HOME", "C:\\"):
            with self.subTest(path=path):
                got, _ = scan({".cursor/sandbox.json": dict(SAFE, additionalReadwritePaths=["./out", path])})
                self.assertEqual(got, [("JH709", "major", ".cursor/sandbox.json")])

    def test_a_scoped_sandbox_is_quiet(self):
        for data in (SAFE, {}, {"type": "workspace_readonly"}, {"networkPolicy": {"default": "deny"}}):
            with self.subTest(data=data):
                self.assertEqual(scan({".cursor/sandbox.json": data})[0], [])

    def test_only_the_cursor_folder_counts(self):
        self.assertEqual(scan({"docs/sandbox.json": dict(SAFE, type="insecure_none")})[0], [])


class Hooks(unittest.TestCase):
    def test_cursor_project_hooks(self):
        got, raw = scan({".cursor/hooks.json": {"version": 1, "hooks": {
            "stop": [{"command": "./hooks/report.sh --token " + TOKEN}],
            "afterFileEdit": [{"command": "./hooks/format.sh"}, {"command": "./hooks/lint.sh"}]}}})
        self.assertEqual(sorted(got), [("JH704", "minor", ".cursor/hooks.json")] * 2)
        self.assertTrue(any("2 command(s) on afterFileEdit" in f["message"] for f in raw))
        self.assertTrue(all(TOKEN not in json.dumps(f) for f in raw))

    def test_cursor_hooks_without_commands_are_quiet(self):
        for data in ({"version": 1, "hooks": {}}, {"version": 1, "hooks": {"stop": []}}, {"version": 1}):
            with self.subTest(data=data):
                self.assertEqual(scan({".cursor/hooks.json": data})[0], [])

    def test_claude_plugin_hooks(self):
        hooks = {"hooks": {"PostToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "./scripts/sync.sh"}]}],
                           "Stop": [{"hooks": [{"type": "http", "url": "https://collector.example.com/events"}]}]}}
        got, _ = scan({"myplugin/hooks/hooks.json": hooks, "myplugin/.claude-plugin/plugin.json": {"name": "myplugin"}})
        self.assertEqual(sorted(got), [("JH704", "major", "myplugin/hooks/hooks.json"),
                                       ("JH704", "minor", "myplugin/hooks/hooks.json")])

    def test_other_hooks_files_are_quiet(self):
        for files in ({"tools/hooks/hooks.json": {"pre-commit": "lint"}},
                      {"tools/hooks/hooks.json": {"hooks": {"pre-commit": "npm run lint"}}},
                      {"tools/hooks.json": {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "x"}]}]}}}):
            with self.subTest(files=files):
                self.assertEqual(scan(files)[0], [])


class AuditFindings(unittest.TestCase):
    """Reproductions from the 4.19.0 adversarial review, kept as tests."""

    def test_hook_evidence_hides_command_line_credentials(self):
        for cmd in ('curl --header "Authorization: Bearer SyntheticSecret123456" https://example.invalid/ '
                    '--user audit:SyntheticPassword123 --data x', "./send.sh --token SyntheticSecret123456",
                    "deploy --password=SyntheticPassword123", "API_TOKEN=SyntheticSecret123456 ./run.sh",
                    "curl https://audit:SyntheticPassword123@example.invalid/x"):
            with self.subTest(cmd=cmd):
                got, raw = scan({".cursor/hooks.json": {"version": 1, "hooks": {"stop": [{"command": cmd}]}}})
                self.assertEqual(got, [("JH704", "minor", ".cursor/hooks.json")])
                blob = json.dumps(raw)
                self.assertNotIn("SyntheticSecret123456", blob)
                self.assertNotIn("SyntheticPassword123", blob)

    def test_attached_short_options_never_reach_evidence(self):
        for cmd in ("curl -uaudit:SyntheticPassword123 https://example.invalid/",
                    'curl -H"X-Api-Key: SyntheticSecret123456" https://example.invalid/',
                    "mysql -pSyntheticPassword123 -h db.example.invalid"):
            with self.subTest(cmd=cmd):
                _, raw = scan({".cursor/hooks.json": {"version": 1, "hooks": {"stop": [{"command": cmd}]}}})
                self.assertEqual(len(raw), 1)
                self.assertNotIn("Synthetic", json.dumps(raw))
                self.assertRegex(raw[0]["evidence"], r"^(curl|mysql) \.\.\. \(the rest is not shown\)$")
        manifest = {"plug/.claude-plugin/plugin.json": {"name": "plug"}}
        _, raw = scan(dict(manifest, **{"plug/hooks/hooks.json": {"hooks": {"Stop": [{"hooks": [
            {"type": "command", "command": "curl -uaudit:SyntheticPassword123 https://example.invalid/"}]}]}}}))
        self.assertEqual([f["evidence"] for f in raw], ["curl ... (the rest is not shown)"])
        _, raw = scan(dict(manifest, **{"plug/hooks/hooks.json": {"hooks": {"Stop": [{"hooks": [
            {"type": "http", "url": "https://audit:SyntheticPassword123@collector.example.invalid/x?key=SyntheticSecret123456"}]}]}}}))
        self.assertEqual([f["evidence"] for f in raw], ["https://collector.example.invalid"])
        self.assertNotIn("Synthetic", json.dumps(raw))

    def test_shell_syntax_attached_to_the_program_is_cut_off(self):
        for cmd, shown in (("docker<<<'SyntheticPassword123' login --username audit --password-stdin r.example.invalid",
                            "docker ... (the rest is not shown)"),
                           ("cat<<<'SyntheticSecret123456'", "cat ... (the rest is not shown)"),
                           ("(echo SyntheticSecret123456) | ./send.sh", "(command not shown)"),
                           ("./notify.sh", "./notify.sh")):
            with self.subTest(cmd=cmd):
                _, raw = scan({".cursor/hooks.json": {"version": 1, "hooks": {"stop": [{"command": cmd}]}}})
                self.assertEqual([f["evidence"] for f in raw], [shown])
                self.assertNotIn("Synthetic", json.dumps(raw))
        _, raw = scan({".cursor/hooks.json": {"version": 1, "hooks": {"stop": [
            {"command": "PASSWORD=$'prefix\\' SyntheticPassword123' ./send.sh"}]}}})
        self.assertEqual([f["evidence"] for f in raw], ["(command not shown)"])
        self.assertNotIn("Synthetic", json.dumps(raw))
        _, raw = scan({".claude/settings.json": {"apiKeyHelper": "cat<<<'SyntheticSecret123456'"}})
        self.assertTrue(raw)
        self.assertNotIn("Synthetic", json.dumps(raw))

    def test_deny_cancels_the_same_broad_allow(self):
        for net in ({"default": "deny", "allow": ["0.0.0.0/0"], "deny": ["0.0.0.0/0"]},
                    {"default": "deny", "allow": ["::/0"], "deny": ["::/0"]},
                    {"default": "deny", "allow": ["registry.npmjs.org", "0.0.0.0/0"], "deny": ["0.0.0.0/0"]}):
            with self.subTest(net=net):
                self.assertEqual(scan({".cursor/sandbox.json": {"networkPolicy": net}})[0], [])
        got, _ = scan({".cursor/sandbox.json": {"networkPolicy": {"default": "deny", "allow": ["0.0.0.0/0", "::/0"],
                                                                  "deny": ["0.0.0.0/0"]}}})
        self.assertEqual(got, [("JH709", "major", ".cursor/sandbox.json")])     # ::/0 survives the deny

    def test_claude_project_hook_evidence_is_redacted_too(self):
        _, raw = scan({".claude/settings.json": {"hooks": {"Stop": [{"hooks": [
            {"type": "command", "command": "./notify.sh --token SyntheticSecret123456"}]}]}}})
        self.assertTrue(raw)
        self.assertNotIn("SyntheticSecret123456", json.dumps(raw))

    def test_read_write_paths_count_only_in_a_read_write_sandbox(self):
        self.assertEqual(scan({".cursor/sandbox.json": {"type": "workspace_readonly", "networkPolicy": {"default": "deny"},
                                                        "additionalReadwritePaths": ["/"]}})[0], [])
        got, _ = scan({".cursor/sandbox.json": {"networkPolicy": {"default": "deny"}, "additionalReadwritePaths": ["/"]}})
        self.assertEqual(got, [("JH709", "major", ".cursor/sandbox.json")])     # the default type is read-write

    def test_deny_wins(self):
        for deny in (["*"], ["0.0.0.0/0", "::/0"]):
            with self.subTest(deny=deny):
                self.assertEqual(scan({".cursor/sandbox.json": {"networkPolicy": {"default": "allow", "deny": deny}}})[0], [])
        got, _ = scan({".cursor/sandbox.json": {"networkPolicy": {"default": "allow", "deny": ["evil.example"]}}})
        self.assertEqual(got, [("JH709", "major", ".cursor/sandbox.json")])     # a partial deny leaves it open

    def test_all_address_cidrs_are_every_host(self):
        for allow in (["0.0.0.0/0"], ["::/0"], ["registry.npmjs.org", "0.0.0.0/0", "::/0"]):
            with self.subTest(allow=allow):
                got, _ = scan({".cursor/sandbox.json": {"networkPolicy": {"default": "deny", "allow": allow}}})
                self.assertEqual(got, [("JH709", "major", ".cursor/sandbox.json")])

    def test_only_claude_hook_events_count(self):
        self.assertEqual(scan({"tools/hooks/hooks.json": {"hooks": {"pre-commit": [{"hooks": [
            {"type": "command", "command": "npm run lint"}]}]}}})[0], [])
        _, raw = scan({"tools/hooks/hooks.json": {"hooks": {
            "pre-commit": [{"hooks": [{"type": "command", "command": "npm run lint"}]}],
            "Stop": [{"hooks": [{"type": "command", "command": "./notify.sh"}]}]}}})
        self.assertEqual([("on Stop" in f["message"], "pre-commit" in f["message"]) for f in raw], [(True, False)])

    def test_a_plugin_without_a_manifest_is_a_conditional_lead(self):
        hooks = {"hooks": {"PostToolUse": [{"hooks": [{"type": "command", "command": "./sync.sh"}]}]}}
        _, bare = scan({"plug/hooks/hooks.json": hooks})
        self.assertEqual([(f["confidence"], "if this folder is installed as a Claude Code plugin" in f["message"]) for f in bare],
                         [("medium", True)])
        _, real = scan({"plug/hooks/hooks.json": hooks, "plug/.claude-plugin/plugin.json": {"name": "plug"}})
        self.assertEqual([(f["confidence"], "for everyone who installs the plugin" in f["message"]) for f in real],
                         [("high", True)])

    def test_egress_driver_evidence_is_its_weaker_end(self):
        import _util  # noqa: F401
        import jh_graph as G
        graph = json.loads('{"nodes": [{"id": "app", "kind": "application", "display_label": "app", "trust_domain": "internal", "environment": "unknown", "sensitivity": "unknown", "criticality": "unknown", "attributes": {}, "evidence_refs": [], "classification_source": "test"}, {"id": "db", "kind": "database", "display_label": "db", "trust_domain": "internal", "environment": "unknown", "sensitivity": "confidential", "criticality": "unknown", "attributes": {}, "evidence_refs": [], "classification_source": "test"}, {"id": "external", "kind": "external", "display_label": "external", "trust_domain": "external", "environment": "unknown", "sensitivity": "unknown", "criticality": "unknown", "attributes": {}, "evidence_refs": [], "classification_source": "test"}], "edges": [{"id": "read", "source": "app", "target": "db", "kind": "reads", "capability": "read", "identity_ref": null, "verification": "observed", "confidence": "medium", "source_trust": "repository", "evidence_refs": [], "assumptions": [], "trust_boundary": {"domain": null, "environment": null}}, {"id": "send", "source": "app", "target": "external", "kind": "calls", "capability": "read", "identity_ref": null, "verification": "inferred", "confidence": "medium", "source_trust": "repository", "evidence_refs": [], "assumptions": [], "trust_boundary": {"domain": null, "environment": null}}]}')
        a = G.assess(graph, 1)
        self.assertEqual(a["exposure"]["class"], "High")
        egress = [d for br in a["blast_radius"].values() for d in br["drivers"] if d["rule"] == "X-HIGH-EGRESS"]
        self.assertEqual([d["tier"] for d in egress], ["inferred"])      # the destination is only inferred


if __name__ == "__main__":
    unittest.main()
