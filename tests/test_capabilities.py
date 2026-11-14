"""Invented two-commit access changes; no downloaded repositories or inputs."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from _util import run_cli, node, edge
import jh_capabilities as C
import jh_graph as G
import jh_map
import jh_policy
import jh_views


@unittest.skipUnless(shutil.which("git"), "git is not installed")
class CapabilityChanges(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="jh-cap-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name, "fixture")
        self.root.mkdir()
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        self.env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        self.git("init", "-q", "--template=")
        self.write("app.py", "value = 1\n")

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.root)] + list(args), env=self.env,
                                       text=True, stderr=subprocess.PIPE).strip()

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def commit(self):
        self.git("add", "-A")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "commit", "-qm", "invented change", "--allow-empty")
        return self.git("rev-parse", "HEAD")

    def passport(self, base=None, *args):
        opts = ["--base", base] if base else []
        proc = run_cli("passport", str(self.root), "--json", *opts, *args)
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout[:1000])
        return json.loads(proc.stdout)

    def changes(self, text, name="app.py", *args):
        base = self.commit()
        self.write(name, text)
        self.commit()
        return self.passport(base, *args)

    def cap_rule(self, report):
        return next(r for r in report["assessment"]["decision"]["rules"] if r["rule"] == "P-CAP-001")

    def test_network_and_ceiling(self):
        host = ".".join(("endpoint", "invalid"))
        base = self.commit()
        self.write("app.py", 'import requests\nrequests.get("https://%s:8443/v1")\n' % host)
        head = self.commit()
        # A surrounding /tmp Git repository must not turn this operator file
        # into repository input. Keep it outside the fixture's ancestor tree.
        external = tempfile.TemporaryDirectory(prefix="jh-cap-operator-", dir=Path(__file__).resolve().parents[1])
        self.addCleanup(external.cleanup)
        ceiling = Path(external.name, "ceiling.json")
        ceiling.write_text(json.dumps(dict(schema="jankhunt.network-ceiling.v1", allow=[dict(host=host, port=8443)])))
        r = self.passport(base, "--sandbox-network-ceiling", str(ceiling))
        d = r["capability_delta"]
        self.assertEqual((d["base_sha"], d["head_sha"], d["state"]), (base, head, "complete"))
        n = next(row for row in d["requests"] if row["kind"] == "network")
        self.assertEqual(n["target"], dict(host=host, port=8443))
        self.assertEqual(n["ceiling"], "within")
        self.assertEqual(self.cap_rule(r)["outcome"], "review")
        ceiling.write_text(json.dumps(dict(schema="jankhunt.network-ceiling.v1", allow=[])))
        d2 = self.passport(base, "--sandbox-network-ceiling", str(ceiling))["capability_delta"]
        self.assertEqual(d2["requests"][0]["ceiling"], "outside")
        self.assertNotEqual(d["context_hash"], d2["context_hash"])

    def test_credential_names_only(self):
        text = 'import os\ncredential = os.environ["STORE_TOKEN"]\n'
        r = self.changes(text)
        rows = [x for x in r["capability_delta"]["requests"] if x["kind"] == "credential"]
        self.assertTrue(any(x["target"] == {"logical_name": "STORE_TOKEN"} for x in rows))
        self.assertTrue(all(x["action"] == "read" for x in rows))
        self.assertEqual(self.cap_rule(r)["outcome"], "review")

    def test_mutating_authority(self):
        for method, action in (("post", "write"), ("delete", "delete")):
            with self.subTest(action=action):
                host = ".".join((method, "invalid"))
                r = self.changes('import requests\nrequests.%s("https://%s/v1")\n' % (method, host))
                self.assertTrue(any(x["kind"] == "authority" and x["action"] == action
                                    for x in r["capability_delta"]["requests"]))

    def test_production_reclassification(self):
        host = ".".join(("stable", "invalid"))
        self.write("app.py", 'import requests\nrequests.get("https://%s/v1")\n' % host)
        base = self.commit()
        self.write(".jankhunt42.json", json.dumps(dict(passport=dict(assets=[dict(match=host, environment="production")]))))
        self.commit()
        d = self.passport(base)["capability_delta"]
        self.assertTrue(any(x["kind"] == "production" for x in d["requests"]), d)
        self.assertFalse(any(x["kind"] == "network" for x in d["requests"]))

    def test_agent_mcp_and_passed_credential(self):
        r = self.changes(json.dumps(dict(mcpServers=dict(helper=dict(command="invented-tool", env=dict(STORE_TOKEN="${STORE_TOKEN}"))))), ".mcp.json")
        rows = r["capability_delta"]["requests"]
        self.assertTrue(any(x["kind"] == "agent" and x["action"] == "start-mcp" for x in rows))
        self.assertTrue(any(x["kind"] == "credential" and x["action"] == "pass" for x in rows))

    def test_embedded_mcp_config_is_inventoried(self):
        r = self.changes(json.dumps(dict(mcpServers=dict(helper=dict(command="invented-tool")))), "custom.json")
        self.assertGreater(r["capability_delta"]["counts"]["agent"], 0)

    def test_agent_bypass_and_hooks_unsuppressible(self):
        base = self.commit()
        self.write(".jankhunt42.json", json.dumps(dict(ignore=[".claude/*", "run.sh"],
                   rules={"JH702": False, "JH704": False})))
        self.write("run.sh", "#!/bin/sh\nclaude --dangerously-skip-permissions # jankhunt42:ignore JH702\n")
        self.write(".claude/settings.json", json.dumps(dict(hooks=dict(SessionStart=[dict(hooks=[dict(type="command", command="invented-hook")])]))))
        self.commit()
        r = self.passport(base)
        controls = {x["target"].get("control") for x in r["capability_delta"]["requests"] if x["kind"] == "agent"}
        self.assertTrue({"JH702", "JH704"} <= controls, controls)
        self.assertGreater(r["capability_delta"]["counts"]["unknown"], 0)

    def test_move_is_not_new_access(self):
        self.write("app.py", 'import requests\nrequests.get("https://%s:8443/v1")\n' % ".".join(("stable", "invalid")))
        base = self.commit()
        self.root.joinpath("app.py").rename(self.root / "moved.py")
        self.commit()
        d = self.passport(base)["capability_delta"]
        self.assertEqual(d["counts"]["total"], 0, d)
        self.assertEqual(d["counts"]["unknown"], 0)

    def test_renamed_environment_binding_stays_uncertain(self):
        self.write("app.py", 'import os\nimport requests\nrequests.get(os.environ["FIRST_API_URL"])\n')
        base = self.commit()
        self.write("app.py", 'import os\nimport requests\nrequests.get(os.environ["SECOND_API_URL"])\n')
        self.commit()
        r = self.passport(base)
        self.assertGreater(r["capability_delta"]["counts"]["unknown"], 0)
        self.assertEqual(self.cap_rule(r)["outcome"], "review")

    def test_resolved_head_does_not_erase_unknown_base(self):
        self.write("app.py", 'import os\nimport requests\nrequests.get(os.environ["FIRST_API_URL"])\n')
        base = self.commit()
        self.write("app.py", 'import requests\nrequests.get("https://%s/v1")\n' % ".".join(("resolved", "invalid")))
        self.commit()
        d = self.passport(base)["capability_delta"]
        self.assertGreater(d["counts"]["unknown"], 0)

    def test_stronger_citizen_outcome_survives_capability_review(self):
        base = self.commit()
        self.write("run.sh", "#!/bin/sh\nclaude --dangerously-skip-permissions\n")
        self.commit()
        r = self.passport(base, "--profile", "citizen")
        self.assertEqual(self.cap_rule(r)["outcome"], "review")
        self.assertEqual(r["assessment"]["decision"]["result"], "block")

    def test_flood_cannot_hide_production_write(self):
        base = self.commit()
        host = ".".join(("important", "invalid"))
        self.write(".jankhunt42.json", json.dumps(dict(passport=dict(assets=[dict(match=host, environment="production")]))))
        text = "import requests\n" + "".join('requests.get("https://%s/v1")\n' % ".".join(("harmless%d" % i, "invalid")) for i in range(200))
        self.write("app.py", text + 'requests.post("https://%s/v1")\n' % host)
        self.commit()
        r = self.passport(base)
        d = r["capability_delta"]
        self.assertEqual((d["requests"][0]["kind"], d["requests"][0]["action"], d["requests"][0]["production"]), ("authority", "write", True))
        self.assertEqual(d["counts"]["network"], 201)
        self.assertGreater(d["truncation"]["omitted"], 0)
        self.assertEqual(d["state"], "complete")
        self.assertEqual(r["assessment"]["decision"]["result"], "review")
        self.assertEqual(self.cap_rule(r)["outcome"], "review")

    def test_dirty_head_snapshot_and_hashes(self):
        base = self.commit()
        self.write("app.py", 'import requests\nrequests.get("https://%s/v1")\n' % ".".join(("committed", "invalid")))
        self.commit()
        before = self.passport(base)
        self.write("app.py", "value = 99\n")
        self.write(".jankhunt42.json", json.dumps(dict(passport=dict(profile="citizen"))))
        self.write("package-lock.json", '{"resolved": "https://%s/pkg/-/pkg-1.tgz"}' % ".".join(("dirty", "invalid")))
        after = self.passport(base)
        self.assertEqual(before["capability_delta"], after["capability_delta"])
        self.assertEqual(after["governance"]["profile"], "standard")
        self.assertEqual(before["package_sources"], after["package_sources"])
        self.assertEqual(before["assessment"], after["assessment"])

    def test_incomplete_comparison_floor(self):
        base = self.commit()
        self.write("extra.py", "value = 2\n")
        self.commit()
        r = self.passport(base, "--max-files", "1")
        self.assertEqual(r["capability_delta"]["state"], "incomplete")
        self.assertEqual(r["assessment"]["decision"]["result"], "insufficient-evidence")

    def test_invalid_base_fails_closed(self):
        self.commit()
        proc = run_cli("passport", str(self.root), "--base", "does-not-exist", "--json")
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn('"state": "complete"', proc.stdout)

    def test_committed_lockfile_and_config_win_over_dirty_files(self):
        base = self.commit()
        self.write("package.json", '{"name":"invented-fixture","version":"1.0.0"}')
        host = ".".join(("committed-registry", "invalid"))
        self.write("package-lock.json", '{"resolved":"https://%s/pkg/-/pkg-1.0.0.tgz"}' % host)
        self.write(".jankhunt42.json", '{"passport":{"owners":["fixture-owner"]}}')
        self.commit()
        self.write("package-lock.json", '{}')
        self.write(".jankhunt42.json", '{}')
        r = self.passport(base)
        npm = r["package_sources"]["ecosystems"]["npm"]
        self.assertEqual(npm["state"], "observed")
        self.assertIn(host, json.dumps(npm))
        self.assertIn("fixture-owner", r["ownership"]["declared_owners"])

    def test_bad_config_or_mcp_is_incomplete(self):
        for name in (".jankhunt42.json", ".mcp.json"):
            with self.subTest(name=name):
                base = self.commit()
                self.write(name, '{bad')
                self.commit()
                r = self.passport(base)
                self.assertEqual(r["capability_delta"]["state"], "incomplete")
                self.assertEqual(r["assessment"]["decision"]["result"], "insufficient-evidence")
                self.root.joinpath(name).unlink()

    def test_mcp_values_never_enter_delta_or_value_hashes(self):
        first, second = "invented-credential-one", "invented-credential-two"
        self.write(".mcp.json", json.dumps(dict(mcpServers=dict(helper=dict(command="invented-tool", env=dict(STORE_TOKEN=first))))))
        base = self.commit()
        self.write(".mcp.json", json.dumps(dict(mcpServers=dict(helper=dict(command="invented-tool", env=dict(STORE_TOKEN=second))))))
        head = self.commit()
        r = self.passport(base)["capability_delta"]
        self.assertEqual(r["counts"]["total"], 0)
        text = json.dumps(r)
        self.assertNotIn(first, text)
        self.assertNotIn(second, text)
        # Same logical requests/uncertainties even though the values changed: the MCP server stays an
        # unchanged unknown and forces no review for this change.
        self.assertEqual(r["counts"]["unknown"], 0)
        self.assertGreater(r["counts"]["unchanged_unknown"], 0)

    def test_unchanged_unknowns_do_not_force_review(self):
        # an unresolved binding present at base and head is listed but needs no review for this change;
        # a newly unresolved one does
        self.write("app.py", "import os\nimport requests\nrequests.get(os.environ['SERVICE_URL'])\n")
        base = self.commit()
        self.write("README.md", "docs only\n")
        self.commit()
        r = self.passport(base)
        delta = r["capability_delta"]
        self.assertEqual((delta["counts"]["total"], delta["counts"]["unknown"]), (0, 0))
        self.assertGreater(delta["counts"]["unchanged_unknown"], 0)
        self.assertEqual(self.cap_rule(r)["outcome"], "pass")

    def opaque_case(self, kind, changed):
        """An agent definition whose identity stays the same while what it does may change (invented)."""
        def write(expanded):
            if kind == "hook":
                command = "invented-helper --access admin" if expanded else "printf ready"
                self.write(".claude/settings.json", json.dumps(dict(hooks=dict(SessionStart=[
                    dict(hooks=[dict(type="command", command=command)])]))))
            else:
                self.write(".mcp.json", json.dumps(dict(mcpServers=dict(helper=dict(
                    command="invented-helper", args=["--scope", "admin" if expanded else "read"])))))
        self.write("app.py", "value = 1\n")
        write(False)
        base = self.commit()
        write(changed)
        self.write("note.txt", "unrelated edit\n")
        self.commit()
        return self.passport(base)

    def test_a_changed_opaque_definition_needs_review(self):
        # the same hook or MCP server name with a different command or arguments is not "unchanged"
        for kind in ("hook", "mcp"):
            with self.subTest(kind=kind):
                r = self.opaque_case(kind, True)
                self.assertGreater(r["capability_delta"]["counts"]["unknown"], 0)
                self.assertEqual(self.cap_rule(r)["outcome"], "review")
                self.assertTrue(any(u.get("change") == "definition-changed" for u in r["capability_delta"]["unknowns"]))
                self.assertNotIn("--scope", json.dumps(r["capability_delta"]))

    def test_an_identical_opaque_definition_stays_unchanged(self):
        for kind in ("hook", "mcp"):
            with self.subTest(kind=kind):
                r = self.opaque_case(kind, False)
                self.assertEqual(r["capability_delta"]["counts"]["unknown"], 0)
                self.assertEqual(self.cap_rule(r)["outcome"], "pass")

    def definitions(self, report):
        return sorted((r["target"]["definition"], r["target"]["path"], r["definition_change"])
                      for r in report["capability_delta"]["requests"] if r["target"].get("definition"))

    def lock(self, base_files, head_files):
        """Commit base_files, then replace the tree with head_files (a missing file is deleted), and return the
        definition requests of passport --base."""
        def put(files):
            for p in list(self.root.rglob("*")):
                if p.is_file() and ".git" not in p.relative_to(self.root).parts:
                    p.unlink()
            for name, data in files.items():
                path = self.root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data if isinstance(data, bytes) else data.encode())
        put(base_files)
        base = self.commit()
        put(head_files)
        self.commit()
        r = self.passport(base)
        return self.definitions(r), r

    def test_agent_definitions_are_locked(self):
        """4.18.0: an added, edited or removed instruction file, skill file, command, subagent or agent settings
        file is a change IT approves; an untouched one is not, and test data is left out."""
        base = {"app.py": "value = 1\n", "AGENTS.md": "Run the tests before committing.\n",
                ".claude/skills/report/SKILL.md": "---\nname: report\ndescription: weekly report\n---\nRun it.\n",
                ".claude/skills/report/scripts/build.py": "print('report')\n",
                ".claude/agents/reviewer.md": "---\nname: reviewer\n---\nReview.\n",
                "tests/fixtures/demo/CLAUDE.md": "fixture\n"}
        head = dict(base, **{"AGENTS.md": "Run the tests before committing.\nAlso deploy when they pass.\n",
                              ".claude/skills/report/scripts/build.py": "print('report and upload')\n",
                              ".claude/commands/ship.md": "Ship it.\n",
                              "tests/fixtures/demo/CLAUDE.md": "fixture, edited\n"})
        del head[".claude/agents/reviewer.md"]
        got, r = self.lock(base, head)
        self.assertEqual(got, [("command", ".claude/commands/ship.md", "added"),
                               ("instructions", "AGENTS.md", "changed"),
                               ("skill file", ".claude/skills/report/scripts/build.py", "changed"),
                               ("subagent", ".claude/agents/reviewer.md", "removed")])
        self.assertEqual(self.cap_rule(r)["outcome"], "review")
        rows = [x for x in r["capability_delta"]["requests"] if x["target"].get("definition")]
        self.assertTrue(all(x["kind"] == "agent" and x["certainty"] == "supported" for x in rows))
        self.assertTrue(all(set(x["target"]) == {"definition", "path"} for x in rows))     # no content digest
        lines = C.approver_lines(r["capability_delta"])
        self.assertTrue(any("an agent definition was changed: instructions AGENTS.md." in l for l in lines), lines)

    def test_a_definition_change_can_be_approved(self):
        """Definitions are concrete requests, so a change to them alone is reviewable by an approval record."""
        import jh_capability_approval as A
        got, r = self.lock({"app.py": "value = 1\n", "AGENTS.md": "one\n"}, {"app.py": "value = 1\n", "AGENTS.md": "two\n"})
        delta = r["capability_delta"]
        self.assertEqual(delta["counts"]["total"], 1)
        self.assertEqual(A.unreviewable(delta), [])

    def test_exact_content_is_compared_and_never_shown(self):
        """Blockers 1 and 7: no redaction and no normalisation decide what changed (a value that looks like a
        secret can be a command; a trailing space inside a string can change behaviour), and nothing derived from
        the content appears in the report."""
        token = "ghp_" + "Ab3Cd4Ef5Gh6Ij7Kl8Mn9Op0Qr1St2Uv3Wx4"
        skill = {".claude/skills/r/SKILL.md": "---\nname: r\n---\nRun scripts/run.py.\n"}
        cases = {
            "secret-shaped value": ('import os\nsecret = "printenv"\nos.system(secret)\n',
                                    'import os\nsecret = "rm -rf ./output"\nos.system(secret)\n'),
            "token rotated": ('TOKEN = "%s"\n' % token, 'TOKEN = "%s"\n' % (token[:-4] + "Zz99")),
            "space in a string": ('status = """approved \n"""\n', 'status = """approved\n"""\n'),
            "leading indentation": ("    pass\n", "pass\n"),
        }
        for name, (old, new) in cases.items():
            with self.subTest(name):
                got, r = self.lock(dict(skill, **{".claude/skills/r/scripts/run.py": old}),
                                   dict(skill, **{".claude/skills/r/scripts/run.py": new}))
                self.assertEqual(got, [("skill file", ".claude/skills/r/scripts/run.py", "changed")])
                self.assertNotIn(token[:12], json.dumps(r))

    def test_root_skills_and_skipped_files_are_locked(self):
        """Blockers 2 and 3: a SKILL.md at the root makes every file beside it part of the skill, and files the
        scanner skips (build folders, binary files, a NUL byte) are compared from the Git tree."""
        root = {"SKILL.md": "---\nname: tool\n---\nRun scripts/run.py.\n", "scripts/run.py": "print('one')\n"}
        got, _ = self.lock(root, dict(root, **{"scripts/run.py": "print('two')\n"}))
        self.assertEqual(got, [("skill file", "scripts/run.py", "changed")])
        skill = {".claude/skills/r/SKILL.md": "---\nname: r\n---\nRun it.\n"}
        for name, old, new in ((".claude/skills/r/build/run.py", "print('one')\n", "print('two')\n"),
                               (".claude/skills/r/data.bin", b"hello\0one", b"hello\0two"),
                               (".claude/skills/r/run.js", '// \0 comment\nconsole.log("review");\n',
                                '// \0 comment\nconsole.log("deploy");\n')):
            with self.subTest(name):
                got, _ = self.lock(dict(skill, **{name: old}), dict(skill, **{name: new}))
                self.assertEqual(got, [("skill file", name, "changed")])

    def test_a_name_inside_an_agent_folder_is_not_test_data(self):
        """Blocker 4: only the folders above an agent definition can make it test data."""
        for name, kind in ((".claude/skills/test/SKILL.md", "skill"), (".claude/commands/test.md", "command"),
                           (".claude/commands/test/run.md", "command"), (".github/agents/tests/r.agent.md", "subagent"),
                           ("tests/AGENTS.md", None), ("tests/fixtures/x/.claude/skills/s/SKILL.md", None),
                           (".claude/skills/r/tests/fixture.py", None)):
            with self.subTest(name):
                base = {name: "---\nname: test\n---\nReview.\n", ".claude/skills/r/SKILL.md": "---\nname: r\n---\n"}
                got, _ = self.lock(base, dict(base, **{name: "---\nname: test\n---\nReview. Deploy afterward.\n"}))
                self.assertEqual(got, [(kind, name, "changed")] if kind else [])

    def test_more_agent_locations(self):
        """Blocker 5: locations agents document (Claude rules, Copilot agent profiles, OpenCode agents, commands
        and configuration, AGENTS.override.md)."""
        for name, kind in (("AGENTS.override.md", "instructions"), (".claude/rules/review.md", "instructions"),
                           (".github/agents/reviewer.agent.md", "subagent"), (".opencode/agents/reviewer.md", "subagent"),
                           (".opencode/commands/deploy.md", "command"), ("opencode.json", "agent settings"),
                           ("opencode.jsonc", "agent settings")):
            with self.subTest(name):
                got, _ = self.lock({name: "Review changes.\n"}, {name: "Deploy changes.\n"})
                self.assertEqual(got, [(kind, name, "changed")])

    def test_long_paths_keep_their_identity(self):
        """Blocker 6: the full path is the identity, not a display label cut at 300 characters."""
        prefix = "a" * 180 + "/" + "b" * 140
        base = {prefix + "/alpha/AGENTS.md": "Review only.\n", prefix + "/beta/AGENTS.md": "Deploy changes.\n"}
        head = {prefix + "/alpha/AGENTS.md": "Deploy changes.\n", prefix + "/beta/AGENTS.md": "Review only.\n"}
        got, r = self.lock(base, head)
        self.assertEqual(len(got), 2)
        ids = [x["id"] for x in r["capability_delta"]["requests"] if x["target"].get("definition")]
        self.assertEqual(len(set(ids)), 2)

    def test_unchanged_definitions_need_nothing(self):
        files = {"CLAUDE.md": "Keep it simple.\n", ".claude/settings.json": json.dumps(dict(permissions=dict(allow=["Read"])))}
        got, r = self.lock(dict(files, **{"app.py": "value = 1\n"}), dict(files, **{"app.py": "value = 2\n"}))
        self.assertEqual(got, [])
        self.assertEqual(self.cap_rule(r)["outcome"], "pass")

    def test_settings_and_skill_controls_are_in_the_comparison(self):
        got, r = self.lock({"app.py": "value = 1\n"}, {
            "app.py": "value = 1\n", ".claude/settings.json": json.dumps(dict(permissions=dict(allow=["Bash(curl:*)"]))),
            ".claude/skills/ops/SKILL.md": "---\nname: ops\nallowed-tools: Bash\n---\nOperate.\n"})
        self.assertEqual([d[:2] for d in got],
                         [("agent settings", ".claude/settings.json"), ("skill", ".claude/skills/ops/SKILL.md")])
        controls = {x["target"].get("control") for x in r["capability_delta"]["requests"] if x["kind"] == "agent"}
        self.assertIn("JH712", controls)

    def test_redaction_covers_unchanged_unknowns(self):
        label = "-".join(("invented", "opaque", "label"))
        self.write(".mcp.json", json.dumps(dict(mcpServers={label: dict(command="invented-tool")})))
        self.write("app.py", "value = 1\n")
        base = self.commit()
        self.write("app.py", "value = 2\n")
        self.commit()
        r = self.passport(base, "--redact")
        self.assertGreater(r["capability_delta"]["counts"]["unchanged_unknown"], 0)
        self.assertNotIn(label, json.dumps(r))

    def test_an_edit_anywhere_in_an_unmapped_file_needs_review(self):
        # a shell script is unresolved as a whole: changing line 11 must not pass as unchanged (invented)
        prefix = "".join("# setup step %d\n" % i for i in range(1, 11))
        for changed in (False, True):
            with self.subTest(changed=changed):
                self.tearDown()
                self.setUp()
                self.write("run.sh", prefix + "printf ready\n")
                base = self.commit()
                self.write("run.sh", prefix + ("invented-tool --upload out.tgz\n" if changed else "printf ready\n"))
                self.write("note.txt", "unrelated edit\n")
                self.commit()
                r = self.passport(base)
                self.assertEqual(self.cap_rule(r)["outcome"], "review" if changed else "pass")

    def test_scanned_subdirectory_uses_committed_ancestor_config(self):
        host = ".".join(("nested", "invalid"))
        self.write("sub/app.py", 'import requests\nrequests.get("https://%s/v1")\n' % host)
        base = self.commit()
        self.write(".jankhunt42.json", json.dumps(dict(passport=dict(assets=[dict(match=host, environment="production")]))))
        self.commit()
        proc = run_cli("passport", str(self.root / "sub"), "--base", base, "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(any(x["kind"] == "production" for x in json.loads(proc.stdout)["capability_delta"]["requests"]))

    def test_no_base_and_views(self):
        base = self.commit()
        r = self.passport()
        self.assertEqual(r["capability_delta"]["state"], "not-requested")
        self.assertNotIn("Access comparison:", jh_views.passport_tty(r, color=False))
        r = self.passport(base)
        tty = jh_views.passport_tty(r, color=False)
        self.assertIn("Access comparison: complete", tty)
        proc = run_cli("passport", str(self.root), "--base", base, "--md")
        self.assertIn("Access comparison: complete", proc.stdout)

    def test_credential_example_in_prose_is_not_a_read(self):
        r = self.changes('Example: os.environ["STORE_TOKEN"]\n', "README.md")
        self.assertEqual(r["capability_delta"]["counts"]["credential"], 0)

    def test_credential_example_in_docstring_is_not_a_read(self):
        r = self.changes('\'\'\'Example: os.environ["STORE_TOKEN"]\'\'\'\nvalue = 1\n')
        self.assertEqual(r["capability_delta"]["counts"]["credential"], 0)

    def test_uninspected_git_links_make_comparison_incomplete(self):
        base = self.commit()
        self.root.joinpath("linked.py").symlink_to("app.py")
        self.commit()
        r = self.passport(base)
        self.assertEqual(r["capability_delta"]["state"], "incomplete")

    def test_redaction_and_cli_guard(self):
        host = ".".join(("private-fixture", "invalid"))
        base = self.commit()
        self.write("app.py", 'import requests\nrequests.get("https://%s/v1")\n' % host)
        self.commit()
        r = self.passport(base, "--redact")
        self.assertNotIn(host, json.dumps(r))
        proc = run_cli("passport", str(self.root), "--base", base, "--emit-sandbox-policy", "codex")
        self.assertEqual(proc.returncode, 2)


class SemanticProjection(unittest.TestCase):
    def report(self, graph, sha):
        return dict(graph=graph, evidence=[], source_revision=sha, scope=dict(max_depth=4),
                    coverage=dict(partial_reasons=[], skipped={}), truncation=dict(reasons=[]))

    def test_actions_are_sets_and_dependency_is_not_authority(self):
        nodes = [node("app", "application"), node("id", "identity"), node("store", "database")]
        first = [edge("admin", "id", "store", "administers", "admin")]
        base = self.report(dict(nodes=nodes, edges=first), "base")
        head = self.report(dict(nodes=nodes, edges=first + [edge("del", "id", "store", "deletes", "delete"),
                                 edge("auth", "app", "id", "authenticates-as", "none")]), "head")
        d = C.compare(base, head, [], [], None, {})
        self.assertTrue(any(r["principal"] == "application" and r["action"] == "admin" for r in d["requests"]))
        self.assertTrue(any(r["action"] == "delete" for r in d["requests"]))
        head["graph"]["edges"][-1] = edge("dep", "app", "id", "depends-on", "none")
        d = C.compare(base, head, [], [], None, {})
        self.assertFalse(any(r["principal"] == "application" and r["kind"] == "authority" for r in d["requests"]))

    def test_unknown_port_never_within_ceiling(self):
        graph = dict(nodes=[node("app", "application"), node("external", "external", trust_domain="external",
                         attributes=dict(host="opaque", engine="unknown"))], edges=[edge("c", "app", "external")])
        empty = self.report(dict(nodes=graph["nodes"][:1], edges=[]), "base")
        d = C.compare(empty, self.report(graph, "head"), [], [], {("opaque", 443)}, {})
        self.assertEqual(d["requests"][0]["ceiling"], "unknown")
        self.assertIsNone(d["requests"][0]["target"]["port"])
        self.assertGreater(d["counts"]["unknown"], 0)

    def test_read_path_cannot_inherit_mutation(self):
        nodes = [node("app", "application"), node("middle", "database"), node("store", "database")]
        edges = [edge("read", "app", "middle", "reads", "read"), edge("write", "middle", "store", "writes", "write")]
        r = C.inventory(self.report(dict(nodes=nodes, edges=edges), "head"), [])[0]
        self.assertFalse(any(row["kind"] == "authority" and row["principal"] == "application" for row in r.values()))

    def test_scope_sets_and_distinct_engine_only_resources(self):
        app = node("app", "application")
        store = node("store", "database", attributes=dict(engine="postgresql", host="fixture", databases=["one"]))
        nodes = [app, store]
        edges = [edge("w", "app", "store", "writes", "write")]
        base = self.report(dict(nodes=nodes, edges=edges), "base")
        expanded = dict(store, attributes=dict(store["attributes"], databases=["one", "two"]))
        head = self.report(dict(nodes=[app, expanded], edges=edges), "head")
        d = C.compare(base, head, [], [], None, {})
        self.assertEqual(d["counts"]["authority"], 1)
        self.assertEqual(d["requests"][0]["target"]["resource_scope"], {"databases": "two"})
        d = C.compare(head, base, [], [], None, {})
        self.assertEqual(d["counts"]["total"], 0)
        cloud1 = node("first", "storage", attributes=dict(engine="cloud"))
        cloud2 = node("second", "storage", attributes=dict(engine="cloud"))
        self.assertNotEqual(C._target(cloud1), C._target(cloud2))

    def test_stronger_evidence_is_not_new_authority(self):
        nodes = [node("app", "application"), node("store", "database")]
        base = self.report(dict(nodes=nodes, edges=[edge("old", "app", "store", "writes", "write", "declared")]), "base")
        head = self.report(dict(nodes=nodes, edges=[edge("new", "app", "store", "writes", "write", "observed")]), "head")
        self.assertEqual(C.compare(base, head, [], [], None, {})["counts"]["total"], 0)

    def test_extraction_limit_and_policy_before_display(self):
        graph = dict(nodes=[node("app", "application"), node("store", "database",
                     attributes=dict(engine="postgresql", host="fixture", port=5432))],
                     edges=[edge("w", "app", "store", "writes", "write")])
        base = self.report(dict(nodes=graph["nodes"][:1], edges=[]), "base")
        with patch.object(C, "DISPLAY_LIMIT", 0):
            delta = C.compare(base, self.report(graph, "head"), [], [], None, {})
        self.assertFalse(delta["requests"])
        self.assertEqual(delta["counts"]["total"], 1)
        self.assertEqual(delta["counts"]["unknown"], 0)
        facts = dict(files_scanned=1, map_files_inspected=1, capability_delta=delta)
        policy = jh_policy.merge(None, [], [])
        policy["actions"]["P-CAP-001"] = "off"
        result = jh_policy.evaluate(policy, facts, graph)
        self.assertEqual(next(r["outcome"] for r in result["rules"] if r["rule"] == "P-CAP-001"), "review")
        with patch.object(C, "MAX_REQUESTS", 0):
            delta = C.compare(base, self.report(graph, "head"), [], [], None, {})
        self.assertEqual(delta["state"], "incomplete")
        self.assertTrue(delta["counts"]["lower_bound"])

    def test_approver_markdown_escapes_labels(self):
        self.assertNotIn("<script>", C.markdown_line("<script>[link](fake)</script>"))
        self.assertIn("\\[link\\]", C.markdown_line("<script>[link](fake)</script>"))
