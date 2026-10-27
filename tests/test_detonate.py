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
