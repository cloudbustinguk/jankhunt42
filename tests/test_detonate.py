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


if __name__ == "__main__":
    unittest.main()
