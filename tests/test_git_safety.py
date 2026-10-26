"""Static commands must never run code that a repository's own Git config, attributes or hooks name.

One synthetic repository combines seven execution paths. A live control first shows that plain Git
does run each of them; then every static jankhunt42 command runs against the repository, and no
marker may appear (the adversarial review of 2026-10-26, finding A1).
"""
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

from _util import run_cli

HOOK = """#!{py}
import os, sys
open(os.path.join({markers!r}, {name!r}), "a").write("ran\\n")
if {name!r} in ("clean", "clean-eq"):
    sys.stdout.write(sys.stdin.read())
elif {name!r} == "textconv":
    sys.stdout.write(open(sys.argv[-1]).read())
elif {name!r} == "fsmonitor":
    sys.stdout.write("token\\0")
elif {name!r} == "gpg":
    sys.exit(1)
"""

MECHANISMS = ("fsmonitor", "textconv", "clean", "clean-eq", "post-index-change", "gpg", "external-diff")


@unittest.skipIf(shutil.which("git") is None, "git is not installed")
class HostileGitConfig(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="jh-gitsafety-")
        cls.repo = os.path.join(cls.tmp, "repo")
        cls.markers = os.path.join(cls.tmp, "markers")
        os.makedirs(cls.repo)
        os.makedirs(cls.markers)
        cls.env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        cls.env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        hooks = {}
        for name in MECHANISMS:
            path = os.path.join(cls.tmp, "hook-%s.py" % name)
            with open(path, "w") as fh:
                fh.write(HOOK.format(py=sys.executable, markers=cls.markers, name=name))
            os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
            hooks[name] = path
        cls.hooks = hooks
        git = cls.git
        git("init", "-q", "--template=")
        cls.write("app.py", "value = 1\n")
        cls.write("cfg.txt", "a = 1\n")
        cls.write(".gitattributes", "app.py diff=evil filter=evil\ncfg.txt filter=a=b\n")
        git("add", "-A")
        git("-c", "user.name=Synthetic", "-c", "user.email=s@example.invalid", "commit", "-qm", "base")
        # a commit carrying a (fake) signature, so log.showSignature calls gpg.program
        tree = git("rev-parse", "HEAD^{tree}").strip()
        parent = git("rev-parse", "HEAD").strip()
        body = ("tree %s\nparent %s\nauthor S <s@example.invalid> 1700000000 +0000\n"
                "committer S <s@example.invalid> 1700000000 +0000\n"
                "gpgsig -----BEGIN PGP SIGNATURE-----\n \n iQEzBAABCAAdFiEEsynthetic\n"
                " -----END PGP SIGNATURE-----\n\nsigned\n" % (tree, parent))
        signed = git("hash-object", "-t", "commit", "-w", "--stdin", input_text=body).strip()
        git("update-ref", "HEAD", signed)
        # the repository's own (hostile) configuration and hooks
        git("config", "core.fsmonitor", hooks["fsmonitor"])
        git("config", "diff.evil.textconv", hooks["textconv"])
        git("config", "filter.evil.clean", hooks["clean"])
        git("config", "filter.a=b.clean", hooks["clean-eq"])
        git("config", "log.showSignature", "true")
        git("config", "gpg.program", hooks["gpg"])
        os.makedirs(os.path.join(cls.repo, ".git", "hooks"), exist_ok=True)
        shutil.copy(hooks["post-index-change"], os.path.join(cls.repo, ".git", "hooks", "post-index-change"))
        os.chmod(os.path.join(cls.repo, ".git", "hooks", "post-index-change"), 0o755)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def git(cls, *args, input_text=None, env=None):
        proc = subprocess.run(["git", "-C", cls.repo] + list(args), capture_output=True, text=True,
                              input=input_text, env=env or cls.env, timeout=30)
        if proc.returncode not in (0, 1):
            raise RuntimeError("git %s: %s" % (args[0], proc.stderr))
        return proc.stdout

    @classmethod
    def write(cls, rel, text):
        with open(os.path.join(cls.repo, rel), "w") as fh:
            fh.write(text)

    def fired(self):
        return sorted(os.listdir(self.markers))

    def clear(self):
        for name in os.listdir(self.markers):
            os.remove(os.path.join(self.markers, name))

    def dirty(self):
        """Edit the worktree and age the index entries, so status must refresh (and may write) the index."""
        self.write("app.py", "value = %d\n" % (len(os.listdir(self.tmp)) + 2))
        self.write("cfg.txt", "a = 2\n")
        for rel in ("app.py", "cfg.txt"):
            os.utime(os.path.join(self.repo, rel), (1, 1))

    def test_1_controls_plain_git_runs_every_mechanism(self):
        """Without hardening, each path really runs: otherwise the test below would pass vacuously."""
        self.clear()
        self.dirty()
        self.git("status", "--porcelain")
        self.git("diff")
        self.git("log", "-1")
        env = dict(self.env, GIT_EXTERNAL_DIFF=self.hooks["external-diff"])
        self.git("diff", env=env)
        self.assertEqual(self.fired(), sorted(MECHANISMS))

    def test_3_a_required_filter_does_not_break_review(self):
        """git-lfs marks its filter required; a blanked required filter must not make git fail."""
        self.git("config", "filter.req.clean", self.hooks["clean"])
        self.git("config", "filter.req.required", "true")
        with open(os.path.join(self.repo, ".gitattributes"), "a") as fh:
            fh.write("big.bin filter=req\n")
        self.write("big.bin", "x\n")
        self.clear()
        proc = run_cli("review", self.repo, "--json")
        self.assertEqual(proc.returncode in (0, 1), True, proc.stderr[-300:])
        self.assertNotIn("filter", proc.stderr)
        self.assertEqual(self.fired(), [])

    def test_4_the_callers_own_git_settings_are_kept(self):
        import jh_core
        old = dict(os.environ)
        try:
            os.environ.update(GIT_INDEX_FILE="/tmp/x-index", GIT_DIR="/tmp/x.git", GIT_EXTERNAL_DIFF="/bin/false",
                              GIT_SSH_COMMAND="/bin/false", GIT_CONFIG_KEY_0="core.pager", GIT_CONFIG_COUNT="1")
            env = jh_core.git_env()
        finally:
            os.environ.clear()
            os.environ.update(old)
        self.assertEqual((env.get("GIT_INDEX_FILE"), env.get("GIT_DIR")), ("/tmp/x-index", "/tmp/x.git"))
        for name in ("GIT_EXTERNAL_DIFF", "GIT_SSH_COMMAND", "GIT_CONFIG_KEY_0", "GIT_CONFIG_COUNT"):
            self.assertNotIn(name, env)

    def test_2_static_commands_run_none_of_them(self):
        self.clear()
        self.dirty()
        env = {"GIT_EXTERNAL_DIFF": self.hooks["external-diff"]}
        commands = [("scan", self.repo, "--json"), ("map", self.repo, "--json"), ("passport", self.repo, "--json"),
                    ("review", self.repo, "--json"), ("review", self.repo, "--base", "HEAD~1", "--json"),
                    ("doctor", self.repo, "--json"), ("score", self.repo, "--since", "HEAD~1", "--json"),
                    ("map", self.repo, "--base", "HEAD~1", "--json")]
        for args in commands:
            self.dirty()
            proc = run_cli(*args, env=env)
            self.assertIn(proc.returncode, (0, 1), (args, proc.stderr[-300:]))
            self.assertEqual(self.fired(), [], "%s ran repository-controlled code" % " ".join(args[:1] + args[2:]))


if __name__ == "__main__":
    unittest.main()
