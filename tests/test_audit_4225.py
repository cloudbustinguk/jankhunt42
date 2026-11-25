"""4.22.5: a link whose target cannot be read never stops a scan (found by the full-corpus run, 1 of 17,529)."""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))
import jh_core  # noqa: E402


@unittest.skipIf(os.name == "nt", "symbolic links")
@unittest.skipUnless(shutil.which("git"), "git unavailable")
class UnreadableLinkTarget(unittest.TestCase):
    """Python 3.9-3.13 raise PermissionError from is_dir() on such a link; 3.14 returns False. The test makes the
    check raise on every version, as a committed link into /root does inside a container."""

    def test_a_committed_link_into_an_unreadable_folder_is_skipped_not_fatal(self):
        root = tempfile.mkdtemp(prefix="jh-4225-")
        self.addCleanup(shutil.rmtree, root, True)
        repo = os.path.join(root, "repo")
        os.makedirs(repo)
        Path(repo, "app.py").write_text("x = 1\n")
        os.symlink("/root/.pub-cache/hosted/plugin-1.0/", os.path.join(repo, "plugin"))
        os.makedirs(os.path.join(repo, "shared"))
        Path(repo, "shared", "lib.py").write_text("y = 2\n")
        os.symlink("shared/lib.py", os.path.join(repo, "inner"))     # inside the folder: reaches the file check
        subprocess.run(["git", "init", "-q", repo], check=True)
        subprocess.run(["git", "-C", repo, "add", "-A"], check=True)
        real_is_dir, real_is_file = pathlib.Path.is_dir, pathlib.Path.is_file

        def raising(real):
            def check(self, *args, **kwargs):
                if self.name in ("plugin", "inner"):
                    raise PermissionError(13, "Permission denied", str(self))
                return real(self, *args, **kwargs)
            return check

        with mock.patch.object(pathlib.Path, "is_dir", raising(real_is_dir)), \
                mock.patch.object(pathlib.Path, "is_file", raising(real_is_file)):
            found = jh_core.discover_files([repo])
        _, files = found                          # (root, files)
        names = sorted(p.name for p in files)
        self.assertIn("app.py", names)
        self.assertIn("lib.py", names)
        self.assertNotIn("plugin", names)
        self.assertNotIn("inner", names)


if __name__ == "__main__":
    unittest.main()
