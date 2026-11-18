"""4.20.0: JH433, ACTIONS_ALLOW_UNSECURE_COMMANDS set to true in GitHub Actions, which turns the set-env and
add-path workflow commands back on (CVE-2020-15228). The runner reads the value with bool.TryParse, so only "true",
in any case and with white space around it, counts, and only as an env entry or a write to $GITHUB_ENV."""
import json
import os
import shutil
import tempfile
import unittest

from _util import run_cli

NAME = "ACTIONS_ALLOW_" + "UNSECURE_COMMANDS"


def scan(files):
    root = tempfile.mkdtemp(prefix="jh-wfcmd-")
    try:
        for rel, text in files.items():
            path = os.path.join(root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
        out = run_cli("scan", root, "--json", "--min-severity", "info", "--no-progress", "--rule", "JH433").stdout
        return json.loads(out)["findings"]
    finally:
        shutil.rmtree(root, ignore_errors=True)


def workflow(env_block, step_env=""):
    return ("name: build\non: pull_request\n%sjobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v4\n      - run: make\n%s" % (env_block, step_env))


class UnsecureCommands(unittest.TestCase):
    def test_workflow_job_and_step_env(self):
        found = scan({
            ".github/workflows/a.yml": workflow("env:\n  %s: true\n" % NAME),
            ".github/workflows/b.yml": workflow("", "        env:\n          %s: 'TRUE'\n" % NAME),
            ".github/workflows/c.yml": workflow("", "      - run: echo \"%s=true\" >> $GITHUB_ENV\n" % NAME),
            "action.yml": ("name: legacy\nruns:\n  using: composite\n  steps:\n    - run: ./setup.sh\n"
                           "      shell: bash\n      env:\n        %s: \"true\"\n" % NAME),
        })
        self.assertEqual(sorted((f["path"], f["line"], f["severity"]) for f in found),
                         [(".github/workflows/a.yml", 4, "major"), (".github/workflows/b.yml", 10, "major"),
                          (".github/workflows/c.yml", 9, "major"), ("action.yml", 8, "major")])

    def test_values_the_runner_reads_as_true(self):
        found = scan({
            ".github/workflows/a.yml": workflow("env:\n  %s: >-\n    true\n" % NAME),
            ".github/workflows/b.yml": workflow("env:\n  %s: ${{ true }}\n" % NAME),
            ".github/workflows/c.yml": workflow("env:\n  %s: \" True \"\n" % NAME),
            ".github/workflows/d.yml": workflow("", "      - run: Add-Content -Path $env:GITHUB_ENV -Value \"%s=true\"\n"
                                                    "        shell: pwsh\n" % NAME),
        })
        self.assertEqual(sorted((f["path"], f["line"]) for f in found),
                         [(".github/workflows/a.yml", 4), (".github/workflows/b.yml", 4),
                          (".github/workflows/c.yml", 4), (".github/workflows/d.yml", 9)])

    def test_values_that_are_not_true_and_mentions_are_quiet(self):
        found = scan({
            ".github/workflows/a.yml": workflow("env:\n  %s: \"true false\"\n" % NAME),
            ".github/workflows/b.yml": workflow("env:\n  %s: \"true.abc\"\n" % NAME),
            ".github/workflows/c.yml": workflow("", "      - run: echo \"Do not set %s=true\"\n" % NAME),
            ".github/workflows/d.yml": workflow("", "      - run: echo \"%s=true false\" >> $GITHUB_ENV\n" % NAME),
            ".github/workflows/e.yml": workflow("", "      - with:\n          %s: true\n" % NAME),
        })
        self.assertEqual(found, [])

    def test_false_other_flags_comments_and_other_files_are_quiet(self):
        found = scan({
            ".github/workflows/a.yml": workflow("env:\n  %s: false\n  # %s: true\n"
                                                "  ACTIONS_RUNNER_ALLOW_EXECUTABLES_IN_PATH: true\n"
                                                "  %s: 1\n  %s_OLD: true\n" % (NAME, NAME, NAME, NAME)),
            "docs/ci.yml": "env:\n  %s: true\n" % NAME,
            "README.md": "Never set %s: true.\n" % NAME,
        })
        self.assertEqual(found, [])


if __name__ == "__main__":
    unittest.main()
