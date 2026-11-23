"""4.22.0: nothing is set aside silently. A config file never filters another project's scan; what a config,
inline ignore comments, the severity floor, rules set aside by name and skipped folders hold back is reported; a
scan with and without git reads the same folders; --ignore-ci sets aside exactly the CI-only rules by name.
Invented projects only."""
import json
import os
import shutil
import tempfile
import unittest

from _util import run_cli
import jh_config

WORKFLOW = """name: ci
on: pull_request_target
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: echo "${{ github.event.pull_request.title }}"
      - uses: some-org/an-action@main
"""
AGENT_WORKFLOW = """name: triage
on: issues
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          prompt: "Triage this: ${{ github.event.issue.body }}"
"""
APP = 'const run = (s) => eval(s);\nmodule.exports = run;\n'


def write(root, files):
    for rel, text in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)


def scan(path, *extra):
    p = run_cli("scan", path, "--json", "--min-severity", "info", "--no-progress", *extra)
    return json.loads(p.stdout), p.stderr


class ConfigScope(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_a_parent_folder_config_does_not_filter_a_project_without_git(self):
        write(self.tmp, {".jankhunt42.toml": '[paths."*"]\nignore = ["*"]\n', "downloads/app/index.js": APP})
        app = os.path.join(self.tmp, "downloads", "app")
        self.assertIsNone(jh_config.find_config(app))
        doc, _ = scan(app)
        self.assertTrue(doc["findings"])
        self.assertIsNone(doc.get("config"))

    def test_the_repository_config_applies_from_a_subfolder_and_is_reported(self):
        os.makedirs(os.path.join(self.tmp, "repo", ".git"))
        write(self.tmp, {"repo/.jankhunt42.toml": '[paths."*"]\nignore = ["*"]\n', "repo/src/index.js": APP})
        self.assertEqual(jh_config.find_config(os.path.join(self.tmp, "repo", "src")),
                         os.path.join(self.tmp, "repo", ".jankhunt42.toml"))
        doc, err = scan(os.path.join(self.tmp, "repo"))
        self.assertEqual(doc["findings"], [])
        self.assertGreaterEqual(doc["config_suppressed"], 1)
        self.assertEqual(doc["set_aside"]["config"], doc["config_suppressed"])
        self.assertEqual(err, "")                     # a valid config is quiet on stderr; the report says it all
        md = run_cli("scan", os.path.join(self.tmp, "repo"), "--md", "--no-progress").stdout
        self.assertIn("`--no-config` shows everything", md)
        full, _ = scan(os.path.join(self.tmp, "repo"), "--no-config")
        self.assertEqual(len(full["findings"]), doc["config_suppressed"])


class IgnoreCi(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        write(self.tmp, {".github/workflows/ci.yml": WORKFLOW, ".github/workflows/triage.yml": AGENT_WORKFLOW,
                         "index.js": APP})

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_sets_aside_ci_rules_by_name_and_nothing_else(self):
        full, _ = scan(self.tmp)
        quiet, _ = scan(self.tmp, "--ignore-ci")
        ci = set(quiet["ignored_rules"])
        self.assertTrue({"JH417", "JH418", "JH419", "JH420"} <= ci, ci)
        self.assertNotIn("JH708", ci)                         # an agent risk, not CI hygiene
        key = lambda f: (f["rule"], f["path"], f["line"])
        self.assertEqual({key(f) for f in quiet["findings"]},
                         {key(f) for f in full["findings"] if f["rule"] not in ci})
        self.assertTrue(any(f["rule"] == "JH708" for f in quiet["findings"]))
        self.assertTrue(any(f["path"] == "index.js" for f in quiet["findings"]))


class SetAside(unittest.TestCase):
    """A small app that hides findings in every way the scan can hold them back."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        write(self.tmp, {
            "package.json": '{"name": "vibe"}\n',
            "src/env/server.ts": 'export const db = "postgres://admin:hunter2hunter2@db.internal:5432/prod";\n',
            "app/api/build/route.ts": "export const run = (s: string) => eval(s);\n",
            "app/page.tsx": "// jankhunt42: ignore JH204\n"
                            "export default function P({ q }: { q: string }) { console.log('debug', q); return q; }\n",
            ".antigravity/mcp_config.json": '{"mcpServers": {"fs": {"command": "npx", "args": ["-y", "some-mcp-server@latest"]}}}\n',
            "node_modules/x/index.js": "module.exports = 1;\n",
            ".github/workflows/ci.yml": WORKFLOW,
        })

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_env_and_agent_folders_are_read_with_or_without_git(self):
        key = lambda d: sorted({(f["rule"], f["path"]) for f in d["findings"]})
        write(self.tmp, {".vercel/output/functions/index.js":
                         'const k = "sk-proj-%s";\nmodule.exports = (s) => eval(s);\n' % ("Qm4x9" * 8)})
        plain, _ = scan(self.tmp)
        self.assertFalse(any(f["path"].startswith(".vercel/") for f in plain["findings"]))
        self.assertIn(".vercel", plain["set_aside"]["folders_not_read"]["build output"]["paths"])
        paths = {f["path"] for f in plain["findings"]}
        self.assertIn("src/env/server.ts", paths)
        self.assertIn(".antigravity/mcp_config.json", paths)
        if shutil.which("git"):
            import subprocess
            subprocess.run(["git", "init", "-q", self.tmp], check=True)
            subprocess.run(["git", "-C", self.tmp, "add", "-A"], check=True)
            gitted, _ = scan(self.tmp)
            self.assertEqual(key(plain), key(gitted))
            self.assertIn(".vercel", gitted["set_aside"]["folders_not_read"]["build output"]["paths"])

    def test_a_python_virtualenv_named_env_is_not_read(self):
        write(self.tmp, {"env/pyvenv.cfg": "home = /usr/bin\n", "env/lib/x.py": 'KEY = "sk-proj-AAAAAAAAAAAAAAAAAAAAAAAA"\n'})
        doc, _ = scan(self.tmp)
        self.assertFalse(any(f["path"].startswith("env/") for f in doc["findings"]))
        self.assertIn("env", doc["set_aside"]["folders_not_read"]["dependencies"]["paths"])

    def test_every_cause_is_reported(self):
        doc, _ = scan(self.tmp, "--min-severity", "major", "--ignore-ci")
        aside = doc["set_aside"]
        self.assertEqual(aside["inline_ignore"], 1)
        self.assertGreaterEqual(sum(v for k, v in aside["below_floor"].items() if k != "floor"), 1)
        self.assertEqual(aside["below_floor"]["floor"], "major")
        self.assertIn("JH418", aside["ignored_rules"]["rules"])
        self.assertEqual(aside["folders_not_read"]["build output"]["paths"], ["app/api/build"])
        self.assertEqual(aside["folders_not_read"]["dependencies"]["paths"], ["node_modules"])
        md = run_cli("scan", self.tmp, "--md", "--no-progress", "--min-severity", "major", "--ignore-ci").stdout
        section = md.split("### Set aside in this run", 1)[1].split("\n## ", 1)[0]
        for words in ("under the severity floor", "jankhunt42: ignore", "set aside by name and not run",
                      "`app/api/build/`", "`node_modules/`"):
            self.assertIn(words, section)

    def test_no_inline_ignore_shows_what_the_comment_hid(self):
        hidden, _ = scan(self.tmp)
        shown, _ = scan(self.tmp, "--no-inline-ignore")
        self.assertFalse(any(f["rule"] == "JH204" for f in hidden["findings"]))
        self.assertTrue(any(f["rule"] == "JH204" for f in shown["findings"]))
        self.assertNotIn("inline_ignore", shown["set_aside"])

    def test_a_scan_that_finds_nothing_is_quiet_not_pristine(self):
        empty = tempfile.mkdtemp()
        try:
            write(empty, {"README.md": "hello\n"})
            doc, _ = scan(empty)
            self.assertEqual(doc["summary"]["jank"]["label"], "quiet")
            md = run_cli("scan", empty, "--md", "--no-progress").stdout
            self.assertIn("quiet", md.split("\n", 3)[2])
            self.assertNotIn("pristine", md)
        finally:
            shutil.rmtree(empty)

    def test_installed_plugin_code_is_listed_and_its_settings_are_read(self):
        write(self.tmp, {".obsidian/plugins/chat/data.json": '{"anthropicApiKey": "sk-ant-api03-%s"}\n' % ("Zq7" * 30),
                         ".obsidian/plugins/chat/main.js": 'var a = {enabled: ":not(:disabled)"};\n'})
        doc, _ = scan(self.tmp)
        paths = {f["path"] for f in doc["findings"]}
        self.assertIn(".obsidian/plugins/chat/data.json", paths)
        self.assertNotIn(".obsidian/plugins/chat/main.js", paths)
        self.assertIn(".obsidian/plugins/chat", doc["set_aside"]["folders_not_read"]["dependencies"]["paths"])

    def test_a_file_over_the_size_limit_is_listed(self):
        write(self.tmp, {"big.js": "x" * 5000})
        doc, _ = scan(self.tmp, "--max-file-bytes", "1000")
        self.assertIn("big.js", doc["set_aside"]["files_too_large"]["paths"])


if __name__ == "__main__":
    unittest.main()
