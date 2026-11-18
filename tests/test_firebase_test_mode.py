"""4.20.0: JH134 reads the rules the Firebase console writes for a Realtime Database created in test mode,
".read": "now < <milliseconds>": open to everyone, signed in or not, until that date. Emulator and test rules are
left out, as they are for Firestore and Storage rules. The rules are read over the whole file with // and /* */
comments blanked, so a rule spread over lines counts and a commented one does not."""
import json
import os
import shutil
import tempfile
import unittest

from _util import run_cli

TEST_MODE = ('{\n  "rules": {\n    ".read": "now < 1714521600000",  // 2024-5-1\n'
             '    ".write": "now < 1714521600000",  // 2024-5-1\n  }\n}\n')


def scan(files):
    root = tempfile.mkdtemp(prefix="jh-rtdb-")
    try:
        for rel, text in files.items():
            path = os.path.join(root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
        out = run_cli("scan", root, "--json", "--min-severity", "info", "--no-progress", "--rule", "JH134").stdout
        return json.loads(out)["findings"]
    finally:
        shutil.rmtree(root, ignore_errors=True)


class TestMode(unittest.TestCase):
    def test_console_test_mode_rules(self):
        found = scan({"database.rules.json": TEST_MODE})
        found.sort(key=lambda f: f["line"])
        self.assertEqual([(f["line"], f["severity"]) for f in found], [(3, "major"), (4, "major")])
        self.assertIn("anyone read this path, signed in or not, until 2024-05-01 (UTC)", found[0]["message"])
        self.assertIn("anyone write", found[1]["message"])

    def test_a_named_rules_file_and_a_nested_path(self):
        found = scan({"firebase/rtdb.rules.json": ('{"rules": {"public": {".read": "now<1893456000000"}, '
                                                   '"private": {".read": "auth != null"}}}\n')})
        self.assertEqual([(f["line"], f["severity"]) for f in found], [(1, "major")])
        self.assertIn("2030-01-01", found[0]["message"])

    def test_conditions_that_need_a_user_and_comments_are_quiet(self):
        found = scan({"database.rules.json": (
            '{\n  "rules": {\n'
            '    ".read": "auth != null && now < 1714521600000",\n'
            '    ".write": "auth.uid === $uid",\n'
            '    // ".read": "now < 1714521600000",\n'
            '    "items": {".read": "now < 1714521600000 && auth != null"}\n'
            '  }\n}\n')})
        self.assertEqual(found, [])

    def test_a_rule_spread_over_lines(self):
        found = scan({"database.rules.json": '{ "rules": { ".read":\n  "now < 1893456000000" }}\n'})
        self.assertEqual([(f["line"], f["severity"]) for f in found], [(1, "major")])

    def test_both_operations_on_one_line(self):
        found = scan({"database.rules.json": '{"rules":{".read":"now < 1893456000000",".write":"now < 1893456000000"}}\n'})
        self.assertEqual(len(found), 1)
        self.assertIn("let anyone read and write this path, signed in or not, until 2030-01-01 (UTC).", found[0]["message"])

    def test_block_comments_and_strings_that_look_like_comments(self):
        self.assertEqual(scan({"database.rules.json": (
            '{ "rules": {\n  /* ".read": "now < 1893456000000", */\n  ".read": false\n}}\n')}), [])
        found = scan({"database.rules.json": (
            '{ "rules": {\n  "note": "see https://firebase.google.com /* docs */",\n'
            '  ".write": "now < 1893456000000"\n}}\n')})
        self.assertEqual([f["line"] for f in found], [3])

    def test_emulator_and_test_rules_are_left_out(self):
        for rel in ("test/database.rules.json", "emulator/database.rules.json", "database.test.rules.json"):
            with self.subTest(rel=rel):
                self.assertEqual(scan({rel: TEST_MODE}), [])

    def test_open_rules_are_unchanged(self):
        found = scan({"database.rules.json": '{\n  "rules": {\n    ".read": true,\n    ".write": true\n  }\n}\n'})
        self.assertEqual(sorted((f["line"], f["severity"]) for f in found), [(3, "major"), (4, "critical")])

    def test_only_rules_files(self):
        self.assertEqual(scan({"src/config.json": TEST_MODE.replace("  // 2024-5-1", "")}), [])


if __name__ == "__main__":
    unittest.main()
