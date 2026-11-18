"""4.20.0: Google Apps Script manifests (appsscript.json). JH161: a web app deployed to anyone, even without a Google
sign-in (webapp.access ANYONE_ANONYMOUS). JH162: the full Drive scope in oauthScopes. Manifest fields from
developers.google.com/apps-script/manifest."""
import json
import os
import shutil
import tempfile
import unittest

from _util import run_cli

DRIVE = "https://www.googleapis.com/auth/drive"


def manifest(**kw):
    data = {"timeZone": "Europe/London", "dependencies": {}, "exceptionLogging": "STACKDRIVER",
            "runtimeVersion": "V8"}
    data.update(kw)
    return json.dumps(data, indent=2) + "\n"


def scan(files):
    root = tempfile.mkdtemp(prefix="jh-gas-")
    try:
        for rel, text in files.items():
            path = os.path.join(root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
        out = run_cli("scan", root, "--json", "--min-severity", "info", "--no-progress",
                      "--rule", "JH161", "--rule", "JH162").stdout
        return json.loads(out)["findings"]
    finally:
        shutil.rmtree(root, ignore_errors=True)


class WebApp(unittest.TestCase):
    def test_anonymous_web_app_running_as_the_deployer(self):
        found = scan({"appsscript.json": manifest(webapp={"executeAs": "USER_DEPLOYING", "access": "ANYONE_ANONYMOUS"})})
        self.assertEqual([(f["rule"], f["severity"], f["line"]) for f in found], [("JH161", "major", 8)])
        self.assertIn("runs it as the account that deploys it", found[0]["message"])

    def test_anonymous_web_app_in_a_clasp_folder(self):
        found = scan({"src/appsscript.json": manifest(webapp={"access": "ANYONE_ANONYMOUS"}),
                      ".clasp.json": '{"scriptId": "abc", "rootDir": "src"}\n'})
        self.assertEqual([(f["rule"], f["path"]) for f in found], [("JH161", "src/appsscript.json")])
        self.assertIn("doGet and doPost", found[0]["message"])

    def test_signed_in_access_is_quiet(self):
        for access in ("MYSELF", "DOMAIN", "ANYONE"):
            with self.subTest(access=access):
                self.assertEqual(scan({"appsscript.json": manifest(webapp={"executeAs": "USER_DEPLOYING",
                                                                           "access": access})}), [])

    def test_other_json_and_text_are_quiet(self):
        self.assertEqual(scan({"config/sharing.json": json.dumps({"webapp": {"access": "ANYONE_ANONYMOUS"}}),
                               "README.md": 'Set "access": "ANYONE_ANONYMOUS" in appsscript.json.\n'}), [])


class DriveScope(unittest.TestCase):
    def test_full_drive_scope(self):
        found = scan({"appsscript.json": manifest(oauthScopes=[
            "https://www.googleapis.com/auth/spreadsheets.currentonly", DRIVE,
            "https://www.googleapis.com/auth/script.external_request"])})
        self.assertEqual([(f["rule"], f["severity"], f["line"]) for f in found], [("JH162", "minor", 8)])

    def test_narrower_drive_scopes_are_quiet(self):
        for scope in (DRIVE + ".file", DRIVE + ".readonly", DRIVE + ".metadata.readonly", DRIVE + ".appdata",
                      "https://www.googleapis.com/auth/spreadsheets"):
            with self.subTest(scope=scope):
                self.assertEqual(scan({"appsscript.json": manifest(oauthScopes=[scope])}), [])

    def test_both_rules_on_one_manifest(self):
        found = scan({"appsscript.json": manifest(oauthScopes=[DRIVE], webapp={"executeAs": "USER_DEPLOYING",
                                                                                "access": "ANYONE_ANONYMOUS"})})
        self.assertEqual(sorted(f["rule"] for f in found), ["JH161", "JH162"])


if __name__ == "__main__":
    unittest.main()
