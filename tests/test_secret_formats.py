"""4.20.0: service tokens with a fixed shape, found by JH101 and masked in every report. Formats from each vendor's
documentation or gitleaks' default rules: Sentry (sntryu_, sntrys_), CircleCI (CCIPAT_, CCIPRJ_), Doppler (dp.pt.,
dp.st. ...), Shippo (shippo_live_), Brevo (xkeysib-), Postman (PMAK-) and Telegram bot tokens in the shape Telegram
issues (<bot id>:AA + 33 characters). Mailchimp keys, and Telegram-shaped values without the AA, are masked but not
reported. Another secret scanner's allow marker on the line does not change the severity.

Every token below is invented and assembled at run time, so this file holds none of them whole."""
import json
import os
import shutil
import tempfile
import unittest

from _util import run_cli
import jh_core

HEX64 = "3f9a0c1e7b2d4a6f" + "8e0c2b4d6f8a1c3e" + "5b7d9f0a2c4e6b8d" + "0f1a3c5e7b9d2f4a"
ALNUM = "Kq8Zt3Lm9Xw2Rb7N" + "c4Vf6Hj1Pd5Sg0Ty" + "2Ua4Ie6Ow8Qe3Rr5"
SENTRY_USER = "sntryu_" + HEX64
SENTRY_ORG = "sntrys_" + "eyJpYXQiOjE3MzA" + "wMDAwMDAsInVybCI6Imh0dHBzOi8vc2VudHJ5LmlvIn0=" + "_" + ALNUM[:43]
CIRCLE_PERSONAL = "CCIPAT_" + "ULUhR6rJLxYbyzyrP19iMZ" + "_" + HEX64[:40]
CIRCLE_PROJECT = "CCIPRJ_" + "4fZt9qWm2NcXv7Rb8Kd3Lp" + "_" + HEX64[24:64]
DOPPLER_PERSONAL = "dp.pt." + ALNUM[:43]
DOPPLER_SERVICE = "dp.st." + "prd." + ALNUM[2:44]
SHIPPO = "shippo_live_" + HEX64[:40]
BREVO = "xkeysib-" + HEX64 + "-" + ALNUM[:16]
POSTMAN = "PMAK-" + HEX64[:24] + "-" + HEX64[24:58]
TELEGRAM = "7391845026" + ":" + "AA" + ALNUM[1:34]
# Telegram's documentation example (32 characters after AA: a near miss), assembled at run time
TELEGRAM_DOCS = "110201543" + ":" + "AA" + "HdqTcvCH1vGWJxfS" + "eofSAs0K5PALDsaw"
MAILCHIMP = HEX64[:32] + "-" + "us14"

PROJECT = {
    ".sentryclirc": "[defaults]\norg = acme\n\n[auth]\ntoken=%s\n" % SENTRY_USER,
    "android/sentry.properties": "defaults.org=acme\ndefaults.project=app\nauth.token=%s\n" % SENTRY_ORG,
    "scripts/trigger-pipeline.sh": ("#!/bin/sh\ncurl -X POST https://circleci.com/api/v2/project/gh/acme/app/pipeline "
                                    "-H \"Circle-Token: %s\"\n" % CIRCLE_PERSONAL),
    "ops/circleci.env": "CIRCLECI_PROJECT_TOKEN=%s\n" % CIRCLE_PROJECT,
    ".github/workflows/deploy.yml": ("on: push\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    env:\n"
                                     "      DOPPLER_TOKEN: %s\n    steps:\n      - run: doppler run -- ./deploy.sh\n"
                                     % DOPPLER_SERVICE),
    "tools/doppler_sync.py": "sdk = DopplerSDK()\nsdk.set_access_token(\"%s\")\n" % DOPPLER_PERSONAL,
    "server/shipping.js": "const shippo = require('shippo')('%s');\n" % SHIPPO,
    "backend/mail.py": "configuration.api_key['api-key'] = '%s'\n" % BREVO,
    "collections/.env": "POSTMAN_API_KEY=%s\n" % POSTMAN,
    "bot/main.py": "import telebot\n\nbot = telebot.TeleBot(\"%s\")\n" % TELEGRAM,
    "bot/notify.sh": "curl -s \"https://api.telegram.org/bot%s/sendMessage\" -d chat_id=42 -d text=done\n" % TELEGRAM,
    "functions/.env": "MAILCHIMP_SERVER=us14\nMAILCHIMP_API_KEY=%s\n" % MAILCHIMP,
}
TOKENS = [SENTRY_USER, SENTRY_ORG, CIRCLE_PERSONAL, CIRCLE_PROJECT, DOPPLER_PERSONAL, DOPPLER_SERVICE, SHIPPO, BREVO,
          POSTMAN, TELEGRAM, MAILCHIMP]

# shaped like the tokens but not them: wrong length, wrong prefix, a letter outside the alphabet, the vendors' own
# documentation examples, and everyday strings that share a piece of a format
NEAR = {
    "near/sentry.env": "A=sntryu_%s\nB=sntryx_%s\n" % (HEX64[:63], HEX64),
    "near/circle.env": "A=CCIPAT_%s_%s\nB=CCIPAT_%s_%s\nC=CCIPXX_%s_%s\n" % (
        "ULUhR6rJLxYbyzyrP19iMZ", HEX64[:39], "ULUhR6rJLxYbyzyrP19iM0", HEX64[:40], "ULUhR6rJLxYbyzyrP19iMZ", HEX64[:40]),
    "near/doppler.env": "A=dp.pt.%s\nB=dp.xx.%s\nC=dp.pt.%s\n" % (ALNUM[:39], ALNUM[:43], ALNUM[:46]),
    "near/shippo.env": "A=shippo_test_%s\nB=shippo_live_%s\n" % (HEX64[:40], HEX64[:39]),
    "near/brevo.env": "A=xkeysib-%s-%s\nB=xkeysix-%s-%s\n" % (HEX64[:63], ALNUM[:16], HEX64, ALNUM[:16]),
    "near/postman.env": "A=PMAK-%s-%s\nB=PMAT-%s-%s\n" % (HEX64[:23], HEX64[24:58], HEX64[:24], HEX64[24:58]),
    "near/telegram.py": ("A = \"7391845026:AA%s\"\nB = \"7391845026:BB%s\"\n"
                         "C = \"123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11\"\n"
                         "D = \"%s\"\n" % (ALNUM[1:33], ALNUM[1:34], TELEGRAM_DOCS)),
    "near/mailchimp.txt": ("bucket %s-us-east-1\nkey %s-us14\nrevision %s-useast\n" % (
        HEX64[:32], HEX64[:31], HEX64[:32])),
}


def write(root, files):
    for rel, text in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)


class Formats(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tempfile.mkdtemp(prefix="jh-formats-")
        write(cls.root, dict(PROJECT, **NEAR))
        cls.out = run_cli("scan", cls.root, "--json", "--min-severity", "info", "--no-progress", "--rule", "JH101").stdout
        cls.found = json.loads(cls.out)["findings"]

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root, ignore_errors=True)

    def test_each_format_is_found_where_projects_keep_it(self):
        got = {(f["path"], f["line"]) for f in self.found if f["rule"] == "JH101"}
        expected = {(".sentryclirc", 5), ("android/sentry.properties", 3), ("scripts/trigger-pipeline.sh", 2),
                    ("ops/circleci.env", 1), (".github/workflows/deploy.yml", 6), ("tools/doppler_sync.py", 2),
                    ("server/shipping.js", 1), ("backend/mail.py", 1), ("collections/.env", 1), ("bot/main.py", 3),
                    ("bot/notify.sh", 1)}
        self.assertEqual(expected - got, set())
        for f in self.found:
            if (f["path"], f["line"]) in expected:
                self.assertEqual(f["severity"], "critical", f)

    def test_look_alikes_are_quiet(self):
        self.assertEqual([(f["path"], f["line"]) for f in self.found if f["path"].startswith("near/")], [])

    def test_no_token_reaches_the_report(self):
        for token in TOKENS:
            self.assertNotIn(token, self.out)
            self.assertNotIn(token[-16:], self.out)
            self.assertNotIn(token[-16:], jh_core.redact_secrets("value = %s" % token))

    def test_a_mailchimp_key_is_masked_but_not_reported(self):
        self.assertFalse(any(f["path"] == "functions/.env" for f in self.found))
        self.assertNotIn(MAILCHIMP, jh_core.redact_secrets("MAILCHIMP_API_KEY=%s" % MAILCHIMP))

    def test_another_scanners_allow_marker_changes_nothing(self):
        root = tempfile.mkdtemp(prefix="jh-formats-allow-")
        try:
            github = "ghp_" + ALNUM[:36]
            write(root, {"app/a.py": "SENTRY = \"%s\"  # gitleaks:allow\n" % SENTRY_USER,
                         "app/b.py": "SENTRY = \"%s\"; label = \"notggignoreanything\"\n" % SENTRY_USER,
                         "app/c.py": "VALUE = \"%s\"  # pragma: allowlist secret\n" % github,
                         "app/d.py": "# gitleaks:allow\nSENTRY = \"%s\"\n" % SENTRY_USER})
            found = json.loads(run_cli("scan", root, "--json", "--min-severity", "info", "--no-progress",
                                       "--rule", "JH101").stdout)["findings"]
            self.assertEqual(sorted((f["path"], f["severity"]) for f in found),
                             [("app/a.py", "critical"), ("app/b.py", "critical"), ("app/c.py", "critical"),
                              ("app/d.py", "critical")])
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_telegram_shape_without_aa_is_masked_not_reported(self):
        other = "7391845026:AB" + ALNUM[1:34]
        root = tempfile.mkdtemp(prefix="jh-formats-tg-")
        try:
            write(root, {"app/bot.py": "value = \"%s\"\n" % other, "app/live.py": "value = \"%s\"\n" % TELEGRAM})
            out = run_cli("scan", root, "--json", "--min-severity", "info", "--no-progress", "--rule", "JH101").stdout
            self.assertEqual([f["path"] for f in json.loads(out)["findings"]], ["app/live.py"])
            self.assertNotIn(other, jh_core.redact_secrets("value = %s" % other))
            self.assertNotIn(other[-16:], out)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_a_shippo_test_key_is_left_alone(self):
        # test-mode keys reach no live account; like Stripe's sk_test_ they are not reported
        self.assertFalse(any(f["path"] == "near/shippo.env" for f in self.found))


if __name__ == "__main__":
    unittest.main()
