"""4.18.1: an Azure Storage shared access signature (SAS) in a URL is judged by what it grants. A read-only link to
one file is a download link (how WinGet manifests and install scripts fetch installers): minor. Reading or listing a
whole container or account: major. Anything that writes, or whose permissions the link does not state: critical.
Invented accounts and signatures only."""
import json
import os
import shutil
import tempfile
import unittest

from _util import run_cli

BASE = "https://pkgs.blob.core.windows.net/winget"
SIG = "sig=" + "Ab3Cd4Ef5Gh6Ij7Kl8Mn9Op0Qr1St2Uv3Wx4Yz5AbC%3D"
EXP = "se=2030-01-01T00%3A00%3A00Z"


def link(path, *params):
    return "%s/%s?%s" % (BASE, path, "&".join(("sv=2022-11-02",) + params + (SIG,)))


def winget(url, extra=""):
    return ("PackageIdentifier: Vendor.App\nPackageVersion: 1.0\nInstallers:\n- Architecture: x64\n"
            "  InstallerUrl: %s%s\nManifestType: installer\nManifestVersion: 1.6.0\n" % (url, extra))


RO = link("app.exe", EXP, "sr=b", "sp=r")
CASES = {
    # (file, text, expected severity, words the message must hold)
    "winget": ("Vendor.App.installer.yaml", winget(RO), "minor", "until 2030-01-01"),
    "winget-quoted": ("q.installer.yaml", winget('"%s"' % RO), "minor", "download this one file"),
    "no-expiry": ("a.installer.yaml", winget(link("app.exe", "sr=b", "sp=r")), "minor", "no expiry"),
    "container": ("b.installer.yaml", winget(link("", EXP, "sr=c", "sp=rl")), "major", "read and list every file in the container"),
    "account-read": ("c.installer.yaml", winget(link("", "ss=bf", "srt=o", "sp=r", EXP)), "major", "Blob, Files"),
    "writes": ("d.installer.yaml", winget(link("app.exe", EXP, "sr=b", "sp=rw")), "critical", "credential-like"),
    "account-full": ("e.installer.yaml", winget(link("", "ss=b", "srt=sco", "sp=rwdlac", EXP)), "critical", "credential-like"),
    "stored-policy": ("f.installer.yaml", winget(link("app.exe", "si=policy1", "sr=b")), "critical", "credential-like"),
    "not-azure": ("l.installer.yaml", winget("https://api.acme-tools.net/admin?sv=2022-11-02&sp=r&sr=b&%s&%s" % (EXP, SIG)),
                  "critical", "credential-like"),
    "encoded-write": ("m.installer.yaml", winget(link("app.exe", EXP, "sr=b", "sp=r", "%73p=rw")), "critical", "credential-like"),
    "encoded-account": ("n.installer.yaml", winget(link("app.exe", EXP, "sp=r", "sr=b", "%73s=b", "%73rt=sco")), "major", "account"),
    # Codex's audits: any doubt keeps it critical
    "comment-token": ("o.installer.yaml", winget(RO, " # https://api.acme-tools.net/run?token=" + "Zq4Xw9Lr2Tb7Nm3Kc8Vf6Hj1Pd5Sg0Ya2"),
                      "critical", "credential-like"),
    "block-scalar": ("p.installer.yaml", "ManifestType: installer\nReleaseNotes: |\n  steps:\n    InstallerUrl: %s\n" % RO,
                     "critical", "credential-like"),
    "not-winget-yaml": ("r.yaml", "url: %s\n" % RO, "critical", "credential-like"),
    "installerurl-elsewhere": ("deploy/config.yaml", "InstallerUrl: %s\n" % RO, "critical", "credential-like"),
    "json": ("s.json", '{"installerUrl": "%s"}\n' % RO, "critical", "credential-like"),
    "script": ("VSInstall.ps1", '$url = "%s"\nInvoke-WebRequest $url -OutFile vs.exe\n' % RO, "critical", "credential-like"),
    "yaml-run-block": (".github/workflows/w.yaml", "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n"
                       "      - shell: python\n        run: |\n          uri = (\"%s&sp=r\" \"w\")\n" % link("app.exe", EXP, "sr=b"),
                       "critical", "credential-like"),
}


class Sas(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tempfile.mkdtemp(prefix="jh-sas-")
        for name, (rel, text, _, _) in CASES.items():
            os.makedirs(os.path.dirname(os.path.join(cls.root, name, rel)), exist_ok=True)
            with open(os.path.join(cls.root, name, rel), "w") as fh:
                fh.write(text)
        out = run_cli("scan", cls.root, "--json", "--no-progress", "--min-severity", "info", "--rule", "JH101")
        cls.found = json.loads(out.stdout)["findings"]
        cls.passport = json.loads(run_cli("passport", os.path.join(cls.root, "winget"), "--json").stdout)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root, ignore_errors=True)

    def test_each_link_by_what_it_grants(self):
        for name, (rel, _, severity, words) in CASES.items():
            with self.subTest(name):
                got = [f for f in self.found if f["path"] == "%s/%s" % (name, rel)]
                self.assertEqual([f["severity"] for f in got], [severity])
                self.assertIn(words, got[0]["message"])

    def test_the_signature_is_never_shown(self):
        self.assertNotIn("Ab3Cd4Ef5Gh6", json.dumps(self.found))

    def test_a_download_link_is_not_a_public_exposure_lead(self):
        rule = next(r for r in self.passport["assessment"]["decision"]["rules"] if r["rule"] == "P-SEC-001")
        self.assertEqual(rule["outcome"], "pass")


if __name__ == "__main__":
    unittest.main()
