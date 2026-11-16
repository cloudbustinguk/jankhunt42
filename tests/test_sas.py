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
    "block-scalar": ("p.installer.yaml", "PackageIdentifier: Vendor.App\nPackageVersion: 1.0\nManifestVersion: 1.6.0\n"
                     "ManifestType: installer\nReleaseNotes: |\n  steps:\n    InstallerUrl: %s\n" % RO, "critical", "credential-like"),
    "block-at-installer-indent": ("u.installer.yaml", "PackageIdentifier: Vendor.App\nPackageVersion: 1.0\n"
                                  "ManifestVersion: 1.6.0\nManifestType: installer\nReleaseNotes: |\n  InstallerUrl: %s\n" % RO,
                                  "critical", "credential-like"),
    "not-a-manifest": ("t.installer.yaml", "ManifestType: installer\nInstallerUrl: %s\n" % RO, "critical", "credential-like"),
    "codex-yaml-tagged-block": (".github/workflows/yaml-tagged-block.installer.yaml", 'name: SAS fixture\non: workflow_dispatch\njobs:\n  probe:\n    runs-on: ubuntu-latest\n    steps:\n      - shell: python\n        run: !!str |\n          InstallerUrl = "url"\n          uri = {\n            InstallerUrl: "https://pkgs.blob.core.windows.net/install/app.exe?sv=2022-11-02&sr=b&sig=Qz7Av8Bw9Cx0Dy1Ez2Fa3Gb4Hc5Id6Je7Kf8Lg9Mh0Ni%3D&sp=r"\n          }[InstallerUrl] + "w"\n          from urllib.parse import urlsplit, parse_qs\n          print(parse_qs(urlsplit(uri).query)["sp"])\n', "critical", "credential-like"),
    "codex-yaml-anchored-block": (".github/workflows/yaml-anchored-block.installer.yaml", 'name: SAS fixture\non: workflow_dispatch\njobs:\n  probe:\n    runs-on: ubuntu-latest\n    steps:\n      - shell: python\n        run: &script |\n          InstallerUrl = "url"\n          uri = {\n            InstallerUrl: "https://pkgs.blob.core.windows.net/install/app.exe?sv=2022-11-02&sr=b&sig=Qz7Av8Bw9Cx0Dy1Ez2Fa3Gb4Hc5Id6Je7Kf8Lg9Mh0Ni%3D&sp=r"\n          }[InstallerUrl] + "w"\n          from urllib.parse import urlsplit, parse_qs\n          print(parse_qs(urlsplit(uri).query)["sp"])\n', "critical", "credential-like"),
    "codex-yaml-long-block": (".github/workflows/yaml-long-block.installer.yaml", 'name: SAS fixture\non: workflow_dispatch\njobs:\n  probe:\n    runs-on: ubuntu-latest\n    steps:\n      - shell: python\n        run: |\n          # padding 0\n          # padding 1\n          # padding 2\n          # padding 3\n          # padding 4\n          # padding 5\n          # padding 6\n          # padding 7\n          # padding 8\n          # padding 9\n          # padding 10\n          # padding 11\n          # padding 12\n          # padding 13\n          # padding 14\n          # padding 15\n          # padding 16\n          # padding 17\n          # padding 18\n          # padding 19\n          # padding 20\n          # padding 21\n          # padding 22\n          # padding 23\n          # padding 24\n          # padding 25\n          # padding 26\n          # padding 27\n          # padding 28\n          # padding 29\n          # padding 30\n          # padding 31\n          # padding 32\n          # padding 33\n          # padding 34\n          # padding 35\n          # padding 36\n          # padding 37\n          # padding 38\n          # padding 39\n          # padding 40\n          # padding 41\n          # padding 42\n          # padding 43\n          # padding 44\n          # padding 45\n          # padding 46\n          # padding 47\n          # padding 48\n          # padding 49\n          # padding 50\n          # padding 51\n          # padding 52\n          # padding 53\n          # padding 54\n          # padding 55\n          # padding 56\n          # padding 57\n          # padding 58\n          # padding 59\n          # padding 60\n          # padding 61\n          # padding 62\n          # padding 63\n          # padding 64\n          # padding 65\n          # padding 66\n          # padding 67\n          # padding 68\n          # padding 69\n          # padding 70\n          # padding 71\n          # padding 72\n          # padding 73\n          # padding 74\n          # padding 75\n          # padding 76\n          # padding 77\n          # padding 78\n          # padding 79\n          # padding 80\n          # padding 81\n          # padding 82\n          # padding 83\n          # padding 84\n          # padding 85\n          # padding 86\n          # padding 87\n          # padding 88\n          # padding 89\n          # padding 90\n          # padding 91\n          # padding 92\n          # padding 93\n          # padding 94\n          # padding 95\n          # padding 96\n          # padding 97\n          # padding 98\n          # padding 99\n          # padding 100\n          # padding 101\n          # padding 102\n          # padding 103\n          # padding 104\n          # padding 105\n          # padding 106\n          # padding 107\n          # padding 108\n          # padding 109\n          # padding 110\n          # padding 111\n          # padding 112\n          # padding 113\n          # padding 114\n          # padding 115\n          # padding 116\n          # padding 117\n          # padding 118\n          # padding 119\n          # padding 120\n          # padding 121\n          # padding 122\n          # padding 123\n          # padding 124\n          # padding 125\n          # padding 126\n          # padding 127\n          # padding 128\n          # padding 129\n          # padding 130\n          # padding 131\n          # padding 132\n          # padding 133\n          # padding 134\n          # padding 135\n          # padding 136\n          # padding 137\n          # padding 138\n          # padding 139\n          # padding 140\n          # padding 141\n          # padding 142\n          # padding 143\n          # padding 144\n          # padding 145\n          # padding 146\n          # padding 147\n          # padding 148\n          # padding 149\n          # padding 150\n          # padding 151\n          # padding 152\n          # padding 153\n          # padding 154\n          # padding 155\n          # padding 156\n          # padding 157\n          # padding 158\n          # padding 159\n          # padding 160\n          # padding 161\n          # padding 162\n          # padding 163\n          # padding 164\n          # padding 165\n          # padding 166\n          # padding 167\n          # padding 168\n          # padding 169\n          # padding 170\n          # padding 171\n          # padding 172\n          # padding 173\n          # padding 174\n          # padding 175\n          # padding 176\n          # padding 177\n          # padding 178\n          # padding 179\n          # padding 180\n          # padding 181\n          # padding 182\n          # padding 183\n          # padding 184\n          # padding 185\n          # padding 186\n          # padding 187\n          # padding 188\n          # padding 189\n          # padding 190\n          # padding 191\n          # padding 192\n          # padding 193\n          # padding 194\n          # padding 195\n          # padding 196\n          # padding 197\n          # padding 198\n          # padding 199\n          # padding 200\n          InstallerUrl = "url"\n          uri = {\n            InstallerUrl: "https://pkgs.blob.core.windows.net/install/app.exe?sv=2022-11-02&sr=b&sig=Qz7Av8Bw9Cx0Dy1Ez2Fa3Gb4Hc5Id6Je7Kf8Lg9Mh0Ni%3D&sp=r"\n          }[InstallerUrl] + "w"\n          from urllib.parse import urlsplit, parse_qs\n          print(parse_qs(urlsplit(uri).query)["sp"])\n', "critical", "credential-like"),
    "codex-yaml-quoted-script": (".github/workflows/yaml-quoted-script.installer.yaml", 'name: SAS fixture\non: workflow_dispatch\njobs:\n  probe:\n    runs-on: ubuntu-latest\n    steps:\n      - shell: python\n        run: "InstallerUrl = \'url\'; uri = {\n          InstallerUrl: \'https://pkgs.blob.core.windows.net/install/app.exe?sv=2022-11-02&sr=b&sig=Qz7Av8Bw9Cx0Dy1Ez2Fa3Gb4Hc5Id6Je7Kf8Lg9Mh0Ni%3D&sp=r\'\n          }[InstallerUrl] + \'w\'; from urllib.parse import urlsplit, parse_qs;\n          print(parse_qs(urlsplit(uri).query)[\'sp\'])"\n', "critical", "credential-like"),

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
