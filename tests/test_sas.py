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


CASES = {
    # (file, text, expected severity, words the message must hold)
    "winget": ("Vendor.App.installer.yaml", "PackageIdentifier: Vendor.App\nInstallers:\n- Architecture: x64\n"
               "  InstallerUrl: %s\n" % link("app.exe", EXP, "sr=b", "sp=r"), "minor", "until 2030-01-01"),
    # in code a URL can be extended (concatenation, .concat, adjacent literals, +=): it stays critical
    "script": ("VSInstall.ps1", '$url = "%s"\nInvoke-WebRequest $url -OutFile vs.exe\n' % link("vs.exe", EXP, "sr=b", "sp=r"),
               "critical", "credential-like"),
    "json-config": ("p.json", '{"installerUrl": "%s"}\n' % link("app.exe", EXP, "sr=b", "sp=r"), "minor", "download this one file"),
    "python-adjacent": ("q.py", 'uri = ("%s&sp=r" "w")\n' % link("app.exe", EXP, "sr=b"), "critical", "credential-like"),
    "js-concat-method": ("r.js", 'const uri = "%s&sp=r".concat("w");\n' % link("app.exe", EXP, "sr=b"), "critical", "credential-like"),
    "no-expiry": ("a.yaml", "url: %s\n" % link("app.exe", "sr=b", "sp=r"), "minor", "no expiry"),
    "container": ("b.yaml", "url: %s\n" % link("", EXP, "sr=c", "sp=rl"), "major", "read and list every file in the container"),
    "account-read": ("c.yaml", "url: %s\n" % link("", "ss=bf", "srt=o", "sp=r", EXP), "major", "Blob, Files"),
    "writes": ("d.yaml", "url: %s\n" % link("app.exe", EXP, "sr=b", "sp=rw"), "critical", "credential-like"),
    "account-full": ("e.yaml", "url: %s\n" % link("", "ss=b", "srt=sco", "sp=rwdlac", EXP), "critical", "credential-like"),
    "stored-policy": ("f.yaml", "url: %s\n" % link("app.exe", "si=policy1", "sr=b"), "critical", "credential-like"),
    # Codex's audit of the first version: any doubt keeps it critical
    "same-line-write": ("g.json", '{"download": "%s", "upload": "%s"}\n' % (
        link("app.exe", EXP, "sr=b", "sp=r"), link("up.exe", EXP, "sr=b", "sp=rw")), "critical", "credential-like"),
    "same-line-token": ("h.json", '{"download": "%s", "token": "%s"}\n' % (
        link("app.exe", EXP, "sr=b", "sp=r"), "ghp_" + "Zq4Xw9Lr2Tb7Nm3Kc8Vf6Hj1Pd5Sg0Ya2Ue7Wo3"), "critical", "credential-like"),
    "concatenated": ("i.js", 'const uri = "%s&sp=r" + "w";\n' % link("app.exe", EXP, "sr=b"), "critical", "credential-like"),
    "continued": ("j.js", 'const uri = "%s"\n  + "w";\n' % (link("app.exe", EXP, "sr=b") + "&sp=r"), "critical", "credential-like"),
    "other-query": ("k.js", 'const cfg = {ref: "https://pkgs.blob.core.windows.net/a.exe?sv=2022-11-02&sp=r&sr=b&sig=x", '
                    'conn: "BlobEndpoint=https://pkgs.blob.core.windows.net/;SharedAccessSignature=sv=2022-11-02&sp=rw&sr=c'
                    '&se=2030-01-01&%s"};\n' % SIG, "critical", "credential-like"),
    "not-azure": ("l.yaml", "url: https://api.acme-tools.net/admin?sv=2022-11-02&sp=r&sr=b&%s&%s\n" % (EXP, SIG),
                  "critical", "credential-like"),
    "encoded-write": ("m.yaml", "url: %s\n" % link("app.exe", EXP, "sr=b", "sp=r", "%73p=rw"), "critical", "credential-like"),
    "encoded-account": ("n.yaml", "url: %s\n" % link("app.exe", EXP, "sp=r", "sr=b", "%73s=b", "%73rt=sco"), "major", "account"),
    "html-escaped": ("o.yaml", 'url: "%s"\n' % link("app.exe", EXP, "sr=b", "sp=r").replace("&", "&amp;").replace(
        "&amp;" + SIG, "&" + SIG), "minor", "download this one file"),
}


class Sas(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tempfile.mkdtemp(prefix="jh-sas-")
        for name, (rel, text, _, _) in CASES.items():
            os.makedirs(os.path.join(cls.root, name))
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
