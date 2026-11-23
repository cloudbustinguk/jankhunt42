"""Precision follow-ups on invented source sites and their neighbours."""
import unittest

from test_precision_422 import scan


class NonSecurityHash(unittest.TestCase):
    def test_explicit_keyword_on_the_weak_hash(self):
        for constructor in ("hashlib.md5(", "hashlib.sha1(", "hashlib.new('md5',", 'hashlib.new("sha1",'):
            with self.subTest(constructor=constructor):
                src = "cache_key = " + constructor + "\n    payload.encode(), usedforsecurity = False,\n).digest()"
                f, = scan("JH107", src, "digest.py")
                self.assertEqual((f.line, f.severity), (1, "info"))
                self.assertIn("usedforsecurity=False", f.message)
                self.assertIn("non-security", f.message)

    def test_password_and_unrelated_flags(self):
        for args in ("password", "password, usedforsecurity=True", "password, usedforsecurity=setting",
                     "password, usedforsecurity=False or setting", "encode(password, usedforsecurity=False)",
                     "b'usedforsecurity=False'"):
            with self.subTest(args=args):
                f, = scan("JH107", "hashlib.md5(" + args + ")  # usedforsecurity=False", "digest.py")
                self.assertEqual(f.severity, "major")
                self.assertNotIn("non-security", f.message)
        for call in ("hashlib.new('sha256', payload, usedforsecurity=False)",
                     "hashlib.new(algorithm, payload, usedforsecurity=False)", "hashlib.new('md5', password)"):
            with self.subTest(call=call):
                self.assertEqual(scan("JH107", call, "digest.py"), [])

    def test_two_hashes_on_one_line(self):
        marked = "hashlib.sha1(payload, usedforsecurity=False)"
        password = "hashlib.md5(password)"
        for calls in ((marked, password), (password, marked)):
            src = "résumé = " + ", ".join(calls)
            with self.subTest(src=src):
                self.assertEqual({(f.column, f.severity) for f in scan("JH107", src, "digest.py")},
                                 {(src.index(marked) + 1, "info"), (src.index(password) + 1, "major")})
