"""Recall controls for consequential error handlers and named credential generators."""
import unittest

import _util
import jh_core
import jh_rules


def hits(path, text, rule):
    source = jh_core.source_from_text(path, "/invented/" + path, text)
    result = jh_rules.scan_sources([source], jh_rules.ScanOptions(rule_ids={rule}))
    return [(f.line, f.severity) for f in sorted(result.findings, key=lambda f: f.line)]


class HandlerComments(unittest.TestCase):
    def test_comment_cannot_hide_a_swallowed_database_write(self):
        source = 'try {\n  db.save(record);\n} catch (error) {\n  // silently dropped\n}\n'
        self.assertEqual(hits("write.js", source, "JH201"), [(3, "major")])

    def test_inline_comment_cannot_hide_a_swallowed_write(self):
        source = 'try { db.save(record); } catch { /* ignored */ }\n'
        self.assertEqual(hits("write.ts", source, "JH201"), [(1, "major")])

    def test_payment_processor_failure_stays_visible(self):
        source = 'try {\n  payment.process();\n} catch (error) {\n  // non-fatal\n}\n'
        self.assertEqual(hits("payment.js", source, "JH201"), [(3, "major")])

    def test_python_write_with_explaining_comment_stays_visible(self):
        source = 'try:\n    db.save(record)\nexcept Exception:\n    pass  # best effort\n'
        self.assertEqual(hits("write.py", source, "JH201"), [(3, "major")])

    def test_documented_cleanup_and_optional_fallback_stay_quiet(self):
        self.assertEqual(hits("close.js", 'try { socket.close(); } catch { /* non-fatal cleanup */ }\n', "JH201"), [])
        self.assertEqual(hits("optional.py", 'try:\n    read_optional()\nexcept ValueError:\n    pass  # optional input\n', "JH201"), [])

    def test_handled_errors_and_import_only_exceptions_stay_quiet(self):
        self.assertEqual(hits("write.js", 'try { db.save(record); } catch (e) { throw e; }\n', "JH201"), [])
        source = 'try:\n    db.save(record)\nexcept ImportError:\n    pass  # optional dependency\n'
        self.assertEqual(hits("optional.py", source, "JH201"), [])


class NamedCredentialGenerators(unittest.TestCase):
    def test_password_generator_return_on_later_line(self):
        source = 'function generatePassword() {\n  return Math.random().toString(36).slice(2);\n}\n'
        self.assertEqual(hits("password.js", source, "JH112"), [(2, "minor")])

    def test_token_generator_parenthesized_return(self):
        source = 'function create_access_token() {\n  return (\n    Math.random().toString(36)\n  );\n}\n'
        self.assertEqual(hits("token.js", source, "JH112"), [(3, "minor")])

    def test_typescript_generator_with_return_type(self):
        source = 'function issueSessionId(): string {\n  return Math.random().toString();\n}\n'
        self.assertEqual(hits("session.ts", source, "JH112"), [(2, "minor")])

    def test_nonsecurity_helpers_and_secure_generation_stay_quiet(self):
        for name in ("randomColor", "createRowKey", "renderPasswordForm", "getTokenColor"):
            with self.subTest(name=name):
                source = 'function ' + name + '() {\n  return Math.random().toString();\n}\n'
                self.assertEqual(hits("ui.js", source, "JH112"), [])
        self.assertEqual(hits("token.js", 'function generateToken() {\n  return crypto.randomUUID();\n}\n', "JH112"), [])

    def test_nested_helper_is_not_treated_as_the_credential_generator(self):
        source = ('function generateToken() {\n  function shade() {\n    return Math.random();\n  }\n'
                  '  return crypto.randomUUID();\n}\n')
        self.assertEqual(hits("token.js", source, "JH112"), [])

    def test_regex_return_text_does_not_generate_a_credential(self):
        source = ('function generateToken() {\n  const pattern = /return Math.random()/;\n'
                  '  return crypto.randomUUID();\n}\n')
        self.assertEqual(hits("token.js", source, "JH112"), [])

    def test_return_line_break_is_not_a_returned_random_value(self):
        source = 'function generatePassword() {\n  return\n  Math.random();\n}\n'
        self.assertEqual(hits("password.js", source, "JH112"), [])

    def test_existing_same_line_and_python_findings_remain(self):
        self.assertEqual(hits("token.js", 'const token = Math.random();\n', "JH112"), [(1, "minor")])
        self.assertEqual(hits("token.py", 'token = random.choice(alphabet)\n', "JH112"), [(1, "minor")])


if __name__ == "__main__":
    unittest.main()
