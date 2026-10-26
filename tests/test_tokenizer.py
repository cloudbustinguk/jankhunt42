"""Invented lexical boundaries; performance must preserve every masked byte."""
import unittest

import _util
import jh_core


class Tokenizer(unittest.TestCase):
    def test_python_strings_and_trailing_comment(self):
        body, note = 'literal # content', '# final note'
        text = 'value = "' + body + '" ' + note + '\nnext = 2'
        code, nc, comments = jh_core.sanitize(text, 'python')
        self.assertEqual(code, ['value = "' + ' ' * len(body) + '" ' + ' ' * len(note), 'next = 2'])
        self.assertEqual(nc, ['value = "' + body + '" ' + ' ' * len(note), 'next = 2'])
        self.assertEqual(comments, [note, ''])

    def test_active_block_is_consumed_before_searching_for_an_opener(self):
        text = 'left /* first\nplain words */ right'
        code, nc, comments = jh_core.sanitize(text, 'c')
        expected = ['left ' + ' ' * len('/* first'), ' ' * len('plain words */') + ' right']
        self.assertEqual(code, expected)
        self.assertEqual(nc, expected)
        self.assertEqual(comments, ['/* first', 'plain words */'])

    def test_multiline_string_and_unterminated_state(self):
        text = 'value = """hidden\nordinary characters\nend"""; run()\n'
        code, nc, comments = jh_core.sanitize(text, 'python')
        self.assertEqual(code, ['value = ' + ' ' * len('"""hidden'),
                                ' ' * len('ordinary characters'), ' ' * len('end"""') + '; run()', ''])
        self.assertEqual(nc, text.split('\n'))
        self.assertEqual(comments, ['', '', '', ''])
        text = '"""still open\nordinary characters'
        self.assertEqual(jh_core.sanitize(text, 'python')[0], [' ' * len(line) for line in text.split('\n')])

    def test_regex_literals_keep_internal_quotes_and_comment_markers(self):
        regex = r'''const pattern = /["']+\/\//g; '''
        for lang in ('js', 'ts', 'vue', 'svelte'):
            with self.subTest(lang=lang):
                code, nc, comments = jh_core.sanitize(regex + 'const value = "opaque";', lang)
                self.assertEqual(code, [regex + 'const value = "      ";'])
                self.assertEqual(nc, [regex + 'const value = "opaque";'])
                self.assertEqual(comments, [''])

    def test_every_registered_line_comment_opener(self):
        tables = (jh_core._ANY_LINE_COMMENTS, jh_core._WS_LINE_COMMENTS)
        for table in tables:
            for lang, tokens in table.items():
                for token in tokens:
                    with self.subTest(lang=lang, token=token):
                        line = token + ' invented note'
                        self.assertEqual(jh_core.sanitize(line, lang),
                                         ([' ' * len(line)], [' ' * len(line)], [line]))

    def test_every_registered_block_opener(self):
        for lang, pairs in jh_core._BLOCK_COMMENTS.items():
            for start, end in pairs:
                with self.subTest(lang=lang, start=start):
                    line = start + ' invented block ' + end
                    self.assertEqual(jh_core.sanitize(line, lang),
                                     ([' ' * len(line)], [' ' * len(line)], [line]))

    def test_whitespace_sensitive_markers_still_require_whitespace(self):
        line = 'alpha#beta # note'
        code, nc, comments = jh_core.sanitize(line, 'shell')
        self.assertEqual(code, ['alpha#beta ' + ' ' * len('# note')])
        self.assertEqual(nc, code)
        self.assertEqual(comments, ['# note'])

    def test_plain_and_very_long_lines_preserve_positions(self):
        prefix = 'ordinary value ' * 10000
        line = prefix + '# note'
        code, nc, comments = jh_core.sanitize(line, 'python')
        self.assertEqual(code, [prefix + ' ' * len('# note')])
        self.assertEqual(nc, code)
        self.assertEqual(comments, ['# note'])
        for lang in ('python', 'js', 'markdown', 'unknown'):
            plain = 'ordinary text\twith unicode \u2603\n\nlast line\r'
            self.assertEqual(jh_core.sanitize(plain, lang),
                             (plain.split('\n'), plain.split('\n'), ['', '', '']))


if __name__ == '__main__':
    unittest.main()
