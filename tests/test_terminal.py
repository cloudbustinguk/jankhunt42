"""Terminal views: golden snapshots at 80/100/120 columns (color, NO_COLOR,
ASCII), redirected output, JSON purity, hostile strings, empty graphs, and
capped output for large graphs. Set JH_UPDATE_SNAPSHOTS=1 to regenerate
after an intentional change, then review the diff."""
import json
import os
import re
import shutil
import tempfile
import unittest
import unittest.mock

import _util
from _util import run_cli
import jh_graph as G
import jh_map
import jh_views

SNAP = os.path.join(_util.HERE, "snapshots")
UPDATE = os.environ.get("JH_UPDATE_SNAPSHOTS") == "1"
ANSI = re.compile(r"\x1b\[[0-9;]*m")


class Snapshots(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="jh-snap-")
        cls.root = os.path.join(cls.tmp, "demo-app")
        shutil.copytree(os.path.join(_util.FIXTURES, "demo-app"), cls.root)
        env = {"SOURCE_DATE_EPOCH": "1700000000"}
        cls.map = json.loads(run_cli("map", cls.root, "--json", env=env).stdout)
        cls.passport = json.loads(run_cli("passport", cls.root, "--json", env=env).stdout)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def compare(self, name, text):
        path = os.path.join(SNAP, name)
        if UPDATE or not os.path.exists(path):
            os.makedirs(SNAP, exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            if not UPDATE:
                self.fail("snapshot %s was missing and has been written; re-run" % name)
        with open(path, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), text, "snapshot drift: %s (JH_UPDATE_SNAPSHOTS=1 to accept)" % name)

    def test_views_at_widths(self):
        for view, data, fn in (("map", self.map, jh_views.map_tty), ("passport", self.passport, jh_views.passport_tty)):
            for cols in (80, 100, 120):
                color = fn(data, color=True, columns=cols)
                mono = fn(data, color=False, columns=cols)
                ascii_ = fn(data, color=False, ascii_only=True, columns=cols)
                self.assertEqual(ANSI.sub("", color), mono)
                width = jh_views.view_width(cols)
                for line in mono.split("\n"):
                    self.assertLessEqual(len(line), max(width, 110), "%s@%d overflows: %r" % (view, cols, line))
                self.assertTrue(all(ord(ch) < 128 for ch in ascii_), "%s ascii mode has non-ASCII" % view)
                self.compare("%s-%d.txt" % (view, cols), mono)
                self.compare("%s-%d.ascii.txt" % (view, cols), ascii_)

    def test_labels_are_words_not_just_color(self):
        mono = jh_views.map_tty(self.map, color=False, columns=100)
        for word in ("[verified]", "[supported]", "[inferred]", "[unknown]"):
            self.assertIn(word, mono)
        self.assertIn("0 known [verified]", mono)

    def test_empty_graph_says_zero_observed_not_none_possible(self):
        col = jh_map.Collected(items=[jh_map.Item("main.go", "package main\n")], considered=1)
        rep = jh_map.build_report(col, "/x", "empty", "t", None)
        out = jh_views.map_tty(rep, color=False, columns=80)
        self.assertIn("Unknown", out)
        self.assertIn("0 observed", out)
        self.assertNotIn("none possible", out)

    def test_long_names_and_hostile_strings(self):
        col = jh_map.Collected(items=[jh_map.Item("k.yaml",
            "kind: Deployment\napiVersion: apps/v1\nmetadata:\n  name: " + "x" * 300 + "\x1b[2J\x1b]0;pwn\x07\n  namespace: n\n")])
        rep = jh_map.build_report(col, "/x", "app\x1b[31m", "t", None)
        out = jh_views.map_tty(rep, color=True, columns=80)
        self.assertNotIn("\x1b[2J", out)
        self.assertNotIn("\x1b]0;", out)
        self.assertNotIn("\x1b[31m" + "app", out)


class CliModes(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="jh-cli-")
        self.root = os.path.join(self.tmp, "demo-app")
        shutil.copytree(os.path.join(_util.FIXTURES, "demo-app"), self.root)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_json_stdout_is_only_json(self):
        for cmd in ("map", "passport"):
            r = run_cli(cmd, self.root, "--json")
            json.loads(r.stdout)
            self.assertNotIn("\x1b", r.stdout)

    def test_no_color_and_term_dumb_and_redirect(self):
        for env in ({"NO_COLOR": "1"}, {"TERM": "dumb"}, {}):
            for cmd in ("map", "passport", "scan"):
                r = run_cli(cmd, self.root, env=env)
                self.assertNotIn("\x1b", r.stdout, (cmd, env))
                self.assertNotIn("\r", r.stdout)

    def test_help_mentions_three_questions(self):
        r = run_cli("--help")
        self.assertIn("What's broken?", r.stdout)
        for cmd in ("map", "passport", "selftest", "scan", "review", "supply-chain", "hunt"):
            self.assertIn(cmd, r.stdout)
            self.assertEqual(run_cli(cmd, "--help").returncode, 0)


class Palette(unittest.TestCase):
    """Terminal colours mirror the HTML views (exact in truecolor, nearest
    xterm-256 otherwise, the light theme for light terminals)."""

    def colors(self, env, palette="explorer"):
        import jh_render
        clean = {k: v for k, v in os.environ.items() if k not in ("COLORTERM", "COLORFGBG")}
        clean.update(env)
        with unittest.mock.patch.dict(os.environ, clean, clear=True):
            return jh_render.Colors(True, palette)

    def test_gradient_blends_cyan_to_magenta_in_rgb(self):
        c = self.colors({"COLORTERM": "truecolor"})
        codes = re.findall(r"\x1b\[38;2;(\d+);(\d+);(\d+)m", c.gradient("JANKHUNT42"))
        self.assertEqual(codes[0], ("56", "225", "255"))    # explorer cyan #38e1ff
        self.assertEqual(codes[-1], ("255", "79", "216"))   # explorer magenta #ff4fd8
        reds = [int(r) for r, _, _ in codes]
        self.assertEqual(reds, sorted(reds))                # monotone blend, not hue jumps

    def test_256_fallback_keeps_greys_neutral(self):
        import jh_render
        c = self.colors({})
        self.assertIn("38;5;", c.grey("x"))
        n = jh_render._xterm256(jh_render._hex(jh_render.PALETTES["scan"]["grey"]))
        self.assertGreaterEqual(n, 232)                     # grey ramp, not a teal cube entry

    def test_light_terminal_uses_light_palette(self):
        c = self.colors({"COLORFGBG": "0;15", "COLORTERM": "truecolor"})
        self.assertIn("38;2;0;119;168", c.cyan("x"))       # light cyan #0077a8

    def test_states_and_badges(self):
        with unittest.mock.patch.dict(os.environ, {"COLORTERM": "truecolor"}):
            t = jh_views.Theme(True, False, 100)
            self.assertIn("38;2;167;139;250", t.label("declared"))   # violet, as in the explorer
            self.assertIn("48;2;53;211;154", t.c.grade("A"))         # HTML grade-A badge
        self.assertEqual(jh_views.Theme(False, False, 100).c.grade("E"), " E ")

    def test_edge_segments_painted_across_wrapped_lines(self):
        lines = ["    app -[writes/write,", "      observed]→ db -[reads/read, declared]→ x"]
        out = jh_views.paint_edges(lines, lambda s: "<%s>" % s, "→")
        self.assertEqual(out[0], "    app <-[writes/write,>")
        self.assertEqual(out[1], "<      observed]→> db <-[reads/read, declared]→> x")
        self.assertEqual([ANSI.sub("", x) for x in jh_views.paint_edges(lines, lambda s: s, "→")], lines)


class LargeGraphs(unittest.TestCase):
    def test_capped_human_output(self):
        files = {"svc%03d.py" % i: 'import requests\nrequests.get("https://h%03d.example.com/x")\n' % i for i in range(400)}
        col = jh_map.Collected(items=[jh_map.Item(k, v) for k, v in files.items()], considered=400)
        rep = jh_map.build_report(col, "/x", "big", "t", None)
        out = jh_views.map_tty(rep, color=False, columns=100)
        self.assertLess(len(out.split("\n")), 80)
        self.assertLess(len(jh_map.markdown(rep).split("\n")), 80)


if __name__ == "__main__":
    unittest.main()
