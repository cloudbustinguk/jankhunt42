"""Rule assertions on invented source sites, including neighboring constructs."""
import unittest

import _util
from jh_core import source_from_text
from jh_rules import ScanOptions, scan_sources


def scan(rule, text, path):
    source = source_from_text(path, "/fixture/" + path, text)
    return scan_sources([source], ScanOptions(rule_ids={rule})).findings


class CredentialRoles(unittest.TestCase):
    value = "Qp7Nz" + "8Rm6At2"
    entries = [
        'parser.option("password", "--relay-v2")',
        'const item = {token: "{sector17}", label: "Sector"}',
        'const item = {label: "Deck", token: "%counter31%"}',
        'const towerLabels = {password: "level seven tower"}',
        'const errorMessages = {token: "relay handover interrupted"}',
    ]

    def test_option_and_display_sites(self):
        for entry in self.entries:
            with self.subTest(entry=entry):
                self.assertEqual(scan("JH101", entry, "ui.js"), [])

    def test_siblings_in_both_orders(self):
        auth = 'ssh.connect(password="%s")' % self.value
        for entry in self.entries:
            for line in (entry + "; " + auth, auth + "; " + entry):
                with self.subTest(line=line):
                    f, = scan("JH101", line, "client.js")
                    self.assertEqual((f.column, f.severity), (line.index("password=", line.index("ssh.")) + 1, "critical"))
                    self.assertIn("supplies a literal as authentication", f.message)
                    self.assertNotIn(self.value, f.evidence)

    def test_auth_default_name_only_and_mock(self):
        f, = scan("JH101", 'const password = "%s"; parser.option("password", "--relay-v2", password)' %
                  self.value, "client.js")
        self.assertEqual((f.column, f.severity), (7, "critical"))
        self.assertIn("Check how", f.message)
        f, = scan("JH101", 'ssh.connect(password="%s")' % self.value, "tests/auth.py")
        self.assertEqual(f.severity, "minor")
        self.assertIn("as authentication material", f.message)

    def test_material_has_an_independent_match(self):
        token = "ghp_" + self.value * 3
        f, = scan("JH101", 'const uiLabels = {password: "%s"}' % token, "ui.js")
        self.assertEqual(f.severity, "critical")
        self.assertNotIn(token, f.evidence)
        pem = "-----BEGIN " + "PRIVATE KEY-----\n" + ("MWNrbXlrcmV4" * 6) + "\n-----END PRIVATE KEY-----"
        f, = scan("JH101", pem, "tests/keys.py")
        self.assertEqual(f.severity, "major")
        self.assertIn("fixture contains private-key-shaped", f.message)
        f, = scan("JH101", 'conn = "Host=db.internal;Password=%s"' % self.value, "db.py")
        self.assertIn("as authentication material", f.message)

    def test_policy_and_shareable_views(self):
        for marker in ("vermilion pebble", "umber shell"):
            positive = 'ssh.connect(password="%s") // %s' % (self.value, marker)
            f, = scan("JH101", positive, "client.js")
            check_views(self, f, marker, self.value)
            check_policy(self, [f], "P-SEC-001", True)
            for entry in self.entries:
                check_policy(self, scan("JH101", entry, "ui.js"), "P-SEC-001", False)


def check_views(case, finding, marker, secret=""):
    import jh_prompt
    import jh_review
    receipt = jh_review.make_receipt(finding, "new", "fixture")
    case.assertEqual(receipt["message"], finding.message)
    case.assertEqual(receipt["verification"], "supported")
    case.assertIn("Static", receipt["counterevidence"])
    prompt = jh_prompt.finding_prompt(finding)
    case.assertNotIn(marker, prompt)
    case.assertNotIn(marker, finding.message)
    if secret:
        case.assertNotIn(secret, repr(receipt))
        case.assertNotIn(secret, prompt)


def check_policy(case, findings, rule, triggers):
    import jh_policy
    from jh_passport import governance_leads
    exposure, agents = governance_leads(findings)
    facts = dict(exposure_findings=exposure, agent_findings=agents)
    for profile, outcome in (("standard", "review"), ("citizen", "block")):
        policy = jh_policy.merge(None, None, [], profile)
        result = jh_policy.evaluate(policy, facts, None)
        matching = [r["outcome"] for r in result["rules"] if r["rule"] == rule]
        case.assertEqual(matching, [outcome if triggers else "pass"])


class PolicyClaims(unittest.TestCase):
    def test_insert_audience_and_adjacent_select(self):
        select = 'create policy "for insert" on decks for select to viewers using (true);'
        for role in ("", "anon", "authenticated", "deckhand", "deckhand, anon"):
            clause = " to " + role if role else ""
            insert = "create policy arrivals on decks for insert" + clause + " with check (true);"
            for sql, location in [(insert + "\n" + select, 1), (select + "\n" + insert, 2)]:
                f, = scan("JH134", sql, "tables.sql")
                self.assertEqual((f.line, f.severity), (location, "minor" if role == "deckhand" else "major"))
                self.assertIn("INSERT check accepts every proposed row for " + (role or "PUBLIC") + ".", f.message)
                self.assertIn("require table privileges", f.message)
                self.assertNotRegex(f.message, "viewers|SELECT|DELETE|UPDATE")
                check_views(self, f, "arrivals")
                check_policy(self, [f], "P-SEC-001", role != "deckhand")

    def test_effective_predicates(self):
        for clause, expected, absent in [
            ("using (true)", "SELECT, INSERT, UPDATE and DELETE", ""),
            ("for all using (true) with check (true)", "no row filter or row check", ""),
            ("using (true) with check (owner())", "USING accepts all existing rows for SELECT, UPDATE and DELETE", "INSERT"),
            ("using (owns(')')) with check (true)", "WITH CHECK accepts all proposed rows for INSERT and UPDATE", "SELECT"),
            ("for delete using (true)", "existing rows for DELETE", "UPDATE"),
        ]:
            f, = scan("JH134", "create policy board on decks " + clause + ";", "tables.sql")
            self.assertIn(expected, f.message)
            if absent:
                self.assertNotIn(absent, f.message)
            self.assertIn("PUBLIC", f.message)

    def test_incomplete_disable_and_firebase(self):
        for tail in ("with check (true)", "using (true) with check ("):
            f, = scan("JH134", "create policy board on decks " + tail, "tables.sql")
            self.assertIn("could not be resolved", f.message)
            self.assertNotIn("PUBLIC", f.message)
        f, = scan("JH134", "alter table decks disable row level security;", "tables.sql")
        self.assertIn("Check the table grants", f.message)
        for ops in ("read", "get, list", "read, write", "write"):
            f, = scan("JH134", "allow " + ops + ": if true;", "firestore.rules")
            self.assertIn(ops, f.message)
            self.assertEqual("write" in f.message, "write" in ops)


class ApprovalOptions(unittest.TestCase):
    flag = "--dangerously" + "-skip-permissions"

    def test_inert_and_invocation_siblings(self):
        import json
        flag = self.flag
        for marker in ("amber ticket", "indigo paper"):
            fixtures = [
                ("catalog.json", json.dumps({"evidence": marker + flag, "command": "claude " + flag})),
                ("package.json", json.dumps({"description": marker + flag, "scripts": {"titleRun": "claude " + flag}})),
                ("guard.js", 'expect(args).not.toContain("%s"); spawn("claude", ["%s"])' % (flag, flag)),
                ("guard.js", 'if (arg === "%s") reject(); else launch("claude %s")' % (flag, flag)),
                ("agent.sh", "printf '%s' ; claude %s" % (flag, flag)),
                (".github/workflows/r.yml", "- run: claude " + flag),
            ]
            for path, text in fixtures:
                with self.subTest(path=path):
                    f, = scan("JH702", text, path)
                    self.assertEqual((f.column, f.severity), (text.rindex(flag) + 1, "major"))
                    self.assertIn("invocation supplies", f.message)
                    check_views(self, f, marker)
                    check_policy(self, [f], "P-AGT-001", True)
            for path, text in (("catalog.json", json.dumps({"help": marker + flag})),
                               ("args.py", 'assert "%s" not in args' % flag),
                               ("args.sh", 'echo "claude %s"' % flag),
                               ("args.js", 'if (arg !== "%s") proceed()' % flag)):
                hits = scan("JH702", text, path)
                self.assertEqual(hits, [])
                check_policy(self, hits, "P-AGT-001", False)

    def test_ambiguous_and_inert_last(self):
        for path, text in (("flags.js", 'const flag = "%s"'), ("job.toml", 'setting = "%s"'),
                           ("unknown.sh", 'relay "%s"')):
            f, = scan("JH702", text % self.flag, path)
            self.assertIn("unresolved", f.message)
            self.assertEqual(f.severity, "major")
        text = 'launch("claude %s"); console.log("%s")' % (self.flag, self.flag)
        f, = scan("JH702", text, "args.js")
        self.assertEqual(f.column, text.index(self.flag) + 1)


class HtmlWrites(unittest.TestCase):
    def test_complete_and_computed_values(self):
        for rhs in ['"fixed"', "'<br>' + 'deck'", '("a" + ("b" + "c"))', '`fixed\nmarkup`']:
            self.assertEqual(scan("JH126", "el.innerHTML = " + rhs + ";", "render.js"), [])
        for rhs in ['"<br>"\n\n\n\n + value', '`<i>${LABEL}</i>`', 'model.render(result)',
                    '("<p>" + "a").trim()', '"deck".slice(1)', 'value[0]', 'sanitizer.sanitize(value)']:
            f, = scan("JH126", "el.outerHTML = " + rhs + ";", "render.js")
            self.assertIn("computed markup to outerHTML", f.message)
            self.assertGreaterEqual(f.line, 1)
        for rhs in ['"open', '"a" +', '("one" + "two"', 'choose("closed"']:
            f, = scan("JH126", "el.innerHTML = " + rhs, "render.js")
            self.assertIn("unresolved", f.message)

    def test_neighbors_and_receipts(self):
        fixed, dynamic = 'a.innerHTML = "<br>" + "deck";', 'b.outerHTML = model.value;'
        for path in ("panel.js", "deck.js"):
            for text in (fixed + dynamic, dynamic + fixed):
                f, = scan("JH126", text, path)
                self.assertEqual((f.column, f.severity), (text.index(".outerHTML") + 1, "major"))
                check_views(self, f, "model.value")
        hits = scan("JH126", dynamic + dynamic, "deck.js")
        self.assertEqual(len({f.column for f in hits}), 2)


class CleanupClaims(unittest.TestCase):
    def test_matched_listener_lifetime(self):
        template = """function observe() {
  bus.%s("rise", watcher);
  return () => {
    try { bus.%s("rise", watcher); } catch {}
  };
}
"""
        for register, remove in [("addEventListener", "removeEventListener"), ("on", "off")]:
            src = template % (register, remove)
            f, = scan("JH201", src, "observe.js")
            self.assertEqual((f.line, f.severity), (4, "info"))
            self.assertIn("unregistering the listener", f.message)
            check_views(self, f, "watcher")
            for changed in (src.replace('("rise", watcher); }', '("fall", watcher); }'),
                            src.replace("try { bus.", "try { return bus."),
                            src.replace("} catch {}", "} catch {}\n    state.done = true;")):
                f, = scan("JH201", changed, "observe.js")
                self.assertNotEqual(f.severity, "info")

    def test_owned_temporary_file(self):
        src = """def collect():
    with tempfile.NamedTemporaryFile(delete=False) as note:
        note.write(payload)
    try:
        os.unlink(note.name)
    except OSError:
        pass
"""
        f, = scan("JH201", src, "notes.py")
        self.assertEqual((f.line, f.severity), (6, "info"))
        self.assertIn("removing the temporary file", f.message)
        for changed in (src.replace("note.name", "saved_path"), src + "    state.done = True\n",
                        src.replace("pass", "pass\n        if required:\n            raise")):
            self.assertFalse(any(f.severity == "info" for f in scan("JH201", changed, "notes.py")))

    def test_primary_and_uncertain_operations(self):
        for body in ("db.commit()", "repo.save(item)", "archive.delete(key)"):
            f, = scan("JH201", "try { " + body + "; } catch {}", "work.js")
            self.assertEqual(f.severity, "major")
            self.assertIn(body.split(".")[1].split("(")[0], f.message)
            self.assertNotIn("succeeded", f.message)
        f, = scan("JH201", "try { pool.close(); } catch {}\npool.closed = true;", "work.js")
        self.assertEqual(f.severity, "minor")
        self.assertIn("close()", f.message)
        self.assertIn("state update", f.message)
        self.assertEqual(scan("JH201", "try { save(); } catch (e) { if (needed) throw e; }", "work.js"), [])
