"""Supabase: a project's migrations replayed as one database. Every table, policy and value here is synthetic."""
import json
import os
import shutil
import tempfile
import unittest

import _util
from _util import run_cli
import jh_supabase as J
from jh_core import source_from_text
from jh_rules import ScanOptions, scan_sources

MIG = 'app/supabase/migrations/%s.sql'
NOTES = 'create table public.notes (\n  id uuid primary key,\n  owner uuid references auth.users,\n  body text\n);\n'


def scan(files, ids=('JH134', 'JH154', 'JH155')):
    sources = [source_from_text(p, '/fixture/' + p, t) for p, t in files.items()]
    return scan_sources([s for s in sources if s], ScanOptions(rule_ids=set(ids))).findings


def hits(files, ids=('JH134', 'JH154', 'JH155')):
    return sorted((f.rule, os.path.basename(f.path), f.line, f.severity) for f in scan(files, ids))


class Statements(unittest.TestCase):
    def test_split_keeps_strings_and_lifts_function_bodies(self):
        text = ("-- a comment; not a statement\ncreate table a (x text default 'semi;colon');\n/* block; */\n"
                "create function f() returns void as $body$ begin perform 1; end $body$ language plpgsql;\n"
                "create policy \"it's; fine\" on a using (x = 'o''k;');\ndo $$ begin alter table b enable row level "
                "security; end $$;\nselect $1")
        got = J.statements(text)
        self.assertEqual([(line, s.split()[0].lower()) for line, s, _ in got],
                         [(2, 'create'), (4, 'create'), (5, 'create'), (6, 'do'), (7, 'select')])
        self.assertIn("'semi;colon'", got[0][1])
        self.assertEqual(got[1][2], ' begin perform 1; end ')
        self.assertIn("\"it's; fine\"", got[2][1])
        self.assertIn("'o''k;'", got[2][1])
        self.assertIn('alter table b enable row level security', got[3][2])


class TablesWithoutRowLevelSecurity(unittest.TestCase):
    def test_exposure_follows_the_grants(self):
        self.assertEqual(hits({MIG % '001_notes': NOTES}), [('JH134', '001_notes.sql', 1, 'major')])
        f = scan({MIG % '001_notes': NOTES})[0]
        self.assertEqual(f.confidence, 'medium')
        self.assertIn('The table public.notes has no row-level security', f.message)
        anon = {MIG % '001_notes': NOTES, MIG % '002_grants': 'grant all on table "public"."notes" to "anon";\n'}
        self.assertEqual(hits(anon), [('JH134', '001_notes.sql', 1, 'critical')])
        self.assertIn('granted to anon', scan(anon)[0].message)
        users = {MIG % '001_notes': NOTES, MIG % '002_grants': 'grant select, insert on public.notes to authenticated;\n'}
        self.assertEqual(hits(users), [('JH134', '001_notes.sql', 1, 'major')])
        self.assertIn('anyone who signs up', scan(users)[0].message)
        for later in ('grant select on all tables in schema public to anon;',
                      'grant select on public.notes to public;'):
            self.assertEqual(hits({MIG % '001_notes': NOTES, MIG % '002_g': later}),
                             [('JH134', '001_notes.sql', 1, 'critical')], later)
        before = {MIG % '000_defaults': 'alter default privileges in schema public grant all on tables to anon;\n',
                  MIG % '001_notes': NOTES}
        self.assertEqual(hits(before), [('JH134', '001_notes.sql', 1, 'critical')])
        revoked = {MIG % '001_notes': NOTES, MIG % '002_r': 'revoke all on public.notes from anon, authenticated;\n'}
        self.assertEqual(hits(revoked), [])
        partial = {MIG % '001_notes': NOTES, MIG % '002_g': 'grant all on public.notes to anon;\n',
                   MIG % '003_r': 'revoke insert on public.notes from anon;\n'}
        self.assertEqual(hits(partial), [('JH134', '001_notes.sql', 1, 'critical')])     # it can still read

    def test_row_level_security_anywhere_in_the_migrations(self):
        for later in ('alter table public.notes enable row level security;',
                      'ALTER TABLE ONLY "public"."notes" ENABLE ROW LEVEL SECURITY;',
                      'do $$ begin\n  alter table public.notes enable row level security;\nend $$;',
                      'do $$ declare t text; begin for t in select tablename from pg_tables loop\n'
                      '  execute format(\'alter table %I enable row level security\', t);\nend loop; end $$;'):
            self.assertEqual(hits({MIG % '001_notes': NOTES, MIG % '002_rls': later}), [], later)
        self.assertEqual(hits({MIG % '002_rls': 'alter table public.notes enable row level security;',
                               MIG % '001_notes': NOTES}), [])                          # applied in name order
        self.assertEqual(hits({MIG % '002_drop': 'drop table public.notes;', MIG % '001_notes': NOTES}), [])
        renamed = {MIG % '001_notes': NOTES, MIG % '002_r': 'alter table public.notes rename to memos;\n'
                                                             'alter table public.memos enable row level security;'}
        self.assertEqual(hits(renamed), [])
        quoted = 'create table "public"."Notes" (id int);\nalter table public."Notes" enable row level security;'
        self.assertEqual(hits({MIG % '001_q': quoted}), [])
        mixed = 'create table "public"."Notes" (id int);\nalter table public.notes enable row level security;'
        self.assertEqual(hits({MIG % '001_q': mixed}), [('JH134', '001_q.sql', 1, 'major')])  # "Notes" is not notes

    def test_tables_that_are_not_served(self):
        self.assertEqual(hits({MIG % '001_notes': NOTES, MIG % '002_drop': 'drop table if exists public.notes;'}), [])
        self.assertEqual(hits({MIG % '001_t': 'create temp table scratch (id int);'}), [])
        self.assertEqual(hits({MIG % '001_p': NOTES.replace('public.notes', 'private.notes')}), [])
        exposed = {MIG % '001_p': NOTES.replace('public.notes', 'api.notes'),
                   'app/supabase/config.toml': '[db]\nport = 54322\n\n[api]\nenabled = true\nschemas = ["public", "api"]\n'}
        self.assertEqual(hits(exposed), [('JH134', '001_p.sql', 1, 'major')])
        self.assertEqual(hits({'db/schema.sql': NOTES}), [])                     # not a Supabase migration folder
        plain = hits({'db/schema.sql': NOTES + 'grant all on public.notes to anon;\n'})
        self.assertEqual(plain, [('JH134', 'schema.sql', 6, 'major')])      # outside one, a grant to anon is still a lead

    def test_policies_without_row_level_security_and_explicit_disable(self):
        files = {MIG % '001_notes': NOTES + 'create policy own on public.notes using (owner = auth.uid());\n'
                                            'create policy mine on public.notes for insert with check (true);\n'}
        got = scan(files, ('JH134',))
        self.assertEqual([(f.line, f.severity) for f in got], [(1, 'major'), (7, 'major')])
        self.assertIn('Its 2 policies are not enforced while row-level security is off.', got[0].message)
        off = {MIG % '001_notes': NOTES + 'alter table public.notes disable row level security;\n'}
        got = scan(off, ('JH134',))
        self.assertEqual([(f.line, f.message[:30]) for f in got], [(6, 'Row-level security is disabled'[:30])])


class PoliciesOnUserMetadata(unittest.TestCase):
    def test_user_metadata_is_not_an_authority(self):
        base = NOTES + 'alter table public.notes enable row level security;\n'
        for policy, found in (
                ("create policy admins on public.notes using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');",
                 True),
                ("create policy admins on public.notes using (exists (select 1 from auth.users u where u.id = "
                 "auth.uid() and u.raw_user_meta_data ->> 'role' = 'admin'));", True),
                ("create policy admins on public.notes using ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');",
                 False),
                ("create policy own on public.notes using (owner = auth.uid());", False)):
            got = hits({MIG % '001_notes': base + policy}, ('JH154',))
            self.assertEqual(got, [('JH154', '001_notes.sql', 7, 'major')] if found else [], policy)
        msg = scan({MIG % '001_notes': base + "create policy admins on public.notes using "
                                               "((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');"}, ('JH154',))
        self.assertIn("The policy 'admins' on public.notes decides access from user_metadata", msg[0].message)
        dropped = {MIG % '001_notes': base + "create policy admins on public.notes using "
                                             "((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');",
                   MIG % '002_fix': 'drop policy if exists admins on public.notes;'}
        self.assertEqual(hits(dropped, ('JH154',)), [])
        trigger = ("create function public.handle_new_user() returns trigger as $$ begin insert into public.profiles "
                   "(name) values (new.raw_user_meta_data ->> 'name'); return new; end $$ language plpgsql;")
        self.assertEqual(hits({MIG % '001_f': trigger}, ('JH154',)), [])


class ViewsAroundRowLevelSecurity(unittest.TestCase):
    BASE = NOTES + 'alter table public.notes enable row level security;\n'

    def view(self, text, extra=None):
        files = {MIG % '001_notes': self.BASE, MIG % '002_view': text}
        files.update(extra or {})
        return hits(files, ('JH155',))

    def test_views_that_run_as_their_owner(self):
        self.assertEqual(self.view('create view public.all_notes as select * from public.notes;'),
                         [('JH155', '002_view.sql', 1, 'major')])
        self.assertEqual(self.view('create materialized view note_counts as select owner, count(*) from notes n '
                                   'group by owner;'), [('JH155', '002_view.sql', 1, 'major')])
        for safe in ('create view public.all_notes with (security_invoker = true) as select * from public.notes;',
                     'create view public.all_notes with (security_invoker) as select * from public.notes;',
                     "create view public.all_notes with (security_barrier, security_invoker='on') as select * "
                     "from public.notes;",
                     'create view public.all_notes as select * from public.notes;\n'
                     'alter view public.all_notes set (security_invoker = on);',
                     'create view private.all_notes as select * from public.notes;',
                     'create view public.all_notes as select * from public.notes;\n'
                     'revoke all on public.all_notes from anon, authenticated;',
                     'create view public.all_notes as select * from public.notes;\ndrop view public.all_notes;',
                     'create view public.counts as select 1 from public.unprotected;'):
            self.assertEqual(self.view(safe), [], safe)
        msgs = scan({MIG % '001_notes': self.BASE,
                     MIG % '002_view': 'create materialized view note_counts as select owner from notes;'}, ('JH155',))
        self.assertIn('materialized view public.note_counts keeps a copy of public.notes', msgs[0].message)

    def test_a_view_of_auth_users(self):
        users = 'create or replace view user_status as select u.id, u.email from auth.users u;'
        self.assertEqual(self.view(users), [('JH155', '002_view.sql', 1, 'critical')])
        self.assertIn('reads auth.users', scan({MIG % '002_view': users}, ('JH155',))[0].message)


class EndToEnd(unittest.TestCase):
    def test_a_project_folder(self):
        root = tempfile.mkdtemp(prefix='jh-supa-')
        try:
            files = {'supabase/migrations/20250101000000_init.sql': NOTES + 'grant all on public.notes to anon;\n',
                     'supabase/migrations/20250102000000_views.sql':
                         'create view public.everyone as select email from auth.users;\n',
                     'supabase/config.toml': '[api]\nschemas = ["public"]\n'}
            for rel, text in files.items():
                os.makedirs(os.path.dirname(os.path.join(root, rel)), exist_ok=True)
                with open(os.path.join(root, rel), 'w', encoding='utf-8') as fh:
                    fh.write(text)
            p = run_cli('scan', root, '--json', '--no-config')
            got = sorted((f['rule'], f['path'], f['line'], f['severity']) for f in json.loads(p.stdout)['findings']
                         if f['rule'] in ('JH134', 'JH154', 'JH155'))
            self.assertEqual(got, [('JH134', 'supabase/migrations/20250101000000_init.sql', 1, 'critical'),
                                   ('JH155', 'supabase/migrations/20250102000000_views.sql', 1, 'critical')])
        finally:
            shutil.rmtree(root, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
