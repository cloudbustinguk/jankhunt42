"""Invented operator limits cannot be enlarged by repository discovery."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest

import _util
import jh_ceiling
import jh_fence
import jh_yaml
from _util import run_cli


class NetworkCeiling(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='jh-ceiling-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'repo'
        self.root.mkdir()
        self.path = self.base / 'operator.json'
        self.first = '.'.join(('first', 'invalid'))
        self.second = '.'.join(('second', 'invalid'))
        self.document = {'schema': jh_ceiling.SCHEMA,
                         'allow': [{'host': self.first, 'port': 8443}]}
        self.save()

    def save(self, doc=None, path=None):
        (path or self.path).write_text(json.dumps(self.document if doc is None else doc))

    def report(self, entries):
        return {'graph': {'nodes': [
            {'id': 'n%d' % index, 'kind': 'external', 'environment': 'unknown',
             'attributes': {'host': host, 'port': port, 'engine': 'https'}}
            for index, (host, port) in enumerate(entries)], 'edges': []}}

    def allowed(self, text):
        doc = jh_yaml.load_all(text)[0]
        return {(ep['host'], ep['port']) for policy in doc['network_policies'].values()
                for ep in policy['endpoints']}

    def test_load_and_empty_ceiling(self):
        self.assertEqual(jh_ceiling.load(str(self.path), str(self.root)), {(self.first, 8443)})
        self.save({'schema': jh_ceiling.SCHEMA, 'allow': []})
        self.assertEqual(jh_ceiling.load(str(self.path), str(self.root)), set())

    def test_repository_file_and_both_symlink_directions_are_rejected(self):
        inside = self.root / 'operator.json'
        self.save(path=inside)
        with self.assertRaises(ValueError):
            jh_ceiling.load(str(inside), str(self.root))
        links = [(self.root / 'outside-link.json', self.path),
                 (self.base / 'inside-link.json', inside),
                 (self.base / 'external-link.json', self.path)]
        for link, target in links:
            with self.subTest(link=link.name):
                link.symlink_to(target)
                with self.assertRaises(ValueError):
                    jh_ceiling.load(str(link), str(self.root))

    def test_repository_root_alias_does_not_hide_inside_input(self):
        alias = self.base / 'root-alias'
        alias.symlink_to(self.root, target_is_directory=True)
        inside = self.root / 'operator.json'
        self.save(path=inside)
        with self.assertRaises(ValueError):
            jh_ceiling.load(str(inside), str(alias))

    def test_directory_alias_cannot_select_an_external_ceiling(self):
        external = self.base / 'operator-directory'
        external.mkdir()
        policy = external / 'ceiling.json'
        self.save(path=policy)
        link = self.base / 'operator-alias'
        link.symlink_to(external, target_is_directory=True)
        with self.assertRaises(ValueError):
            jh_ceiling.load(str(link / 'ceiling.json'), str(self.root))
        root_alias = self.base / 'repo-alias'
        root_alias.symlink_to(self.root, target_is_directory=True)
        (self.root / 'policy-link').symlink_to(external, target_is_directory=True)
        result = run_cli('passport', str(root_alias), '--emit-sandbox-policy', 'openshell',
                         '--sandbox-network-ceiling', str(root_alias / 'policy-link' / 'ceiling.json'))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, '')

    def test_hard_link_to_repository_input_is_rejected(self):
        inside = self.root / 'linked.json'
        os.link(self.path, inside)
        with self.assertRaises(ValueError):
            jh_ceiling.load(str(self.path), str(self.root))

    def test_scanning_a_subdirectory_cannot_promote_parent_repository_policy(self):
        (self.base / '.git').mkdir()
        with self.assertRaises(ValueError):
            jh_ceiling.load(str(self.path), str(self.root))

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'FIFO unavailable')
    def test_fifo_is_rejected_without_reading(self):
        fifo = self.base / 'ceiling-fifo'
        os.mkfifo(fifo)
        with self.assertRaises(ValueError):
            jh_ceiling.load(str(fifo), str(self.root))

    def test_duplicate_fields_and_excessive_size_are_rejected(self):
        self.path.write_text('{"schema": ' + json.dumps(jh_ceiling.SCHEMA) + ', "allow": [], "allow": []}')
        with self.assertRaises(ValueError):
            jh_ceiling.load(str(self.path), str(self.root))
        self.path.write_bytes(b' ' * (jh_ceiling.MAX_BYTES + 1))
        with self.assertRaises(ValueError):
            jh_ceiling.load(str(self.path), str(self.root))

    def test_invalid_endpoint_shapes_are_rejected(self):
        entries = [{'host': host, 'port': 443} for host in
                   ('*', '*.' + self.first, self.first.upper(), 'https://' + self.first, self.first + ':443')]
        entries += [{'host': self.first, 'port': port} for port in (True, False, 0, -1, 65536, '443', None)]
        entries += [{'host': self.first}, {'host': self.first, 'port': 443, 'methods': ['GET']}, None]
        for index, entry in enumerate(entries):
            with self.subTest(case=index):
                self.save({'schema': jh_ceiling.SCHEMA, 'allow': [entry]})
                with self.assertRaises(ValueError):
                    jh_ceiling.load(str(self.path), str(self.root))

    def test_unknown_schema_fields_and_unbounded_lists_are_rejected(self):
        cases = [{}, {'schema': 'unknown', 'allow': []},
                 {'schema': jh_ceiling.SCHEMA, 'allow': [], 'network': 'unmodeled'},
                 {'schema': jh_ceiling.SCHEMA, 'allow': {}},
                 {'schema': jh_ceiling.SCHEMA, 'allow': self.document['allow'] * (jh_ceiling.MAX_ENDPOINTS + 1)}]
        for index, doc in enumerate(cases):
            with self.subTest(case=index):
                self.save(doc)
                with self.assertRaises(ValueError):
                    jh_ceiling.load(str(self.path), str(self.root))

    def test_exact_intersection_preserves_ports_and_never_adds_approval_only_entries(self):
        report = self.report([(self.first, 443), (self.first, 8443), (self.second, 8443)])
        ceiling = {(self.first, 8443), ('.'.join(('absent', 'invalid')), 443)}
        original = copy.deepcopy(report)
        text, notes = jh_fence.emit('openshell', report, None, 'test', ceiling)
        self.assertEqual(self.allowed(text), {(self.first, 8443)})
        self.assertEqual(report, original)
        self.assertTrue(any('operator network ceiling applied' in note for note in notes))

    def test_empty_ceiling_emits_an_empty_mapping(self):
        text, _ = jh_fence.emit('openshell', self.report([(self.first, 8443)]), None, 'test', set())
        self.assertEqual(jh_yaml.load_all(text)[0]['network_policies'], {})
        self.assertEqual(self.allowed(text), set())

    def test_ceiling_cannot_reintroduce_excluded_production_assets(self):
        report = self.report([(self.first, 8443)])
        report['graph']['nodes'][0]['environment'] = 'production'
        text, _ = jh_fence.emit('openshell', report, None, 'test', {(self.first, 8443)})
        self.assertEqual(self.allowed(text), set())

    def test_candidate_wildcard_cannot_be_authorized_by_an_exact_host(self):
        plan = {'allow': [{'host': '*.' + self.first, 'port': 443}], 'excluded': [], 'runtimes': []}
        self.assertEqual(jh_ceiling.constrain(plan, {(self.first, 443)})['allow'], [])

    def test_invalid_candidate_ports_do_not_become_valid_when_filtered(self):
        for port in (True, 0, -1, 65536):
            with self.subTest(port=port):
                plan = {'allow': [{'host': self.first, 'port': port}], 'excluded': [], 'runtimes': []}
                with self.assertRaises(ValueError):
                    jh_ceiling.constrain(plan, set())

    def test_host_only_exporters_are_refused(self):
        for fmt in ('codex',):
            with self.subTest(format=fmt):
                with self.assertRaises(ValueError):
                    jh_fence.emit(fmt, self.report([(self.first, 8443)]), None, 'test', set())

    def cli(self, *extra):
        return run_cli('passport', str(self.root), '--emit-sandbox-policy', 'openshell',
                       '--sandbox-network-ceiling', str(self.path), *extra)

    def test_cli_new_endpoint_cannot_enlarge_export(self):
        source = self.root / 'app.py'
        source.write_text('import requests\nrequests.get(' + repr('https://' + self.first + ':8443/') + ')\n')
        before = self.cli()
        self.assertEqual(before.returncode, 0, before.stderr)
        self.assertEqual(self.allowed(before.stdout), {(self.first, 8443)})
        with source.open('a') as f:
            f.write('requests.get(' + repr('https://' + self.second + ':8443/') + ')\n')
        after = self.cli()
        self.assertEqual(after.returncode, 0, after.stderr)
        self.assertEqual(before.stdout, after.stdout)

    def test_cli_rejects_repository_supplied_limit(self):
        inside = self.root / 'ceiling.json'
        self.save(path=inside)
        result = run_cli('passport', str(self.root), '--emit-sandbox-policy', 'openshell',
                         '--sandbox-network-ceiling', str(inside))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, '')

    def test_cli_requires_compatible_export(self):
        for args in ([], ['--emit-sandbox-policy', 'codex']):
            result = run_cli('passport', str(self.root), '--sandbox-network-ceiling', str(self.path), *args)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, '')

    def test_explicit_empty_ceiling_path_does_not_disable_limit(self):
        result = run_cli('passport', str(self.root), '--emit-sandbox-policy', 'openshell',
                         '--sandbox-network-ceiling', '')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, '')

    def test_malformed_utf8_and_deep_json_are_rejected(self):
        for index, raw in enumerate((b'{', b'\xff', b'[' * 2048 + b']' * 2048)):
            with self.subTest(case=index):
                self.path.write_bytes(raw)
                with self.assertRaises(ValueError):
                    jh_ceiling.load(str(self.path), str(self.root))


if __name__ == '__main__':
    unittest.main()
