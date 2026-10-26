"""Invented destinations with independent expected host/port decisions."""
import json
from pathlib import Path
import tempfile
import unittest

import _util
import jh_egress
import jh_fence
import jh_map
import jh_views
from _util import run_cli


class ClaudePorts(unittest.TestCase):
    def setUp(self):
        self.first = '.'.join(('first', 'invalid'))
        self.second = '.'.join(('second', 'invalid'))

    def report(self, endpoints):
        nodes = [{'id': 'app', 'kind': 'application', 'display_label': 'app', 'attributes': {}}]
        for index, (host, port, engine) in enumerate(endpoints):
            attrs = {'host': host, 'engine': engine}
            if port is not None:
                attrs['port'] = port
            nodes.append({'id': str(index), 'kind': 'external', 'trust_domain': 'external',
                          'environment': 'unknown', 'attributes': attrs})
        return {'graph': {'nodes': nodes}, 'assessment': {'blast_radius': {'app': {
            'impacts': {'confidentiality': {str(i): {'tier': 2} for i in range(len(endpoints))}}}}}}

    def boundary(self, allow, deny=()):
        return jh_map.Item('.claude/settings.json', json.dumps({'sandbox': {'enabled': True,
            'network': {'allowedDomains': allow, 'deniedDomains': list(deny)}}}))

    def assess(self, endpoints, allow, deny=(), others=()):
        return jh_egress.compare(jh_egress.boundaries([self.boundary(allow, deny), *others]), self.report(endpoints))

    def pairs(self, rows):
        return [(row['host'], row.get('port')) for row in rows]

    def domains(self, text):
        return json.loads(text)['sandbox']['network']['allowedDomains']

    def test_default_export_keeps_unqualified_domains_and_no_version_note(self):
        report = self.report([(self.first, 443, 'https'), (self.first, 8443, 'https')])
        text, notes = jh_fence.emit('claude-code', report, None, 'test')
        self.assertEqual(self.domains(text), [self.first])
        self.assertNotIn(jh_fence.CLAUDE_PORT_NOTE, notes)

    def test_ceiling_keeps_distinct_ports_and_exact_compatibility_note(self):
        report = self.report([(self.first, 443, 'https'), (self.first, 8443, 'https'),
                              (self.first, 9443, 'https')])
        ceiling = {(self.first, 443), (self.first, 8443), (self.second, 443)}
        text, notes = jh_fence.emit('claude-code', report, None, 'test', ceiling)
        self.assertEqual(self.domains(text), [self.first + ':443', self.first + ':8443'])
        self.assertIn('port-qualified entries verified on Claude Code 2.1.310; earlier versions are unverified, '
                      'and the sandbox runtime before July 2026 rejected port suffixes', notes)
        self.assertNotIn('https://', '\n'.join(notes))
        self.assertNotIn('PR 426', '\n'.join(notes))
        result = jh_egress.compare(jh_egress.boundaries([jh_map.Item('.claude/settings.json', text)]), report)
        self.assertEqual(result['state'], 'declared')
        self.assertEqual(self.pairs(result['outside']), [(self.first, 9443)])

    def test_same_host_different_ports_are_not_covered_by_one_grant(self):
        result = self.assess([(self.first, 443, 'https'), (self.first, 8443, 'https')], [self.first + ':443'])
        self.assertEqual((result['state'], self.pairs(result['outside'])), ('declared', [(self.first, 8443)]))

    def test_both_outside_ports_survive_aggregation(self):
        result = self.assess([(self.first, 443, 'https'), (self.first, 8443, 'https')], [])
        self.assertEqual(self.pairs(result['outside']), [(self.first, 443), (self.first, 8443)])

    def test_unqualified_entry_admits_every_known_or_unknown_port(self):
        result = self.assess([(self.first, 443, 'https'), (self.first, 22, 'ssh'),
                              (self.first, None, 'custom')], [self.first])
        self.assertEqual((result['state'], result['outside'], result['unassessed']), ('declared', [], []))

    def test_denial_applies_only_to_its_port(self):
        result = self.assess([(self.first, 443, 'https'), (self.first, 8443, 'https')],
                             [self.first], [self.first + ':8443'])
        self.assertEqual(self.pairs(result['outside']), [(self.first, 8443)])
        self.assertIn('denied', result['outside'][0]['why'])

    def test_unqualified_denial_covers_all_ports(self):
        result = self.assess([(self.first, 443, 'https'), (self.first, 8443, 'https')], [self.first], [self.first])
        self.assertEqual(self.pairs(result['outside']), [(self.first, 443), (self.first, 8443)])

    def test_unknown_port_is_unassessed_instead_of_guessed(self):
        for allow, deny in (([self.first + ':443'], []), ([self.first], [self.first + ':443'])):
            with self.subTest(allow=allow, deny=deny):
                result = self.assess([(self.first, None, 'custom')], allow, deny)
                self.assertEqual((result['state'], result['outside']), ('unknown', []))
                self.assertEqual(self.pairs(result['unassessed']), [(self.first, None)])
                self.assertEqual(result['contexts'][0]['unused'], [])

    def test_unknown_port_still_allows_definite_outside_or_deny(self):
        for allow, deny in (([self.second + ':443'], []), ([self.first + ':443'], [self.first])):
            result = self.assess([(self.first, None, 'custom')], allow, deny)
            self.assertEqual((result['state'], self.pairs(result['outside'])), ('declared', [(self.first, None)]))

    def test_only_known_protocol_defaults_are_inferred(self):
        cases = [('https', 443), ('http', 80), ('postgresql', 5432)]
        for engine, port in cases:
            with self.subTest(engine=engine):
                result = self.assess([(self.first, None, engine)], [self.first + ':' + str(port)])
                self.assertEqual((result['state'], result['outside']), ('declared', []))
        for port in (True, False, '443', 0, 65536):
            result = self.assess([(self.first, port, 'https')], [self.first + ':443'])
            self.assertEqual(result['state'], 'unknown')

    def test_unused_entry_distinguishes_ports(self):
        result = self.assess([(self.first, 443, 'https')], [self.first + ':443', self.first + ':8443'])
        self.assertEqual(result['unused'], [self.first + ':8443 (.claude/settings.json)'])

    def test_wildcard_port_requires_a_strict_subdomain_and_matching_port(self):
        child = 'child.' + self.first
        result = self.assess([(child, 8443, 'https'), (child, 443, 'https'), (self.first, 8443, 'https')],
                             ['*.' + self.first + ':8443'])
        self.assertEqual(self.pairs(result['outside']), [(child, 443), (self.first, 8443)])

    def test_port_scoped_deny_all_is_not_an_allow_all(self):
        result = self.assess([(self.first, 22, 'ssh'), (self.first, 443, 'https')], [self.first], ['*:22'])
        self.assertEqual(self.pairs(result['outside']), [(self.first, 22)])
        self.assertEqual(self.assess([(self.first, 443, 'https')], ['*:443'])['state'], 'unknown')

    def test_malformed_suffixes_never_turn_into_host_grants(self):
        suffixes = (':0', ':65536', ':0443', ':443.' + self.second, ':', ':443:8443', ':443/path')
        for suffix in suffixes:
            with self.subTest(suffix=suffix):
                entry = self.first + suffix
                result = self.assess([(self.first, 443, 'https')], [entry])
                self.assertEqual(result['state'], 'unknown')
                self.assertEqual(result['outside'], [])
                self.assertIsNone(jh_fence.split_claude_domain(entry))
                text, _ = jh_fence.emit('claude-code', self.report([]), None, 'test')
                doc = json.loads(text)
                doc['sandbox']['network']['allowedDomains'] = [entry]
                self.assertTrue(jh_fence.validate('claude-code', json.dumps(doc)))

    def test_native_port_limits_and_bracketed_ip_are_supported(self):
        address = ':'.join(('2001', 'db8', '', '7'))
        for entry, expected in ((self.first, (self.first, None)),
                                (self.first.upper() + ':1', (self.first, 1)),
                                (self.first + ':65535', (self.first, 65535)),
                                ('[' + address + ']:8443', (address, 8443))):
            self.assertEqual(jh_fence.split_claude_domain(entry), expected)
        result = self.assess([(address, 443, 'https'), (address, 8443, 'https')], ['[' + address + ']:8443'])
        self.assertEqual(self.pairs(result['outside']), [(address, 443)])
        self.assertIsNone(jh_fence.split_claude_domain(address + ':443'))

    def test_context_union_keeps_both_ports_without_cross_tool_permission(self):
        codex = jh_map.Item('.codex/config.toml', '[features]\nnetwork_proxy = true\n'
                            '[features.network_proxy.domains]\n' + json.dumps(self.second) + ' = "allow"\n')
        result = self.assess([(self.first, 443, 'https'), (self.first, 8443, 'https')],
                             [self.first + ':443'], others=[codex])
        self.assertEqual(result['state'], 'declared')
        self.assertEqual([(r['port'], r['contexts']) for r in result['outside']],
                         [(443, ['codex']), (8443, ['claude-code', 'codex'])])

    def test_ordinary_strings_outside_settings_do_not_declare_a_boundary(self):
        ordinary = jh_map.Item('README.md', json.dumps({'sandbox': {'enabled': True,
            'network': {'allowedDomains': [self.first + ':443']}}}))
        self.assertEqual(jh_egress.boundaries([ordinary]), [])

    def test_cli_ceiling_is_opt_in_and_cannot_add_or_widen_discovery(self):
        with tempfile.TemporaryDirectory(prefix='jh-claude-ports-') as temp:
            base = Path(temp)
            root = base / 'repo'
            root.mkdir()
            (root / 'app.py').write_text('import requests\n' + '\n'.join(
                'requests.get(' + repr('https://' + self.first + ':' + str(port) + '/') + ')'
                for port in (443, 8443, 9443)) + '\n')
            ceiling = base / 'ceiling.json'
            ceiling.write_text(json.dumps({'schema': 'jankhunt.network-ceiling.v1',
                'allow': [{'host': host, 'port': port} for host, port in
                          ((self.first, 443), (self.first, 8443), (self.second, 443))]}))
            default = run_cli('passport', str(root), '--emit-sandbox-policy', 'claude-code')
            self.assertEqual(default.returncode, 0, default.stderr)
            self.assertIn(self.first, self.domains(default.stdout))
            result = run_cli('passport', str(root), '--emit-sandbox-policy', 'claude-code',
                             '--sandbox-network-ceiling', str(ceiling))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(self.domains(result.stdout), [self.first + ':443', self.first + ':8443'])
            self.assertIn(jh_fence.CLAUDE_PORT_NOTE, result.stderr)
            ceiling.write_text(json.dumps({'schema': 'jankhunt.network-ceiling.v1', 'allow': []}))
            empty = run_cli('passport', str(root), '--emit-sandbox-policy', 'claude-code',
                            '--sandbox-network-ceiling', str(ceiling))
            self.assertEqual(empty.returncode, 0, empty.stderr)
            self.assertEqual(self.domains(empty.stdout), [])
            self.assertIn(jh_fence.CLAUDE_PORT_NOTE, empty.stderr)

    def test_text_views_show_ports_for_distinct_outside_destinations(self):
        source = 'import requests\n' + '\n'.join(
            'requests.get(' + repr('https://' + self.first + ':' + str(port) + '/') + ')'
            for port in (443, 8443)) + '\n'
        col = jh_map.Collected(items=[jh_map.Item('app.py', source), self.boundary([])], considered=2)
        report = jh_map.build_report(col, '/x', 'app', 'fixture', None)
        self.assertEqual(self.pairs(report['egress']['outside']), [(self.first, 443), (self.first, 8443)])
        for view in (jh_map.markdown(report), jh_views.map_tty(report, color=False, ascii_only=True, columns=120)):
            for port in (443, 8443):
                self.assertIn(self.first + ':' + str(port), view)


if __name__ == '__main__':
    unittest.main()
