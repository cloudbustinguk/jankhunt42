"""Invented exports only. No n8n, JavaScript, database or network execution."""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from _util import run_cli
from test_map import build
import jh_capabilities as C
import jh_graph as G
import jh_explorer
import jh_map
import jh_n8n as N
import jh_views
from jh_core import source_from_text
from jh_rules import ScanOptions, scan_sources


def node(typ='httpRequest', version=4.2, params=None, nid='node-a', name='Node A'):
    return dict(id=nid, name=name, type='n8n-nodes-base.' + typ, typeVersion=version,
                parameters=params or {}, position=[0, 0])


def workflow(*nodes):
    return dict(id='workflow-a', name='Invented workflow', nodes=list(nodes), connections={})


def report(flow, path='flows/export.json'):
    r = build({path: json.dumps(flow)})
    r['source_revision'] = 'invented-snapshot'
    return r


def compare(before, after, path='flows/export.json', newpath=None):
    old = [jh_map.Item(path, json.dumps(before))]
    new = [jh_map.Item(newpath or path, json.dumps(after, indent=2))]
    return C.compare(report(before, path), report(after, newpath or path), old, new, None, {})


class N8nParsing(unittest.TestCase):
    def test_a_credential_type_selector_is_not_a_secret(self):
        # nodeCredentialType names a kind of credential ("exampleApi"); it held no secret in three corpus exports
        params = dict(url='https://api.example.invalid/v1', method='GET', authentication='predefinedCredentialType',
                      nodeCredentialType='exampleOAuth2Api', genericAuthType='httpHeaderAuth')
        flow = workflow(node(params=params))
        self.assertEqual(N.secret_sites(params), [])
        self.assertIsNotNone(N.parse('flows.json', json.dumps(flow))[0]['definition'])
        # a literal secret beside it is still a lead
        params['headerParameters'] = {'parameters': [{'name': 'Authorization',
                                                       'value': 'Bearer ' + 'Zx9' * 12}]}
        self.assertEqual(len(N.secret_sites(params)), 1)

    def test_detection_and_arrays(self):
        f = workflow(node())
        self.assertEqual(len(N.parse('flows.json', json.dumps(f))), 1)
        self.assertEqual(len(N.parse('flows.json', '\ufeff' + json.dumps(f))), 1)
        other = copy.deepcopy(f)
        other['id'] = 'workflow-b'
        self.assertEqual(len(N.parse('flows.json', json.dumps([f, other]))), 2)
        self.assertIsNone(N.parse('graph.json', json.dumps(dict(nodes=[dict(id='a')], connections={}))))
        self.assertIsNone(N.parse('notes.md', json.dumps(f)))
        self.assertEqual(jh_map._classify_file('graph.json', '{"nodes": []}')[0], 'unsupported')
        # An adversary cannot hide a real export by putting it in tests/.
        self.assertEqual(jh_map._classify_file('tests/example.json', json.dumps(f))[0], 'n8n')
        community = workflow(node())
        community['nodes'][0]['type'] = 'custom-package.unknownNode'
        self.assertEqual(len(N.parse('community.json', json.dumps(community))), 1)
        self.assertEqual(N.operation(community['nodes'][0])[1], 'unknown')

    def test_invalid_is_partial(self):
        f = workflow(node())
        cases = [json.dumps(f)[:-1], json.dumps(f).replace('"connections": {}', '"connections": {}, "connections": {}')]
        for mutate in (lambda x: x['nodes'].append(copy.deepcopy(x['nodes'][0])),
                       lambda x: x['nodes'][0].pop('id'), lambda x: x.pop('connections'),
                       lambda x: x.update(connections={'missing': {'main': [[]]}})):
            bad = copy.deepcopy(f)
            mutate(bad)
            cases.append(json.dumps(bad))
        for text in cases:
            with self.subTest(text=text[:40]):
                r = build({'flow.json': text})
                self.assertTrue(r['coverage']['partial_reasons'], r['coverage'])
                self.assertTrue(r['coverage']['parse_failures'])

    def test_malformed_fields_never_abort_scanning(self):
        f = workflow(node())
        variants = []
        for target in (None, [], {}, 1, True):
            bad = copy.deepcopy(f)
            bad['connections'] = {'Node A': {'main': [[dict(node=target, type='main', index=0)]]}}
            variants.append(bad)
        bad = copy.deepcopy(f)
        bad['name'] = chr(0xd800)
        variants.append(bad)
        for bad in variants:
            text = json.dumps(bad)
            with self.assertRaises(ValueError):
                N.parse('flow.json', text)
            sf = source_from_text('flow.json', 'flow.json', text)
            scan_sources([sf], ScanOptions(rule_ids=['JH101'], min_severity='info'))
            self.assertTrue(build({'flow.json': text})['coverage']['parse_failures'])

    def test_limits_no_clean_truncation(self):
        f = workflow(node(params={'value': {'nested': {'again': [1, 2, 3]}}}))
        for limit, value in (('MAX_BYTES', 8), ('MAX_WORKFLOWS', 0), ('MAX_NODES', 0),
                             ('MAX_FIELDS', 3), ('MAX_DEPTH', 2), ('MAX_STRING', 3)):
            with self.subTest(limit=limit), patch.object(N, limit, value):
                self.assertTrue(report(f)['coverage']['partial_reasons'])
        f['nodes'].append(node(nid='b', name='B'))
        f['connections'] = {'Node A': {'main': [[dict(node='B', type='main', index=0)]]}}
        with patch.object(N, 'MAX_LINKS', 0):
            self.assertTrue(report(f)['coverage']['partial_reasons'])

    def test_execution_samples_ignored_and_no_path_reads(self):
        f = workflow(node('code', 2, {'jsCode': 'throw new Error("never execute")', 'filePath': '../../do-not-open'}))
        f['pinData'] = {'value': 'x' * 50000}
        f['staticData'] = {'value': 'x' * 50000}
        self.assertEqual(len(N.parse('flow.json', json.dumps(f))), 1)
        r = report(f)
        self.assertTrue(any(n['attributes'].get('unresolved') for n in r['graph']['nodes']))
        self.assertEqual({e['path'] for e in r['evidence']}, {'flows/export.json'})

    def test_versioned_operation_tables(self):
        cases = [('postgres', 2.8, 'select', 'read'), ('postgres', 2.8, 'upsert', 'write'),
                 ('postgres', 2.8, 'deleteTable', 'delete'), ('mySql', 2.5, 'deleteTable', 'delete'),
                 ('mongoDb', 1.5, 'find', 'read'), ('mongoDb', 1, 'findOneAndUpdate', 'write'),
                 ('googleSheets', 4.7, 'clear', 'delete'), ('googleSheets', 4.7, 'remove', 'delete'),
                 ('airtable', 1, 'append', 'write'), ('airtable', 2.2, 'deleteRecord', 'delete'),
                 ('airtable', 2.2, 'search', 'read')]
        for typ, v, op, cap in cases:
            with self.subTest(typ=typ, op=op):
                self.assertEqual(N.operation(node(typ, v, {'operation': op}))[1], cap)
        for n in (node('postgres', 99, {'operation': 'deleteTable'}), node('postgres', 2, {'operation': 'executeQuery'}),
                  node('postgres', 1, {'operation': 'select'}), node('mongoDb', 1, {'operation': 'aggregate'}),
                  node('airtable', 2, {'operation': 'delete'}), node('googleSheets', 4, {'operation': 'read', 'resource': 'spreadsheet'}),
                  node('httpRequest', 4, {'method': '={{$json.method}}'}), node('httpRequest', True)):
            self.assertEqual(N.operation(n)[1], 'unknown')


class N8nMapping(unittest.TestCase):
    def test_http_port_method_and_canonical_principal(self):
        host = '.'.join(('endpoint', 'invalid'))
        f = workflow(node(params={'url': 'https://' + host + ':8443/v1', 'method': 'DELETE'}))
        r = report(f)
        targets = [n for n in r['graph']['nodes'] if n['attributes'].get('host') == host]
        self.assertEqual(targets[0]['attributes']['port'], 8443)
        self.assertTrue(any(e['kind'] == 'calls' and e['capability'] == 'delete' for e in r['graph']['edges']))
        before = workflow()
        d = compare(before, f)
        self.assertTrue(any(x['kind'] == 'network' and x['target'] == dict(host=host, port=8443) for x in d['requests']))
        self.assertTrue(any(x['kind'] == 'authority' and x['action'] == 'delete' for x in d['requests']))
        self.assertTrue(all(x['principal'].startswith('n8n:') for x in d['requests']))
        for e in r['evidence']:
            self.assertEqual(e['line'], 1)
        self.assertTrue(any('JSON pointer: /nodes/0' in e['assumptions'] for e in r['evidence']))

    def test_unknown_http_code_trigger_and_community(self):
        for n in (node(params={'url': '={{$json.url}}'}), node(params={'url': 'https://' + '.'.join(('endpoint', 'invalid')), 'method': 'COPY'}),
                  node('code', 2, {'jsCode': 'return [];'}), node('function', 1), node('functionItem', 1),
                  node('unfamiliar', 1)):
            with self.subTest(typ=n['type']):
                r = report(workflow(n))
                rows, unknowns, _ = C.inventory(r, [])
                self.assertTrue(unknowns)
                self.assertTrue(any(x['kind'] == 'binding' for x in rows.values()))
        n = node(params={'url': 'https://' + '.'.join(('endpoint', 'invalid')), 'body': '={{$json.value}}'})
        self.assertTrue(C.inventory(report(workflow(n)), [])[1])
        n = node(params={'url': 'postgresql://' + '.'.join(('endpoint', 'invalid')), 'method': 'DELETE'})
        r = report(workflow(n))
        self.assertFalse(any(x['kind'] == 'database' for x in r['graph']['nodes']))
        self.assertTrue(C.inventory(r, [])[1])

    def test_db_scope_case_and_unknown_host(self):
        f = workflow(node('googleSheets', 4.7, {'operation': 'clear', 'documentId': {'__rl': True, 'value': 'DocCase', 'mode': 'id'},
                                             'sheetName': {'__rl': True, 'value': 'SheetCase', 'mode': 'id'}}))
        r = report(f)
        db = next(n for n in r['graph']['nodes'] if n['kind'] == 'database')
        self.assertEqual(db['attributes']['scope'], dict(documentId='DocCase', sheetName='SheetCase'))
        self.assertNotIn('host', db['attributes'])
        self.assertTrue(any(e['capability'] == 'delete' for e in r['graph']['edges']))
        self.assertTrue(db['attributes']['unresolved'])

    def test_connections_never_transfer_authority(self):
        a, b = node('code', 2), node(nid='b', name='B', params={'url': 'https://' + '.'.join(('endpoint', 'invalid')), 'method': 'DELETE'})
        f = workflow(a, b)
        f['connections'] = {'Node A': {'main': [[dict(node='B', type='main', index=0)]]}}
        r = report(f)
        rows, _, _ = C.inventory(r, [])
        ak = N.parse('f.json', json.dumps(f))[0]['nodes'][0]['key']
        self.assertFalse(any(x['principal'] == ak and x['kind'] == 'authority' for x in rows.values()))
        self.assertTrue(any(x['kind'] == 'authority' for x in rows.values()))

    def test_credentials_and_value_free_findings(self):
        secret = 'invented-' + 'credential-42'
        n = node(params={'headerParameters': {'parameters': [{'name': 'Authorization', 'value': secret}]}, 'password': secret})
        n['credentials'] = {'httpHeaderAuth': dict(id='cred-a', name='Named identity', password=secret)}
        f = workflow(n)
        text = json.dumps(f)
        sf = source_from_text('flow.json', 'flow.json', text)
        result = scan_sources([sf], ScanOptions(rule_ids=['JH101'], min_severity='info'))
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.extra['sites'], 2)
        self.assertTrue(any('/headerParameters/parameters/0/value' in p for p in finding.extra['json_pointers']))
        r = report(f)
        self.assertTrue(any(e['kind'] == 'authenticates-as' for e in r['graph']['edges']))
        self.assertIn('httpHeaderAuth:Named identity', json.dumps(r))
        self.assertIn('literal parameter /headerParameters/parameters/0/value', json.dumps(r))
        self.assertNotIn(secret, json.dumps(r) + str(finding) + json.dumps(N.definitions([jh_map.Item('flow.json', text)])))
        pretty = source_from_text('flow.json', 'flow.json', json.dumps(f, indent=2))
        self.assertNotIn(secret, str(scan_sources([pretty], ScanOptions(rule_ids=['JH101'], min_severity='info')).findings))
        for value in ('={{$env.AUTH_TOKEN}}', 'YOUR_TOKEN_HERE', 'short'):
            self.assertEqual(N.secret_sites({'password': value}), [])
        self.assertEqual(N.secret_sites({'jsonHeaders': json.dumps({'Authorization': secret})}), ['/jsonHeaders'])
        provider = 'ghp' + '_' + 'a1B2' * 10
        self.assertEqual(N.secret_sites({'body': provider}), ['/body'])
        shared = G.pseudonymize(r)
        self.assertNotIn('Named identity', json.dumps(shared))
        self.assertNotIn('credential_refs', json.dumps(shared))

    def test_label_paths_and_html_safety(self):
        n = node('code', 2, {'filePath': '../../outside'}, name='<script>\x1b[31mNode</script>')
        r = report(workflow(n), 'flows/export.json')
        self.assertEqual({e['path'] for e in r['evidence']}, {'flows/export.json'})
        labels = ' '.join(n['display_label'] for n in r['graph']['nodes'])
        self.assertNotIn('\x1b', labels)
        self.assertNotIn('../../outside', json.dumps(r))
        html = jh_explorer.render_map(r)
        self.assertEqual(html.count('<script'), 2)
        self.assertNotIn('<', html.split('id="jh-data">', 1)[1].split('</script>', 1)[0])
        self.assertNotIn('\x1b', jh_views.map_tty(r, color=False))
        n['name'] = '=FORMULA()'
        csv = jh_map.render_csv(report(workflow(n)))[0]
        self.assertIn("'=FORMULA()", csv)

    def test_defaults_legacy_scope_disabled_and_relabel(self):
        host = '.'.join(('endpoint', 'invalid'))
        for v in N.VERSIONS['httpRequest']:
            self.assertEqual(N.operation(node(version=v, params={'url': 'https://' + host}))[1], 'read')
        _, _, scope = N.operation(node('airtable', 1, {'operation': 'read', 'application': {'__rl': True, 'value': 'BaseCase'}, 'table': 'TableCase'}))
        self.assertEqual(scope, {'application': 'BaseCase', 'table': 'TableCase'})
        f = workflow(node(params={'url': 'https://' + host}))
        f['nodes'][0]['disabled'] = True
        r = report(f)
        self.assertTrue(any(n['attributes'].get('disabled') for n in r['graph']['nodes']))
        self.assertTrue(any(n['attributes'].get('host') == host for n in r['graph']['nodes']))
        changed = copy.deepcopy(f)
        changed['name'] = 'Relabeled workflow'
        changed['nodes'][0]['name'] = 'Relabeled node'
        self.assertEqual(compare(f, changed)['counts']['total'], 0)
        f.pop('id')
        self.assertEqual(compare(f, copy.deepcopy(f), newpath='elsewhere/export.json')['counts']['total'], 0)
        f['nodes'][0]['parameters']['options'] = {'proxy': 'https://' + '.'.join(('proxy', 'invalid'))}
        self.assertTrue(C.inventory(report(f), [])[1])

    def test_global_graph_caps_preserve_incomplete_comparison(self):
        f = workflow(node('code', 2))
        with patch.object(G, 'MAX_NODES', 1):
            r = report(f)
            self.assertTrue(r['coverage']['partial_reasons'])
            self.assertTrue(C.compare(r, r, [], [], None, {})['counts']['lower_bound'])

    def test_jh101_generic_patterns_preserved(self):
        value = 'ghp' + '_' + 'a1B2' * 10
        text = 'TOKEN = "' + value + '"\n'
        sf = source_from_text('app.py', 'app.py', text)
        result = scan_sources([sf], ScanOptions(rule_ids=['JH101'], min_severity='info'))
        self.assertTrue(result.findings)
        self.assertNotIn(value, str(result.findings))

    def test_whole_definition_move_rotation_and_late_edits(self):
        n = node('code', 2, {**{'padding' + str(i): i for i in range(30)}, 'jsCode': 'return [];'})
        f = workflow(n)
        d = compare(f, copy.deepcopy(f), newpath='moved/export.json')
        self.assertEqual(d['counts']['unknown'], 0)
        self.assertGreater(d['counts']['unchanged_unknown'], 0)
        changed = copy.deepcopy(f)
        changed['nodes'][0]['parameters']['jsCode'] = 'throw new Error("invented change");'
        d = compare(f, changed)
        self.assertGreater(d['counts']['unknown'], 0)
        self.assertTrue(any(u['change'] == 'definition-changed' for u in d['unknowns']))
        f['nodes'][0]['parameters']['password'] = 'invented-secret-a'
        changed = copy.deepcopy(f)
        changed['nodes'][0]['parameters']['password'] = 'invented-secret-b'
        # A community/Code node could treat a "password" parameter as code:
        # masked parameter values cannot prove an unchanged execution binding.
        self.assertGreater(compare(f, changed)['counts']['unknown'], 0)
        f['nodes'][0]['parameters'].pop('password')
        f['nodes'][0]['credentials'] = {'exampleApi': dict(id='reference-a', name='Named identity', value='invented-a')}
        changed = copy.deepcopy(f)
        changed['nodes'][0]['credentials']['exampleApi']['value'] = 'invented-b'
        self.assertEqual(compare(f, changed)['counts']['unknown'], 0)

    def test_upstream_and_rewire_changes_need_review(self):
        f = workflow(node('code', 2, {'jsCode': 'return []'}), node('code', 2, {'jsCode': 'return $json'}, nid='b', name='B'))
        changed = copy.deepcopy(f)
        changed['connections'] = {'Node A': {'main': [[dict(node='B', type='main', index=0)]]}}
        self.assertGreater(compare(f, changed)['counts']['unknown'], 0)
        changed = copy.deepcopy(f)
        changed['nodes'][1]['parameters']['jsCode'] = 'return [1]'
        self.assertGreater(compare(f, changed)['counts']['unknown'], 0)


@unittest.skipUnless(shutil.which('git'), 'git is not installed')
class N8nSnapshots(unittest.TestCase):
    def test_passport_git_delta_and_redaction(self):
        with tempfile.TemporaryDirectory(prefix='jh-n8n-') as tmp:
            root = Path(tmp, 'fixture')
            root.mkdir()
            env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
            env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull)
            def git(*args):
                return subprocess.check_output(['git', '-C', str(root)] + list(args), env=env, text=True, stderr=subprocess.PIPE).strip()
            def commit():
                git('add', '-A')
                git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'invented')
                return git('rev-parse', 'HEAD')
            git('init', '-q', '--template=')
            flow = workflow(node('code', 2, {'jsCode': 'return [];'}))
            path = root / 'export.json'
            path.write_text(json.dumps(flow))
            base = commit()
            flow['nodes'][0]['parameters']['jsCode'] = 'throw new Error("changed")'
            path.write_text(json.dumps(flow, indent=2))
            commit()
            for flags in ((), ('--redact',)):
                proc = run_cli('passport', str(root), '--base', base, '--json', *flags)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                r = json.loads(proc.stdout)
                self.assertGreater(r['capability_delta']['counts']['unknown'], 0)
                cap = next(x for x in r['assessment']['decision']['rules'] if x['rule'] == 'P-CAP-001')
                self.assertEqual(cap['outcome'], 'review')
                if flags:
                    self.assertNotIn('Invented workflow', proc.stdout)
                    self.assertNotIn('n8n_key', proc.stdout)


if __name__ == '__main__':
    unittest.main()
