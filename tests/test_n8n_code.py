"""Invented embedded programs are inert strings. No n8n/JS/package execution."""
import copy
import hashlib
import json
import re
import unittest
from unittest.mock import patch

import _util
import jh_capabilities as C
import jh_explorer
import jh_graph as G
import jh_map as M
import jh_n8n as N
import jh_n8n_code as E
import jh_views
from test_map import build
from test_n8n import compare, node, report, workflow


HOST = '.'.join(('invented-endpoint', 'invalid'))
URL = 'https://' + HOST + '/items'


def code_node(text, **kwargs):
    return node('code', 2, dict(jsCode=text), **kwargs)


def http_edges(rep):
    return [e for e in rep['graph']['edges'] if any(
        x['id'] in e['evidence_refs'] and x['adapter'] == 'javascript:http-call' for x in rep['evidence'])]


class EmbeddedCode(unittest.TestCase):
    def test_literal_call_contract_and_call_local_methods(self):
        for source, expected in (
            ('this.helpers.httpRequest({url: U, method: "DELETE"})', 'delete'),
            ('$http({url: U, method: "POST"})', 'write'),
            ('fetch(U)', 'read'), ('fetch(U, {method: "HEAD"})', 'read'),
            ('axios(U, {method: "PATCH"})', 'write'), ('axios.delete(U)', 'delete'),
            ('axios({url: U, method: "PUT"})', 'write'), ('axios.request({url: U})', 'read'),
            ('fetch(U); const unrelated = {method: "DELETE"};', 'read'),
            ('this.helpers.httpRequest({url: U, body: {method: "DELETE"}})', 'read')):
            with self.subTest(source=source):
                source = re.sub(r'\bU\b', lambda _: repr(URL), source)
                r = report(workflow(code_node(source)))
                self.assertEqual([e['capability'] for e in http_edges(r)], [expected])
                self.assertTrue(any(n['kind'] == 'unknown' for n in r['graph']['nodes']))

    def test_dynamic_and_example_text_never_invent_literal_calls(self):
        for source in ('fetch(runtimeUrl)', 'fetch(U + suffix)', 'fetch(`https://${host}/items`)',
                       'fetch(U, {method: verb})', 'fetch(U, {...options})',
                       'axios({url: U, url: runtimeUrl})', 'axios({[key]: U})',
                       'this.helpers.httpRequest({uri: U})', '$http(U)', '$http(runtimeOptions)',
                       '// fetch(U)', 'const prose = `fetch(U)`;', 'const name = "axios.delete(U)";',
                       'const send = fetch; send(U);'):
            with self.subTest(source=source):
                r = report(workflow(code_node(re.sub(r'\bU\b', lambda _: repr(URL), source))))
                self.assertEqual(http_edges(r), [])
                self.assertTrue(any(n['kind'] == 'unknown' for n in r['graph']['nodes']))

    def test_every_result_belongs_to_the_node_and_carries_provenance(self):
        source = '\n\nfetch(' + repr(URL) + ');'
        a = workflow(code_node(source, name='Same label'))
        b = copy.deepcopy(a)
        b['id'] = 'workflow-b'
        r = report([a, b])
        nodes = {n['id']: n for n in r['graph']['nodes']}
        calls = http_edges(r)
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(nodes[e['source']]['attributes'].get('n8n_key') for e in calls))
        evs = [v for v in r['evidence'] if v['adapter'] == 'javascript:http-call']
        self.assertEqual({v['json_pointer'] for v in evs}, {
            '/0/nodes/0/parameters/jsCode', '/1/nodes/0/parameters/jsCode'})
        self.assertEqual(len({v['id'] for v in evs}), 2)
        self.assertEqual({(v['path'], v['line'], v['code_line']) for v in evs}, {('flows/export.json', 1, 3)})
        requests, _, _ = C.inventory(r, [M.Item('flows/export.json', json.dumps([a, b]))])
        network = [v for v in requests.values() if v['kind'] == 'network']
        self.assertEqual(len(network), 2)
        self.assertTrue(all(v['principal'].startswith('n8n:') for v in network))
        self.assertTrue(all(v['evidence'][0].get('code_line') == 3 for v in network))
        shared = G.pseudonymize(r)
        self.assertTrue(any(v.get('code_line') == 3 for v in shared['evidence']))
        self.assertIn('code line 3', M.markdown(r))
        self.assertIn('code line 3', jh_views.map_tty(r, color=False, columns=160))
        self.assertIn('Code line: 3', jh_explorer.render_map(r))

    def test_deferred_operations_cannot_cross_nodes_or_inherit_repo_env(self):
        host_a = '.'.join(('invented-a', 'invalid'))
        host_b = '.'.join(('invented-b', 'invalid'))
        def body(host):
            return 'const pg = require("pg");\nconst conn = ' + repr('postgresql://' + host + '/fixture') + \
                   ';\nconst statement = "DELETE FROM fixture_rows";\nconst env = process.env.DATABASE_URL;'
        flow = workflow(code_node(body(host_a)), code_node(body(host_b), nid='node-b', name='Node B'))
        r = build({'flows/export.json': json.dumps(flow), 'config.env': 'DATABASE_URL=' + 'postgresql://' +
                   '.'.join(('invented-unrelated', 'invalid')) + '/fixture\n'})
        nodes = {n['id']: n for n in r['graph']['nodes']}
        principals = {n['display_label']: n['id'] for n in nodes.values() if n['attributes'].get('n8n_key')}
        for name, host in (('Node A', host_a), ('Node B', host_b)):
            deletes = [e for e in r['graph']['edges'] if e['source'] == principals[name] and e['capability'] == 'delete']
            self.assertEqual({nodes[e['target']]['attributes'].get('host') for e in deletes
                              if nodes[e['target']]['attributes'].get('host')}, {host})
            self.assertTrue(all(nodes[e['target']]['attributes'].get('engine') == 'postgresql' for e in deletes))
        code_edges = [e for e in r['graph']['edges'] if any(v.get('code_line') and v['id'] in e['evidence_refs']
                     for v in r['evidence'])]
        self.assertTrue(code_edges)
        self.assertTrue(all(nodes[e['source']]['attributes'].get('n8n_key') for e in code_edges))
        self.assertFalse(any(nodes[e['target']]['attributes'].get('host', '').startswith('invented-unrelated')
                             for e in code_edges))
        self.assertEqual(len([v for v in r['evidence'] if v['adapter'] == 'env:unresolved']), 2)

    def test_exact_upstream_parameters_and_defaults(self):
        body = 'fetch(' + repr(URL) + ')'
        for typ, version, params, count in (
            ('code', 1, dict(jsCode=body, language='python'), 1),
            ('code', 2, dict(jsCode=body), 1),
            ('code', 2, dict(jsCode=body, mode='runOnceForEachItem'), 1),
            ('code', 2, dict(jsCode=body, language='python', pythonCode=body), 0),
            ('code', 2, dict(jsCode=body, language='pythonNative', pythonCode=body), 0),
            ('code', 2, dict(jsCode=body, language='javascript'), 0),
            ('code', 2, dict(jsCode=body, mode='runtime-mode'), 0),
            ('code', True, dict(jsCode=body), 0), ('code', 99, dict(jsCode=body), 0),
            ('function', 1, dict(functionCode=body), 1), ('functionItem', 1, dict(functionCode=body), 1),
            ('function', 1, dict(jsCode=body), 0)):
            with self.subTest(typ=typ, version=version, params=params):
                r = report(workflow(node(typ, version, params)))
                self.assertEqual(len(http_edges(r)), count)
        missing = code_node(body)
        missing.pop('typeVersion')
        self.assertEqual(http_edges(report(workflow(missing))), [])

    def test_whole_code_comparison_and_no_label_path_injection(self):
        body = 'fetch(' + repr(URL) + ');\n' + '// harmless padding\n' * 40 + 'const tail = 1;'
        before = workflow(code_node(body))
        moved = compare(before, before, newpath='moved/export.json')
        self.assertEqual(moved['counts']['total'], 0)
        self.assertGreater(moved['counts']['unchanged_unknown'], 0)
        after = copy.deepcopy(before)
        after['nodes'][0]['parameters']['jsCode'] = body.replace('tail = 1', 'tail = 2')
        self.assertTrue(any(u.get('change') == 'definition-changed' for u in compare(before, after)['unknowns']))
        before['nodes'][0]['name'] = '../../forged\n<' + 'script>\x1b[31m'
        before['nodes'][0]['disabled'] = True
        before['active'] = False
        before['nodes'][0]['parameters']['jsCode'] = '// ../../not-open /nodes/99/parameters/jsCode\n' + body
        r = report(before)
        self.assertEqual({v['path'] for v in r['evidence']}, {'flows/export.json'})
        self.assertTrue(http_edges(r))
        self.assertEqual({v['json_pointer'] for v in r['evidence'] if 'json_pointer' in v}, {'/nodes/0/parameters/jsCode'})
        self.assertNotIn('\x1b', json.dumps(r, ensure_ascii=False))

    def test_caps_remain_partial_and_unknown(self):
        source = ('fetch(' + repr(URL) + ');\n') * 2
        for owner, name, value in ((E, 'MAX_CALLS', 0), (E, 'MAX_CALL_CHARS', 1),
                                   (E, 'MAX_CALL_DEPTH', 0), (M, 'MAX_LINE', 1), (N, 'MAX_STRING', 8)):
            with self.subTest(name=name), patch.object(owner, name, value):
                r = report(workflow(code_node(source)))
                self.assertTrue(r['coverage']['partial_reasons'])

    def test_provenance_api_rejects_forged_pointers(self):
        graph = G.Graph('fixture')
        for pointer in ('../../outside', '/nodes/../parameters/jsCode', '/nodes/0/parameters/../../elsewhere'):
            with self.assertRaises(ValueError):
                graph.add_evidence('flows/export.json', 1, 'javascript', '', 'observed',
                                   json_pointer=pointer, code_line=1)

    def test_embedded_source_credentials_stay_redacted(self):
        token = 'ghp' + '_' + 'a1B2c3D4' * 5
        source = 'const driver = require("pg"); const token = "' + token + '";\nfetch(' + repr(URL) + ')'
        r = report(workflow(code_node(source)))
        for rendered in (json.dumps(r), json.dumps(G.pseudonymize(r)), M.markdown(r),
                         jh_views.map_tty(r, color=False), jh_explorer.render_map(r)):
            self.assertNotIn(token, rendered)

    def test_ordinary_file_equivalence_fixture(self):
        # Golden captured before A12 from exact v3.6.1; tool version frozen for future releases.
        db = 'postgresql://' + '.'.join(('invented-data', 'invalid')) + '/fixture'
        files = {
            'plain.js': 'fetch(' + repr(URL) + ', {method: "DELETE"});\n',
            'client.ts': 'import axios from "axios";\naxios.post(' + repr(URL) + ', {});\n',
            'data.js': 'const driver = require("pg");\nconst source = ' + repr(db) + ';\nconst q = "DELETE FROM fixture_rows";\n',
            'reader.py': 'import requests\nrequests.get(' + repr(URL) + ')\n',
            'environment.js': 'const driver = require("pg");\nconst source = process.env.DATABASE_URL;\n',
            'config.env': 'DATABASE_URL=' + db + '\n',
            'comments.js': '// fetch(' + repr(URL) + ');\nconst text = "plain prose";\n',
        }
        items = [M.Item(k, v) for k, v in files.items()]
        # every embedded tool version stays frozen for the whole render, the HTML generator tag included
        frozen = patch.object(jh_explorer, 'VERSION', '3.6.1')
        frozen.start()
        self.addCleanup(frozen.stop)
        with patch.object(M, 'VERSION', '3.6.1'):
            r = M.build_report(M.Collected(items=items, considered=len(items)), '/nonexistent', 'invented-app',
                               'fixture', None, None, None, False, 'inventory.json')
        r['source_revision'] = 'invented-snapshot'
        r.pop('generated_at', None)
        requests, unknowns, reasons = C.inventory(r, items)
        data = dict(report=r, share=G.pseudonymize(r), inventory=dict(requests=requests, unknowns=unknowns, reasons=reasons),
                    markdown=M.markdown(r), html=jh_explorer.render_map(r),
                    tty=jh_views.map_tty(r, color=False, columns=160))
        digest = hashlib.sha256(json.dumps(data, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        self.assertEqual(digest, '7563abe6c71013c3a3bc706d9f6b27158c5c938c13c05445f6ee183f73dc70f2')



class MethodCase(unittest.TestCase):
    def test_a_lowercase_method_maps_like_an_uppercase_one(self):
        import jh_n8n_code
        calls, capped = jh_n8n_code.http_calls(
            "await axios({url: 'https://api.example.invalid/v1', method: 'post'});\n"
            "await fetch('https://api.example.invalid/v2', {method: 'delete'});\n")
        self.assertFalse(capped)
        self.assertEqual([(line, verb) for line, _, verb in calls], [(1, "write"), (2, "delete")])

if __name__ == '__main__':
    unittest.main()
