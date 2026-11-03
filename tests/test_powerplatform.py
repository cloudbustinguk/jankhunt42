"""Power Platform: Power Automate flows in solution exports. Every flow, name and value here is synthetic."""
import io
import json
import os
import shutil
import tempfile
import unittest
import zipfile

import _util
from _util import run_cli
import jh_powerplatform as P
from jh_core import source_from_text
from jh_rules import ScanOptions, scan_sources

IDS = {'JH144', 'JH145', 'JH146', 'JH147'}
SCHEMA = 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'


def flow(triggers=None, actions=None, refs=None):
    return json.dumps({'properties': {
        'connectionReferences': refs or {},
        'definition': {'$schema': SCHEMA, 'contentVersion': '1.0.0.0',
                       'triggers': triggers or {'manual': {'type': 'Request', 'kind': 'Button', 'inputs': {}}},
                       'actions': actions or {}}}}, indent=2)


def api(connector, op, **extra):
    node = {'type': 'OpenApiConnection',
            'inputs': {'host': {'apiId': '/providers/Microsoft.PowerApps/apis/' + connector, 'operationId': op,
                                'connectionName': connector}, 'parameters': {}}}
    node.update(extra)
    return node


def scan(files, ids=IDS):
    sources = [source_from_text(p, '/fixture/' + p, t) for p, t in files.items()]
    return scan_sources([s for s in sources if s], ScanOptions(rule_ids=ids)).findings


def found(text, rid, name='Workflows/Flow-1.json'):
    return [f for f in scan({name: text}, {rid}) if f.rule == rid]


class HttpTrigger(unittest.TestCase):
    def test_open_unknown_and_signed_in_triggers(self):
        open_ = flow({'manual': {'type': 'Request', 'kind': 'Http', 'inputs': {'triggerAuthenticationType': 'Anyone'}}})
        hits = found(open_, 'JH144')
        self.assertEqual([(f.severity, f.confidence) for f in hits], [('major', 'medium')])
        # public flow definitions write the open mode as All
        all_ = flow({'manual': {'type': 'Request', 'kind': 'Http', 'inputs': {'triggerAuthenticationType': 'All'}}})
        self.assertEqual([f.severity for f in found(all_, 'JH144')], ['major'])
        self.assertEqual(hits[0].line, [i for i, l in enumerate(open_.split('\n'), 1) if l.strip() == '"manual": {'][0])
        unknown = found(flow({'manual': {'type': 'Request', 'kind': 'Http', 'inputs': {'schema': {}}}}), 'JH144')
        self.assertEqual([(f.severity, f.confidence) for f in unknown], [('minor', 'low')])
        for trig in [{'type': 'Request', 'kind': 'Http', 'inputs': {'triggerAuthenticationType': 'Tenant'}},
                     {'type': 'Request', 'kind': 'Button', 'inputs': {}},
                     {'type': 'Request', 'kind': 'PowerAppV2', 'inputs': {}},
                     {'type': 'Recurrence', 'recurrence': {'frequency': 'Day'}}]:
            self.assertEqual(found(flow({'t': trig}), 'JH144'), [], trig)

    def test_only_flow_definitions_are_read(self):
        self.assertEqual(found(json.dumps({'definition': {'triggers': {'manual': {'type': 'Request'}}}}), 'JH144'), [])
        self.assertEqual(found('{"definition": "triggers", "actions": [1, 2]}', 'JH144'), [])
        self.assertEqual(found('{"properties": {"definition": ' + '[' * 3000 + ']' * 3000 + '}}', 'JH144'), [])


class SecretsInRunHistory(unittest.TestCase):
    def test_key_vault_and_http_credentials(self):
        kv = api('shared_keyvault', 'GetSecret')
        self.assertEqual([f.severity for f in found(flow(actions={'Get_secret': kv}), 'JH145')], ['major'])
        kv['runtimeConfiguration'] = {'secureData': {'properties': ['inputs', 'outputs']}}
        self.assertEqual(found(flow(actions={'Get_secret': kv}), 'JH145'), [])
        http = {'type': 'Http', 'inputs': {'method': 'GET', 'uri': 'https://api.example.invalid/v1',
                                           'headers': {'Authorization': "@{parameters('Token')}"}}}
        self.assertEqual([f.severity for f in found(flow(actions={'Call': http}), 'JH145')], ['minor'])
        http['runtimeConfiguration'] = {'secureData': {'properties': ['inputs']}}
        self.assertEqual(found(flow(actions={'Call': http}), 'JH145'), [])
        basic = {'type': 'Http', 'inputs': {'uri': 'https://api.example.invalid/', 'authentication':
                                            {'type': 'Basic', 'username': 'svc', 'password': "@parameters('Pw')"}}}
        self.assertEqual(len(found(flow(actions={'Call': basic}), 'JH145')), 1)
        plain = {'type': 'Http', 'inputs': {'uri': 'https://api.example.invalid/', 'headers': {'Accept': 'json'}}}
        self.assertEqual(found(flow(actions={'Call': plain}), 'JH145'), [])

    def test_actions_inside_scopes_conditions_switches_and_loops(self):
        kv = api('shared_keyvault', 'GetSecret')
        nested = {'Scope': {'type': 'Scope', 'actions': {
            'If': {'type': 'If', 'actions': {}, 'else': {'actions': {
                'Switch': {'type': 'Switch', 'cases': {'a': {'actions': {
                    'Loop': {'type': 'Foreach', 'actions': {'Deep_secret': kv}}}}}, 'default': {'actions': {}}}}}}}}}
        self.assertEqual([f.line > 1 for f in found(flow(actions=nested), 'JH145')], [True])


class ConsumerConnectors(unittest.TestCase):
    def test_personal_account_connectors_through_references(self):
        refs = {'PersonalMail': {'connection': {'connectionReferenceLogicalName': 'demo_gmail'},
                                 'api': {'name': 'shared_gmail'}}}
        send = {'type': 'OpenApiConnection', 'inputs': {'host': {'connectionName': 'PersonalMail',
                                                                 'operationId': 'SendEmailV2'}}}
        self.assertEqual(len(found(flow(actions={'Send': send}, refs=refs), 'JH146')), 1)
        for connector in ('shared_outlook', 'shared_dropbox', 'shared_onedrive', 'shared_googledrive'):
            self.assertEqual(len(found(flow(actions={'A': api(connector, 'X')}), 'JH146')), 1, connector)
        for connector in ('shared_office365', 'shared_onedriveforbusiness', 'shared_sharepointonline'):
            self.assertEqual(found(flow(actions={'A': api(connector, 'X')}), 'JH146'), [], connector)


class PersonalDataToAi(unittest.TestCase):
    def test_ai_connectors_ai_builder_and_ai_hosts(self):
        body = {'model': 'gpt-x', 'messages': [{'role': 'user', 'content': "Summarise for @{triggerBody()?['email']}"}]}
        http = {'type': 'Http', 'inputs': {'method': 'POST', 'uri': 'https://api.openai.com/v1/chat/completions',
                                           'body': body}}
        self.assertEqual(len(found(flow(actions={'Ask': http}), 'JH147')), 1)
        prompt = api('shared_commondataserviceforapps', 'aibuilderpredict_customprompt')
        prompt['inputs']['parameters'] = {'item/requestv2/text': "@outputs('Get_row')?['body/emailaddress1']"}
        self.assertEqual(len(found(flow(actions={'Prompt': prompt}), 'JH147')), 1)
        openai = api('shared_openaiip', 'ChatCompletion')
        openai['inputs']['parameters'] = {'prompt': "@{body('Parse')?['DateOfBirth']}"}
        self.assertEqual(len(found(flow(actions={'Ask': openai}), 'JH147')), 1)
        # no personal field, a redaction step, or a host that is not an AI service
        safe = json.loads(json.dumps(http))
        safe['inputs']['body']['messages'][0]['content'] = "Summarise @{triggerBody()?['ticketText']}"
        self.assertEqual(found(flow(actions={'Ask': safe}), 'JH147'), [])
        red = json.loads(json.dumps(http))
        red['inputs']['body']['messages'][0]['content'] = "@{body('Redact_PII')?['email']}"
        self.assertEqual(found(flow(actions={'Ask': red}), 'JH147'), [])
        # the word in a prompt is not a redaction step, and one redacted field does not cover another
        said = json.loads(json.dumps(http))
        said['inputs']['body']['messages'][0]['content'] = "Do not redact this: @{triggerBody()?['email']}"
        self.assertEqual(len(found(flow(actions={'Ask': said}), 'JH147')), 1)
        both = json.loads(json.dumps(http))
        both['inputs']['body']['messages'][0]['content'] = "@{body('Redact_PII')?['email']} @{triggerBody()?['phone']}"
        self.assertEqual(len(found(flow(actions={'Ask': both}), 'JH147')), 1)
        other = json.loads(json.dumps(http))
        other['inputs']['uri'] = 'https://openai.com.example.invalid/v1'
        self.assertEqual(found(flow(actions={'Ask': other}), 'JH147'), [])
        dataverse = api('shared_commondataserviceforapps', 'UpdateRecord')
        dataverse['inputs']['parameters'] = {'item/emailaddress1': "@triggerBody()?['email']"}
        self.assertEqual(found(flow(actions={'Save': dataverse}), 'JH147'), [])


def solution_zip(members, extra=()):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('solution.xml', '<ImportExportXml><SolutionManifest><UniqueName>Demo</UniqueName>'
                                    '</SolutionManifest></ImportExportXml>')
        zf.writestr('customizations.xml', '<ImportExportXml/>')
        zf.writestr('[Content_Types].xml', '<Types/>')
        for name, text in members.items():
            zf.writestr(name, text)
        for info, data in extra:
            zf.writestr(info, data)
    return buf.getvalue()


class SolutionZip(unittest.TestCase):
    def test_flows_are_read_from_inside_the_export(self):
        token = 'a8f3kd92' + 'jf83kd0s'
        open_ = flow({'manual': {'type': 'Request', 'kind': 'Http', 'inputs': {'triggerAuthenticationType': 'Anyone'}}},
                     {'Call': {'type': 'Http', 'inputs': {'uri': 'https://api.example.invalid/',
                                                          'headers': {'Authorization': 'Bearer ' + token}}}})
        members, gaps = P.expand(solution_zip({'Workflows/Open-1A2B.json': open_, 'Other/Notes.txt': 'x'}), 'solutions/demo.zip')
        self.assertEqual([m for m, _ in members], ['solutions/demo.zip!/solution.xml', 'solutions/demo.zip!/Workflows/Open-1A2B.json'])
        self.assertEqual(gaps, [])
        root = tempfile.mkdtemp(prefix='jh-pp-')
        try:
            os.makedirs(os.path.join(root, 'solutions'))
            with open(os.path.join(root, 'solutions', 'demo.zip'), 'wb') as fh:
                fh.write(solution_zip({'Workflows/Open-1A2B.json': open_, 'Workflows/Big.json': ' ' * (3 << 20)}))
            with open(os.path.join(root, 'solutions', 'other.zip'), 'wb') as fh:
                fh.write(solution_zip({}, ()).replace(b'solution.xml', b'solutionX.xml'))
            p = run_cli('scan', root, '--json', '--no-config')
            report = json.loads(p.stdout)
            got = sorted((f['rule'], f['path'], f['severity']) for f in report['findings']
                         if f['rule'] in ('JH101', 'JH144', 'JH145'))
            self.assertEqual(got, [('JH101', 'solutions/demo.zip!/Workflows/Open-1A2B.json', 'critical'),
                                   ('JH144', 'solutions/demo.zip!/Workflows/Open-1A2B.json', 'major'),
                                   ('JH145', 'solutions/demo.zip!/Workflows/Open-1A2B.json', 'minor')])
            self.assertNotIn(token, p.stdout)
            self.assertTrue(any('Big.json: too large or too compressed' in w for w in report['warnings']), report['warnings'])
            for fmt in ('--md', '--sarif', '--html'):
                self.assertIn('Big.json: too large or too compressed', run_cli('scan', root, fmt, '--no-config').stdout, fmt)
            sarif = json.loads(run_cli('scan', root, '--sarif', '--no-config').stdout)
            self.assertEqual(sarif['runs'][0]['invocations'][0]['toolExecutionNotifications'][0]['level'], 'warning')
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_a_flow_package_is_read_too(self):
        buf = io.BytesIO()
        kv = flow(actions={'Get_secret': api('shared_keyvault', 'GetSecret')})
        with zipfile.ZipFile(buf, 'w') as zf:
            zf.writestr('manifest.json', '{"schema": "1.0"}')
            zf.writestr('Microsoft.Flow/flows/manifest.json', '{}')
            zf.writestr('Microsoft.Flow/flows/0000-aaaa/definition.json', kv)
            zf.writestr('Microsoft.Flow/flows/0000-aaaa/apisMap.json', '{}')
        members, gaps = P.expand(buf.getvalue(), 'p.zip')
        self.assertEqual([m for m, _ in members], ['p.zip!/manifest.json', 'p.zip!/Microsoft.Flow/flows/0000-aaaa/definition.json'])
        hits = scan(dict(members), {'JH145'})
        self.assertEqual([f.path for f in hits], ['p.zip!/Microsoft.Flow/flows/0000-aaaa/definition.json'])

    def test_limits_and_lookalikes(self):
        self.assertEqual(P.expand(b'not a zip', 'a.zip'), ([], []))
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as zf:
            zf.writestr('Workflows/x.json', '{}')
        self.assertEqual(P.expand(buf.getvalue(), 'plain.zip'), ([], []))       # no solution manifest: not an export
        bomb = solution_zip({'Workflows/Bomb.json': ' ' * (3 * 1024 * 1024)})
        members, gaps = P.expand(bomb, 'b.zip')
        self.assertEqual([m for m, _ in members], ['b.zip!/solution.xml'])
        self.assertTrue(gaps and 'too large or too compressed' in gaps[0], gaps)
        members, _ = P.expand(solution_zip({'Workflows/../../etc/passwd.json': '{}', 'Workflows/sub/x.json': '{}'}), 'c.zip')
        self.assertEqual([m for m, _ in members], ['c.zip!/solution.xml'])
        self.assertTrue(P.expand(b'0' * (P.MAX_ZIP_BYTES + 1), 'd.zip')[1])
        # names that are not UTF-8 under the UTF-8 flag: reported, not silently skipped
        raw = bytearray(solution_zip({'Workflows/ab.json': '{}'}))
        for at in [i for i in range(len(raw)) if raw.startswith(b'Workflows/ab.json', i)]:
            raw[at + 10] = 0xff
        for at in [i for i in range(len(raw)) if raw.startswith(b'PK\x01\x02', i) or raw.startswith(b'PK\x03\x04', i)]:
            flag = at + (9 if raw.startswith(b'PK\x01\x02', at) else 7)
            raw[flag] |= 0x08                      # bit 11 is 0x0800: the high byte of the flag field
        members, gaps = P.expand(bytes(raw), 'e.zip')
        self.assertTrue(any('not valid UTF-8' in g for g in gaps), gaps)
        # a member whose recorded size understates its content is never read past the limit
        big = ' ' * (P.MAX_MEMBER_BYTES + 100)
        raw = bytearray(solution_zip({'Workflows/Lie.json': big}))
        import struct
        for at in [i for i in range(len(raw)) if raw.startswith(b'PK\x01\x02', i)]:
            if raw[at + 46:at + 46 + 17] == b'Workflows/Lie.json'[:17]:
                raw[at + 24:at + 28] = struct.pack('<I', 100)      # central directory: uncompressed size 100
        members, gaps = P.expand(bytes(raw), 'f.zip')
        self.assertFalse(any(len(t) > P.MAX_MEMBER_BYTES for _, t in members))
        self.assertEqual([m for m, _ in members], ['f.zip!/solution.xml'])
        self.assertTrue(any('Lie.json' in g for g in gaps), gaps)


if __name__ == '__main__':
    unittest.main()
