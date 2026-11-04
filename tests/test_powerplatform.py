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


# ---------------------------------------------------------------- canvas apps, Copilot Studio agents, env variables

def msapp(members):
    """A synthetic .msapp: a zip with Header.json and Properties.json, member names written with backslashes."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('Header.json', '{"DocVersion": "1.346"}')
        zf.writestr('Properties.json', '{"Name": "Demo"}')
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def control(name, rules, children=()):
    return {'Name': name, 'Rules': [{'Property': p, 'InvariantScript': s} for p, s in rules], 'Children': list(children)}


def plain_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        zf.writestr('readme.txt', 'x')
    return buf.getvalue()


class CanvasApps(unittest.TestCase):
    KEY = 'q7Zr2' + 'mX9pL4vN8wK3'

    def test_formulas_from_controls_are_listed(self):
        doc = {'TopParent': control('Screen1', [('OnVisible', 'Set(gblApiKey, "%s");\nNavigate(Home)' % self.KEY)],
                                    [control('btnGo', [('OnSelect', 'Launch("https://example.invalid")'), ('X', ' ')])])}
        self.assertEqual(P.formulas(json.dumps(doc)),
                         'Screen1.OnVisible: =Set(gblApiKey, "%s");\n    Navigate(Home)\n'
                         'btnGo.OnSelect: =Launch("https://example.invalid")\n' % self.KEY)
        self.assertEqual(P.formulas('not json'), '')
        self.assertEqual(P.formulas('{"TopParent": {"Name": "x", "Rules": []}}'), '')
        members, gaps = P.expand(msapp({'Controls\\1.json': json.dumps(doc), 'References\\DataSources.json': '{}'}),
                                 'apps/Demo.msapp')
        self.assertEqual(([m for m, _ in members], gaps), (['apps/Demo.msapp!/Controls/1.json!/formulas.yaml'], []))
        hits = scan(dict(members), {'JH101'})
        self.assertEqual([(f.rule, f.line) for f in hits], [('JH101', 1)])
        self.assertNotIn(self.KEY, hits[0].evidence)

    def test_the_source_format_is_preferred(self):
        src = 'Screens:\n  Screen1:\n    Properties:\n      OnVisible: =Set(gblApiKey, "%s")\n' % self.KEY
        doc = {'TopParent': control('Screen1', [('OnVisible', 'Set(gblApiKey, "%s")' % self.KEY)])}
        members, _ = P.expand(msapp({'Src\\Screen1.pa.yaml': src, 'Controls\\1.json': json.dumps(doc)}), 'a.msapp')
        self.assertEqual(members, [('a.msapp!/Src/Screen1.pa.yaml', src)])
        self.assertEqual([f.rule for f in scan(dict(members), {'JH101'})], ['JH101'])
        self.assertEqual(P.expand(plain_zip(), 'b.msapp'), ([], []))           # a zip named .msapp that is no app

    def test_a_security_namespace_prefix_is_not_a_secret(self):
        # Azure DevOps permission checks pass {token: "NAMESPACE:"}, an upper-case prefix, not a credential
        doc = {'TopParent': control('ddOrg', [('OnChange', 'UpdateContext({ok: First(Ado.HasPermissions(org, '
                                                           '"4", {token:"NAMESPACE:"}).value).Value})')])}
        members, _ = P.expand(msapp({'Controls\\59.json': json.dumps(doc)}), 'a.msapp')
        self.assertEqual(scan(dict(members), {'JH101'}), [])
        hidden = {'x.js': 'const c = {token: "HASH:%s"};\n' % self.KEY}
        self.assertEqual([f.rule for f in scan(hidden, {'JH101'})], ['JH101'])

    def test_an_app_inside_a_solution_is_read_one_level_deep(self):
        inner = msapp({'Src\\App.pa.yaml': 'App:\n  Properties:\n    OnStart: =Set(gblToken, "%s")\n' % self.KEY,
                       'Src\\Nested.msapp': msapp({'Src\\Deep.pa.yaml': 'x: =1\n'})})
        members, gaps = P.expand(solution_zip({'CanvasApps/demo_DocumentUri.msapp': inner,
                                               'CanvasApps/broken_DocumentUri.msapp': b'not a zip',
                                               'CanvasApps/plain_DocumentUri.msapp': plain_zip()}), 's.zip')
        self.assertEqual([m for m, _ in members],
                         ['s.zip!/solution.xml', 's.zip!/CanvasApps/demo_DocumentUri.msapp!/Src/App.pa.yaml'])
        self.assertEqual(sorted(gaps), ['s.zip!/CanvasApps/broken_DocumentUri.msapp: not a readable zip, not read',
                                        's.zip!/CanvasApps/plain_DocumentUri.msapp: not a canvas app this version reads, '
                                        'not read'])
        self.assertEqual([f.path for f in scan(dict(members), {'JH101'})],
                         ['s.zip!/CanvasApps/demo_DocumentUri.msapp!/Src/App.pa.yaml'])

    def test_app_limits(self):
        app = msapp({'Src\\App.pa.yaml': 'App: {}\n'})
        two = solution_zip({'CanvasApps/a.msapp': app, 'CanvasApps/b.msapp': app})
        saved = P.MAX_APPS, P.MAX_APP_BYTES, P.MAX_TOTAL_BYTES
        try:
            P.MAX_APPS = 1
            members, gaps = P.expand(two, 't.zip')
            self.assertEqual([m for m, _ in members], ['t.zip!/solution.xml', 't.zip!/CanvasApps/a.msapp!/Src/App.pa.yaml'])
            self.assertEqual(gaps, ['t.zip: more than 1 canvas apps, the rest not read'])
            P.MAX_APPS, P.MAX_APP_BYTES = saved[0], 64
            members, gaps = P.expand(two, 't.zip')
            self.assertEqual(len(members), 1)
            self.assertTrue(all('too large or too compressed' in g for g in gaps) and len(gaps) == 2, gaps)
            # the app and its members draw on the zip's one total: room for the manifest and the app, not its source
            manifest = zipfile.ZipFile(io.BytesIO(two)).getinfo('solution.xml').file_size
            P.MAX_APP_BYTES, P.MAX_TOTAL_BYTES = saved[1], manifest + len(app) + 4
            members, gaps = P.expand(two, 't.zip')
            self.assertEqual([m for m, _ in members], ['t.zip!/solution.xml'])
            self.assertEqual(gaps, ['t.zip: more than 0 MB to read, the rest not read'])
        finally:
            P.MAX_APPS, P.MAX_APP_BYTES, P.MAX_TOTAL_BYTES = saved


BOT = ('<bot schemaname="cr123_helpdesk">\n  <authenticationmode>%d</authenticationmode>\n'
       '  <authenticationtrigger>0</authenticationtrigger>\n  <name>Help &amp; Desk</name>\n</bot>\n')


class CopilotAgents(unittest.TestCase):
    def test_an_agent_with_no_sign_in(self):
        hits = scan({'src/bots/cr123_helpdesk/bot.xml': BOT % 1}, {'JH148'})
        self.assertEqual([(f.rule, f.line, f.severity) for f in hits], [('JH148', 2, 'major')])
        self.assertIn("'Help & Desk'", hits[0].message)
        for mode in (0, 2, 3, 4):
            self.assertEqual(scan({'src/bots/cr123_helpdesk/bot.xml': BOT % mode}, {'JH148'}), [], mode)
        self.assertEqual(scan({'bot.xml': BOT % 1}, {'JH148'}), [])                     # not an exported agent
        self.assertEqual(scan({'bots/x/bot.xml': '<other><authenticationmode>1</authenticationmode></other>'}, {'JH148'}), [])

    def test_agents_inside_a_solution_zip(self):
        members, _ = P.expand(solution_zip({'bots/cr123_helpdesk/bot.xml': BOT % 1,
                                            'bots/cr123_helpdesk/configuration.json': '{"$kind": "BotConfiguration"}',
                                            'botcomponents/cr123_helpdesk.topic.Greeting/data': 'kind: AdaptiveDialog\n',
                                            'botcomponents/cr123_helpdesk.topic.Greeting/botcomponent.xml': '<x/>',
                                            'botcomponents/cr123_helpdesk.file.Doc/filedata/doc.pdf': '%PDF'}),
                              's.zip')
        self.assertEqual([m for m, _ in members], ['s.zip!/solution.xml', 's.zip!/bots/cr123_helpdesk/bot.xml',
                                                   's.zip!/bots/cr123_helpdesk/configuration.json',
                                                   's.zip!/botcomponents/cr123_helpdesk.topic.Greeting/data'])
        self.assertEqual([f.path for f in scan(dict(members), {'JH148'})], ['s.zip!/bots/cr123_helpdesk/bot.xml'])


# Copilot Studio components, as a solution export keeps them (botcomponents/<bot>.<type>.<name>/data) and as the
# VS Code extension clones them (*.mcs.yml). The YAML follows Microsoft's published samples.
TOOL = ('kind: TaskDialog\ninputs:\n  - kind: AutomaticTaskInput\n    propertyName: query\n'
        '    description: What to look up.\n\nmodelDisplayName: %s\nmodelDescription: Looks up records.\naction:\n'
        '  kind: InvokeConnectorTaskAction\n  connectionReference: cr123_helpdesk.shared_commondataserviceforapps.abc\n'
        '  connectionProperties:\n    mode: %s\n\n  operationId: ListRecords\n')
MCP_TOOL = ('kind: TaskDialog\nmodelDisplayName: Orders server\nmodelDescription: Orders.\naction:\n'
            '  kind: InvokeExternalAgentTaskAction\n  connectionReference: cr123_helpdesk.shared_orders-5fmcp.abc\n'
            '  connectionProperties:\n    mode: Maker\n\n  operationDetails:\n    kind: ModelContextProtocolMetadata\n'
            '    operationId: InvokeServer\n')
TOPIC_STEP = ('kind: AdaptiveDialog\nbeginDialog:\n  kind: OnRecognizedIntent\n  id: main\n  actions:\n'
              '    - kind: InvokeConnectorAction\n      id: lookup\n      displayName: Find the order\n      input:\n'
              '        binding:\n          organization: current\n\n'
              '      connectionReference: cr123_helpdesk.shared_commondataserviceforapps.abc\n'
              '      connectionProperties:\n        mode: Maker\n')
SETTINGS = ('displayName: Help Desk\nschemaName: cr123_helpdesk\naccessControlPolicy: ChatbotReaders\n'
            'authenticationMode: %s\nconfiguration:\n  settings:\n    GenerativeActionsEnabled: %s\n\n'
            '  recognizer:\n    kind: GenerativeAIRecognizer\n')
AGENT = ('mcs.metadata:\n  componentName: Help Desk\nkind: GptComponentMetadata\ndisplayName: Help Desk\n'
         'instructions:%s\ngptCapabilities:\n  webBrowsing: false\n')
GPT = 'kind: GptComponentMetadata\ninstructions:%s\ngptCapabilities:\n  webBrowsing: false\n'
MAIL = ('kind: TaskDialog\n%smodelDisplayName: Send an email (V2)\nmodelDescription: Sends an email.\naction:\n'
        '  kind: InvokeConnectorTaskAction\n  connectionReference: cr123_helpdesk.%s.abc\n'
        '  connectionProperties:\n    mode: Invoker\n\n  operationId: %s\n')
AUTO_TO = 'inputs:\n  - kind: AutomaticTaskInput\n    propertyName: To\n    description: Who to email.\n\n'
MANUAL_TO = 'inputs:\n  - kind: ManualTaskInput\n    propertyName: %s\n    value: %s\n\n'
COMP = 'src/botcomponents/cr123_helpdesk.%s/data'
B = 'src/bots/cr123_helpdesk/bot.xml'
C = 'src/bots/cr123_helpdesk/configuration.json'


def topic_http(url, headers=''):
    return ('kind: AdaptiveDialog\nbeginDialog:\n  kind: OnRecognizedIntent\n  id: main\n  actions:\n'
            '    - kind: HttpRequestAction\n      id: call\n      method: Post\n      url: %s\n%s' % (url, headers))


def config(generative):
    return json.dumps({'$kind': 'BotConfiguration', 'settings': {'GenerativeActionsEnabled': generative}}, indent=2)


def line_of(text, words):
    return text[:text.index(words)].count('\n') + 1


def scan_tree(files, ids):
    """Scan files written to a real folder, so a component can look up its agent's other files."""
    root = tempfile.mkdtemp(prefix='jh-cs-')
    try:
        for rel, text in files.items():
            path = os.path.join(root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'w', encoding='utf-8') as fh:
                fh.write(text)
        sources = [source_from_text(rel, os.path.join(root, rel), text) for rel, text in files.items()]
        return scan_sources([s for s in sources if s], ScanOptions(rule_ids=ids)).findings
    finally:
        shutil.rmtree(root, ignore_errors=True)


class CopilotStudioComponents(unittest.TestCase):
    def test_component_files_are_yaml(self):
        from jh_core import detect_lang
        for rel, lang in (('botcomponents/cr1_a.topic.B/data', 'yaml'), ('x.zip!/botcomponents/c/data', 'yaml'),
                          ('src/data', 'text'), ('botcomponents/data', 'text'), ('botcomponents/a/b/data', 'text'),
                          ('agent/topics/Greeting.topic.mcs.yml', 'yaml')):
            self.assertEqual(detect_lang(rel), lang, rel)

    def test_tools_with_the_makers_credentials(self):
        files = {B: BOT % 2, COMP % 'action.Lookup': TOOL % ('Lookup accounts', 'Maker'),
                 COMP % 'action.Mine': TOOL % ('My records', 'Invoker'), COMP % 'action.Orders': MCP_TOOL,
                 COMP % 'topic.Orders': TOPIC_STEP,
                 COMP % 'topic.Other': 'kind: AdaptiveDialog\nsettings:\n  mode: Maker\n',     # not a connection
                 'notes/tool.yaml': TOOL % ('Not a component', 'Maker')}
        hits = sorted((f.path.split('.', 1)[1], f.line, f.severity, f.message) for f in scan_tree(files, {'JH150'}))
        self.assertEqual([h[:3] for h in hits], [('action.Lookup/data', 13, 'major'), ('action.Orders/data', 8, 'major'),
                                                 ('topic.Orders/data', 15, 'major')])
        self.assertIn("connector tool 'Lookup accounts' runs with the maker's own connection", hits[0][3])
        self.assertIn("MCP server tool 'Orders server'", hits[1][3])
        self.assertIn("connector action 'Find the order' in topic 'Orders'", hits[2][3])
        files[B] = BOT % 1                                     # and the agent needs no sign-in: anyone acts as the maker
        hits = scan_tree(files, {'JH150'})
        self.assertEqual(sorted(f.severity for f in hits), ['critical'] * 3)
        self.assertTrue(all('needs no sign-in' in f.message for f in hits))

    def test_an_agent_cloned_by_vs_code(self):
        files = {'agent/settings.mcs.yml': SETTINGS % ('None', 'true'), 'agent/agent.mcs.yml': AGENT % '',
                 'agent/actions/Lookup.mcs.yml': TOOL % ('Lookup accounts', 'Maker'),
                 'agent/actions/Mail.mcs.yml': MAIL % (AUTO_TO, 'shared_office365', 'SendEmailV2'),
                 'agent/topics/Call.topic.mcs.yml': topic_http('http://api.example.invalid/orders')}
        hits = sorted((f.rule, f.path, f.line, f.severity) for f in scan_tree(
            files, {'JH148', 'JH150', 'JH151', 'JH152', 'JH153'}))
        self.assertEqual(hits, [
            ('JH148', 'agent/settings.mcs.yml', 4, 'major'), ('JH150', 'agent/actions/Lookup.mcs.yml', 13, 'critical'),
            ('JH151', 'agent/topics/Call.topic.mcs.yml', 9, 'major'), ('JH152', 'agent/agent.mcs.yml', 5, 'minor'),
            ('JH153', 'agent/actions/Mail.mcs.yml', 15, 'major')])
        agent = scan_tree(files, {'JH148', 'JH152'})
        self.assertIn("'Help Desk' is set to No authentication (authenticationMode: None)", agent[0].message + agent[1].message)
        files['agent/settings.mcs.yml'] = SETTINGS % ('Integrated', 'false')
        self.assertEqual(sorted((f.rule, f.severity) for f in scan_tree(files, {'JH148', 'JH150', 'JH152'})),
                         [('JH150', 'major')])

    def test_http_requests_in_topics(self):
        cases = [('http://api.example.invalid/orders', 'major', 'over plain HTTP'),
                 ('="http://api.example.invalid/orders/" & Topic.OrderId', 'major', 'over plain HTTP'),
                 ('|-\n        http://api.example.invalid/orders', 'major', 'over plain HTTP'),
                 ('https://api.example.invalid:8443/orders', 'major', 'non-standard port'),
                 ('https://graph.microsoft.com/v1.0/me', 'minor', 'calls graph.microsoft.com with a raw HTTP request'),
                 ('https://contoso.sharepoint.com/sites/x/_api/web', 'minor', 'contoso.sharepoint.com'),
                 ('https://api.example.invalid/orders', None, None),
                 ('https://api.example.invalid:443/orders', None, None),
                 ('=Env.cr123_endpoint', None, None), ('="https://" & Env.cr123_host', None, None),
                 ('http://localhost:3978/api', None, None), ('http://127.0.0.1/x', None, None),
                 ('http://[::1', None, None)]
        for url, severity, words in cases:
            hits = found(topic_http(url), 'JH151', COMP % 'topic.Orders')
            self.assertEqual([(f.line, f.severity) for f in hits], [(9, severity)] if severity else [], url)
            if words:
                self.assertIn(words, hits[0].message, url)
                self.assertIn("topic 'Orders'", hits[0].message, url)
        secret = 'Vb7' + 'q4Lx9Mz2'
        hit = found(topic_http('http://api.example.invalid/x?code=' + secret), 'JH151', COMP % 'topic.Orders')[0]
        self.assertEqual(hit.evidence, 'url: http://api.example.invalid/x')
        self.assertNotIn(secret, hit.message)
        self.assertEqual(found(topic_http('http://api.example.invalid/'), 'JH151', 'notes/topic.yaml'), [])

    def test_generative_orchestration_without_instructions(self):
        def hits(files):
            return [(f.path.split('.', 1)[1], f.line, f.severity) for f in scan_tree(files, {'JH152'})]
        on = {C: config(True)}
        self.assertEqual(hits(dict(on, **{COMP % 'gpt.default': GPT % ''})), [('gpt.default/data', 2, 'minor')])
        self.assertEqual(hits(dict(on, **{COMP % 'gpt.default': GPT % ' ""'})), [('gpt.default/data', 2, 'minor')])
        self.assertEqual(hits(dict(on, **{COMP % 'gpt.default': GPT % ' |\n  \n'})), [('gpt.default/data', 2, 'minor')])
        self.assertEqual(hits(dict(on, **{COMP % 'gpt.default': 'kind: GptComponentMetadata\n'})),
                         [('gpt.default/data', 1, 'minor')])
        self.assertEqual(hits(dict(on, **{COMP % 'gpt.default': GPT % ' |\n  Answer questions about orders only.'})), [])
        self.assertEqual(hits({C: config(False), COMP % 'gpt.default': GPT % ''}), [])
        self.assertEqual(hits({COMP % 'gpt.default': GPT % ''}), [])                    # no configuration in the export
        self.assertEqual(hits(dict(on, **{COMP % 'gpt.other': GPT % ''})), [])
        self.assertEqual(hits(dict(on, **{COMP % 'gpt.default': 'kind: AdaptiveDialog\ninstructions:\n'})), [])
        msg = scan_tree(dict(on, **{COMP % 'gpt.default': GPT % ''}), {'JH152'})[0].message
        self.assertIn("The agent 'cr123_helpdesk' uses generative orchestration but has no instructions", msg)

    def test_email_sent_where_the_ai_chooses(self):
        def hits(inputs, api='shared_office365', op='SendEmailV2', path=COMP % 'action.Mail'):
            text = MAIL % (inputs, api, op)
            return [(f.line, f.severity) for f in found(text, 'JH153', path)], line_of(text, 'operationId')
        got, at = hits(AUTO_TO)
        self.assertEqual(got, [(at, 'major')])
        got, at = hits('')                                     # no input listed: the AI fills every one
        self.assertEqual(got, [(at, 'major')])
        for api, op in (('shared_outlook', 'SendEmail'), ('shared_office365', 'SharedMailboxSendEmailV2'),
                        ('shared_gmail', 'SendEmail'), ('shared_office365', 'ForwardEmail_V2'),
                        ('shared_office365', 'SendApprovalMail')):
            got, at = hits(AUTO_TO, api, op)
            self.assertEqual(got, [(at, 'major')], op)
        self.assertEqual(hits(MANUAL_TO % ('To', '=System.User.Email'))[0], [])
        self.assertEqual(hits(MANUAL_TO % ("'emailMessage/To'", 'helpdesk@example.invalid'))[0], [])
        self.assertEqual(hits(MANUAL_TO % ('ToRecipients', '=System.User.Email'), op='ForwardEmail_V2')[0], [])
        self.assertEqual(hits(MANUAL_TO % ('Subject', 'Your order'))[0][0][1], 'major')     # only the subject is fixed
        self.assertEqual(hits(AUTO_TO, op='GetEmailsV3')[0], [])
        self.assertEqual(hits(AUTO_TO, op='ReplyToV3')[0], [])
        self.assertEqual(hits(AUTO_TO, api='shared_sharepointonline')[0], [])
        self.assertEqual(hits(AUTO_TO, path='notes/mail.yaml')[0], [])
        msg = found(MAIL % (AUTO_TO, 'shared_office365', 'SendEmailV2'), 'JH153', COMP % 'action.Mail')[0].message
        self.assertIn("The tool 'Send an email (V2)' sends email (SendEmailV2) and the AI chooses who receives it", msg)

    def test_credentials_written_into_a_topic(self):
        token = 'Qm7' + 'x2Lp9Zr4Kd8W'
        for header, hit in (('Authorization: Bearer %s', True), ('Authorization: ="Bearer %s"', True),
                            ('x-api-key: %s', True), ('X-Functions-Key: %s', True),
                            ('Ocp-Apim-Subscription-Key: ="%s"', True), ("'api-key': =\"%s\"", True),
                            ('x-api-key: =Env.cr123_key', False), ('x-api-key: ="Bearer " & Env.cr123_key', False),
                            ('x-api-key: your-key-here', False), ('Content-Type: %s', False)):
            text = topic_http('https://api.example.invalid/', '      headers:\n        %s\n' % (
                header % token if '%s' in header else header))
            hits = found(text, 'JH101', COMP % 'topic.Orders')
            self.assertEqual([(f.line, f.severity) for f in hits], [(11, 'critical')] if hit else [], header)
            for f in hits:
                self.assertNotIn(token, f.evidence + f.message)
        text = topic_http('https://api.example.invalid/', '      headers:\n        x-api-key: %s\n' % token)
        self.assertEqual(found(text, 'JH101', 'notes/topic.yaml'), [])

    def test_a_solution_zip_with_an_agent(self):
        token = 'Wq3' + 'n8Kd2Lx7Pz5'
        export = solution_zip({
            'bots/cr123_helpdesk/bot.xml': BOT % 1, 'bots/cr123_helpdesk/configuration.json': config(True),
            'botcomponents/cr123_helpdesk.gpt.default/data': GPT % '',
            'botcomponents/cr123_helpdesk.action.Lookup/data': TOOL % ('Lookup accounts', 'Maker'),
            'botcomponents/cr123_helpdesk.topic.Orders/data': topic_http(
                'https://api.example.invalid/', '      headers:\n        x-api-key: %s\n' % token)})
        root = tempfile.mkdtemp(prefix='jh-cs-')
        try:
            with open(os.path.join(root, 'agent.zip'), 'wb') as fh:
                fh.write(export)
            p = run_cli('scan', root, '--json', '--no-config')
            got = sorted((f['rule'], f['path'], f['severity']) for f in json.loads(p.stdout)['findings']
                         if f['rule'] in ('JH101', 'JH148', 'JH150', 'JH151', 'JH152', 'JH153'))
            self.assertEqual(got, [
                ('JH101', 'agent.zip!/botcomponents/cr123_helpdesk.topic.Orders/data', 'critical'),
                ('JH148', 'agent.zip!/bots/cr123_helpdesk/bot.xml', 'major'),
                ('JH150', 'agent.zip!/botcomponents/cr123_helpdesk.action.Lookup/data', 'critical'),
                ('JH152', 'agent.zip!/botcomponents/cr123_helpdesk.gpt.default/data', 'minor')])
            for fmt in ('--json', '--md', '--sarif', '--html'):
                self.assertNotIn(token, run_cli('scan', root, fmt, '--no-config').stdout, fmt)
        finally:
            shutil.rmtree(root, ignore_errors=True)


def envdef(schema, typ, default=None, display=None):
    return ('<environmentvariabledefinition schemaname="%s">\n' % schema +
            ('  <defaultvalue>%s</defaultvalue>\n' % default if default is not None else '') +
            ('  <displayname default="%s">\n    <label description="%s" languagecode="1033" />\n  </displayname>\n'
             % (display, display) if display else '') +
            '  <secretstore>0</secretstore>\n  <type>%s</type>\n</environmentvariabledefinition>\n' % typ)


def envval(*values):
    items = [{'iscustomizable': '1', 'value': v} for v in values]
    return json.dumps({'environmentvariablevalues': {'environmentvariablevalue': items[0] if len(items) == 1 else items}},
                      indent=2)


DEF = 'src/environmentvariabledefinitions/%s/environmentvariabledefinition.xml'
VAL = 'src/environmentvariabledefinitions/%s/environmentvariablevalues.json'


class EnvironmentVariables(unittest.TestCase):
    SECRET = 'Zk4' + 'p9QwX2mR7tY5'

    def hits(self, files):
        found_ = scan(files, {'JH149'})
        for f in found_:
            self.assertNotIn(self.SECRET, f.evidence + f.message)
        return sorted((f.path.split('/')[2], f.severity, f.line) for f in found_)

    def test_text_variables_named_for_secrets(self):
        files = {DEF % 'cr1_OpenAIApiKey': envdef('cr1_OpenAIApiKey', 100000000),
                 DEF % 'cr1_ClientSecret': envdef('cr1_ClientSecret', 100000000, self.SECRET),
                 DEF % 'cr1_SmtpPassword': envdef('cr1_SmtpPassword', 100000000, 'Enter the password here'),
                 DEF % 'cr1_GraphPw': envdef('cr1_GraphPw', 100000000, 'replace-me-later'),
                 DEF % 'cr1_Setting7': envdef('cr1_Setting7', 100000000, display='Search API Key'),
                 DEF % 'cr1_VaultKey': envdef('cr1_VaultKey', 100000005),                 # Secret: Key Vault
                 DEF % 'cr1_StoragePwd': envdef('cr1_StoragePwd', 100000003),             # JSON
                 DEF % 'cr1_Endpoint': envdef('cr1_Endpoint', 100000000, 'https://api.example.invalid'),
                 DEF % 'cr1_TokenUrl': envdef('cr1_TokenUrl', 100000000, 'https://login.example.invalid/token')}
        self.assertEqual(self.hits(files), [('cr1_ClientSecret', 'critical', 2), ('cr1_GraphPw', 'major', 4),
                                            ('cr1_OpenAIApiKey', 'major', 3), ('cr1_Setting7', 'major', 6),
                                            ('cr1_SmtpPassword', 'major', 4)])

    def test_exported_current_values(self):
        kv = ('/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.KeyVault/'
              'vaults/v/secrets/s')
        files = {VAL % 'cr1_ClientSecret': envval(self.SECRET),
                 VAL % 'cr1_VaultSecret': envval(kv),
                 VAL % 'cr1_DemoKey': envval('a1b2' + self.SECRET + 'c3d4'),
                 VAL % 'cr1_LookupKey': envval('customer-region'),                       # ends in key, not a secret
                 VAL % 'cr1_TenantKey': envval('11111111-2222-3333-4444-555555555555'),  # a GUID id under a key name
                 VAL % 'cr1_Greeting': envval(self.SECRET),                              # not named for a secret
                 VAL % 'cr1_ApiToken': envval('changeme-please', 'second' + self.SECRET)}
        self.assertEqual(self.hits(files), [('cr1_ApiToken', 'critical', 10), ('cr1_ClientSecret', 'critical', 5),
                                            ('cr1_DemoKey', 'critical', 5)])

    def test_a_solution_zip_never_shows_the_values(self):
        token = 'Pq8' + 'r2Lm5Zx9Kd3W'
        app = msapp({'Src\\App.pa.yaml': 'App:\n  Properties:\n    OnStart: =Set(gblApiKey, "%s")\n' % token})
        export = solution_zip({DEF[4:] % 'cr1_ClientSecret': envdef('cr1_ClientSecret', 100000000, self.SECRET),
                               VAL[4:] % 'cr1_ClientSecret': envval(self.SECRET),
                               'bots/cr123_helpdesk/bot.xml': BOT % 1,
                               'CanvasApps/cr1_demo_DocumentUri.msapp': app})
        root = tempfile.mkdtemp(prefix='jh-pp-')
        try:
            with open(os.path.join(root, 'demo.zip'), 'wb') as fh:
                fh.write(export)
            with open(os.path.join(root, 'Loose.msapp'), 'wb') as fh:
                fh.write(app)
            p = run_cli('scan', root, '--json', '--no-config')
            got = sorted((f['rule'], f['path'], f['severity']) for f in json.loads(p.stdout)['findings']
                         if f['rule'] in ('JH101', 'JH148', 'JH149'))
            self.assertEqual(got, [
                ('JH101', 'Loose.msapp!/Src/App.pa.yaml', 'critical'),
                ('JH101', 'demo.zip!/CanvasApps/cr1_demo_DocumentUri.msapp!/Src/App.pa.yaml', 'critical'),
                ('JH148', 'demo.zip!/bots/cr123_helpdesk/bot.xml', 'major'),
                ('JH149', 'demo.zip!/environmentvariabledefinitions/cr1_ClientSecret/environmentvariabledefinition.xml',
                 'critical'),
                ('JH149', 'demo.zip!/environmentvariabledefinitions/cr1_ClientSecret/environmentvariablevalues.json',
                 'critical')])
            for fmt in ('--json', '--md', '--sarif', '--html'):
                out = run_cli('scan', root, fmt, '--no-config').stdout
                self.assertNotIn(self.SECRET, out, fmt)
                self.assertNotIn(token, out, fmt)
        finally:
            shutil.rmtree(root, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
