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
                                            'botcomponents/cr123_helpdesk.topic.Greeting/data': 'kind: AdaptiveDialog\n'}),
                              's.zip')
        self.assertEqual([m for m, _ in members], ['s.zip!/solution.xml', 's.zip!/bots/cr123_helpdesk/bot.xml'])
        self.assertEqual([f.path for f in scan(dict(members), {'JH148'})], ['s.zip!/bots/cr123_helpdesk/bot.xml'])


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
