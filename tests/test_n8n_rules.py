"""n8n workflow rules JH156-JH159. Invented exports only; nothing is executed or evaluated."""
import json
import os
import shutil
import tempfile
import unittest

from _util import run_cli
from test_map import build
import jh_n8n as N
from jh_core import source_from_text
from jh_rules import ScanOptions, scan_sources

IDS = {'JH156', 'JH157', 'JH158', 'JH159'}
LC = '@n8n/n8n-nodes-langchain.'


def node(name, typ, params=None, version=1, **extra):
    n = dict(id='id-' + name.lower().replace(' ', '-'), name=name,
             type=typ if '.' in typ else 'n8n-nodes-base.' + typ, typeVersion=version,
             parameters=params or {}, position=[0, 0])
    n.update(extra)
    return n


def link(*pairs, channel='main'):
    """{source: {channel: [[{node: target}]]}} for (source, target) pairs."""
    out = {}
    for source, target in pairs:
        out.setdefault(source, {}).setdefault(channel, [[]])[0].append(dict(node=target, type=channel, index=0))
    return out


def workflow(nodes, *connections):
    merged = {}
    for c in connections:
        for source, outputs in c.items():
            for channel, groups in outputs.items():
                merged.setdefault(source, {}).setdefault(channel, [[]])[0].extend(groups[0])
    return json.dumps(dict(id='wf', name='Invented', nodes=nodes, connections=merged), indent=2)


def scan(text, ids=IDS, name='flows/export.json'):
    sf = source_from_text(name, '/fixture/' + name, text)
    return [f for f in scan_sources([sf], ScanOptions(rule_ids=ids)).findings if f.rule in ids]


def found(text, rid):
    return scan(text, {rid})


HOOK = node('Hook', 'webhook', {'path': 'in', 'httpMethod': 'POST'}, version=2)


class OpenTriggers(unittest.TestCase):
    def test_webhook_without_authentication(self):
        text = workflow([HOOK])
        [f] = found(text, 'JH156')
        self.assertEqual((f.severity, f.confidence), ('major', 'medium'))
        self.assertEqual(f.line, text.splitlines().index('      "id": "id-hook",') + 1)
        self.assertIn("The Webhook node 'Hook'", f.message)
        self.assertEqual(f.extra['json_pointer'], '/nodes/0')

    def test_authenticated_filtered_disabled_or_unknown_is_not_open(self):
        for n in (node('Hook', 'webhook', {'authentication': 'headerAuth'}),
                  node('Hook', 'webhook', {'authentication': 'jwtAuth'}),
                  node('Hook', 'webhook', {'options': {'ipWhitelist': '10.0.0.1'}}),
                  node('Hook', 'webhook', {'authentication': '={{ $vars.mode }}'}),
                  node('Hook', 'webhook', disabled=True),
                  node('Hook', 'n8n-nodes-community.webhook'),
                  node('Chat', LC + 'chatTrigger', {'public': False}),
                  node('Chat', LC + 'chatTrigger', {'public': True, 'authentication': 'n8nUserAuth'}),
                  node('Form', 'formTrigger', {'authentication': 'basicAuth'}, version=2.3)):
            with self.subTest(n=n):
                self.assertEqual(found(workflow([n]), 'JH156'), [])

    def test_public_chat_and_form(self):
        [chat] = found(workflow([node('Chat', LC + 'chatTrigger', {'public': True, 'mode': 'webhook'})]), 'JH156')
        self.assertEqual(chat.severity, 'major')
        self.assertIn('make it use its tools', chat.message)
        [form] = found(workflow([node('Form', 'formTrigger', {'formTitle': 'Contact'})]), 'JH156')
        self.assertEqual((form.severity, form.confidence), ('minor', 'low'))
        self.assertIn('meant to be public', form.message)


class ShellCommands(unittest.TestCase):
    def test_command_built_from_data(self):
        [f] = found(workflow([node('Dig', 'executeCommand', {'command': '=dig NS {{ $json.query.q }}'})]), 'JH157')
        self.assertEqual((f.severity, f.confidence), ('major', 'high'))
        self.assertIn('builds a shell command from workflow data ({{ $json.query.q }})', f.message)
        self.assertIn('on the n8n host', f.message)
        self.assertIn('n8n 2.0', f.message)
        self.assertEqual(f.evidence, 'Dig: {{ $json.query.q }}')

    def test_an_open_webhook_makes_it_critical(self):
        cmd = node('Dig', 'executeCommand', {'command': '=dig NS {{ $json.query.q }}'})
        middle = node('Tidy', 'set', {'mode': 'raw'})
        [f] = found(workflow([HOOK, middle, cmd], link(('Hook', 'Tidy'), ('Tidy', 'Dig'))), 'JH157')
        self.assertEqual(f.severity, 'critical')
        self.assertIn("open webhook trigger ('Hook')", f.message)
        guarded = node('Hook', 'webhook', {'authentication': 'basicAuth'})
        [f] = found(workflow([guarded, cmd], link(('Hook', 'Dig'))), 'JH157')
        self.assertEqual(f.severity, 'major')
        [f] = found(workflow([HOOK, cmd], link(('Dig', 'Hook'))), 'JH157')   # the trigger is downstream
        self.assertEqual(f.severity, 'major')

    def test_values_that_are_not_data(self):
        config = node('Config', 'set', {'assignments': {'assignments': [
            {'id': 'a', 'name': 'folder', 'type': 'string', 'value': '/srv/reports'},
            {'id': 'b', 'name': 'host', 'type': 'string', 'value': '={{ $env.HOST }}'},
            {'id': 'c', 'name': 'who', 'type': 'string', 'value': '={{ $json.user }}'}]}}, version=3.4)
        watch = node('Watch', 'localFileTrigger', {'path': '/srv/in'})
        for command in ('dig NS {{ $json.q }}',                                   # not an expression: literal text
                        '=echo {{ $execution.id }} {{ $now }} {{ $env.HOME }} {{ $vars.dir }}',
                        "=ls {{ $('Config').item.json.folder }} {{ $('Config').first().json.host }}",
                        "=ls {{ $('Watch').params.path }} {{ $node[\"Watch\"].parameter[\"path\"] }}"):
            with self.subTest(command=command):
                cmd = node('Run', 'executeCommand', {'command': command})
                self.assertEqual(found(workflow([config, watch, cmd]), 'JH157'), [])
        for command in ("=ls {{ $('Config').item.json.who }}", "=ls {{ $('Config').item.json.other }}",
                        "=ls {{ $node[\"Watch\"].json[\"path\"] }}", '=ls {{ $input.first().json.d }}'):
            with self.subTest(command=command):
                cmd = node('Run', 'executeCommand', {'command': command})
                self.assertEqual(len(found(workflow([config, watch, cmd]), 'JH157')), 1)

    def test_ssh_and_whole_commands(self):
        [f] = found(workflow([node('Remote', 'ssh', {'command': '={{ $json.sh }}', 'cwd': '/'})]), 'JH157')
        self.assertIn('runs a command taken whole from workflow data ({{ $json.sh }})', f.message)
        self.assertIn('the server the SSH credential reaches', f.message)
        self.assertNotIn('n8n 2.0', f.message)
        self.assertEqual(found(workflow([node('Remote', 'ssh', {'resource': 'file', 'command': '={{ $json.sh }}'})]),
                         'JH157'), [])
        [f] = found(workflow([node('Remote', 'ssh', {'command': '={{ $json.a }} {{ $json.b }}'})]), 'JH157')
        self.assertIn('builds a shell command', f.message)                    # two values, not one whole command
        self.assertEqual(found(workflow([node('Run', 'executeCommand', {'command': '=ls {{ $json.d }}'},
                                              disabled=True)]), 'JH157'), [])

    def test_agent_command_tool(self):
        chat = node('Chat', LC + 'chatTrigger', {'public': True})
        agent = node('Agent', LC + 'agent', {'promptType': 'auto'})
        tool = node('Shell', 'executeCommandTool', {'command': "={{ $fromAI('command') }}"})
        text = workflow([chat, agent, tool], link(('Chat', 'Agent')), link(('Shell', 'Agent'), channel='ai_tool'))
        [f] = found(text, 'JH157')
        self.assertEqual(f.severity, 'critical')
        self.assertIn("The AI agent's Execute Command tool 'Shell' runs a command the AI writes", f.message)
        self.assertIn("The agent answers an open chat trigger ('Chat')", f.message)


class SqlQueries(unittest.TestCase):
    def test_values_spliced_into_sql(self):
        q = node('Find', 'postgres', {'operation': 'executeQuery',
                                      'query': "SELECT * FROM t WHERE email = '{{ $json.email }}'"}, version=2.5)
        [f] = found(workflow([q]), 'JH158')
        self.assertEqual((f.severity, f.confidence), ('major', 'high'))
        self.assertIn("The Postgres node 'Find' splices workflow data into its SQL ({{ $json.email }})", f.message)
        self.assertIn('Query Parameters', f.message)

    def test_parameters_other_operations_and_constants_are_fine(self):
        for params in ({'operation': 'executeQuery', 'query': 'SELECT * FROM t WHERE id = $1',
                        'options': {'queryReplacement': '={{ $json.id }}'}},
                       {'operation': 'insert', 'table': '={{ $json.table }}'},
                       {'operation': 'executeQuery', 'query': 'SELECT {{ $now }} AS at'}):
            with self.subTest(params=params):
                self.assertEqual(found(workflow([node('Q', 'postgres', params, version=2.5)]), 'JH158'), [])

    def test_whole_query_from_the_ai_and_an_open_trigger(self):
        form = node('Form', 'formTrigger', {}, version=2.2)
        sql = node('Lookup', 'microsoftSql', {'operation': 'executeQuery', 'query': '=SELECT * FROM t WHERE n = {{ $json.n }}'})
        [f] = found(workflow([form, sql], link(('Form', 'Lookup'))), 'JH158')
        self.assertEqual(f.severity, 'critical')
        self.assertIn("Microsoft SQL node 'Lookup'", f.message)
        tool = node('Run SQL', 'mySqlTool', {'operation': 'executeQuery', 'query': '{{ $fromAI("sql_query") }}'}, version=2.4)
        [f] = found(workflow([tool]), 'JH158')
        self.assertIn('runs SQL taken whole from what the AI writes', f.message)
        self.assertEqual(f.severity, 'major')

    def test_hand_escaped_values(self):
        one = "INSERT INTO n VALUES ('{{ $json.text.replace(/'/g, \"''\") }}')"
        [f] = found(workflow([node('Save', 'postgres', {'operation': 'executeQuery', 'query': one})]), 'JH158')
        self.assertEqual((f.severity, f.confidence), ('minor', 'low'))
        self.assertIn('escapes quotes by hand', f.message)
        both = "INSERT INTO n VALUES ('{{ $json.text.replace(/'/g, \"''\") }}', '{{ $json.speaker }}')"
        [f] = found(workflow([node('Save', 'postgres', {'operation': 'executeQuery', 'query': both})]), 'JH158')
        self.assertEqual(f.severity, 'major')
        self.assertIn('{{ $json.speaker }}', f.message)


class PersonalDataToAi(unittest.TestCase):
    def agent(self, text, model='lmChatOpenAi', source=None):
        nodes = [node('Agent', LC + 'agent', {'promptType': 'define', 'text': text}),
                 node('Model', LC + model, {'model': 'invented'})]
        if source:
            nodes.append(node(*source))
        return workflow(nodes, link(('Model', 'Agent'), channel='ai_languageModel'))

    def test_personal_fields_to_a_hosted_model(self):
        [f] = found(self.agent('=Reply to {{ $json.customerEmail }} at {{ $json["Phone Number"] }}'), 'JH159')
        self.assertEqual((f.severity, f.confidence), ('major', 'medium'))
        self.assertIn("The node 'Agent' sends personal data (customerEmail, Phone Number) to an AI model ('Model')",
                      f.message)

    def test_local_models_redaction_and_lookalikes(self):
        self.assertEqual(found(self.agent('={{ $json.email }}', model='lmChatOllama'), 'JH159'), [])
        for text, source in (("={{ $('Redact PII').item.json.email }}", ('Redact PII', 'code')),
                             ("={{ $('Check').item.json.email }}", ('Check', LC + 'guardrails')),
                             ('={{ $json.email_subject }} {{ $json.ip_address }} {{ $json.emailBody }}', None),
                             ('Summarise {{ $json.email }}', None)):          # not an expression: never evaluated
            with self.subTest(text=text):
                self.assertEqual(found(self.agent(text, source=source), 'JH159'), [])
        self.assertEqual(len(found(self.agent("={{ $('Lookup').item.json.email }}", source=('Lookup', 'code')),
                                   'JH159')), 1)

    def test_vendor_and_http_nodes(self):
        [f] = found(workflow([node('Ask', LC + 'openAi', {'messages': {'values': [
            {'content': '=Write to {{ $json.date_of_birth }}'}]}})]), 'JH159')
        self.assertIn('to an AI model (OpenAI)', f.message)
        [f] = found(workflow([node('Call', 'httpRequest', {'method': 'POST', 'url': 'https://api.anthropic.com/v1/messages',
                                                           'jsonBody': '={"text": "{{ $json.surname }}"}'}, version=4.2)]),
                    'JH159')
        self.assertIn('an AI API', f.message)
        self.assertEqual(found(workflow([node('Call', 'httpRequest', {'url': 'https://example.invalid/x',
                                                                      'jsonBody': '={{ $json.surname }}'})]), 'JH159'), [])
        self.assertEqual(found(workflow([node('Local', LC + 'ollama', {'prompt': '={{ $json.email }}'})]), 'JH159'), [])


class OlderExports(unittest.TestCase):
    def test_exports_from_before_ids(self):
        flow = json.loads(workflow([HOOK, node('Dig', 'executeCommand', {'command': '=dig {{ $json.q }}'})],
                                   link(('Hook', 'Dig'))))
        for n in flow['nodes']:
            n.pop('id')
            n['credentials'] = {'httpHeaderAuth': 'Shared header'}           # before credential IDs: a name
        flow['connections']['Hook']['main'].insert(0, None)                  # an output with nothing connected
        [parsed] = N.parse('flow.json', json.dumps(flow))
        self.assertEqual([n['raw']['id'] for n in parsed['nodes']], ['name:Hook', 'name:Dig'])
        self.assertEqual(parsed['nodes'][0]['credentials'], {'httpHeaderAuth': {'id': None, 'name': 'Shared header'}})
        got = sorted((f.rule, f.severity) for f in scan(json.dumps(flow)))
        self.assertEqual(got, [('JH156', 'major'), ('JH157', 'critical')])
        r = build({'flows/old.json': json.dumps(flow)})
        self.assertFalse(r['coverage']['parse_failures'])
        flow['nodes'][1]['credentials'] = {'httpHeaderAuth': 'Another header'}
        r = build({'flows/old.json': json.dumps(flow)})
        identities = {n['id'] for n in r['graph']['nodes'] if n['kind'] == 'identity'}
        self.assertEqual(len(identities), 2)                                  # one per named credential

    def test_rejected_exports_are_reported(self):
        flow = json.loads(workflow([HOOK]))
        flow['connections'] = {'id-hook': {'main': [[]]}}                    # keyed by ID: not what n8n writes
        root = tempfile.mkdtemp()
        try:
            with open(os.path.join(root, 'flow.json'), 'w') as fh:
                json.dump(flow, fh)
            p = run_cli('scan', root, '--json', '--no-config')
            report = json.loads(p.stdout)
            self.assertIn('flow.json: n8n workflow the reader rejects (connection source), not checked',
                          report['warnings'])
            self.assertIn('n8n workflow the reader rejects', run_cli('scan', root, '--md', '--no-config').stdout)
        finally:
            shutil.rmtree(root)


if __name__ == '__main__':
    unittest.main()
