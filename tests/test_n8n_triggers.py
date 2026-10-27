"""Invented trigger declarations; no n8n, shell, clock or network execution."""
import copy
import hashlib
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
from test_n8n import node, workflow, report, compare
import jh_capabilities as C
import jh_explorer
import jh_graph as G
import jh_map
import jh_n8n as N
import jh_passport
import jh_views
from jh_core import source_from_text
from jh_rules import ScanOptions, scan_sources


def webhook(**params):
    return node('webhook', 2.2, dict(path='invented-route', **params))


def schedule():
    return node('scheduleTrigger', 1.4, {'rule': {'interval': [{'field': 'cronExpression', 'expression': '0 5 * * *'}]}})


class TriggerFacts(unittest.TestCase):
    def test_known_version_modes_and_defaults(self):
        for version in N.TRIGGER_VERSIONS['webhook']:
            n = webhook()
            n['typeVersion'] = version
            t = N.trigger(n)
            self.assertEqual((t['kind'], t['direction'], t['methods'], t['authentication']),
                             ('webhook', 'inbound', ['GET'], 'none'))
        n = webhook(httpMethod=['POST', 'GET'], multipleMethods=True, authentication='n8nOAuth2', requireExecuteAccess=False,
                    trustedSource='invented-source', options={'ipWhitelist': 'invented-filter', 'onlyRunIf': '={{true}}'})
        t = N.trigger(n)
        self.assertEqual(t['methods'], ['GET', 'POST'])
        self.assertFalse(t['require_execute_access'])
        self.assertTrue(t['ip_filter_declared'])
        self.assertTrue(t['request_filter_declared'])
        self.assertEqual(t['trusted_source'], 'declared')
        self.assertNotIn('invented-source', json.dumps(t))
        n['parameters'].pop('httpMethod')
        self.assertEqual(N.trigger(n)['methods'], ['GET', 'POST'])

    def test_unknown_versions_and_expressions_never_guess(self):
        n = webhook(httpMethod='={{$json.method}}', authentication='={{$json.auth}}')
        n['parameters']['path'] = '={{$json.route}}'
        t = N.trigger(n)
        self.assertEqual((t['methods'], t['authentication'], t['route']), ([], 'unknown', 'expression'))
        n['parameters'] = {}
        n['typeVersion'] = 99
        t = N.trigger(n)
        self.assertFalse(t['known_version'])
        self.assertEqual((t['methods'], t['authentication']), ([], 'unknown'))
        self.assertIsNone(N.trigger(node('httpRequest', 4)))
        n['type'] = 'community.webhook'
        self.assertIsNone(N.trigger(n))

    def test_schedule_units_timezone_and_activation(self):
        f = workflow(schedule())
        f['active'] = False
        f['settings'] = {'timezone': 'Etc/UTC'}
        r = report(f)
        t = next(n['attributes']['trigger'] for n in r['graph']['nodes'] if 'trigger' in n['attributes'])
        self.assertEqual((t['direction'], t['interval_fields'], t['rule_count']), ('unattended', ['cronExpression'], 1))
        self.assertEqual(t['timezone_source'], 'workflow-declared')
        self.assertEqual(t['activation'], 'unverified')
        self.assertIs(t['exported_active'], False)
        self.assertNotIn('0 5 * * *', json.dumps(r))
        self.assertNotIn('Etc/UTC', json.dumps(r['triggers']))
        self.assertEqual(N.trigger(schedule())['timezone_source'], 'instance-unverified')

    def test_summary_and_no_outbound_permission(self):
        a, b = webhook(), schedule()
        b.update(id='schedule-b', name='Schedule B')
        r = report(workflow(a, b))
        self.assertEqual(r['triggers']['counts'], dict(total=2, inbound=1, unattended=1, anonymous_inbound=1, auth_unknown=0))
        self.assertEqual(len(r['triggers']['entries']), 2)
        self.assertFalse(any(e['kind'] == 'calls' for e in r['graph']['edges']))
        rows, unknowns, _ = C.inventory(r, [])
        self.assertEqual({x['action'] for x in rows.values() if x['kind'] == 'trigger'}, {'receive', 'run-unattended'})
        self.assertFalse(any(x['kind'] == 'network' for x in rows.values()))
        self.assertEqual(len(unknowns), 2)

    def test_disabled_and_inactive_do_not_exempt_new_trigger(self):
        n = webhook(authentication='headerAuth')
        n['disabled'] = True
        f = workflow(n)
        f['active'] = False
        r = report(f)
        rows, unknowns, _ = C.inventory(r, [])
        triggers = [x for x in rows.values() if x['kind'] == 'trigger']
        self.assertEqual(len(triggers), 1)
        self.assertTrue(triggers[0]['target']['disabled'])
        self.assertEqual(triggers[0]['certainty'], 'unresolved')
        self.assertTrue(unknowns)

    def test_path_timing_filter_activation_edits_need_review(self):
        for n, change in (
            (webhook(), lambda f: f['nodes'][0]['parameters'].update(path='another-route')),
            (webhook(authentication='headerAuth'), lambda f: f['nodes'][0]['parameters'].update(authentication='none')),
            (webhook(options={'onlyRunIf': '={{true}}'}), lambda f: f['nodes'][0]['parameters']['options'].update(onlyRunIf='={{false}}')),
            (schedule(), lambda f: f['nodes'][0]['parameters']['rule']['interval'][0].update(expression='0 10 * * *')),
            (schedule(), lambda f: f.update(settings={'timezone': 'Etc/UTC'})),
            (webhook(), lambda f: f.update(active=True)),
        ):
            with self.subTest(node=n['type']):
                old = workflow(n)
                new = copy.deepcopy(old)
                change(new)
                self.assertGreater(compare(old, new)['counts']['unknown'], 0)
        old = workflow(webhook())
        d = compare(old, copy.deepcopy(old), newpath='moved/workflow.json')
        self.assertEqual(d['counts']['total'], 0)
        self.assertEqual(d['counts']['unknown'], 0)
        self.assertEqual(d['counts']['unchanged_unknown'], 1)

    def test_caps_count_before_display_and_security_view(self):
        nodes = [webhook() for _ in range(6)]
        for i, n in enumerate(nodes):
            n.update(id='fixture-' + str(i), name='Fixture ' + str(i))
        f = workflow(*nodes)
        with patch.object(N, 'TRIGGER_LIMIT', 2), patch.object(C, 'DISPLAY_LIMIT', 2):
            r = report(f)
            self.assertEqual((r['triggers']['counts']['total'], len(r['triggers']['entries']), r['triggers']['omitted']), (6, 2, 4))
            rows, _, _ = C.inventory(r, [])
            self.assertEqual(sum(x['kind'] == 'trigger' for x in rows.values()), 6)
            delta = compare(workflow(), f)
            self.assertEqual((delta['counts']['trigger'], len(delta['requests']), delta['truncation']['omitted']), (6, 2, 4))
        with patch.object(G, 'MAX_NODES', 2):
            r = report(f)
            self.assertTrue(r['coverage']['partial_reasons'])

    def test_conflicting_exports_are_partial(self):
        a = workflow(webhook())
        b = workflow(webhook(authentication='headerAuth'))
        r = build({'a.json': json.dumps(a), 'b.json': json.dumps(b)})
        self.assertTrue(r['coverage']['parse_failures'])
        self.assertTrue(r['coverage']['partial_reasons'])

    def test_metadata_selectors_are_not_secrets(self):
        n = webhook(authentication='headerAuth', nodeCredentialType='exampleOAuth2Api', genericAuthType='httpHeaderAuth')
        n['parameters']['headerParameters'] = {'parameters': [{'name': 'Authorization', 'value': 'invented-' + 'credential-42'}]}
        sites = N.secret_sites(n['parameters'])
        self.assertEqual(sites, ['/headerParameters/parameters/0/value'])
        self.assertNotIn('nodeCredentialType', json.dumps(N.trigger(n)))
        plain = workflow(webhook(authentication='headerAuth'))
        sf = source_from_text('flow.json', 'flow.json', json.dumps(plain))
        self.assertFalse(scan_sources([sf], ScanOptions(rule_ids=['JH101'], min_severity='info')).findings)

    def test_private_route_no_fingerprint_and_share_counts_only(self):
        route = 'invented-private-route-value'
        n = webhook()
        n['parameters']['path'] = route
        n['name'] = '<script>\x1b[31mFixture</script>'
        r = report(workflow(n))
        d = compare(workflow(webhook(authentication='headerAuth')), workflow(n))
        outputs = [json.dumps(r), json.dumps(d), jh_map.markdown(r), jh_views.map_tty(r, color=False),
                   jh_explorer.render_map(r)]
        for output in outputs:
            self.assertNotIn(route, output)
            self.assertNotIn(hashlib.sha256(route.encode()).hexdigest(), output)
        shared = G.pseudonymize(r)
        self.assertEqual(shared['triggers']['counts'], r['triggers']['counts'])
        self.assertTrue(shared['triggers']['entries_withheld'])
        self.assertNotIn('entries', shared['triggers'])
        self.assertNotIn('n8n_key', json.dumps(shared))
        self.assertIn('1 inbound', jh_map.markdown(r))
        self.assertIn('1 inbound', jh_views.map_tty(r, color=False))
        self.assertNotIn('<script>Fixture', jh_explorer.render_map(r))


@unittest.skipUnless(shutil.which('git'), 'git is not installed')
class TriggerSnapshots(unittest.TestCase):
    def test_new_trigger_policy_and_passport_views(self):
        with tempfile.TemporaryDirectory(prefix='jh-trigger-') as tmp:
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
            (root / 'app.py').write_text('value = 1\n')
            base = commit()
            (root / 'workflow.json').write_text(json.dumps(workflow(webhook())))
            commit()
            for flags in ((), ('--redact',)):
                proc = run_cli('passport', str(root), '--base', base, '--json', *flags)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                p = json.loads(proc.stdout)
                self.assertEqual(p['capability_delta']['counts']['trigger'], 1)
                self.assertEqual(p['triggers']['counts']['inbound'], 1)
                self.assertTrue(p['triggers']['entries_withheld'])
                cap = next(x for x in p['assessment']['decision']['rules'] if x['rule'] == 'P-CAP-001')
                self.assertEqual(cap['outcome'], 'review')
                self.assertIn('1 inbound', jh_passport.markdown(p))
                self.assertIn('1 inbound', jh_views.passport_tty(p, color=False))
                self.assertIn('declared triggers', jh_explorer.render_passport(p))
                if flags:
                    self.assertNotIn('n8n_key', proc.stdout)


if __name__ == '__main__':
    unittest.main()
