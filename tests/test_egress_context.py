"""Invented in-memory declarations; expected decisions do not use exporters."""
import json
import unittest

import _util
import jh_egress
import jh_graph
import jh_map
import jh_passport
from _util import run_cli


class Item:
    def __init__(self, rel, text):
        self.rel, self.text = rel, text


class EgressContext(unittest.TestCase):
    def setUp(self):
        self.first = '.'.join(('first', 'invalid'))
        self.second = '.'.join(('second', 'invalid'))
        nodes = [{'id': 'app', 'display_label': 'app', 'kind': 'application', 'attributes': {}}]
        nodes += [{'id': str(i), 'kind': 'external', 'trust_domain': 'external',
                   'attributes': {'host': name}} for i, name in enumerate((self.first, self.second))]
        self.report = {'graph': {'nodes': nodes}, 'assessment': {'blast_radius': {'app': {
            'impacts': {'confidentiality': {str(i): {'tier': 2} for i in range(2)}}}}}}

    def assess(self, *items):
        return jh_egress.compare(jh_egress.boundaries(items), self.report)

    def codex(self, selected='safe', proxy=True, inactive=True):
        lines = ['default_permissions = ' + json.dumps(selected),
                 '[features.network_proxy]', 'enabled = ' + str(proxy).lower(),
                 '[permissions.safe.network]', 'enabled = true',
                 '[permissions.safe.network.domains]', json.dumps(self.first) + ' = "allow"']
        if inactive:
            lines += ['[permissions.other.network]', 'enabled = true',
                      '[permissions.other.network.domains]', json.dumps(self.second) + ' = "allow"']
        return Item('.codex/config.toml', '\n'.join(lines) + '\n')

    def claude(self, enabled=True, allowed=None, denied=None, path='.claude/settings.json'):
        box = {'network': {'allowedDomains': allowed or [], 'deniedDomains': denied or []}}
        if enabled is not None:
            box['enabled'] = enabled
        return Item(path, json.dumps({'sandbox': box}))

    def test_inactive_profile_cannot_cover_reach(self):
        result = self.assess(self.codex())
        self.assertEqual(result['state'], 'declared')
        self.assertEqual([row['host'] for row in result['outside']], [self.second])
        self.assertEqual(len(result['boundaries']), 2)
        self.assertEqual([b['profile'] for b in result['boundaries'] if b['selected']], ['safe'])

    def test_adding_inactive_permissions_does_not_change_selected_result(self):
        before = self.assess(self.codex(inactive=False))
        after = self.assess(self.codex(inactive=True))
        self.assertEqual((before['state'], before['outside'], before['unused'], before['wildcards']),
                         (after['state'], after['outside'], after['unused'], after['wildcards']))

    def test_disabled_or_missing_activation_is_unknown(self):
        for enabled in (False, None):
            with self.subTest(enabled=enabled):
                result = self.assess(self.claude(enabled, [self.first, self.second]))
                self.assertEqual(result['state'], 'unknown')
                self.assertEqual(len(result['unassessed']), 2)
                self.assertTrue(result['note'])

    def test_boolean_proxy_form_matches_nested_form(self):
        for enabled in (True, False):
            nested = self.codex(proxy=enabled)
            boolean = Item(nested.rel, nested.text.replace(
                '[features.network_proxy]\nenabled = ' + str(enabled).lower(),
                '[features]\nnetwork_proxy = ' + str(enabled).lower()))
            self.assertEqual(self.assess(boolean), self.assess(nested))

    def test_invalid_or_conflicting_boolean_proxy_is_not_credited(self):
        original = self.codex(inactive=False)
        nested = '[features.network_proxy]\nenabled = true'
        cases = [original.text.replace(nested, '[features]\nnetwork_proxy = ' + value)
                 for value in ('"true"', '1', '{ enabled = true }')]
        cases += [original.text.replace(nested, '[features]\nnetwork_proxy = false\n' + nested),
                  original.text + '\n[features]\nnetwork_proxy = false\n']
        for index, declaration in enumerate(cases):
            with self.subTest(case=index):
                self.assertEqual(self.assess(Item(original.rel, declaration))['state'], 'unknown')

    def test_disabled_proxy_is_unknown(self):
        result = self.assess(self.codex(proxy=False))
        self.assertEqual(result['state'], 'unknown')
        self.assertEqual(len(result['unassessed']), 2)

    def test_unknown_selected_profile_is_not_guessed(self):
        result = self.assess(self.codex(selected='absent'))
        self.assertEqual(result['state'], 'unknown')
        self.assertEqual(len(result['unassessed']), 2)

    def test_tools_are_assessed_separately(self):
        # each tool is assessed on its own and never lends its allowlist to another; a host is outside
        # when any one tool's selected declaration does not admit it
        result = self.assess(self.codex(inactive=False), self.claude(True, [self.second]))
        self.assertEqual(result['state'], 'declared')
        self.assertEqual(result['unassessed'], [])
        self.assertEqual([(r['host'], r['contexts']) for r in result['outside']],
                         [(self.first, ['claude-code']), (self.second, ['codex [safe]'])])
        self.assertEqual(len(result['contexts']), 2)
        per_tool = {context['tool']: context for context in result['contexts']}
        self.assertEqual([r['host'] for r in per_tool['codex']['outside']], [self.second])
        self.assertEqual([r['host'] for r in per_tool['claude-code']['outside']], [self.first])

    def test_one_unresolved_tool_makes_coverage_unknown(self):
        result = self.assess(self.codex(proxy=False, inactive=False), self.claude(True, [self.first, self.second]))
        self.assertEqual(result['state'], 'unknown')
        self.assertEqual((result['outside'], len(result['unassessed'])), ([], 2))

    def test_the_same_tool_in_both_says_outside_once(self):
        result = self.assess(self.codex(inactive=False), self.claude(True, [self.first]))
        self.assertEqual([(r['host'], r['contexts']) for r in result['outside']],
                         [(self.second, ['claude-code', 'codex [safe]'])])

    def test_settings_scopes_are_not_union_merged(self):
        result = self.assess(self.claude(True, [self.first]),
                             self.claude(True, [self.second], path='.claude/settings.local.json'))
        self.assertEqual(result['state'], 'unknown')
        self.assertEqual(len(result['unassessed']), 2)

    def test_enabled_boundary_keeps_real_outside_and_deny_decisions(self):
        result = self.assess(self.claude(True, [self.first, self.second], [self.second]))
        self.assertEqual(result['state'], 'declared')
        self.assertEqual([row['host'] for row in result['outside']], [self.second])
        self.assertIn('denied', result['outside'][0]['why'])
        self.assertEqual(result['unassessed'], [])

    def test_no_named_profile_selection_is_not_inferred_from_a_single_table(self):
        item = self.codex(inactive=False)
        item.text = '\n'.join(item.text.splitlines()[1:])
        self.assertEqual(self.assess(item)['state'], 'unknown')

    def test_unknown_egress_redaction_keeps_counts_only(self):
        declaration = self.claude(False, [self.first, self.second])
        code = 'import requests\nrequests.get(' + repr('https://' + self.first + '/') + ')\n'
        col = jh_map.Collected(items=[jh_map.Item(declaration.rel, declaration.text),
                                     jh_map.Item('main.py', code)], considered=2)
        report = jh_map.build_report(col, '/x', 'app', 'fixture', None)
        shared = jh_graph.pseudonymize(report)
        self.assertEqual(shared['egress']['state'], 'unknown')
        self.assertEqual(shared['egress']['unassessed'], 1)
        self.assertEqual(shared['egress']['contexts'], 1)
        self.assertNotIn(self.first, json.dumps(shared))
        self.assertNotIn(self.second, json.dumps(shared))

    def test_multiline_control_decoys_are_not_credited(self):
        item = self.codex(inactive=False)
        item.text = 'description = """\n' + item.text + '\n"""\n'
        self.assertEqual(self.assess(item)['state'], 'unknown')

    def test_string_boolean_is_not_activation(self):
        item = self.codex(inactive=False)
        item.text = item.text.replace('enabled = true', 'enabled = "true"')
        self.assertEqual(self.assess(item)['state'], 'unknown')

    def test_unmodeled_inheritance_is_not_credited(self):
        item = self.codex(inactive=False)
        item.text += '\n[permissions.safe]\nextends = "unresolved-parent"\n'
        self.assertEqual(self.assess(item)['state'], 'unknown')

    def test_invalid_domain_list_is_not_credited(self):
        item = Item('.claude/settings.json', json.dumps({'sandbox': {'enabled': True,
            'network': {'allowedDomains': '*'}}}))
        self.assertEqual(self.assess(item)['state'], 'unknown')

    def test_empty_explicit_list_is_still_a_declared_boundary(self):
        result = self.assess(self.claude(True))
        self.assertEqual(result['state'], 'declared')
        self.assertEqual(len(result['outside']), 2)

    def test_passport_redacts_unknown_contexts(self):
        result = run_cli('passport', _util.FIXTURES + '/demo-app', '--json')
        self.assertEqual(result.returncode, 0, result.stderr)
        passport = json.loads(result.stdout)
        passport['egress'] = self.assess(self.claude(False, [self.first, self.second]))
        shared = jh_passport.redact(passport)
        self.assertEqual(shared['egress']['state'], 'unknown')
        self.assertEqual(shared['egress']['unassessed'], 2)
        self.assertNotIn(self.first, json.dumps(shared))
        self.assertNotIn(self.second, json.dumps(shared))

    def test_legacy_sandbox_selection_does_not_credit_named_permissions(self):
        for mode in ('read-only', 'workspace-write', 'danger-full-access'):
            with self.subTest(mode=mode):
                item = self.codex(inactive=False)
                item.text = 'sandbox_mode = ' + json.dumps(mode) + '\n' + item.text
                result = self.assess(item)
                self.assertEqual(result['state'], 'unknown')
                self.assertEqual(len(result['unassessed']), 2)

    def test_custom_proxy_does_not_credit_builtin_domain_rules(self):
        for key in ('httpProxyPort', 'socksProxyPort'):
            for port in (8080, 0, None, '8080'):
                with self.subTest(key=key, value_type=type(port).__name__):
                    item = self.claude(True, [self.first, self.second])
                    doc = json.loads(item.text)
                    doc['sandbox']['network'][key] = port
                    item.text = json.dumps(doc)
                    result = self.assess(item)
                    self.assertEqual(result['state'], 'unknown')
                    self.assertEqual(len(result['unassessed']), 2)

    def test_comments_and_prose_do_not_act_as_policy_overrides(self):
        item = self.codex(inactive=False)
        item.text = '# sandbox_mode = "danger-full-access"\n' + item.text
        self.assertEqual(self.assess(item)['state'], 'declared')
        item = self.claude(True, [self.first, self.second])
        doc = json.loads(item.text)
        doc['description'] = 'Documentation mentions httpProxyPort and socksProxyPort.'
        item.text = json.dumps(doc)
        self.assertEqual(self.assess(item)['state'], 'declared')

    def test_invalid_control_values_remain_unknown(self):
        original = self.codex(inactive=False)
        cases = [original.text.replace('default_permissions = "safe"', 'default_permissions = true'),
                 original.text.replace('= "allow"', '= "unsupported"'),
                 original.text + '\n[permissions.safe]\nextends = false\n']
        for text in cases:
            with self.subTest(text_kind=cases.index(text)):
                self.assertEqual(self.assess(Item(original.rel, text))['state'], 'unknown')
