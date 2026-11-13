"""Bounded, inert n8n JSON exports. No expressions, code or credentials are loaded.

Operation spellings/version families follow upstream nodes-base descriptions;
see references/n8n.md. Everything else is an unresolved execution binding.
"""
from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from jh_core import cut, redact_secrets
from jh_graph import sanitize_text

MAX_BYTES = 2 * 1024 * 1024
MAX_WORKFLOWS, MAX_NODES, MAX_LINKS, MAX_FIELDS = 100, 1000, 5000, 20000
MAX_DEPTH, MAX_STRING = 32, 16384
_TYPE = re.compile(r'"type"\s*:\s*"(?:n8n-nodes-[\w-]+\.|@n8n/[\w-]+\.)')
_SECRET = re.compile(r'password|passwd|(?:^|[_-])pwd$|secret|token|api.?key|authorization|credential', re.I)
# a parameter that selects a credential or auth TYPE (nodeCredentialType: "exampleApi") names a kind, not a secret
_TYPE_SELECTOR = re.compile(r'(?:credentials?|auth)_?type$', re.I)


def _secret_name(name):
    return bool(_SECRET.search(name)) and not _TYPE_SELECTOR.search(name)


def candidate(path, text):
    if not path.lower().endswith('.json') or not re.search(r'"nodes"\s*:', text):
        return False
    return bool(_TYPE.search(text)) or all(re.search(r'"' + k + r'"\s*:', text)
        for k in ('connections', 'typeVersion', 'parameters', 'position'))


def dynamic(value):
    if isinstance(value, dict):
        return any(dynamic(v) for v in value.values())
    if isinstance(value, list):
        return any(dynamic(v) for v in value)
    return isinstance(value, str) and (value.startswith('=') or '{{' in value or '}}' in value)


def literal(value):
    if isinstance(value, dict) and value.get('__rl') is True:
        value = value.get('value')
    return value if isinstance(value, (str, int)) and not isinstance(value, bool) and not dynamic(value) else None


def http_url(value):
    if not isinstance(value, str) or dynamic(value):
        return None
    try:
        parsed = urlsplit(value)
        return value if parsed.scheme in ('http', 'https') and parsed.netloc else None
    except ValueError:
        return None


def pointer(parts):
    return '/' + '/'.join(str(p).replace('~', '~0').replace('/', '~1') for p in parts)


def safe_pointer(value):
    return '/'.join(sanitize_text(t, 120) for t in value.split('/'))[:1000]


def key(*parts):
    return 'n8n:' + hashlib.sha256(json.dumps(parts, sort_keys=True).encode()).hexdigest()[:32]


def _pairs(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError('n8n duplicate JSON key')
        out[k] = v
    return out


def _bounded(value):
    todo, fields = [(value, 0)], 0
    while todo:
        v, depth = todo.pop()
        fields += 1
        if fields > MAX_FIELDS or depth > MAX_DEPTH:
            raise ValueError('n8n field/depth limit')
        if isinstance(v, str) and (len(v) > MAX_STRING or re.search(r'[\ud800-\udfff]', v)):
            raise ValueError('n8n string limit')
        if isinstance(v, dict):
            todo.extend((k, depth + 1) for k in v)
            todo.extend((x, depth + 1) for x in v.values())
        elif isinstance(v, list):
            todo.extend((x, depth + 1) for x in v)


def _secret_value(value, name):
    # Local import avoids the checks -> core -> rule-registration dependency.
    from jh_checks import _looks_secret_value
    if not isinstance(value, str):
        return False
    if redact_secrets(value) != value:
        return True
    if dynamic(value):
        return False
    if 'header' in name.lower() and value.lstrip().startswith(('{', '[')):
        try:
            headers = json.loads(value, object_pairs_hook=_pairs)
            _bounded(headers)
            return bool(secret_sites(headers))
        except (ValueError, RecursionError):
            return False
    return _secret_name(name) and _looks_secret_value(value, 'AUTH_TOKEN')


def secret_sites(value, parts=()):
    """Return generated pointers only. Never retain literal values or their hashes."""
    out = []
    if isinstance(value, dict):
        pair_name = str(value.get('name', ''))
        for k, v in value.items():
            name = pair_name if k == 'value' and _secret_name(pair_name) else k
            if _secret_value(v, name):
                out.append(pointer(parts + (k,)))
            else:
                out.extend(secret_sites(v, parts + (k,)))
    elif isinstance(value, list):
        for i, v in enumerate(value):
            out.extend(secret_sites(v, parts + (i,)))
    return out


def _normalized(value, name=''):
    if isinstance(value, dict):
        pair_name = str(value.get('name', ''))
        return {k: _normalized(v, pair_name if k == 'value' and _secret_name(pair_name) else k)
                for k, v in value.items()}
    if isinstance(value, list):
        return [_normalized(v, name) for v in value]
    if isinstance(value, str):
        if _secret_name(name) and not dynamic(value):
            return '<credential-value>'
        # Keep code/expressions and URL paths in memory for definition comparison.
        # Strip URL userinfo and credential query values, without collapsing hosts.
        if value.startswith(('http://', 'https://')):
            try:
                u = urlsplit(value)
                value = urlunsplit((u.scheme, u.netloc.rsplit('@', 1)[-1], u.path,
                    urlencode([(k, '<credential-value>' if _secret_name(k) else v)
                               for k, v in parse_qsl(u.query, keep_blank_values=True)]), u.fragment))
            except ValueError:
                pass
        return redact_secrets(value)
    return value


def parse(path, text):
    """None for non-candidates; invalid candidates raise a value-free error.

    Returned definitions are private comparison data, never graph attributes.
    Execution samples, UI layout and credential values are deliberately absent.
    """
    if not candidate(path, text):
        return None
    text = text.removeprefix('\ufeff')
    if len(text.encode('utf-8')) > MAX_BYTES:
        raise ValueError('n8n byte limit')
    try:
        raw = json.loads(text, object_pairs_hook=_pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, RecursionError):
        raise ValueError('n8n invalid or duplicate JSON') from None
    roots = raw if isinstance(raw, list) else [raw]
    if not 1 <= len(roots) <= MAX_WORKFLOWS:
        raise ValueError('n8n workflow limit')
    out, seen_workflows, total_nodes, total_links = [], set(), 0, 0
    for wi, root in enumerate(roots):
        if not isinstance(root, dict) or not isinstance(root.get('nodes'), list) or not isinstance(root.get('connections'), dict):
            raise ValueError('n8n workflow shape')
        relevant = {k: v for k, v in root.items() if k not in ('pinData', 'staticData')}
        _bounded(relevant)
        if 'name' in root and (not isinstance(root['name'], str) or len(root['name']) > 256):
            raise ValueError('n8n workflow name shape')
        if 'id' in root and (isinstance(root['id'], bool) or not isinstance(root['id'], (str, int))):
            raise ValueError('n8n workflow identity shape')
        nodes, names, ids = [], {}, set()
        total_nodes += len(root['nodes'])
        if total_nodes > MAX_NODES:
            raise ValueError('n8n node limit')
        for ni, node in enumerate(root['nodes']):
            if not isinstance(node, dict) or not isinstance(node.get('parameters'), dict):
                raise ValueError('n8n node shape')
            if 'id' not in node and isinstance(node.get('name'), str):
                # an export from before node IDs (mid-2022): n8n gives each node a new random ID on import, so its name
                # is the only stable identity. The node is this parse's own copy.
                node['id'] = 'name:' + node['name']
            for field in ('id', 'name', 'type'):
                if not isinstance(node.get(field), str) or not 1 <= len(node[field]) <= 256:
                    raise ValueError('n8n missing/oversized identity')
            if node['id'] in ids or node['name'] in names:
                raise ValueError('n8n ambiguous node identity')
            ids.add(node['id'])
            names[node['name']] = node['id']
            creds = node.get('credentials', {})
            if not isinstance(creds, dict):
                raise ValueError('n8n credential reference shape')
            refs = {}
            for k, v in creds.items():
                if isinstance(v, str):      # before credential IDs a node named its credential; n8n still finds it by name
                    v = {'id': None, 'name': v}
                if not isinstance(v, dict) or not isinstance(v.get('name'), str) or \
                        v.get('id') is not None and not isinstance(v.get('id'), (str, int)):
                    raise ValueError('n8n credential reference shape')
                refs[k] = {'id': v.get('id'), 'name': v['name']}
            definition = {k: v for k, v in node.items() if k not in ('position', 'notes', 'notesInFlow', 'credentials')}
            definition['credentials'] = refs
            nodes.append(dict(raw=node, pointer=([wi] if isinstance(raw, list) else []) + ['nodes', ni],
                              definition=_normalized(definition), credentials=refs))
        workflow_key = key('workflow', root.get('id') or sorted(ids))
        if workflow_key in seen_workflows:
            raise ValueError('n8n duplicate workflow identity')
        seen_workflows.add(workflow_key)
        links, edges = [], []
        for source, outputs in root['connections'].items():
            if source not in names or not isinstance(outputs, dict):
                raise ValueError('n8n connection source')
            for channel, groups in outputs.items():
                if not isinstance(groups, list):
                    raise ValueError('n8n connection groups')
                for group in groups:
                    if group is None:       # an output with nothing connected: n8n's own connection type allows null
                        continue
                    if not isinstance(group, list):
                        raise ValueError('n8n connection group')
                    for link in group:
                        total_links += 1
                        if total_links > MAX_LINKS:
                            raise ValueError('n8n connection limit')
                        if not isinstance(link, dict) or not isinstance(link.get('node'), str) or link['node'] not in names or not isinstance(link.get('index'), int) or \
                                isinstance(link.get('index'), bool) or link['index'] < 0 or link.get('type') != channel:
                            raise ValueError('n8n connection target')
                        links.append((names[source], names[link['node']]))
                        edges.append((names[source], names[link['node']], channel))
        context = dict(nodes=sorted([n['definition'] for n in nodes], key=lambda n: n['id']),
                       connections=_normalized(root['connections']), settings=_normalized(root.get('settings', {})),
                       active=root.get('active'), disabled=root.get('disabled'))
        for n in nodes:
            n['key'] = key(workflow_key, n['raw']['id'])
        # An unknown/community node could interpret a parameter named "token"
        # as executable code. Mask its value, but never grant unchanged-unknown
        # treatment when that masking removed possible behavior. Credential
        # store reference extras alone are safely excluded from definitions.
        comparable = all(_normalized(n['raw']['parameters']) == n['raw']['parameters'] for n in nodes)
        comparable = comparable and _normalized(root.get('settings', {})) == root.get('settings', {})
        out.append(dict(key=workflow_key, name=root.get('name', 'workflow'), nodes=nodes, links=links, edges=edges,
                        active=root.get('active'), settings=root.get('settings', {}),
                        definition=json.dumps(context, sort_keys=True) if comparable else None))
    return out


def definitions(items):
    out = {}
    for item in items:
        try:
            flows = parse(item.rel, item.text) or []
        except (ValueError, RecursionError):
            continue
        for flow in flows:
            if flow['definition'] is None:
                continue
            for node in flow['nodes']:
                out.setdefault(node['key'], []).append(flow['definition'])
    return {k: sorted(v) for k, v in out.items()}


TRIGGER_VERSIONS = {'webhook': (1, 1.1, 2, 2.1, 2.2), 'scheduleTrigger': (1, 1.1, 1.2, 1.3, 1.4)}
TRIGGER_LIMIT = 100
TRIGGER_NOTE = 'Declared triggers; deployment, public reach and actual activation are unverified.'


def trigger(node, active=None, settings=None):
    """Value-free facts from exact upstream parameter names; no path/cron hashes.

    Other parameters remain in private workflow equivalence. Authentication
    is a mode declaration, never proof of an effective grant.
    """
    typ = node['type'].removeprefix('n8n-nodes-base.')
    if node['type'] != 'n8n-nodes-base.' + typ or typ not in TRIGGER_VERSIONS:
        return None
    p, version = node['parameters'], node.get('typeVersion')
    known = not isinstance(version, bool) and version in TRIGGER_VERSIONS[typ]
    fact = dict(kind='webhook' if typ == 'webhook' else 'schedule',
                direction='inbound' if typ == 'webhook' else 'unattended', verification='declared',
                activation='unverified', known_version=known, disabled=node.get('disabled') is True,
                exported_active=active if isinstance(active, bool) else None)
    if typ == 'webhook':
        multiple = p.get('multipleMethods', node.get('multipleMethods', False)) is True
        method = p.get('httpMethod', ['GET', 'POST'] if multiple else 'GET') if known else None
        methods = method if isinstance(method, list) else [method]
        allowed = ('GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE')
        fact['methods'] = sorted(set(methods)) if methods and all(isinstance(m, str) and m in allowed for m in methods) else []
        auth = p.get('authentication', 'none') if known else None
        fact['authentication'] = auth if auth in ('none', 'basicAuth', 'headerAuth', 'jwtAuth', 'n8nOAuth2') else 'unknown'
        path = p.get('path')
        fact['route'] = 'expression' if dynamic(path) else 'literal-withheld' if isinstance(path, str) and path else 'missing'
        options = p.get('options') if isinstance(p.get('options'), dict) else {}
        fact['ip_filter_declared'] = bool(options.get('ipWhitelist'))
        fact['request_filter_declared'] = bool(options.get('onlyRunIf'))
        if fact['authentication'] == 'n8nOAuth2':
            access = p.get('requireExecuteAccess', True)
            fact['require_execute_access'] = access if isinstance(access, bool) else None
            fact['trusted_source'] = 'declared' if p.get('trustedSource') else 'instance-unverified'
    else:
        rule = p.get('rule') if isinstance(p.get('rule'), dict) else {}
        intervals = rule.get('interval') if isinstance(rule.get('interval'), list) and known else []
        fields = ('seconds', 'minutes', 'hours', 'days', 'weeks', 'months', 'cronExpression')
        fact['rule_count'] = len(intervals)
        fact['interval_fields'] = sorted({r['field'] if isinstance(r, dict) and r.get('field') in fields else 'unknown'
                                          for r in intervals})
        zone = settings.get('timezone') if isinstance(settings, dict) else None
        fact['timezone_source'] = 'expression' if dynamic(zone) else 'workflow-declared' if isinstance(zone, str) and zone else 'instance-unverified'
    return fact


def trigger_summary(nodes):
    entries, counts = [], dict(total=0, inbound=0, unattended=0, anonymous_inbound=0, auth_unknown=0)
    for node in sorted(nodes, key=lambda n: n['id']):
        fact = node['attributes'].get('trigger')
        if not fact:
            continue
        counts['total'] += 1
        counts[fact['direction']] += 1
        counts['anonymous_inbound'] += fact.get('authentication') == 'none'
        counts['auth_unknown'] += fact.get('authentication') == 'unknown'
        if len(entries) < TRIGGER_LIMIT:
            entries.append(dict(node=node['id'], declaration=fact, evidence_refs=node['evidence_refs'][:10]))
    return dict(counts=counts, entries=entries, omitted=counts['total'] - len(entries), note=TRIGGER_NOTE)


def trigger_counts(summary):
    counts = summary.get('counts', {})
    return dict(counts={k: counts.get(k, 0) if isinstance(counts.get(k, 0), int) else 0
                        for k in ('total', 'inbound', 'unattended', 'anonymous_inbound', 'auth_unknown')},
                note=TRIGGER_NOTE, entries_withheld=True)


def trigger_line(summary):
    c = (summary or {}).get('counts') or {}
    if not c.get('total'):
        return ''
    return '%d inbound (%d declared without authentication, %d unknown auth), %d unattended; activation unverified.' % (
        c['inbound'], c['anonymous_inbound'], c['auth_unknown'], c['unattended'])


# Explicit version sets: future and legacy nodes outside these tables stay opaque.
VERSIONS = {
    'httpRequest': (1, 2, 3, 4, 4.1, 4.2, 4.3, 4.4, 4.5),
    'postgres': (2, 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8),
    'mySql': (2, 2.1, 2.2, 2.3, 2.4, 2.5),
    'mongoDb': (1, 1.1, 1.2, 1.3, 1.4, 1.5),
    'googleSheets': (3, 4, 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7),
    'airtable': (1, 2, 2.1, 2.2),
}
_SQL = dict(select='read', insert='write', update='write', upsert='write', deleteTable='delete')
_MONGO = dict(find='read', insert='write', update='write', findOneAndReplace='write', findOneAndUpdate='write', delete='delete')
_SHEET = dict(read='read', append='write', appendOrUpdate='write', update='write', create='write', clear='delete', delete='delete', remove='delete')
_AIR = dict(get='read', search='read', create='write', update='write', upsert='write', deleteRecord='delete')
_AIR1 = dict(read='read', list='read', append='write', update='write', delete='delete')
_HTTP = dict(GET='read', HEAD='read', POST='write', PUT='write', PATCH='write', DELETE='delete')


def operation(node):
    """(engine, capability, scope); arbitrary queries/aggregates remain unknown."""
    typ = node['type'].removeprefix('n8n-nodes-base.')
    p, version = node['parameters'], node.get('typeVersion')
    if not node['type'].startswith('n8n-nodes-base.') or isinstance(version, bool) or version not in VERSIONS.get(typ, ()):
        return 'n8n', 'unknown', {}
    if typ == 'httpRequest':
        method = p.get('requestMethod' if version in (1, 2) else 'method', 'GET')
        return 'http', _HTTP.get(str(method), 'unknown'), {'url': p.get('url')}
    table, engine, resource, fields = {
        'postgres': (_SQL, 'postgresql', 'database', ('schema', 'table')),
        'mySql': (_SQL, 'mysql', 'database', ('table',)),
        'mongoDb': (_MONGO, 'mongodb', 'document', ('collection',)),
        'googleSheets': (_SHEET, 'google-sheets', 'sheet', ('documentId', 'sheetName')),
        'airtable': (_AIR1 if version == 1 else _AIR, 'airtable', 'record', ('application' if version == 1 else 'base', 'table')),
    }[typ]
    op = p.get('operation')  # Require explicit operations for data nodes in this first reader.
    cap = table.get(str(op), 'unknown') if p.get('resource', resource) == resource else 'unknown'
    return engine, cap, {k: literal(p.get(k)) for k in fields}


# ------------------------------------------------------------------ rules: JH156-JH159
#
# What an exported workflow declares, read from exact upstream parameter names. Expressions are matched as text and
# never evaluated. An export leaves out parameters left at their default, so a missing authentication is the default,
# None. A disabled node is not reported (it does not run); the map still lists it.

_BASE, _LANGCHAIN = 'n8n-nodes-base.', '@n8n/n8n-nodes-langchain.'
_EXPR = re.compile(r'\{\{(.*?)\}\}', re.S)
# a reference to another node's output: $('Name'), $node["Name"], $items("Name"), then an optional .item / .first() /
# .last() / .all()[0] / [0], then .json and the field it reads
_REF = re.compile(r'''\$(?:\(\s*|node\s*\[\s*|items\s*\(\s*)(['"])((?:(?!\1)[^\\\n]){1,256})\1\s*[)\]]'''
                  r'''(?:\s*\.\s*(?:item\b|(?:first|last)\s*\(\s*\)|all\s*\(\s*\)\s*\[\s*\d+\s*\])|\s*\[\s*\d+\s*\])?'''
                  r'''\s*\.\s*json\s*(?:\.\s*([A-Za-z_$][\w$]*)|\[\s*(['"])([^'"\\\n]{1,256})\4\s*\])''')
# what makes an expression read workflow data: the current item, another node's output, or an AI-chosen value.
# $env, $vars, $now, $execution and $workflow are not data a caller supplies.
_DATA = re.compile(r'''\$(?:json|input|binary|items?|node)\b|\$\(|\$fromai\s*\(''', re.I)
_FROM_AI = re.compile(r'\$fromai\s*\(', re.I)
_JSON_ONLY = re.compile(r'''\s*\$json\s*(?:\.\s*[A-Za-z_$][\w$]*|\[\s*(['"])[^'"\\\n]{1,256}\1\s*\])\s*''')   # {{ $json.script }}
# another node's settings, not its output: $('Local File Trigger').params.path, $node["X"].parameter["path"]
_PARAMS = re.compile(r'''\$(?:\(\s*|node\s*\[\s*)(['"])(?:(?!\1)[^\\\n]){1,256}\1\s*[)\]]\s*\.\s*param(?:eter|s)\b''')


GAPS = []       # workflow exports the rules could not read during this scan, for the report's warnings


def flows(sf):
    """The workflows in a scanned file, parsed once per file; [] for anything else. An export that fails validation
    is not checked, and the report says so."""
    cached = getattr(sf, '_jh_n8n', None)
    if cached is not None:
        return cached
    result = []
    if sf.lang == 'json':
        try:
            result = parse(sf.rel, sf.text) or []
        except (ValueError, RecursionError) as exc:
            reason = str(exc).removeprefix('n8n ') if isinstance(exc, ValueError) else 'nested too deeply'
            GAPS.append('%s: n8n workflow the reader rejects (%s), not checked' % (sf.rel, cut(reason, 60)))
    sf._jh_n8n = result
    return result


def _short(node):
    """'webhook' for n8n-nodes-base.webhook, 'agent' for the LangChain agent; None for a community node."""
    for prefix in (_BASE, _LANGCHAIN):
        if node['type'].startswith(prefix):
            return node['type'][len(prefix):]
    return None


def open_trigger(node):
    """'webhook', 'form' or 'chat' when an enabled trigger node answers anyone who has its URL, else None."""
    if node.get('disabled') is True:
        return None
    p, typ = node['parameters'], node['type']
    auth = p.get('authentication', 'none')
    if typ == _BASE + 'webhook':
        options = p.get('options') if isinstance(p.get('options'), dict) else {}
        return 'webhook' if auth == 'none' and not options.get('ipWhitelist') else None
    if typ == _BASE + 'formTrigger':
        return 'form' if auth == 'none' else None         # version 1 has no authentication option at all
    if typ == _LANGCHAIN + 'chatTrigger':
        return 'chat' if p.get('public') is True and auth == 'none' else None   # not public: the editor's chat only
    return None


_CODE_NODES = {_BASE + 'code', _BASE + 'function', _BASE + 'functionItem'}
_REFUSES = re.compile(r'\b(?:throw|raise)\b|\b(?:createHmac|timingSafeEqual|compare_digest)\b')   # refuses, or verifies a signature
_BRANCH_NODES = {_BASE + 'if', _BASE + 'switch', _BASE + 'filter'}


def _guard(flow, trigger):
    """The name of the step that checks a request header before anything else runs, else None: every node the
    trigger starts is an enabled Code node that reads the headers and throws or verifies a signature (an HMAC), or an
    If, Switch or Filter on a header."""
    raw = {n['raw']['id']: n['raw'] for n in flow['nodes']}
    starts = [raw[dst] for src, dst, channel in flow['edges'] if src == trigger['id'] and channel == 'main']

    def checks(n):
        p = n['parameters']
        if n.get('disabled') is True:
            return False
        if n['type'] in _CODE_NODES:
            code = '\n'.join(p[k] for k in ('jsCode', 'pythonCode', 'functionCode') if isinstance(p.get(k), str))
            return 'headers' in code and bool(_REFUSES.search(code))
        return n['type'] in _BRANCH_NODES and 'headers' in json.dumps(p)
    return starts[0]['name'] if starts and all(checks(n) for n in starts) else None


def _built_by_code(flow, node):
    """The Code node that writes this node's input, when every connection into it comes from one, else None."""
    raw = {n['raw']['id']: n['raw'] for n in flow['nodes']}
    before = [raw[src] for src, dst, channel in flow['edges'] if dst == node['id'] and channel == 'main']
    return before[0]['name'] if before and all(n['type'] in _CODE_NODES for n in before) else None


def _fed(flow):
    """{node id: (kind, trigger name)} for every node an open trigger's data can reach: along main connections, and
    from an AI node to the model, memory and tools plugged into it. A trigger whose first step checks a header is not
    open here."""
    raw = {n['raw']['id']: n['raw'] for n in flow['nodes']}
    nexts = {}
    for src, dst, channel in flow['edges']:
        if channel == 'main':
            nexts.setdefault(src, []).append(dst)
        elif channel.startswith('ai_'):
            nexts.setdefault(dst, []).append(src)
    fed = {}
    for nid in sorted(raw):
        kind = open_trigger(raw[nid])
        todo = [nid] if kind and not _guard(flow, raw[nid]) else []
        while todo:
            cur = todo.pop()
            if cur not in fed:
                fed[cur] = (kind, raw[nid]['name'])
                todo.extend(nexts.get(cur, ()))
    return fed


def _constants(flow):
    """{node name: field names} for the fields Set nodes give a value that reads no workflow data (typed in, or from
    $env or another node's settings): reading one of those fields reads what the workflow's author chose."""
    out = {}
    for n in flow['nodes']:
        raw = n['raw']
        if raw['type'] != _BASE + 'set':
            continue
        names, todo = set(), [raw['parameters']]
        while todo:
            v = todo.pop()
            if isinstance(v, dict):
                # one field: {name, value} (3.3+), {name, stringValue} (3.0-3.2), {name, value} under values.string
                if isinstance(v.get('name'), str) and not any(
                        _reads_data(s, {}) for x in v.values() for s in _segments(x)):
                    names.add(v['name'])
                todo.extend(v.values())
            elif isinstance(v, list):
                todo.extend(v)
        out[raw['name']] = names
    return out


def _reads_data(segment, constants):
    """Whether an expression reads workflow data, once reads of other nodes' settings and of Set node fields that
    hold no data are taken out."""
    def strip(m):
        field = m.group(3) or m.group(5)
        return '' if field in constants.get(m.group(2), ()) else m.group(0)
    return bool(_DATA.search(_REF.sub(strip, _PARAMS.sub('', segment))))


def _segments(value, always=False):
    """The {{ }} expressions n8n evaluates in a parameter: in an expression value (it starts with '='), or anywhere in
    a SQL query, which the database nodes resolve themselves."""
    if not isinstance(value, str) or not (always or value.startswith('=')):
        return []
    return [m.group(1) for m in _EXPR.finditer(value)]


def _whole(value):
    """The parameter is a single expression: the data supplies all of it, not a value inside it."""
    return isinstance(value, str) and value.count('{{') == 1 and bool(re.fullmatch(r'=?\s*\{\{.*\}\}\s*', value, re.S))


def _line(sf, node):
    for key, value in (('id', node['id']), ('name', node['name'])):
        for text in (json.dumps(value, ensure_ascii=False), json.dumps(value)):
            m = re.search(r'"%s"\s*:\s*%s' % (key, re.escape(text)), sf.text)
            if m:
                return sf.text.count('\n', 0, m.start()) + 1
    return 1


def _show(segment):
    return sanitize_text('{{ %s }}' % ' '.join(segment.split()), 100)


def _finding(sf, rule, n, message, segment=None, **kw):
    from jh_core import make_finding
    raw = n['raw']
    evidence = sanitize_text(raw['name'], 60) + (': ' + _show(segment) if segment else '')
    return make_finding(rule, sf, _line(sf, raw), evidence=evidence, message=message,
                        extra={'json_pointer': safe_pointer(pointer(n['pointer']))}, **kw)


def _fed_by(fed, raw, tool):
    if raw['id'] not in fed:
        return ''
    kind, name = fed[raw['id']]
    if tool:
        return (" The agent answers an open %s trigger ('%s'), so anyone who can reach it can steer the AI."
                % (kind, sanitize_text(name, 60)))
    return (" The workflow starts from an open %s trigger ('%s'), so anyone who finds its URL supplies that data."
            % (kind, sanitize_text(name, 60)))


_TRIGGER_TEXT = {
    'webhook': ("The Webhook node '%s' starts the workflow for anyone who calls its URL: its authentication is None. "
                "The URL is the only key, and it travels in logs, browser history and shared templates."),
    'form': ("The Form Trigger '%s' publishes a form anyone with the link can submit: its authentication is None. "
             "Check the form is meant to be public, and that the workflow treats every answer as untrusted."),
    'chat': ("The Chat Trigger '%s' makes the chat public with no authentication: anyone with the URL can talk to the "
             "agent behind it and make it use its tools."),
}


def _open_triggers(sf, rule, flow, fed, constants):
    out = []
    for n in flow['nodes']:
        kind = open_trigger(n['raw'])
        guard = kind and _guard(flow, n['raw'])
        if guard:
            out.append(_finding(sf, rule, n, (
                "The %s trigger '%s' has authentication None; its first step ('%s') checks a request header instead. "
                "n8n's own authentication turns a caller away before the workflow runs. A check in a node runs it, "
                "and lets everyone in if its secret is ever unset." % (
                    kind, sanitize_text(n['raw']['name'], 60), sanitize_text(guard, 60))),
                severity='minor', confidence='low'))
        elif kind:
            out.append(_finding(sf, rule, n, _TRIGGER_TEXT[kind] % sanitize_text(n['raw']['name'], 60),
                                **({'severity': 'minor', 'confidence': 'low'} if kind == 'form' else {})))
    return out


_SHELL = {'executeCommand': 'Execute Command', 'ssh': 'SSH'}


def _commands(sf, rule, flow, fed, constants):
    out = []
    for n in flow['nodes']:
        raw = n['raw']
        short = _short(raw) if raw['type'].startswith(_BASE) else None
        tool = bool(short) and short.endswith('Tool')
        label = _SHELL.get(short[:-4] if tool else short) if short else None
        p = raw['parameters']
        if not label or raw.get('disabled') is True or label == 'SSH' and (
                p.get('resource', 'command') != 'command' or p.get('operation', 'execute') != 'execute'):
            continue
        data = [s for s in _segments(p.get('command')) if _reads_data(s, constants)]
        if not data:
            continue
        where = 'on the n8n host' if label == 'Execute Command' else 'on the server the SSH credential reaches'
        name = sanitize_text(raw['name'], 60)
        extra = {}
        if any(_FROM_AI.search(s) for s in data):
            message = ("The AI agent's %s tool '%s' runs a command the AI writes (%s) %s: instructions hidden in a "
                       "message, email or web page the agent reads can make it any command." % (label, name, _show(data[0]), where))
        elif _whole(p.get('command')):
            message = ("The %s node '%s' runs a command taken whole from workflow data (%s) %s: whatever writes that "
                       "field chooses the command." % (label, name, _show(data[0]), where))
            author = _built_by_code(flow, raw) if _JSON_ONLY.fullmatch(data[0]) else None
            if author:
                message += (" The Code node '%s' writes it: check that it quotes every value it takes from a request."
                            % sanitize_text(author, 60))
                extra['confidence'] = 'medium'
        else:
            message = ("The %s node '%s' builds a shell command from workflow data (%s): a quote, semicolon or $( ) in "
                       "that data runs a command of its own %s." % (label, name, _show(data[0]), where))
        if label == 'Execute Command':
            message += " n8n 2.0 and later leave this node off unless the instance turns it back on."
        if raw['id'] in fed:
            extra['severity'] = 'critical'
        out.append(_finding(sf, rule, n, message + _fed_by(fed, raw, tool), data[0], **extra))
    return out


_SQL_NODES = {'postgres': 'Postgres', 'mySql': 'MySQL', 'microsoftSql': 'Microsoft SQL'}
# a value whose quotes are doubled in the expression: .replace(/'/g, "''"), .replaceAll("'", "''")
_ESCAPED = re.compile(r'''\.replace(?:All)?\s*\(\s*(?:/'/g|["']'["']|"\\'"|'\\''),\s*["']''["']\s*\)''')


def _queries(sf, rule, flow, fed, constants):
    out = []
    for n in flow['nodes']:
        raw = n['raw']
        short = _short(raw) if raw['type'].startswith(_BASE) else None
        tool = bool(short) and short.endswith('Tool')
        label = _SQL_NODES.get(short[:-4] if tool else short) if short else None
        p = raw['parameters']
        if not label or raw.get('disabled') is True or p.get('operation') != 'executeQuery':
            continue
        data = [s for s in _segments(p.get('query'), always=True) if _reads_data(s, constants)]
        if not data:
            continue
        data.sort(key=lambda s: bool(_ESCAPED.search(s)))      # show a value nothing escapes, if there is one
        name = sanitize_text(raw['name'], 60)
        ai = any(_FROM_AI.search(s) for s in data)
        extra = {}
        if _whole(p.get('query')):
            message = ("The %s node '%s' runs SQL taken whole from %s (%s): whoever shapes that %s chooses the query, "
                       "and can read or change anything the credential reaches." % (
                           label, name, 'what the AI writes' if ai else 'workflow data', _show(data[0]),
                           'prompt' if ai else 'data'))
            author = _built_by_code(flow, raw) if _JSON_ONLY.fullmatch(data[0]) else None
            if author:
                message += (" The Code node '%s' writes it: check that it quotes every value it takes from a request."
                            % sanitize_text(author, 60))
                extra['confidence'] = 'medium'
        else:
            message = ("The %s node '%s' splices %s into its SQL (%s): a quote in a value rewrites the query. Use $1, "
                       "$2 placeholders and pass the values as Query Parameters." % (
                           label, name, 'values the AI chooses' if ai else 'workflow data', _show(data[0])))
        if _ESCAPED.search(data[0]):
            message = ("The %s node '%s' puts workflow data into its SQL (%s) and escapes quotes by hand. One value "
                       "it misses, or a backslash on MySQL, rewrites the query; use $1, $2 placeholders and Query "
                       "Parameters." % (label, name, _show(data[0])))
            out.append(_finding(sf, rule, n, message + _fed_by(fed, raw, tool), data[0], severity='minor',
                                confidence='low'))
            continue
        if raw['id'] in fed:
            extra['severity'] = 'critical'
        out.append(_finding(sf, rule, n, message + _fed_by(fed, raw, tool), data[0], **extra))
    return out


# AI nodes that send their parameters to a model. Chains and agents send to the model plugged into them; the vendor
# nodes are the model. Local runtimes (Ollama, Lemonade) keep the data on the machine.
_AI_CHAINS = {'agent', 'agenttool', 'chainllm', 'chainsummarization', 'chainretrievalqa', 'informationextractor',
              'textclassifier', 'sentimentanalysis', 'openaiassistant'}
_AI_VENDORS = {'openai': 'OpenAI', 'anthropic': 'Anthropic', 'googlegemini': 'Google Gemini', 'alibabacloud': 'Alibaba Cloud',
               'minimax': 'MiniMax', 'moonshot': 'Moonshot', 'mistralai': 'Mistral AI', 'perplexity': 'Perplexity'}
_LOCAL = re.compile(r'(?i)ollama|lemonade')
_PERSONAL = re.compile(r'(?i)^\w*?(?:e_?mail(?:_?address)?|phone(?:_?number)?|mobile(?:_?number)?|birth_?date|birthday|'
                       r'date_?of_?birth|dob|ssn|social_?security(?:_?number)?|national_?id|passport(?:_?number)?|'
                       r'full_?name|surname|last_?name|address)\d?$')
_NOT_PERSONAL = re.compile(r'(?i)(?:ip|mac|wallet|contract|server|host|node|web|url|bitcoin|btc|eth|token|base|pool|'
                           r'vault|ens)_?address\d?$')
_REDACTOR = re.compile(r'(?i)redact|anonymi[sz]|pseudonymi[sz]|mask|guardrail')
_FIELD = re.compile(r'''\.\s*([A-Za-z_$][\w$]*)|\[\s*(['"])([^'"\\\n]{1,100})\2\s*\]''')
_SOURCE = re.compile(r'''\$(?:\(\s*|node\s*\[\s*|items\s*\(\s*)(['"])((?:(?!\1)[^\\\n]){1,256})\1''')


def _strings(value):
    if isinstance(value, dict):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _strings(v)
    elif isinstance(value, str):
        yield value


def _personal(parameters, types):
    """Personal field names an AI node's expressions read, except from a node named or built for redaction."""
    found = []
    for value in _strings(parameters):
        for segment in _segments(value):
            sources = [(m.start(), m.group(2)) for m in _SOURCE.finditer(segment)]
            for m in _FIELD.finditer(segment):
                field = m.group(1) or m.group(3)
                plain = re.sub(r'[\s-]+', '_', field)
                if not _PERSONAL.match(plain) or _NOT_PERSONAL.search(plain):
                    continue
                source = [name for at, name in sources if at < m.start()]
                if source and (_REDACTOR.search(source[-1]) or _REDACTOR.search(types.get(source[-1], ''))):
                    continue
                if field not in found:
                    found.append(field)
    return found


def _ai_personal(sf, rule, flow, fed, constants):
    raw_by_id = {n['raw']['id']: n['raw'] for n in flow['nodes']}
    types = {n['raw']['name']: n['raw']['type'] for n in flow['nodes']}
    models = {}
    for src, dst, channel in flow['edges']:
        if channel == 'ai_languageModel':
            models.setdefault(dst, []).append(raw_by_id[src])
    out = []
    for n in flow['nodes']:
        raw = n['raw']
        short = (_short(raw) or '').lower()
        if raw.get('disabled') is True:
            continue
        if short in _AI_CHAINS and raw['type'].startswith(_LANGCHAIN):
            attached = models.get(raw['id'], [])
            if attached and all(_LOCAL.search(m['type']) for m in attached):
                continue
            target = ', '.join("'%s'" % sanitize_text(m['name'], 40) for m in attached[:2]) or 'its model'
        elif short in _AI_VENDORS:
            target = _AI_VENDORS[short]
        elif raw['type'] == _BASE + 'httpRequest' and _ai_host(raw['parameters'].get('url')):
            target = 'an AI API'
        else:
            continue
        fields = _personal(raw['parameters'], types)
        if fields:
            out.append(_finding(sf, rule, n, (
                "The node '%s' sends personal data (%s) to an AI model (%s) with no visible redaction. Check the "
                "service is approved for this data and that only what the prompt needs is sent." % (
                    sanitize_text(raw['name'], 60), ', '.join(sanitize_text(f, 40) for f in fields[:4]), target))))
    return out


def _ai_host(url):
    from jh_powerplatform import _AI_HOST
    return isinstance(url, str) and not dynamic(url) and bool(_AI_HOST.match(url))


_CHECKS = {'n8n_open_trigger': _open_triggers, 'n8n_command': _commands, 'n8n_sql': _queries,
           'n8n_ai_personal': _ai_personal}


def findings(sf, rule):
    check = _CHECKS.get(rule.check)
    out = []
    for flow in flows(sf) if check else ():
        out.extend(check(sf, rule, flow, _fed(flow), _constants(flow)))
    return out
