"""Bounded, inert n8n JSON exports. No expressions, code or credentials are loaded.

Operation spellings/version families follow upstream nodes-base descriptions;
see references/n8n.md. Everything else is an unresolved execution binding.
"""
from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from jh_core import redact_secrets
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
            for field in ('id', 'name', 'type'):
                if not isinstance(node.get(field), str) or not 1 <= len(node[field]) <= 256:
                    raise ValueError('n8n missing/oversized identity')
            if node['id'] in ids or node['name'] in names:
                raise ValueError('n8n ambiguous node identity')
            ids.add(node['id'])
            names[node['name']] = node['id']
            creds = node.get('credentials', {})
            if not isinstance(creds, dict) or any(not isinstance(v, dict) or
                    not isinstance(v.get('name'), str) or not isinstance(v.get('id'), (str, int)) for v in creds.values()):
                raise ValueError('n8n credential reference shape')
            refs = {k: {f: v.get(f) for f in ('id', 'name')} for k, v in creds.items()}
            definition = {k: v for k, v in node.items() if k not in ('position', 'notes', 'notesInFlow', 'credentials')}
            definition['credentials'] = refs
            nodes.append(dict(raw=node, pointer=([wi] if isinstance(raw, list) else []) + ['nodes', ni],
                              definition=_normalized(definition), credentials=refs))
        workflow_key = key('workflow', root.get('id') or sorted(ids))
        if workflow_key in seen_workflows:
            raise ValueError('n8n duplicate workflow identity')
        seen_workflows.add(workflow_key)
        links = []
        for source, outputs in root['connections'].items():
            if source not in names or not isinstance(outputs, dict):
                raise ValueError('n8n connection source')
            for channel, groups in outputs.items():
                if not isinstance(groups, list):
                    raise ValueError('n8n connection groups')
                for group in groups:
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
        out.append(dict(key=workflow_key, name=root.get('name', 'workflow'), nodes=nodes, links=links,
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
