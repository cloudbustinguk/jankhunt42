"""Bounded inert HTTP-call shapes in n8n JavaScript; runtime availability stays unknown."""
import re

from jh_core import sanitize

_CALL = re.compile(r'(?<![\w$.])(?:this\s*\.\s*helpers\s*\.\s*httpRequest|\$http|fetch|'
                   r'axios(?:\s*\.\s*(?:get|head|delete|post|put|patch|request))?)\s*\(')
_KEY = re.compile(r'''\s*(?:([A-Za-z_$][\w$]*)|["']([A-Za-z_$][\w$]*)["'])\s*:\s*''')
VERBS = {'GET': 'read', 'HEAD': 'read', 'DELETE': 'delete', 'POST': 'write', 'PUT': 'write', 'PATCH': 'write'}
MAX_CALLS, MAX_CALL_CHARS, MAX_CALL_DEPTH = 128, 4000, 32


def _parts(mask, raw):
    """Split commas at this scope; strings/comments were masked with offsets preserved."""
    depth, start, parts = 0, 0, []
    for i, c in enumerate(mask):
        if c in '([{':
            depth += 1
        elif c in ')]}':
            depth -= 1
        elif c == ',' and depth == 0:
            parts.append((mask[start:i], raw[start:i]))
            start = i + 1
    parts.append((mask[start:], raw[start:]))
    return parts


def _literal(raw):
    text = raw.strip()
    if len(text) < 2 or text[0] not in '\'"`' or text[-1] != text[0]:
        return None
    body = text[1:-1]
    if '\\' in body or '${' in body or text[0] in body or '\n' in body:
        return None
    return body


def _options(mask, raw):
    offset = len(raw) - len(raw.lstrip())
    raw = raw.strip()
    mask = mask[offset:offset + len(raw)]
    if not raw.startswith('{') or not raw.endswith('}'):
        return None
    values, seen = {}, set()
    for _, field in _parts(mask[1:-1], raw[1:-1]):
        if not field.strip():
            continue
        match = _KEY.match(field)
        if not match:
            return None  # spreads, computed keys, shorthand, methods
        key = match.group(1) or match.group(2)
        if key in seen:
            return None
        seen.add(key)
        if key in ('url', 'method'):
            value = _literal(field[match.end():])
            if value is None:
                return None
            values[key] = value
    return values


def _end(mask, start):
    stack = []
    for i in range(start, min(len(mask), start + MAX_CALL_CHARS)):
        c = mask[i]
        if c in '([{':
            stack.append(c)
            if len(stack) > MAX_CALL_DEPTH:
                return None
        elif c in ')]}':
            if not stack or stack.pop() != {')': '(', ']': '[', '}': '{'}[c]:
                return None
            if not stack:
                return i
    return None


def http_calls(text):
    code, nocomment, _ = sanitize(text, 'js')
    mask, raw = '\n'.join(code), '\n'.join(nocomment)
    calls, capped = [], False
    for number, match in enumerate(_CALL.finditer(mask)):
        if number >= MAX_CALLS:
            capped = True
            break
        start, end = match.end() - 1, _end(mask, match.end() - 1)
        if end is None:
            capped = True
            continue
        args = _parts(mask[start + 1:end], raw[start + 1:end])
        name = re.sub(r'\s+', '', mask[match.start():start])
        options, url, method = None, None, None
        if name in ('this.helpers.httpRequest', '$http') or name == 'axios.request' or \
                (name == 'axios' and args and args[0][1].lstrip().startswith('{')):
            if len(args) == 1:
                options = _options(*args[0])
                if options is not None:
                    url, method = options.get('url'), options.get('method', 'GET')
        elif name in ('fetch', 'axios') and 1 <= len(args) <= 2:
            url = _literal(args[0][1])
            options = _options(*args[1]) if len(args) == 2 else {}
            if options is not None:
                method = options.get('method', 'GET')
        elif name.startswith('axios.') and 1 <= len(args) <= 3:
            url, method = _literal(args[0][1]), name.split('.')[1].upper()
        method = method.upper() if isinstance(method, str) else method   # axios writes 'post' as often as 'POST'
        if url and method in VERBS and url.startswith(('http://', 'https://')):
            calls.append((raw.count('\n', 0, match.start()) + 1, url, VERBS[method]))
    return calls, capped
