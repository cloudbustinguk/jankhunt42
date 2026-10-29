"""Structural ASP.NET Core leads, not a C# compiler or proof of deployment behavior.

Code views exclude comments and strings. Balanced call/block spans keep policies, route groups and guards local;
project-local context supports fallback authorization and HTTPS middleware without mixing neighboring apps.
"""
from __future__ import annotations

import os
import json
from functools import lru_cache
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Sequence

from jh_core import SourceFile, Rule, Finding, make_finding
from jh_graph import sanitize_text

_PRIVATE = re.compile(r'(?i)users?|customers?|patients?|employees?|accounts?|profiles?|bookings?|intakes?|events?|'
                      r'reports?|invoices?|payments?|documents?|files?|messages?|config|admin|expenses?|timesheets?')
_PERSONAL = re.compile(r'(?i)\b(?:Email|FullName|Phone|SSN|SocialSecurityNumber|DateOfBirth|MedicalRecord)\b')
_AI = re.compile(r'(?i)openai|anthropic|generativelanguage|gemini|ai[-.]|/chat/completions|\b(?:I?ChatClient|AIClient)\b')


@lru_cache(maxsize=2)
def _delimiters(code: str) -> Dict[int, int]:
    """Index masked delimiters once: malformed/nested calls must not repeatedly rescan a file."""
    stack, ends = [], {}
    pairs = {')': '(', ']': '[', '}': '{'}
    for i, c in enumerate(code):
        if c in '([{':
            stack.append((c, i))
        elif c in pairs:
            if stack and stack[-1][0] == pairs[c]:
                _, begin = stack.pop()
                ends[begin] = i + 1
            else:
                stack.clear()
    return ends


def _end(code: str, start: int, opening: str = '(', closing: str = ')') -> int:
    limit = min(len(code), start + 65536)
    finish = _delimiters(code).get(start)
    return finish if finish is not None and finish <= limit else limit


def _statement(code: str, start: int) -> int:
    ends = _delimiters(code)
    limit = min(len(code), start + 65536)
    i = start
    while i < limit:
        c = code[i]
        if c in '([{':
            finish = ends.get(i)
            if finish is None or finish > limit:
                return limit
            i = finish
            continue
        if c in ')]}':
            return i
        if c == ';':
            return i + 1
        i += 1
    return limit


def _args(code: str, start: int, end: int) -> List[tuple]:
    parts, last, i = [], start, start
    ends = _delimiters(code)
    while i < end:
        c = code[i]
        if c in '([{':
            finish = ends.get(i)
            if finish is None or finish > end:
                break
            i = finish
            continue
        if c == ',':
            parts.append((last,i))
            last = i + 1
        i += 1
    return parts + [(last, end)]


def _views(sf: SourceFile) -> tuple:
    return '\n'.join(sf.code), '\n'.join(sf.nocomment)


def _condition_value(code: str, raw: str, development: bool) -> Optional[bool]:
    """Evaluate only literal booleans and development checks; everything else stays unknown."""
    pairs = _delimiters(code)

    def evaluate(a: int, b: int, depth: int) -> Optional[bool]:
        if depth > 16:
            return None
        while a < b and raw[a].isspace():
            a += 1
        while b > a and raw[b - 1].isspace():
            b -= 1
        if a == b:
            return None
        if code[a] == '(' and pairs.get(a) == b:
            return evaluate(a + 1, b - 1, depth + 1)
        for op in ('||', '&&'):
            parts, last, i = [], a, a
            while i < b:
                if code[i] in '([{':
                    finish = pairs.get(i)
                    if finish is None or finish > b:
                        return None
                    i = finish
                    continue
                if code.startswith(op, i):
                    parts.append((last, i))
                    last = i + len(op)
                    i = last
                    continue
                i += 1
            if parts:
                values = [evaluate(x, y, depth + 1) for x, y in parts + [(last, b)]]
                decisive = op == '||'
                if any(v is decisive for v in values):
                    return decisive
                return None if None in values else not decisive
        if code[a] == '!':
            value = evaluate(a + 1, b, depth + 1)
            return None if value is None else not value
        fragment = code[a:b]
        comparison = re.fullmatch(r'(.+?)\s*(==|!=|is\s+not|is)\s*(true|false)', fragment, re.S)
        reverse = False
        if not comparison:
            comparison = re.fullmatch(r'(true|false)\s*(==|!=)\s*(.+)', fragment, re.S)
            reverse = True
        if comparison:
            group = 3 if reverse else 1
            value = evaluate(a + comparison.start(group), a + comparison.end(group), depth + 1)
            literal = comparison[1 if reverse else 3] == 'true'
            if value is None:
                return None
            equal = value == literal
            return not equal if ' '.join(comparison[2].split()) in ('!=', 'is not') else equal
        if fragment in ('true', 'false'):
            return fragment == 'true'
        if re.fullmatch(r'(?:\w+\.)*IsDevelopment\s*\(\s*\)', fragment):
            return development
        env = re.fullmatch(r'\s*(?:\w+\.)*EnvironmentName\s*(==|!=)\s*"Development"\s*', raw[a:b])
        if env:
            return development if env[1] == '==' else not development
        return None

    return evaluate(0, len(code), 0)


def _branches(code: str, raw: str) -> List[tuple]:
    """Conditional body spans and whether each branch is known to run outside development."""
    branches = []
    for m in re.finditer(r'\bif\s*\(', code):
        start = code.find('(', m.start())
        end = _end(code, start)
        if _delimiters(code).get(start) != end:
            continue
        value = _condition_value(code[start:end], raw[start:end], development=False)
        body = end
        while body < len(code) and code[body].isspace():
            body += 1
        finish = _end(code, body, '{', '}') if code[body:body+1] == '{' else _statement(code, body)
        branches.append((body, finish, value))
        other = re.match(r'\s*else\b\s*', code[finish:])
        if other:
            begin = finish + other.end()
            stop = _end(code, begin, '{', '}') if code[begin:begin+1] == '{' else _statement(code, begin)
            branches.append((begin, stop, None if value is None else not value))
    return branches


def _unconditional_in_production(pos: int, branches: Sequence[tuple]) -> bool:
    return all(value is True for a, b, value in branches if a <= pos < b)


def _finding(sf: SourceFile, rule: Rule, pos: int, **kw: Any) -> Finding:
    code, _ = _views(sf)
    line = code[:pos].count('\n') + 1
    evidence = sanitize_text(sf.raw[line - 1] if line <= len(sf.raw) else '', 200)
    return make_finding(rule, sf, line, evidence=evidence, **kw)


def context(sources: Sequence[SourceFile]) -> Dict[str, Dict[str, Any]]:
    dirs = {os.path.dirname(s.rel) for s in sources if s.rel.lower().endswith('.csproj')}
    out: Dict[str, Dict[str, Any]] = {}
    groups: Dict[str, Dict[str, Any]] = {}
    for sf in sources:
        if sf.lang != 'csharp' and not sf.rel.lower().endswith('.json'):
            continue
        parent = os.path.dirname(sf.rel)
        candidates = [d for d in dirs if not d or parent == d or parent.startswith(d + '/')]
        group = max(candidates, key=len) if candidates else parent
        item = groups.setdefault(group, {'fallback': False, 'https': False, 'controllers': False, 'ai_types': set(), 'fallback_bad': False})
        code, raw = _views(sf)
        if sf.lang == 'csharp':
            branches = _branches(code, raw)
            for m in re.finditer(r'\b(?:FallbackPolicy\s*=|SetFallbackPolicy\s*\()', code):
                finish = _statement(code, m.end())
                fragment = code[m.end():finish]
                if re.search(r'\bRequireAuthenticatedUser\s*\(', fragment) and _unconditional_in_production(m.start(), branches):
                    item['fallback'] = True
                else:
                    item['fallback_bad'] = True
            item['https'] |= any(_unconditional_in_production(m.start(), branches)
                                 for m in re.finditer(r'\.UseHttpsRedirection\s*\(', code))
            item['controllers'] |= any(_unconditional_in_production(m.start(), branches)
                                       for m in re.finditer(r'\.MapControllers\s*\(\s*\)\s*\.RequireAuthorization\s*\(', code))
            for m in re.finditer(r'AddHttpClient\s*<\s*(\w+)\s*>\s*\(', code):
                end = _end(code, code.find('(', m.start()))
                if _AI.search(raw[m.start():end]):
                    item['ai_types'].add(m[1])
        out[sf.rel] = item
    for item in groups.values():
        item['fallback'] = item['fallback'] and not item['fallback_bad']
    return out


def _constant_response(body: str) -> bool:
    # Strings are blank in this view. Empty/constant health/metrics objects do not expose application data.
    if re.search(r'\b(?:SaveChanges|ExecuteAsync|InsertAsync|UpdateAsync|DeleteAsync)\s*\(', body):
        return False
    if re.search(r'(?:\breturn|=>)\s*(?:Results\.)?(?:Ok|Json|File)\s*\(\s*[A-Za-z_]\w*(?!\w)\s*[,.)]', body) \
            and not re.search(r'\(\s*(?:true|false|null)\s*\)', body):
        return False
    if re.search(r'(?:\breturn|=>)\s*(?!(?:new|true|false|null|Results|Ok|Json|File)\b)[A-Za-z_]\w*\s*(?:[.;(]|$)', body):
        return False
    if re.search(r'\b\w+\s*=\s*(?!(?:true|false|null)\b)[A-Za-z_]\w*', body):
        return False
    return True


def _sensitive(verb: str, route: str, body: str) -> bool:
    if route.lower().strip('/') in {'login', 'register', 'signup', 'token', 'forgot-password', 'reset-password'}:
        return False
    writes = re.search(r'\.\s*(?:SaveChanges(?:Async)?|InsertAsync|UpdateAsync|DeleteAsync|ExecuteAsync)\s*\(', body)
    if writes:
        return True
    return bool((_PRIVATE.search(route) or _PERSONAL.search(body)) and not _constant_response(body))


def _authorization(sf: SourceFile, rule: Rule, ctx: Dict[str, Any]) -> List[Finding]:
    code, raw = _views(sf)
    out = []
    protected, anonymous_vars = set(), set()
    branches = _branches(code, raw)
    assignments = {}
    for m in re.finditer(r'\b(\w+)\s*=(?!=|>)', code):
        assignments[m[1]] = assignments.get(m[1], 0) + 1
    for m in re.finditer(r'\b(\w+)\.(RequireAuthorization|AllowAnonymous)\s*\(', code):
        if m[2] == 'AllowAnonymous':
            anonymous_vars.add(m[1])
        elif assignments.get(m[1], 0) <= 1 and _unconditional_in_production(m.start(), branches):
            protected.add(m[1])
    for m in re.finditer(r'\b(?:var|RouteGroupBuilder)\s+(\w+)\s*=\s*(\w+)\.MapGroup\s*\(', code):
        end = _statement(code, m.end() - 1)
        if re.search(r'\.AllowAnonymous\s*\(', code[m.end():end]) or m[2] in anonymous_vars:
            anonymous_vars.add(m[1])
        if assignments.get(m[1], 0) <= 1 and _unconditional_in_production(m.start(), branches) and \
                (re.search(r'\.RequireAuthorization\s*\(', code[m.end():end]) or m[2] in protected):
            protected.add(m[1])
    protected = {v for v in protected if assignments.get(v, 0) <= 1}
    for m in re.finditer(r'\b(\w+)\.Map(Get|Post|Put|Patch|Delete|Methods)\s*\(', code):
        start = code.find('(', m.start())
        end = _end(code, start)
        if _delimiters(code).get(start) != end:
            continue
        finish = _statement(code, m.start())
        tail = code[end:finish]
        assigned = re.search(r'(?:var|RouteHandlerBuilder)\s+(\w+)\s*=\s*$', code[max(0,m.start()-150):m.start()])
        anonymous = bool(re.search(r'\.AllowAnonymous\s*\(', tail)) or m[1] in anonymous_vars or (assigned and assigned[1] in anonymous_vars)
        metadata_auth = re.search(r'\.WithMetadata\s*\(\s*new\s+(?:\w+\.)*AuthorizeAttribute\s*\(', tail)
        if not anonymous and (ctx.get('fallback') or m[1] in protected or (assigned and assigned[1] in protected) or metadata_auth or re.search(r'\.RequireAuthorization\s*\(', tail)):
            continue
        args = _args(code, start + 1, end - 1)
        route_match = re.search(r'"((?:[^"\\]|\\.)*)"', raw[args[0][0]:args[0][1]]) if args else None
        route = route_match[1] if route_match else ''
        body = code[args[1][0]:end] if len(args) > 1 else ''
        if _sensitive(m[2], route, body):
            out.append(_finding(sf, rule, m.start()))
    # Controller attributes apply to their own class/actions; AllowAnonymous overrides an Authorize attribute.
    attribute = lambda name, text: bool(re.search(r'(?:\[|,)\s*(?:\w+\.)*' + name + r'(?:Attribute)?\b', text))
    for cls in re.finditer(r'\bclass\s+(\w+)\s*:\s*[^{};]{0,500}\bController(?:Base)?\b[^{};]{0,500}\{', code):
        begin = code.find('{', cls.start())
        end = _end(code, begin, '{', '}')
        prefix = code[max(0, max(code.rfind('}', 0, cls.start()), code.rfind(';', 0, cls.start()))):cls.start()]
        class_auth = attribute('Authorize', prefix)
        class_anon = attribute('AllowAnonymous', prefix)
        for action in re.finditer(r'(?:\[|,)\s*(?:\w+\.)*Http(Get|Post|Put|Patch|Delete)(?:Attribute)?\b', code[begin:end]):
            pos = begin + action.start()
            boundary = max(code.rfind('}', begin, pos), code.rfind(';', begin, pos), begin)
            attrs_end = code.find('public', pos, min(end, pos + 3000))
            if attrs_end < 0:
                continue
            attrs = code[boundary:attrs_end]
            params = code.find('(', attrs_end, min(end, attrs_end + 2000))
            if params < 0:
                continue
            after_params = _end(code, params)
            tail = re.match(r'\s*(=>|\{)', code[after_params:])
            if not tail:
                continue
            method_end = (_end(code, after_params + tail.end() - 1, '{', '}') if tail[1] == '{'
                          else _statement(code, after_params))
            auth = class_auth or attribute('Authorize', attrs) or ctx.get('fallback') or ctx.get('controllers')
            anon = class_anon or attribute('AllowAnonymous', attrs)
            if auth and not anon:
                continue
            route_text = cls[1] + raw[pos:attrs_end]
            if _sensitive(action[1], route_text, code[attrs_end:method_end]):
                out.append(_finding(sf, rule, pos))
    return out


def _cors(sf: SourceFile, rule: Rule) -> List[Finding]:
    code, _ = _views(sf)
    out = []
    for m in re.finditer(r'\.\s*(AllowAnyOrigin|SetIsOriginAllowed)\s*\(', code):
        start = code.find('(', m.start())
        end = _end(code, start)
        if m[1] == 'SetIsOriginAllowed' and not re.search(r'=>\s*(?:true\b|\{\s*return\s+true\s*;)', code[start:end]):
            continue
        # Stay in this lambda/statement, not another named CORS policy nearby.
        begin = max(code.rfind('=>', 0, m.start()), code.rfind(';', 0, m.start()), code.rfind('{', 0, m.start()), 0)
        finish = end
        while True:
            nxt = re.match(r'\s*\.\s*\w+\s*\(', code[finish:])
            if not nxt:
                break
            finish = _end(code, finish + nxt.end() - 1)
        if re.search(r'\.AllowCredentials\s*\(', code[begin:finish]):
            out.append(_finding(sf, rule, m.start()))
    return out


def _development(sf: SourceFile, rule: Rule) -> List[Finding]:
    code, raw = _views(sf)
    guarded = [(a,b) for a,b,value in _branches(code, raw) if value is False]
    return [_finding(sf, rule, m.start()) for m in re.finditer(r'\.UseDeveloperExceptionPage\s*\(|\bDetailedErrors\s*=\s*true\b', code)
            if not any(a <= m.start() < b for a,b in guarded)]


def _http(sf: SourceFile, rule: Rule, ctx: Dict[str, Any]) -> List[Finding]:
    if ctx.get('https') or sf.rel.lower().endswith('launchsettings.json') or '.development.' in sf.rel.lower():
        return []
    code, raw = _views(sf)
    if sf.lang == 'csharp':
        out = []
        for m in re.finditer(r'\.ListenAnyIP\s*\(|\.UseUrls\s*\(', code):
            end = _end(code, code.find('(', m.start()))
            text = raw[m.start():end]
            if m[0].startswith('.ListenAnyIP'):
                bad = not re.search(r'\.UseHttps\s*\(', code[m.start():end])
            else:
                bad = bool(re.search(r'http://(?:0\.0\.0\.0|\*|\+|\[::\])(?=[:/"\s])', text, re.I))
            if bad:
                out.append(_finding(sf, rule, m.start()))
        return out
    if sf.lang == 'json' and os.path.basename(sf.rel).lower().startswith('appsettings'):
        try:
            config = json.loads(sf.text)
        except (ValueError, RecursionError):
            return []
        values = set()
        pending = [(config, ())]
        while pending:
            item, path = pending.pop()
            if isinstance(item, dict):
                pending.extend((v,path+(str(k).lower(),)) for k,v in item.items())
            elif isinstance(item, str) and (path == ('urls',) or (path[:2] == ('kestrel','endpoints') and path[-1:] == ('url',))):
                values.add(item)
        return [_finding(sf, rule, m.start()) for m in re.finditer(r'"(?:urls|url)"\s*:\s*"([^"\\]*)"', sf.text, re.I)
                if m[1] in values and re.search(r'http://(?:0\.0\.0\.0|\*|\+|\[::\])(?=[:/;]|$)',m[1],re.I)]
    return []


def _sql(sf: SourceFile, rule: Rule) -> List[Finding]:
    code, raw = _views(sf)
    out, seen = [], set()
    pattern = r'\b(?:FromSqlRaw|ExecuteSqlRaw(?:Async)?|SqlQueryRaw|Query(?:Single|First|Multiple)?(?:OrDefault)?(?:Async)?|Execute(?:Scalar)?(?:Async)?|SqlCommand)\s*(?:<[^<>\n]{1,150}>)?\s*\(|\bCommandText\s*='
    for m in re.finditer(pattern, code):
        if m[0].rstrip().endswith('='):
            a, b = m.end(), _statement(code, m.end())
        else:
            start = code.find('(', m.start())
            end = _end(code, start)
            parts = _args(code, start + 1, end - 1)
            a,b = parts[0]
        first = raw[a:b].strip()
        pos = a
        if re.fullmatch(r'\w+', first):
            assigns = list(re.finditer(r'\b' + re.escape(first) + r'\s*=\s*', code[:m.start()]))
            if not assigns:
                continue
            pos = assigns[-1].end()
            first = raw[pos:_statement(code, pos)].strip()
        # The generic SQL rule already handles concatenation. This adds C# interpolation at string sinks only;
        # FromSql/FromSqlInterpolated are deliberately absent because EF parameterizes those arguments.
        if re.search(r'(?:\$@?|@\$)"', first) and re.search(r'\b(?:SELECT|INSERT|UPDATE|DELETE|EXEC)\b', first, re.I) and \
                re.search(r'(?<!\{)\{(?!\{)[^}]+\}', first) and pos not in seen:
            out.append(_finding(sf, rule, pos))
            seen.add(pos)
    return out


def _types(sf: SourceFile, rule: Rule) -> List[Finding]:
    code, _ = _views(sf)
    uses = []
    for use in re.finditer(r'\b(?:\w+\.)?Deserialize(?:Object)?(?:<[^<>]{1,100}>)?\s*\(', code):
        uses.append((use.start(), _end(code, code.find('(',use.start()))))
    out = []
    for m in re.finditer(r'\bTypeNameHandling\s*\.\s*(?:All|Auto|Objects|Arrays)\b|\bnew\s+SimpleTypeResolver\s*\(', code):
        # Tie the setting to a deserialization call, rather than an unrelated serializer in this file.
        begin = code.rfind(';', 0, m.start()) + 1
        finish = _statement(code, begin)
        fragment = code[begin:finish]
        if re.search(r'\b(?:SerializationBinder|Binder)\s*=\s*new\b', fragment):
            continue         # correctness of an explicit binder needs review beyond this lead
        assigned = re.search(r'\b(\w+)\s*=\s*new\s+(?:\w+\.)*(?:JsonSerializerSettings|JavaScriptSerializer)\b', fragment)
        variable = assigned[1] if assigned else None
        direct = re.search(r'\b(\w+)\.TypeNameHandling\s*=', fragment)
        variable = direct[1] if direct else variable
        if any(a <= m.start() < b or (variable and re.search(r'\b'+re.escape(variable)+r'\b', code[a:b])) for a,b in uses):
            out.append(_finding(sf, rule, m.start()))
    return out


def _ai(sf: SourceFile, rule: Rule, ctx: Dict[str, Any]) -> List[Finding]:
    code, raw = _views(sf)
    receivers = set()
    for typ in ctx.get('ai_types', set()):
        receivers.update(re.findall(r'\b' + re.escape(typ) + r'\s+(\w+)\b', code))
    out = []
    for m in re.finditer(r'\b(\w+)\.(\w+)\s*\(', code):
        start = code.find('(', m.start())
        end = _end(code, start)
        args = raw[start:end]
        known = m[1] in receivers or m[2] in {'CompleteChatAsync', 'GetChatCompletionsAsync', 'GetResponseAsync'} or \
                (m[2] in {'PostAsJsonAsync','PostAsync','SendAsync'} and _AI.search(args))
        field = r'\b\w+\.(?:Email|FullName|Phone|SSN|SocialSecurityNumber|DateOfBirth)\b'
        def unredacted(fragment: str) -> bool:
            spans = []
            for red in re.finditer(r'\b(?:Redact|Anonymi[sz]e|Saniti[sz]e(?:Pii|PersonalData)|RemovePii)\w*\s*\(', fragment, re.I):
                spans.append((red.start(), _end(fragment, fragment.find('(',red.start()))))
            return any(not any(a <= p.start() < b for a,b in spans) for p in re.finditer(field,fragment,re.I))
        personal = unredacted(code[start:end])
        # Interpolated strings are blank in the code view. Only expressions inside their braces count.
        if not personal and re.search(r'(?:\$@?|@\$)"', args):
            personal = any(unredacted(expr) for expr in re.findall(r'(?<!\{)\{(?!\{)([^}]+)\}', args))
        if known and personal:
            out.append(_finding(sf, rule, m.start()))
    return out


def _xml(sf: SourceFile, rule: Rule) -> List[Finding]:
    text = sf.text
    if '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper():
        return []
    try:
        root = ET.fromstring(text)
    except (ET.ParseError, ValueError, RecursionError):
        return []
    # Remove comments/CDATA in linear time, preserving offsets for the real element starts.
    view, cursor = [], 0
    while cursor < len(text):
        a = text.find('<!--', cursor)
        b = text.find('<![CDATA[', cursor)
        candidates = [(p,token) for p,token in ((a,'-->'),(b,']]>')) if p >= 0]
        if not candidates:
            view.append(text[cursor:]); break
        pos, token = min(candidates)
        view.append(text[cursor:pos])
        finish = text.find(token, pos)
        finish = len(text) if finish < 0 else finish + len(token)
        view.append(''.join('\n' if c=='\n' else ' ' for c in text[pos:finish]))
        cursor = finish
    masked = ''.join(view)
    starts = list(re.finditer(r'<(?:[\w.-]+:)?(?:PackageReference|PackageVersion|Exec)\b', masked))
    elements = [e for e in root.iter() if e.tag.rsplit('}',1)[-1] in {'PackageReference','PackageVersion','Exec'}]
    out = []
    for match, element in zip(starts, elements):
        tag = element.tag.rsplit('}',1)[-1]
        if rule.id == 'JH142' and tag in ('PackageReference','PackageVersion'):
            v = element.get('Version') or next((e.text or '' for e in element if e.tag.rsplit('}',1)[-1]=='Version'), '')
            if '*' in v:
                out.append(_finding(sf, rule, match.start()))
        if rule.id == 'JH143' and tag == 'Exec':
            command = element.get('Command', '')
            if re.search(r'\b(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod|DownloadString|DownloadFile)\b', command, re.I) and \
                    re.search(r'https?://', command, re.I):
                out.append(_finding(sf, rule, match.start()))
    return out


def findings(sf: SourceFile, rule: Rule, contexts: Dict[str, Dict[str, Any]]) -> List[Finding]:
    ctx = contexts.get(sf.rel, {})
    if rule.id in ('JH142','JH143'):
        return _xml(sf,rule)
    if sf.lang != 'csharp' and rule.id != 'JH138':
        return []
    return {'JH135': lambda: _authorization(sf,rule,ctx), 'JH136': lambda: _cors(sf,rule),
            'JH137': lambda: _development(sf,rule), 'JH138': lambda: _http(sf,rule,ctx),
            'JH139': lambda: _sql(sf,rule), 'JH140': lambda: _types(sf,rule),
            'JH141': lambda: _ai(sf,rule,ctx)}[rule.id]()
