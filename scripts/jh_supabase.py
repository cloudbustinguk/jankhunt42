"""Supabase: judge a project's database as its migrations leave it, inertly.

A Supabase project keeps its schema as SQL migrations, supabase/migrations/<timestamp>_<name>.sql, applied in name
order. Whether a table is open is decided across them: it is created in one file, may get row-level security in
another (or never), is granted to the API roles (anon, authenticated) by a schema dump or a hand-written grant, and
gains policies and views later. context() replays every migration folder of a scan, in order, into one picture per
folder; the rules report the statement that made each problem, in the file where it is. Nothing here connects to a
database or runs SQL.

Exposure has two layers. The Data API serves the schemas listed in supabase/config.toml ([api] schemas; public when
there is no config). A role reaches a table only with a grant: until 2026 every new public table was granted to anon
and authenticated automatically; projects created from May 30, 2026, and all projects from October 30, 2026, need an
explicit grant (Supabase changelog). Row-level security is the second layer: a granted table without it gives every
row to every request made with the public anon key.
"""
from __future__ import annotations

import bisect
import os
import re
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from jh_core import Finding, Rule, SourceFile, cut, make_finding

_MIGRATION = re.compile(r"(?i)(?:^|/)supabase/migrations/[^/]+\.sql$")
_CONFIG = re.compile(r"(?i)(?:^|/)supabase/config\.toml$")
MAX_STATEMENTS = 100000                  # per file: a dump larger than this is read only this far
API_ROLES = {"anon", "authenticated", "public"}

_IDENT = r'(?:"(?:[^"]|"")+"|[A-Za-z_][\w$]*)'
_QNAME = r"%s(?:\s*\.\s*%s)?" % (_IDENT, _IDENT)
_QNAMES = r"%s(?:\s*,\s*%s)*" % (_QNAME, _QNAME)
_SPECIAL = re.compile(r"--|/\*|['\";$]")
_COPY_STDIN = re.compile(r"(?is)^copy\b.*\bfrom\s+stdin\b")
_DOLLAR = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)?\$")


def in_migrations(rel: str) -> bool:
    return bool(_MIGRATION.search(rel))


# ------------------------------------------------------------------ reading SQL

def statements(text: str) -> List[Tuple[int, str, str]]:
    """Each statement as (line, text, bodies): comments removed, strings and quoted names kept, and the bodies of
    dollar-quoted blocks (functions, DO blocks) taken out of the text and returned apart."""
    nl = [m.start() for m in re.finditer("\n", text)]
    out: List[Tuple[int, str, str]] = []
    buf: List[str] = []
    bodies: List[str] = []
    first: Optional[int] = None
    i, n = 0, len(text)

    def flush() -> None:
        stmt = "".join(buf).strip()
        if stmt and first is not None:
            out.append((bisect.bisect_left(nl, first) + 1, stmt, "\n".join(bodies)))

    while i < n and len(out) < MAX_STATEMENTS:
        m = _SPECIAL.search(text, i)
        end = m.start() if m else n
        chunk = text[i:end]
        if chunk:
            if first is None and chunk.strip():
                first = i + len(chunk) - len(chunk.lstrip())
            buf.append(chunk)
        if not m:
            break
        tok, i = m.group(0), m.start()
        if tok == "--":
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif tok == "/*":
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            buf.append(" ")
        elif tok in "'\"":
            # E'...' takes backslash escapes (E'it\'s'); any string takes a doubled quote ('it''s')
            escapes = tok == "'" and i > 0 and text[i - 1] in "eE" and not (i > 1 and (text[i - 2].isalnum() or
                                                                                      text[i - 2] == "_"))
            j = i + 1
            while True:
                j = text.find(tok, j)
                if j < 0:
                    j = n
                    break
                if escapes:
                    k = j
                    while k > i + 1 and text[k - 1] == "\\":
                        k -= 1
                    if (j - k) % 2:                      # an odd run of backslashes escapes this quote
                        j += 1
                        continue
                if text.startswith(tok * 2, j):      # '' or "" inside the quotes
                    j += 2
                    continue
                break
            if first is None:
                first = i
            buf.append(text[i:j + 1])
            i = j + 1
        elif tok == "$":
            d = _DOLLAR.match(text, i)
            if d and not (i and (text[i - 1].isalnum() or text[i - 1] == "_")):
                close = text.find(d.group(0), d.end())
                close = n if close < 0 else close
                bodies.append(text[d.end():close])
                if first is None:
                    first = i
                buf.append(" $$ ")
                i = close + len(d.group(0))
            else:
                buf.append("$")
                i += 1
        else:                                            # ;
            before = len(out)
            flush()
            copying = len(out) > before and bool(_COPY_STDIN.match(out[-1][1]))
            buf, bodies, first = [], [], None
            i += 1
            if copying:                                  # COPY ... FROM stdin: data rows up to a line of \.
                end_data = re.compile(r"(?m)^\\\.\r?$").search(text, i)
                i = n if end_data is None else end_data.end()
    flush()
    return out


def _part(p: str) -> str:
    p = p.strip()
    return p[1:-1].replace('""', '"') if p.startswith('"') else p.lower()


def _qualify(name: str) -> Tuple[str, str]:
    parts = re.findall(_IDENT, name)
    if len(parts) >= 2:
        return _part(parts[0]), _part(parts[1])
    return "public", _part(parts[0]) if parts else ""


def _names(text: str) -> List[Tuple[str, str]]:
    return [_qualify(m.group(0)) for m in re.finditer(_QNAME, text)]


def _roles(text: str) -> Set[str]:
    return {_part(r) for r in re.findall(_IDENT, text)} - {"with", "grant", "option", "granted", "by"}


def _show(key: Tuple[str, str]) -> str:
    return "%s.%s" % key


# ------------------------------------------------------------------ replaying migrations

_CREATE_TABLE = re.compile(r"(?is)^create\s+(?:(?:global|local)\s+)?(temp(?:orary)?\s+|unlogged\s+)?table\s+"
                           r"(?:if\s+not\s+exists\s+)?(%s)" % _QNAME)
_ALTER_TABLE = re.compile(r"(?is)^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(%s)(.*)$" % _QNAME)
_RLS = re.compile(r"(?is)\b(enable|disable)\s+row\s+level\s+security\b")
_RENAME = re.compile(r"(?is)^\s*rename\s+to\s+(%s)\s*$" % _IDENT)
_SET_SCHEMA = re.compile(r"(?is)^\s*set\s+schema\s+(%s)\s*$" % _IDENT)
_DROP = re.compile(r"(?is)^drop\s+(table|view|materialized\s+view)\s+(?:if\s+exists\s+)?(%s)" % _QNAMES)
_GRANT = re.compile(r"(?is)^(grant|revoke)\s+(?:grant\s+option\s+for\s+)?(.+?)\s+on\s+(?:table\s+)?(%s)\s+"
                    r"(?:to|from)\s+(.+?)\s*(?:with\s+grant\s+option|granted\s+by\s+\S+|cascade|restrict)?\s*$" % _QNAMES)
_GRANT_ALL = re.compile(r"(?is)^(grant|revoke)\s+(?:grant\s+option\s+for\s+)?(.+?)\s+on\s+all\s+tables\s+in\s+schema\s+"
                        r"(%s(?:\s*,\s*%s)*)\s+(?:to|from)\s+(.+?)\s*(?:with\s+grant\s+option|cascade|restrict)?\s*$"
                        % (_IDENT, _IDENT))
_DEFAULTS = re.compile(r"(?is)^alter\s+default\s+privileges\b(.*?)\b(grant|revoke)\b.*?\bon\s+tables\s+(?:to|from)\s+"
                       r"(.+?)\s*(?:with\s+grant\s+option|cascade|restrict)?\s*$")
_POLICY = re.compile(r"(?is)^(create|alter)\s+policy\s+(%s)\s+on\s+(%s)(.*)$" % (_IDENT, _QNAME))
_DROP_POLICY = re.compile(r"(?is)^drop\s+policy\s+(?:if\s+exists\s+)?(%s)\s+on\s+(%s)" % (_IDENT, _QNAME))
_VIEW = re.compile(r"(?is)^create\s+(?:or\s+replace\s+)?(?:temp(?:orary)?\s+)?(?:recursive\s+)?(materialized\s+)?view\s+"
                   r"(?:if\s+not\s+exists\s+)?(%s)(?:\s*\([^)]*\))?(?:\s+with\s*\(([^)]*)\))?\s+as\s+(.*)$" % _QNAME)
_ALTER_VIEW = re.compile(r"(?is)^alter\s+(?:materialized\s+)?view\s+(?:if\s+exists\s+)?(%s)\s+set\s*\(([^)]*)\)" % _QNAME)
_INVOKER = re.compile(r"(?i)\bsecurity_invoker\b(?:\s*=\s*'?(?:true|on|1|yes)\b|\s*(?:,|$))")   # bare = true
_FROM = re.compile(r"(?is)\b(?:from|join)\s+(%s)" % _QNAME)
_STATIC_RLS = re.compile(r"(?is)\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(%s)\s+enable\s+row\s+level\s+security"
                         % _QNAME)
_USER_METADATA = re.compile(r"(?i)\b(?:raw_)?user_meta_?data\b")


def _new_state() -> Dict[str, Any]:
    return {"tables": {}, "views": {}, "policies": [], "defaults": {}, "dynamic": False, "schemas": {"public"}}


def _table(state: Dict[str, Any], key: Tuple[str, str]) -> Dict[str, Any]:
    """A table's entry, made on first mention; one created outside these migrations is not reported."""
    return state["tables"].setdefault(key, {"rel": None, "line": 0, "rls": False, "disabled": False,
                                            "roles": set(), "revoked": set(), "policies": 0})


def _apply(state: Dict[str, Any], rel: str, line: int, stmt: str, bodies: str) -> None:
    s = re.sub(r"\s+", " ", stmt).strip()
    low = s[:40].lower()
    if bodies and re.search(r"(?i)enable\s+row\s+level\s+security", bodies):
        if re.search(r"(?i)\bexecute\b", bodies):
            state["dynamic"] = True                       # row-level security turned on by a loop: tables unknown
        if low.startswith("do "):
            for m in _STATIC_RLS.finditer(bodies):
                _table(state, _qualify(m.group(1)))["rls"] = True
    m = _CREATE_TABLE.match(s)
    if m:
        if m.group(1):                                   # a temporary table lives for one session
            return
        key = _qualify(m.group(2))
        old = state["tables"].get(key)
        if old is None or old["rel"] is None:
            entry = _table(state, key)
            entry.update(rel=rel, line=line)
            entry["roles"] |= state["defaults"].get(key[0], set())
        return
    m = _ALTER_TABLE.match(s)
    if m:
        key, rest = _qualify(m.group(1)), m.group(2)
        rls = _RLS.search(rest)
        if rls:
            entry = _table(state, key)
            entry["rls"] = rls.group(1).lower() == "enable"
            entry["disabled"] |= not entry["rls"]
        renamed = _RENAME.match(rest)
        if renamed and key in state["tables"]:
            state["tables"][(key[0], _part(renamed.group(1)))] = state["tables"].pop(key)
        moved = _SET_SCHEMA.match(rest)
        if moved and key in state["tables"]:
            state["tables"][(_part(moved.group(1)), key[1])] = state["tables"].pop(key)
        return
    m = _DROP.match(s)
    if m:
        where = "tables" if m.group(1).lower() == "table" else "views"
        for key in _names(m.group(2)):
            state[where].pop(key, None)
        return
    m = _GRANT_ALL.match(s)
    if m:
        grant, privileges, roles = m.group(1).lower() == "grant", m.group(2).lower(), _roles(m.group(4)) & API_ROLES
        schemas = {_part(x) for x in re.findall(_IDENT, m.group(3))}
        for key, entry in state["tables"].items():
            if key[0] in schemas:
                _grant(entry, grant, privileges, roles)
        return
    m = _GRANT.match(s)
    if m:
        grant, privileges, roles = m.group(1).lower() == "grant", m.group(2).lower(), _roles(m.group(4)) & API_ROLES
        if re.match(r"(?i)(?:schema|function|procedure|routine|sequence|all\s|type|database|domain|usage)\b", m.group(3)) \
                or not roles:
            return
        for key in _names(m.group(3)):
            if key in state["views"]:
                _grant(state["views"][key], grant, privileges, roles)
            else:
                _grant(_table(state, key), grant, privileges, roles)
        return
    m = _DEFAULTS.match(s)
    if m:
        schema = re.search(r"(?is)\bin\s+schema\s+(%s)" % _IDENT, m.group(1))
        target = _part(schema.group(1)) if schema else "public"
        roles = _roles(m.group(3)) & API_ROLES
        current = state["defaults"].setdefault(target, set())
        if m.group(2).lower() == "grant":
            current |= roles
        else:
            current -= roles
        return
    m = _POLICY.match(s)
    if m:
        key = _qualify(m.group(3))
        if m.group(1).lower() == "create":
            _table(state, key)["policies"] += 1
        state["policies"].append({"rel": rel, "line": line, "name": _part(m.group(2)), "table": key,
                                  "text": m.group(4), "dropped": False})
        return
    m = _DROP_POLICY.match(s)
    if m:
        name, key = _part(m.group(1)), _qualify(m.group(2))
        for policy in state["policies"]:
            if policy["name"] == name and policy["table"] == key:
                policy["dropped"] = True
        if key in state["tables"] and state["tables"][key]["policies"]:
            state["tables"][key]["policies"] -= 1
        return
    m = _VIEW.match(s)
    if m:
        key = _qualify(m.group(2))
        state["views"][key] = {"rel": rel, "line": line, "materialized": bool(m.group(1)),
                               "invoker": bool(_INVOKER.search(m.group(3) or "")),
                               "reads": [_qualify(x) for x in _FROM.findall(m.group(4))],
                               "roles": set(), "revoked": set()}
        return
    m = _ALTER_VIEW.match(s)
    if m and _qualify(m.group(1)) in state["views"]:
        state["views"][_qualify(m.group(1))]["invoker"] = bool(_INVOKER.search(m.group(2)))


def _grant(entry: Dict[str, Any], grant: bool, privileges: str, roles: Set[str]) -> None:
    if grant:
        entry["roles"] |= roles
        entry["revoked"] -= roles
    elif re.search(r"\ball\b|\bselect\b", privileges):           # without SELECT, a role cannot read it any more
        entry["roles"] -= roles
        entry["revoked"] |= roles


def _schemas(config: Optional[SourceFile]) -> Set[str]:
    """The schemas the Data API serves: [api] schemas in supabase/config.toml, else public."""
    if config is None:
        return {"public"}
    api = re.search(r"(?ms)^\[api\]\s*$(.*?)(?=^\[|\Z)", config.text)
    listed = re.search(r"(?ms)^\s*schemas\s*=\s*\[(.*?)\]", api.group(1)) if api else None
    if not listed:
        return {"public"}
    return {x.strip().strip("'\"") for x in listed.group(1).split(",") if x.strip().strip("'\"")} or {"public"}


def context(sources: Sequence[SourceFile]) -> Dict[str, Dict[str, Any]]:
    """Each migration folder's database as its migrations leave it, by folder; each migration file points to its
    folder's state under its own path too."""
    folders: Dict[str, List[SourceFile]] = {}
    configs: Dict[str, SourceFile] = {}
    for sf in sources:
        if _MIGRATION.search(sf.rel):
            folders.setdefault(os.path.dirname(sf.rel), []).append(sf)
        elif _CONFIG.search(sf.rel):
            configs[os.path.dirname(sf.rel)] = sf
    out: Dict[str, Dict[str, Any]] = {}
    for folder, files in folders.items():
        state = _new_state()
        state["schemas"] = _schemas(configs.get(os.path.dirname(folder)))
        for sf in sorted(files, key=lambda s: os.path.basename(s.rel)):
            for line, stmt, bodies in statements(sf.text):
                _apply(state, sf.rel, line, stmt, bodies)
            out[sf.rel] = state
    return out


# ------------------------------------------------------------------ rules

def table_findings(sf: SourceFile, rule: Rule, ctx: Dict[str, Dict[str, Any]]) -> List[Finding]:
    """JH134: a table in an API schema that the migrations leave without row-level security."""
    state = ctx.get(sf.rel)
    if not state or state["dynamic"]:
        return []
    out = []
    for key, t in sorted(state["tables"].items(), key=lambda kv: kv[1]["line"]):
        if t["rel"] != sf.rel or t["rls"] or t["disabled"] or key[0] not in state["schemas"]:
            continue                 # an explicit DISABLE is reported where it is written
        policies = (" Its %d %s not enforced while row-level security is off." % (
            t["policies"], "policy is" if t["policies"] == 1 else "policies are")) if t["policies"] else ""
        if t["roles"] & {"anon", "public"}:
            sev, conf, msg = "critical", "high", (
                "The table %s is granted to anon and has no row-level security: anyone with the project URL and the "
                "public anon key reads and changes every row through the Data API." % _show(key))
        elif "authenticated" in t["roles"]:
            sev, conf, msg = "major", "high", (
                "The table %s is granted to authenticated users and has no row-level security: anyone who signs up "
                "reads and changes every row through the Data API." % _show(key))
        elif t["revoked"] >= {"anon", "authenticated"}:
            continue
        else:
            sev, conf, msg = "major", "medium", (
                "The table %s has no row-level security. A Supabase project made before May 30, 2026 serves new "
                "public tables to the API automatically, so anyone with the anon key reads and changes every row; "
                "a newer one serves it once it is granted." % _show(key))
        out.append(make_finding(rule, sf, t["line"], severity=sev, confidence=conf, message=msg + policies))
    return out[:20]


def findings(sf: SourceFile, rule: Rule, ctx: Dict[str, Dict[str, Any]]) -> List[Finding]:
    state = ctx.get(sf.rel)
    if not state:
        return []
    out: List[Finding] = []
    if rule.check == "supabase_user_metadata":
        for p in state["policies"]:
            if p["rel"] == sf.rel and not p["dropped"] and _USER_METADATA.search(p["text"]):
                out.append(make_finding(rule, sf, p["line"], message=(
                    "The policy '%s' on %s decides access from user_metadata, which every signed-in user can change "
                    "for themselves (auth.updateUser), so a user can grant themselves what it checks." % (
                        cut(p["name"], 60), _show(p["table"])))))
    if rule.check == "supabase_view_bypass":
        for key, v in sorted(state["views"].items(), key=lambda kv: kv[1]["line"]):
            if v["rel"] != sf.rel or v["invoker"] or key[0] not in state["schemas"] or \
                    v["revoked"] >= {"anon", "authenticated"}:
                continue
            users = ("auth", "users") in v["reads"]
            guarded = sorted({_show(t) for t in v["reads"] if state["tables"].get(t, {}).get("rls")})
            if users:
                out.append(make_finding(rule, sf, v["line"], severity="critical", message=(
                    "The view %s reads auth.users and is served by the Data API: it can show every user's email and "
                    "metadata to whoever may read the view." % _show(key))))
            elif guarded:
                what = "materialized view %s keeps a copy of" % _show(key) if v["materialized"] else \
                    "view %s runs as its owner and reads" % _show(key)
                out.append(make_finding(rule, sf, v["line"], message=(
                    "The %s %s, so their row-level security does not apply: whoever may read the view sees every "
                    "row. Create it with (security_invoker = true), or keep it out of the API schema." % (
                        what, ", ".join(guarded[:3])))))
    return out[:20]
