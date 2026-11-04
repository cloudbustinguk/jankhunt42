"""Power Platform: read solution exports and canvas apps, inertly.

A citizen developer exports a solution as a .zip (solution.xml, customizations.xml, Workflows/<flow>.json) or commits
the unpacked folder. expand() opens a solution zip within fixed limits and returns the members worth reading as text,
each named <zip path>!/<member>, so every rule (hardcoded secrets included) reads a flow inside a zip as it reads an
unpacked one. Nothing here runs a flow, evaluates an expression, resolves a connection or fetches anything.

What is read: cloud flows (Workflows/*.json, or a flow package's definition.json), Copilot Studio agents
(bots/<schema>/bot.xml and configuration.json) and their components (botcomponents/<schema>/data: topics, tools,
instructions), environment variables (environmentvariabledefinitions/<schema>/), and canvas apps. An agent cloned by
the Copilot Studio extension for VS Code (*.mcs.yml) is read from disk the same way. A canvas app
is an .msapp, itself a zip, committed on its own or kept in a solution as CanvasApps/<name>.msapp; one inside a solution
is opened one level deep and no further. From an app, the Power Fx source (Src/*.pa.yaml) is read as written. An app
saved before that format exists keeps its formulas in Controls/*.json and Components/*.json; those are read as a
listing, one line per property, `<control>.<property>: =<formula>`, named <member>!/formulas.yaml, so secret rules see
the formula and not JSON escapes.

Flow definitions use the Logic Apps workflow definition language: properties.definition.triggers and .actions, with
connectors named by API (/providers/Microsoft.PowerApps/apis/shared_<connector>) through properties.connectionReferences
or the action's host. The rules here report what the export shows; tenant DLP policy, the connection's real account and
whether the flow is turned on are not in an export and are never assumed.
"""
from __future__ import annotations

import html
import io
import json
import os
import re
import urllib.parse
import zipfile
from typing import Any, Dict, Iterator, List, Optional, Tuple

from jh_core import MAX_ARCHIVE_BYTES, Finding, Rule, SourceFile, make_finding, source_from_text

MAX_ZIP_BYTES = MAX_ARCHIVE_BYTES        # a solution zip larger than this is not opened
MAX_MEMBERS = 5000                       # entries in the central directory
MAX_MEMBER_BYTES = 4 * 1024 * 1024       # one member, uncompressed
MAX_TOTAL_BYTES = 48 * 1024 * 1024       # everything read from one zip, uncompressed
MAX_RATIO = 200                          # uncompressed / compressed, per member: beyond this it is a bomb
MAX_DEPTH = 64                           # nesting of actions inside scopes, conditions and loops
MAX_APP_BYTES = 16 * 1024 * 1024         # one canvas app inside a solution zip (images make apps large)
MAX_APPS = 32                            # canvas apps opened from one solution zip
MAX_APP_MEMBER_BYTES = 16 * 1024 * 1024  # one screen's formulas: a large screen's Controls/<n>.json passes 12 MB

# members read as text: the flows, and the manifest that identifies the zip. A solution export keeps flows in
# Workflows/<flow>.json; the older flow package (Export > Package (.zip)) keeps each in
# Microsoft.Flow/flows/<id>/definition.json beside a root manifest.json.
_READ = re.compile(r"(?i)^(?:solution\.xml|manifest\.json|workflows/[^/]{1,200}\.json|"
                   r"microsoft\.flow/flows/[^/]{1,100}/definition\.json|bots/[^/]{1,200}/(?:bot\.xml|configuration\.json)|"
                   r"botcomponents/[^/]{1,200}/data|"
                   r"environmentvariabledefinitions/[^/]{1,200}/environmentvariable(?:definition\.xml|values\.json))$")
# an agent's own files, kept by virtual path while a zip's members are loaded, for its components to look up
_AGENT_FILE = re.compile(r"(?i)(?:^|/)bots/[^/]{1,200}/(?:bot\.xml|configuration\.json)$")
_PACKAGE_FLOW = re.compile(r"(?i)^microsoft\.flow/flows/[^/]{1,100}/definition\.json$")
_CANVAS_APP = re.compile(r"(?i)^canvasapps/[^/]{1,200}\.msapp$")
# inside an .msapp, whose member names use backslashes (read here with forward slashes)
_APP_SOURCE = re.compile(r"(?i)^src/[^/]{1,200}\.pa\.yaml$")
_APP_CONTROLS = re.compile(r"(?i)^(?:controls|components)/[^/]{1,200}\.json$")
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._/ ()+-]")


def is_archive(rel: str) -> bool:
    return rel.lower().endswith((".zip", ".msapp"))


def _open(data: Any, rel: str) -> Tuple[Optional[zipfile.ZipFile], List[zipfile.ZipInfo], List[str]]:
    try:
        zf = zipfile.ZipFile(data)
        return zf, zf.infolist(), []
    except UnicodeDecodeError:
        return None, [], ["%s: entry names are not valid UTF-8, not read" % rel]
    except (zipfile.BadZipFile, zipfile.LargeZipFile, ValueError, OSError, EOFError, NotImplementedError):
        return None, [], []


def _kind(infos: List[zipfile.ZipInfo]) -> str:
    """'solution', 'package' (a flow package), 'app' (an .msapp), or '' for any other zip."""
    names = {i.filename.replace("\\", "/").lower() for i in infos[:MAX_MEMBERS]}
    if "solution.xml" in names and "customizations.xml" in names:
        return "solution"
    if "manifest.json" in names and any(_PACKAGE_FLOW.match(n) for n in names):
        return "package"
    if "header.json" in names and "properties.json" in names:
        return "app"
    return ""


class _Reader:
    """Reads members within the limits and records what it could not read. One per expand() call, so a canvas app
    opened from inside a solution zip draws on the same total as the zip around it."""

    def __init__(self, gaps: List[str]) -> None:
        self.gaps = gaps
        self.total = 0
        self.full = False

    def read(self, zf: zipfile.ZipFile, info: zipfile.ZipInfo, where: str, limit: int = MAX_MEMBER_BYTES
             ) -> Optional[bytes]:
        if self.full:
            return None
        if info.flag_bits & 0x1:
            self.gaps.append("%s: encrypted, not read" % where)
            return None
        if info.file_size > limit or info.file_size > MAX_RATIO * max(info.compress_size, 1):
            self.gaps.append("%s: too large or too compressed, not read" % where)
            return None
        self.total += info.file_size
        if self.total > MAX_TOTAL_BYTES:
            self.gaps.append("%s: more than %d MB to read, the rest not read" % (where.split("!/")[0], MAX_TOTAL_BYTES >> 20))
            self.full = True
            return None
        try:
            with zf.open(info) as fh:
                raw = fh.read(limit + 1)                 # the header's size may lie; never read past the limit
        except (zipfile.BadZipFile, NotImplementedError, ValueError, OSError, EOFError, RuntimeError):
            self.gaps.append("%s: unreadable, not read" % where)
            return None
        if len(raw) > limit:
            self.gaps.append("%s: too large, not read" % where)
            return None
        if len(raw) != info.file_size:          # the directory and the data disagree: a truncated or forged entry
            self.gaps.append("%s: size does not match the zip directory, not read" % where)
            return None
        return raw


def expand(data: Any, rel: str, size: Optional[int] = None) -> Tuple[List[Tuple[str, str]], List[str]]:
    """The text members of a Power Platform export or canvas app (bytes, or a seekable binary file of `size` bytes),
    as (virtual path, text), and what could not be read. Only the central directory and the members read are touched.
    A zip that is neither gives nothing and no warning."""
    out: List[Tuple[str, str]] = []
    gaps: List[str] = []
    if isinstance(data, (bytes, bytearray)):
        size, data = len(data), io.BytesIO(data)
    if size is None or size > MAX_ZIP_BYTES:
        return out, ["%s: larger than %d MB, not opened" % (rel, MAX_ZIP_BYTES >> 20)]
    zf, infos, gaps = _open(data, rel)
    kind = _kind(infos) if zf else ""
    if not kind:
        return out, gaps                                 # an ordinary zip, not a Power Platform export
    if len(infos) > MAX_MEMBERS:
        return out, ["%s: more than %d entries, not read" % (rel, MAX_MEMBERS)]
    reader = _Reader(gaps)
    if kind == "app":
        _read_app(zf, infos, rel, reader, out)
        return out, gaps
    apps = 0
    for info in infos:
        name = info.filename
        if info.is_dir():
            continue
        where = "%s!/%s" % (rel, _SAFE_NAME.sub("_", name))
        if _CANVAS_APP.match(name):
            apps += 1
            if apps > MAX_APPS:
                if apps == MAX_APPS + 1:
                    gaps.append("%s: more than %d canvas apps, the rest not read" % (rel, MAX_APPS))
                continue
            raw = reader.read(zf, info, where, MAX_APP_BYTES)
            if raw is None:
                continue
            inner, inner_infos, bad = _open(io.BytesIO(raw), where)
            if inner is None:
                gaps.extend(bad or ["%s: not a readable zip, not read" % where])
            elif _kind(inner_infos) != "app" or len(inner_infos) > MAX_MEMBERS:
                gaps.append("%s: not a canvas app this version reads, not read" % where)
            else:
                _read_app(inner, inner_infos, where, reader, out)        # one level deep: an app holds no apps
            continue
        if not _READ.match(name):
            continue
        raw = reader.read(zf, info, where)
        if raw is not None:
            out.append((where, raw.decode("utf-8-sig", "replace")))
    return out, gaps


def _read_app(zf: zipfile.ZipFile, infos: List[zipfile.ZipInfo], rel: str, reader: _Reader,
              out: List[Tuple[str, str]]) -> None:
    """A canvas app's formulas: Src/*.pa.yaml when the app has them, else a listing of Controls/ and Components/."""
    named = [(i, i.filename.replace("\\", "/")) for i in infos if not i.is_dir()]
    source = [(i, n) for i, n in named if _APP_SOURCE.match(n)]
    for info, name in source or [(i, n) for i, n in named if _APP_CONTROLS.match(n)]:
        where = "%s!/%s" % (rel, _SAFE_NAME.sub("_", name))
        raw = reader.read(zf, info, where, MAX_APP_MEMBER_BYTES)
        if raw is None:
            continue
        text = raw.decode("utf-8-sig", "replace")
        if source:
            out.append((where, text))
        else:
            listing = formulas(text)
            if listing:
                out.append((where + "!/formulas.yaml", listing))


def formulas(text: str) -> str:
    """The Power Fx formulas in a canvas app's Controls/<n>.json, one `<control>.<property>: =<formula>` per line
    (a formula's further lines indented beneath it), or '' when the file holds none."""
    try:
        doc = json.loads(text)
    except (ValueError, RecursionError):
        return ""
    lines: List[str] = []
    stack = [(doc.get("TopParent"), 0)] if isinstance(doc, dict) else []
    while stack:
        node, depth = stack.pop()
        if not isinstance(node, dict) or depth > MAX_DEPTH:
            continue
        control = re.sub(r"\s+", " ", str(node.get("Name") or "?"))[:100]
        for rule in node.get("Rules") if isinstance(node.get("Rules"), list) else []:
            script = rule.get("InvariantScript") if isinstance(rule, dict) else None
            if isinstance(script, str) and script.strip():
                prop = re.sub(r"\s+", " ", str(rule.get("Property") or "?"))[:100]
                first, *rest = script.split("\n")
                lines.append("%s.%s: =%s" % (control, prop, first))
                lines.extend("    " + more for more in rest)
        children = node.get("Children")
        if isinstance(children, list):
            stack.extend((child, depth + 1) for child in reversed(children))
    return "\n".join(lines) + "\n" if lines else ""


GAPS: List[str] = []                     # what load_archive could not read during this load, for the report's warnings
MEMBERS: Dict[str, str] = {}             # agents' bot.xml and configuration.json read from zips, by virtual path


def load_archive(path: Any, root: Any) -> List[SourceFile]:
    """The readable members of a solution zip or canvas app on disk, as sources named <file>!/<member>; gaps go to
    GAPS, and each agent's own files to MEMBERS, where its components look them up."""
    rel = os.path.relpath(str(path), str(root)).replace(os.sep, "/")
    try:
        with open(path, "rb") as fh:
            members, gaps = expand(fh, rel, os.fstat(fh.fileno()).st_size)
    except OSError:
        return []
    GAPS.extend(gaps)
    out = []
    for name, text in members:
        where = str(path) + name[len(rel):]
        if _AGENT_FILE.search(name):
            MEMBERS[os.path.normpath(where)] = text
        sf = source_from_text(name, where, text)
        if sf is not None:
            out.append(sf)
    return out


# ------------------------------------------------------------------ flows

def flow(sf: SourceFile) -> Optional[Dict[str, Any]]:
    """The flow in a JSON file (an exported Workflows/<flow>.json or a Logic Apps-style definition), or None."""
    if sf.lang != "json" or '"definition"' not in sf.text or ('"triggers"' not in sf.text and '"actions"' not in sf.text):
        return None
    cached = getattr(sf, "_jh_flow", False)
    if cached is not False:
        return cached
    doc: Any = None
    try:
        doc = json.loads(sf.text)
    except (ValueError, RecursionError):
        doc = None
    result = None
    if isinstance(doc, dict):
        props = doc.get("properties") if isinstance(doc.get("properties"), dict) else doc
        definition = props.get("definition")
        if isinstance(definition, dict) and (isinstance(definition.get("triggers"), dict) or
                                             isinstance(definition.get("actions"), dict)) and \
                ("workflowdefinition" in str(definition.get("$schema", "")).lower() or
                 "connectionReferences" in props or "contentVersion" in definition):
            refs = props.get("connectionReferences") if isinstance(props.get("connectionReferences"), dict) else {}
            result = {"definition": definition, "refs": refs}
    try:
        sf._jh_flow = result                             # type: ignore[attr-defined]
    except AttributeError:
        pass
    return result


def nodes(definition: Dict[str, Any]) -> Iterator[Tuple[str, str, Dict[str, Any]]]:
    """(kind, name, node) for every trigger and every action, including those inside scopes, conditions, switches and
    loops."""
    for name, node in (definition.get("triggers") or {}).items():
        if isinstance(node, dict):
            yield "trigger", str(name), node
    pending = [(definition.get("actions") or {}, 0)]
    while pending:
        actions, depth = pending.pop()
        if not isinstance(actions, dict) or depth > MAX_DEPTH:
            continue
        for name, node in actions.items():
            if not isinstance(node, dict):
                continue
            yield "action", str(name), node
            pending.append((node.get("actions"), depth + 1))
            if isinstance(node.get("else"), dict):
                pending.append((node["else"].get("actions"), depth + 1))
            if isinstance(node.get("default"), dict):
                pending.append((node["default"].get("actions"), depth + 1))
            for case in (node.get("cases") or {}).values() if isinstance(node.get("cases"), dict) else ():
                if isinstance(case, dict):
                    pending.append((case.get("actions"), depth + 1))


_API = re.compile(r"\bshared_[a-z0-9]+(?:_[a-z][a-z0-9]*)*", re.I)


def connector(node: Dict[str, Any], refs: Dict[str, Any]) -> Optional[str]:
    """The connector an action uses (shared_gmail), from its host and the flow's connection references."""
    inputs = node.get("inputs") if isinstance(node.get("inputs"), dict) else {}
    host = inputs.get("host") if isinstance(inputs.get("host"), dict) else {}
    name = host.get("connectionName")
    if isinstance(name, str):
        ref = refs.get(name)
        api = ref.get("api") if isinstance(ref, dict) else None
        if isinstance(api, dict) and isinstance(api.get("name"), str):
            return api["name"].lower()
    for value in (host.get("apiId"), name, json.dumps(host)[:4000]):
        if isinstance(value, str):
            m = _API.search(value)
            if m:
                return re.sub(r"_\d+$", "", m.group(0).lower())
    return None


def operation(node: Dict[str, Any]) -> str:
    inputs = node.get("inputs") if isinstance(node.get("inputs"), dict) else {}
    host = inputs.get("host") if isinstance(inputs.get("host"), dict) else {}
    return str(host.get("operationId", ""))


def _secured(node: Dict[str, Any], what: str) -> bool:
    rc = node.get("runtimeConfiguration")
    secure = rc.get("secureData") if isinstance(rc, dict) else None
    props = secure.get("properties") if isinstance(secure, dict) else None
    return isinstance(props, list) and what in props


def _at(sf: SourceFile, rule: Rule, name: str, **kw: Any) -> Finding:
    """A finding at the line where a trigger or action is named. A flow package is one minified line, so the evidence
    is the name itself rather than the start of the file."""
    key = json.dumps(name)
    m = re.search(re.escape(key) + r"\s*:", sf.text)
    line = sf.text.count("\n", 0, m.start()) + 1 if m else 1
    return make_finding(rule, sf, line, evidence=key[:120] + ": {", **kw)


# "Who can trigger the flow: Anyone". Microsoft documents the options, not their serialization; public flow
# definitions write the open mode as All. Tenant and specific-user modes are anything else.
OPEN_MODES = {"all", "anyone"}

# consumer-capable connectors: each can connect a personal account, so a flow using one can move work data out of the
# organisation. Whether this connection is personal is not in the export.
CONSUMER = {
    "shared_gmail": "Gmail", "shared_outlook": "Outlook.com", "shared_onedrive": "OneDrive (personal)",
    "shared_dropbox": "Dropbox", "shared_googledrive": "Google Drive", "shared_googlesheet": "Google Sheets",
    "shared_googlecalendar": "Google Calendar", "shared_googlecontacts": "Google Contacts",
}
# AI services reached through a connector; AI Builder prompts run through Dataverse as aibuilderpredict_* operations
AI_CONNECTORS = {"shared_openaiip", "shared_azureopenai", "shared_azureopenaiservice", "shared_anthropic"}
_AI_HOST = re.compile(r"(?i)https://(?:[\w-]+\.)*(?:openai\.com|openai\.azure\.com|anthropic\.com|"
                      r"generativelanguage\.googleapis\.com|api\.mistral\.ai|api\.cohere\.(?:ai|com))(?:[/:?]|$)")
# personal fields as flows name them: request schema properties, list columns, Dataverse columns (emailaddress1,
# telephone1, mobilephone, birthdate, address1_line1)
_PERSONAL = re.compile(r"(?i)\[\s*'(?:[^'\]]*/)?(?:\w*(?:e-?mail|phone|mobile|birth(?:date|day)?|dateofbirth|dob|ssn|"
                       r"socialsecurity|nationalid|passport|fullname|surname|lastname|address(?:\d_line\d)?)\w*)'\s*\]")
_REDACTOR = re.compile(r"(?i)redact|anonymi[sz]|pseudonymi[sz]|mask")
# the step a field is read from: body('Redact_PII')?['email'], outputs('Anonymise')?['body/fullname']
_SOURCE = re.compile(r"(?i)\b(?:body|outputs|actions|items|actionBody|actionOutputs)\s*\(\s*'([^']{1,200})'\s*\)\s*\??\s*(?:\[[^\]]*\]\s*\??\s*)*$")


def _redacted_source(before: str) -> bool:
    source = _SOURCE.search(before)
    return bool(source and _REDACTOR.search(source.group(1)))


# ------------------------------------------------------------------ Copilot Studio agents

# bots/<schema>/bot.xml. authenticationmode is the Dataverse bot table's choice: 0 Unspecified, 1 None (the maker's "No
# authentication"), 2 Integrated (Authenticate with Microsoft), 3 Custom Entra ID, 4 Generic OAuth2.
_BOT_FILE = re.compile(r"(?i)(?:^|/)bots/[^/]{1,200}/bot\.xml$")
_AUTH_MODE = re.compile(r"<authenticationmode>\s*(\d{1,3})\s*</authenticationmode>")


def _line_at(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


# The VS Code extension writes the same choice to settings.mcs.yml as a top-level authenticationMode: None.
_SETTINGS_FILE = re.compile(r"(?i)(?:^|/)settings\.mcs\.ya?ml$")
_MCS_NO_AUTH = re.compile(r"(?m)^authenticationMode:[ \t]*['\"]?None['\"]?[ \t]*\r?$")      # a file saved on Windows too


def _no_sign_in(text: Optional[str], settings: bool) -> Optional["re.Match[str]"]:
    """Where an agent's bot.xml (or settings.mcs.yml) says it needs no sign-in, or None."""
    if not text:
        return None
    if settings:
        return _MCS_NO_AUTH.search(text)
    if not re.search(r"<bot[\s>]", text[:4096]):
        return None
    mode = _AUTH_MODE.search(text)
    return mode if mode and mode.group(1) == "1" else None


def _agent_open(sf: SourceFile, rule: Rule) -> List[Finding]:
    settings = bool(_SETTINGS_FILE.search(sf.rel))
    if not (settings or _BOT_FILE.search(sf.rel)):
        return []
    mode = _no_sign_in(sf.text, settings)
    if not mode:
        return []
    if settings:
        named = re.search(r"(?m)^displayName:[ \t]*['\"]?([^'\"\n]{1,200})", sf.text)
        how = "authenticationMode: None"
    else:
        named = re.search(r"<name>([^<]{1,200})</name>", sf.text) or \
            re.search(r'<bot\s+schemaname="([^"]{1,200})"', sf.text)
        how = "authenticationmode 1"
    label = html.unescape(named.group(1)).strip()[:80] if named else "?"
    return [make_finding(rule, sf, _line_at(sf.text, mode.start()), message=(
        "The Copilot Studio agent '%s' is set to No authentication (%s): anyone who can reach it, on a website, the "
        "demo page or another channel, can chat with it without signing in, and the connector actions it calls run "
        "with the maker's connections, since there is no user to sign in." % (label, how)))]


# ------------------------------------------------------------------ Copilot Studio components
#
# An agent's topics, tools (actions) and instructions are components. A solution export keeps each as
# botcomponents/<schema>/data, YAML, where <schema> is <bot>.<type>.<name>; the agent's settings are in
# bots/<bot>/configuration.json. The VS Code extension clones an agent as agent.mcs.yml (instructions), settings.mcs.yml
# and topics/ and actions/ of *.mcs.yml, in the same YAML. Only the keys these rules need are read, line by line by
# indentation; no expression is evaluated and no connection is resolved.

_COMPONENT = re.compile(r"(?i)(?:^|/)botcomponents/([^/]{1,200})/data$")
_MCS = re.compile(r"(?i)\.mcs\.ya?ml$")


def _component(sf: SourceFile) -> Optional[str]:
    """The component's name (its schema, or the .mcs.yml file's name), or None for any other file."""
    m = _COMPONENT.search(sf.rel)
    if m:
        return m.group(1)
    if _MCS.search(sf.rel):
        return re.sub(r"(?i)\.mcs\.ya?ml$", "", os.path.basename(sf.rel))
    return None


def _sibling(sf: SourceFile, rel: str) -> Optional[str]:
    """Another file of the same export, by a path relative to this one: from the zip's members when this source came
    from a zip, else from disk, inside the folder being scanned (not through a link, and not if large). None when it
    is not there."""
    target = os.path.normpath(os.path.join(os.path.dirname(sf.abspath), rel))
    if "!" + os.sep in sf.abspath or "!/" in sf.abspath:
        return MEMBERS.get(target)
    posix = sf.abspath.replace(os.sep, "/")
    if not posix.endswith("/" + sf.rel):
        return None
    root = os.path.realpath(sf.abspath[:len(sf.abspath) - len(sf.rel)])
    try:
        if not os.path.realpath(target).startswith(os.path.join(root, "")):
            return None                                  # above the folder being scanned
        if os.path.islink(target) or os.path.getsize(target) > MAX_MEMBER_BYTES:
            return None
        with open(target, encoding="utf-8-sig", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def _agent_settings(sf: SourceFile, name: str) -> Tuple[Optional[str], bool]:
    """The agent's bot.xml (solution export) or settings.mcs.yml (VS Code), and whether it is the latter."""
    if _COMPONENT.search(sf.rel):
        return _sibling(sf, "../../bots/%s/bot.xml" % name.split(".")[0]), False
    for up in ("settings.mcs.yml", "../settings.mcs.yml"):        # agent folder, or its topics/ or actions/
        text = _sibling(sf, up)
        if text is not None:
            return text, True
    return None, True


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _end(lines: List[str], i: int) -> int:
    """The index past the block line i opens: the lines after it indented deeper, blank lines included."""
    base, j = _indent(lines[i]), i + 1
    while j < len(lines) and (not lines[j].strip() or _indent(lines[j]) > base):
        j += 1
    return j


def _value(lines: List[str], i: int) -> str:
    """The scalar after the key on line i: inline, quoted, or a block scalar (| |- >) on the deeper lines below."""
    rest = lines[i].split(":", 1)[1].strip() if ":" in lines[i] else ""
    if re.fullmatch(r"[|>][+-]?\d?", rest):
        return "\n".join(line.strip() for line in lines[i + 1:_end(lines, i)]).strip()
    if len(rest) >= 2 and rest[0] == rest[-1] and rest[0] in "\"'":
        rest = rest[1:-1]
    return rest


def _top(lines: List[str], key: str) -> Optional[int]:
    """The line of a top-level key, or None."""
    pat = re.compile(r"^%s:(?:\s|$)" % re.escape(key))
    return next((i for i, line in enumerate(lines) if pat.match(line)), None)


def _short(name: str) -> str:
    """A component's own name: Greeting from <bot>.topic.Greeting."""
    parts = name.split(".", 2)
    return parts[2] if len(parts) == 3 and parts[2] else name


def _label(sf: SourceFile, name: str) -> str:
    i = _top(sf.raw, "modelDisplayName")
    if i is None:
        i = _top(sf.raw, "displayName")
    return (_value(sf.raw, i) if i is not None else "")[:80] or _short(name)[:80]


def _step(lines: List[str], i: int) -> Optional[Tuple[str, str]]:
    """The topic step (a list item `- kind: Invoke...`) that holds line i, as (kind, displayName), or None when line i
    belongs to a tool's own top-level action."""
    ind = _indent(lines[i])
    for j in range(i - 1, -1, -1):
        m = re.match(r"^(\s*)-\s*kind:\s*(Invoke\w+)\s*$", lines[j])
        if m and len(m.group(1)) < ind:
            shown = next((_value(lines, k) for k in range(j + 1, _end(lines, j))
                          if re.match(r"^\s*displayName:", lines[k])), "")
            return m.group(2), shown[:80]
        if lines[j].strip() and _indent(lines[j]) == 0:
            return None
    return None


# --- JH150: a tool runs with the maker's credentials ("Maker-provided credentials")

_TOOL_KIND = {"invokeconnectortaskaction": "connector tool", "invokeflowtaskaction": "flow tool",
              "invokeexternalagenttaskaction": "MCP server tool", "invokeaiplugintaskaction": "plugin tool",
              "invokeconnectoraction": "connector action"}


def _maker_credentials(sf: SourceFile, rule: Rule) -> List[Finding]:
    name = _component(sf)
    if name is None:
        return []
    lines, out = sf.raw, []
    for i, line in enumerate(lines):
        if not re.match(r"^\s*connectionProperties:\s*$", line):
            continue
        for j in range(i + 1, _end(lines, i)):
            if not re.match(r"^\s*mode:\s*['\"]?Maker['\"]?\s*$", lines[j]):
                continue
            step = _step(lines, i)
            if step:                                     # a connector or flow step inside a topic
                shown = step[1] or step[0]
                what = "%s '%s' in topic '%s'" % (_TOOL_KIND.get(step[0].lower(), "step"), shown, _short(name)[:80])
            else:                                        # a tool: the whole component is the tool
                kind = re.search(r"(?m)^\s+kind:\s*(Invoke\w+)\s*$", sf.text)
                what = "%s '%s'" % ("MCP server tool" if "ModelContextProtocolMetadata" in sf.text else
                                    _TOOL_KIND.get(kind.group(1).lower(), "tool") if kind else "tool", _label(sf, name))
            settings, mcs = _agent_settings(sf, name)
            if _no_sign_in(settings, mcs):
                out.append(make_finding(rule, sf, j + 1, severity="critical", message=(
                    "The %s runs with the maker's own connection (Maker-provided credentials), and the agent needs no "
                    "sign-in: anyone who reaches the agent acts with the maker's access to that service." % what)))
            else:
                out.append(make_finding(rule, sf, j + 1, message=(
                    "The %s runs with the maker's own connection (Maker-provided credentials): everyone who chats with "
                    "the agent acts with the maker's access to that service, not their own." % what)))
    return out


# --- JH151: an HTTP request in a topic, over plain HTTP, to an unusual port, or around a connector

_HTTP_ACTION = re.compile(r"^\s*-\s*kind:\s*HttpRequestAction\s*$")
_LOOPBACK = {"localhost", "127.0.0.1", "::1"}
# hosts reached through a Microsoft connector, whose data policies a raw HTTP request does not pass through
_CONNECTOR_HOST = re.compile(r"(?i)^(?:graph\.microsoft\.com|(?:[\w-]+\.)*sharepoint\.com|(?:[\w-]+\.)*dynamics\.com|"
                             r"outlook\.office(?:365)?\.com|management\.azure\.com|api\.powerbi\.com|"
                             r"(?:[\w-]+\.)*vault\.azure\.net)$")


def _literal_url(value: str) -> Optional[str]:
    """A URL written as text, or the text a Power Fx URL starts with (="http://host/" & Topic.Id); else None."""
    v = value.strip()
    if v.startswith("="):
        m = re.match(r'=\s*"([^"]*)"', v)
        if not m:
            return None
        v = m.group(1)
    return v if re.match(r"(?i)^https?://", v) else None


def _http_request(sf: SourceFile, rule: Rule) -> List[Finding]:
    name = _component(sf)
    if name is None:
        return []
    lines, out = sf.raw, []
    for i, line in enumerate(lines):
        if not _HTTP_ACTION.match(line):
            continue
        at = next((j for j in range(i + 1, _end(lines, i)) if re.match(r"^\s*url:", lines[j])), None)
        url = _literal_url(_value(lines, at)) if at is not None else None
        if not url:
            continue
        try:
            parts = urllib.parse.urlsplit(url)
            host, port = (parts.hostname or "").lower(), parts.port
        except ValueError:
            continue
        if not host or host in _LOOPBACK:
            continue
        shown = "%s://%s%s%s" % (parts.scheme.lower(), host, ":%d" % port if port else "", parts.path[:60])
        if parts.scheme.lower() == "http":
            out.append(make_finding(rule, sf, at + 1, evidence="url: " + shown, message=(
                "The topic '%s' sends an HTTP request over plain HTTP (%s): what it sends and receives, including any "
                "header credential, can be read or changed on the way." % (_short(name)[:80], shown))))
        elif port and port != 443:
            out.append(make_finding(rule, sf, at + 1, evidence="url: " + shown, message=(
                "The topic '%s' sends an HTTP request to a non-standard port (%s): check the endpoint is meant to be "
                "reached from the agent, and is not a management or test port." % (_short(name)[:80], shown))))
        elif _CONNECTOR_HOST.match(host):
            out.append(make_finding(rule, sf, at + 1, severity="minor", evidence="url: " + shown, message=(
                "The topic '%s' calls %s with a raw HTTP request where a connector exists, so the data policies that "
                "govern that connector do not apply to this call." % (_short(name)[:80], host))))
    return out


# --- JH152: generative orchestration with no instructions

_AGENT_MCS = re.compile(r"(?i)(?:^|/)agent\.mcs\.ya?ml$")


def _generative(text: Optional[str], settings: bool) -> bool:
    if not text:
        return False
    if settings:
        return bool(re.search(r"(?mi)^[ \t]+GenerativeActionsEnabled:[ \t]*true[ \t]*\r?$", text))
    try:
        doc = json.loads(text)
    except ValueError:
        return False
    s = doc.get("settings") if isinstance(doc, dict) else None
    return isinstance(s, dict) and s.get("GenerativeActionsEnabled") is True


def _no_instructions(sf: SourceFile, rule: Rule) -> List[Finding]:
    name = _component(sf)
    if name is None:
        return []
    if _COMPONENT.search(sf.rel):
        if not name.lower().endswith(".gpt.default"):
            return []
        on = _generative(_sibling(sf, "../../bots/%s/configuration.json" % name.split(".")[0]), False)
    elif _AGENT_MCS.search(sf.rel):
        on = _generative(_sibling(sf, "settings.mcs.yml"), True)
    else:
        return []
    lines = sf.raw
    if not on or _top(lines, "kind") is None or _value(lines, _top(lines, "kind")) != "GptComponentMetadata":
        return []
    at = _top(lines, "instructions")
    if at is not None and _value(lines, at):
        return []
    return [make_finding(rule, sf, at + 1 if at is not None else 1, evidence="instructions:", message=(
        "The agent '%s' uses generative orchestration but has no instructions: the model chooses which topics, tools "
        "and knowledge to use, and what to say, with nothing stating the agent's purpose, scope or limits." % (
            _label(sf, name.split(".")[0]))))]


# --- JH153: a tool sends email to whoever the AI chooses

_MAIL_API = re.compile(r"(?i)\.shared_(?:office365|outlook|gmail|sendmail)\.")
# operations that send to a recipient given as an input (To, or ToRecipients when forwarding), per Microsoft's
# connector reference; a reply goes back to the sender and a draft was addressed when it was made
_MAIL_OP = re.compile(r"(?i)^(?:SendEmail(?:V\d+)?|SendMailWithOptions|SendApprovalMail|SharedMailboxSendEmail(?:V\d+)?|"
                      r"ForwardEmail(?:_?V\d+)?)$")


def _ai_email(sf: SourceFile, rule: Rule) -> List[Finding]:
    name = _component(sf)
    if name is None:
        return []
    lines = sf.raw
    kind = _top(lines, "kind")
    if kind is None or _value(lines, kind) != "TaskDialog":
        return []
    ref = next((j for j, line in enumerate(lines) if re.match(r"^\s+connectionReference:", line)), None)
    op = next((j for j, line in enumerate(lines) if re.match(r"^\s+operationId:", line)), None)
    if ref is None or op is None or not _MAIL_API.search(_value(lines, ref) + ".") or \
            not _MAIL_OP.match(_value(lines, op)):
        return []
    fixed = False
    inputs = _top(lines, "inputs")
    if inputs is not None:
        end = _end(lines, inputs)
        for j in range(inputs + 1, end):
            if not re.match(r"^\s*-\s*kind:\s*ManualTaskInput\s*$", lines[j]):
                continue
            for k in range(j + 1, _end(lines, j)):
                if re.match(r"^\s*propertyName:", lines[k]) and \
                        _value(lines, k).strip("'\"").split("/")[-1].lower() in ("to", "torecipients"):
                    fixed = True
    if fixed:
        return []
    return [make_finding(rule, sf, op + 1, message=(
        "The tool '%s' sends email (%s) and the AI chooses who receives it: a message or document that injects "
        "instructions can make the agent mail conversation data to any address. Set the recipient as a fixed input, "
        "or have a person confirm each email." % (_label(sf, name), _value(lines, op)[:40])))]


# --- JH101 in topics: a credential header of an HTTP step, written into the agent

_CREDENTIAL_HEADER = re.compile(r"(?i)^(?:(?:proxy-)?authorization|x-?api-?key|api-?key|ocp-apim-subscription-key|"
                                r"subscription-key|x-functions-key|x-(?:auth|access)-token|access-token|x-token|token|"
                                r"x-client-secret|client-secret)$")
_SCHEME = re.compile(r"(?i)^(?:bearer|basic|token|apikey|sharedaccesssignature)\s+")


def is_component(rel: str) -> bool:
    return bool(_COMPONENT.search(rel) or _MCS.search(rel))


def header_secrets(sf: SourceFile, rule: Rule) -> List[Finding]:
    """Credential headers of a topic's HTTP step written as text, plain or as a Power Fx text ="..."; a value read
    from an environment variable, a variable or any other formula is not written here and is not reported."""
    name = _component(sf)
    if name is None:
        return []
    lines, out = sf.raw, []
    for i, line in enumerate(lines):
        if not _HTTP_ACTION.match(line):
            continue
        head = next((j for j in range(i + 1, _end(lines, i)) if re.match(r"^\s*headers:\s*$", lines[j])), None)
        if head is None:
            continue
        for j in range(head + 1, _end(lines, head)):
            m = re.match(r"^\s*['\"]?([A-Za-z0-9_-]{1,64})['\"]?:", lines[j])
            if not m or not _CREDENTIAL_HEADER.match(m.group(1)):
                continue
            value = _value(lines, j).strip()
            if value.startswith("="):
                text = re.fullmatch(r'=\s*"([^"]*)"', value)
                if not text:
                    continue                             # Env.cr1_key, Topic.token, a concatenation: not written here
                value = text.group(1)
            value = _SCHEME.sub("", value).strip()
            if not _secret_value(value, True):
                continue
            out.append(make_finding(rule, sf, j + 1, evidence="%s: (%d characters, not shown)" % (m.group(1), len(value)),
                                    message=(
                "The topic '%s' sends a credential written into the agent (the %s header): anyone who can read the "
                "export, or open the agent's topics, has it. Keep it in an environment variable of type Secret (Azure "
                "Key Vault)." % (_short(name)[:80], m.group(1)))))
    return out


# ------------------------------------------------------------------ environment variables

# environmentvariabledefinitions/<schema>/environmentvariabledefinition.xml holds the type and any default value;
# environmentvariablevalues.json beside it holds the current value when the solution is exported with values. Type is
# the Dataverse choice: 100000000 String (the maker's "Text"), 100000001 Number, 100000002 Boolean, 100000003 JSON,
# 100000004 Data source, 100000005 Secret (an Azure Key Vault reference, never the secret itself).
_ENV_FILE = re.compile(r"(?i)(?:^|/)environmentvariabledefinitions/([^/]{1,200})/"
                       r"(environmentvariabledefinition\.xml|environmentvariablevalues\.json)$")
TEXT_TYPE = "100000000"
# a name, publisher prefix and punctuation removed, that ends in a credential word: AzureOpenAIAPIKey, ClientSecret,
# SmtpPassword, GraphPfxPw, AccessToken, StorageConnectionString
_SECRET_NAME = re.compile(r"(?i)(?:api_?key|access_?key|subscription_?key|account_?key|shared_?(?:access_?)?key|sas_?key|"
                          r"private_?key|signing_?key|master_?key|secret(?:_?key)?|passw(?:or)?d|pwd|pw|"
                          r"(?:access|auth|bearer|api|refresh|sas)?_?token|connection_?string|conn_?str)$")
_KEY_NAME = re.compile(r"(?i)key$")                # DemoKey: a secret only when its value looks like one
_KV_REF = re.compile(r"(?i)^/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.keyvault/")
_PLACEHOLDER = re.compile(r"(?i)^(?:<.*>|\[.*\]|\{.*\}|\$\(.*\)|x+|\*+|-+|\.+|0+|none|null|nil|n/?a|tbd|todo)$|"
                          r"placeholder|changeme|change_me|your_?|enter_?|replace|insert|example|sample|dummy|fake|redact")
_GUID = re.compile(r"(?i)^\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?$")


def _bare_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "", re.sub(r"^[A-Za-z0-9]{1,12}_(?=.)", "", name.strip()))


def _secret_value(value: str, named: bool) -> bool:
    """A value that could be the credential itself, not a placeholder, a URL or a Key Vault reference. Under a
    credential name any such value of 8 characters counts; under a name that only ends in 'key', a long mixed one."""
    v = value.strip()
    if len(v) < 8 or re.search(r"\s", v) or "://" in v or _KV_REF.match(v) or _PLACEHOLDER.search(v):
        return False
    if named:
        return True
    return len(v) >= 20 and bool(re.search(r"\d", v)) and bool(re.search(r"[A-Za-z]", v)) and not _GUID.match(v)


def _values(doc: Any) -> List[str]:
    """The value strings in an environmentvariablevalues.json."""
    vals = doc.get("environmentvariablevalues") if isinstance(doc, dict) else None
    vals = vals.get("environmentvariablevalue") if isinstance(vals, dict) else None
    items = vals if isinstance(vals, list) else [vals]
    return [i["value"] for i in items if isinstance(i, dict) and isinstance(i.get("value"), str)]


def _env_secret(sf: SourceFile, rule: Rule) -> List[Finding]:
    where = _ENV_FILE.search(sf.rel)
    if not where:
        return []
    schema, member = where.group(1), where.group(2).lower()
    if member.endswith(".xml"):
        typ = re.search(r"<type>\s*(\d{1,12})\s*</type>", sf.text)
        if not typ or typ.group(1) != TEXT_TYPE:
            return []
        display = re.search(r'<displayname\s+default="([^"]{0,200})"', sf.text)
        names = [schema] + ([html.unescape(display.group(1))] if display else [])
        if not any(_SECRET_NAME.search(_bare_name(n)) for n in names):
            return []
        default = re.search(r"<defaultvalue>([^<]{0,4000})</defaultvalue>", sf.text)
        value = html.unescape(default.group(1)) if default else ""
        if _secret_value(value, True):
            return [make_finding(rule, sf, _line_at(sf.text, default.start()), severity="critical", confidence="high",
                                 evidence="<defaultvalue>(%d characters, not shown)</defaultvalue>" % len(value.strip()),
                                 message=(
                "The environment variable '%s' is Text, not Secret, and the export carries its default value (%d "
                "characters, not shown): the secret ships with every copy of the solution. Rotate it, clear the default, "
                "and make it a Secret variable, which keeps the value in Azure Key Vault." % (schema[:80], len(value.strip()))))]
        return [make_finding(rule, sf, _line_at(sf.text, typ.start()), evidence="<type>%s</type>" % TEXT_TYPE, message=(
            "The environment variable '%s' is named for a secret but is Text, not Secret: its value is stored in plain "
            "text, readable by anyone who can read environment variables, and exported with the solution. Make it a "
            "Secret variable, which keeps the value in Azure Key Vault." % schema[:80]))]
    named = bool(_SECRET_NAME.search(_bare_name(schema)))
    if not named and not _KEY_NAME.search(_bare_name(schema)):
        return []
    try:
        doc = json.loads(sf.text)
    except (ValueError, RecursionError):
        return []
    out: List[Finding] = []
    for value in _values(doc):
        if _secret_value(value, named):
            at = sf.text.find(json.dumps(value)[1:-1])
            out.append(make_finding(rule, sf, _line_at(sf.text, max(at, 0)), severity="critical", confidence="high",
                                    evidence='"value": "(%d characters, not shown)"' % len(value.strip()), message=(
                "The export carries the current value of the environment variable '%s' (%d characters, not shown): the "
                "secret ships with every copy of the solution. Rotate it, export the solution without current values, "
                "and make it a Secret variable, which keeps the value in Azure Key Vault." % (schema[:80], len(value.strip())))))
    return out


# ------------------------------------------------------------------ dispatch

def findings(sf: SourceFile, rule: Rule) -> List[Finding]:
    if rule.check == "powerplatform_agent_open":
        return _agent_open(sf, rule)
    if rule.check == "powerplatform_env_secret":
        return _env_secret(sf, rule)
    if rule.check == "powerplatform_maker_credentials":
        return _maker_credentials(sf, rule)
    if rule.check == "powerplatform_agent_http":
        return _http_request(sf, rule)
    if rule.check == "powerplatform_no_instructions":
        return _no_instructions(sf, rule)
    if rule.check == "powerplatform_ai_email":
        return _ai_email(sf, rule)
    parsed = flow(sf)
    if not parsed:
        return []
    out: List[Finding] = []
    definition, refs = parsed["definition"], parsed["refs"]
    for kind, name, node in nodes(definition):
        typ = str(node.get("type", ""))
        inputs = node.get("inputs") if isinstance(node.get("inputs"), dict) else {}
        if rule.check == "powerplatform_http_trigger" and kind == "trigger" and typ.lower() == "request" and \
                str(node.get("kind", "")).lower() in ("http", ""):      # not Button, PowerApp or Skills: those sign in
            mode = inputs.get("triggerAuthenticationType")
            if isinstance(mode, str) and mode.strip().lower() in OPEN_MODES:
                # 'Anyone' is the designer's label; public exports serialize the open mode as 'All'
                out.append(_at(sf, rule, name, confidence="medium", message=(
                    "The flow's HTTP trigger '%s' is open to anyone (triggerAuthenticationType '%s'): whoever has its URL "
                    "can start the flow, with no sign-in. The URL is the only key, and it travels in logs, scripts and "
                    "chat." % (name[:60], mode.strip()[:20]))))
            elif mode is None:
                out.append(_at(sf, rule, name, severity="minor", confidence="low", message=(
                    "The flow starts from an HTTP request ('%s') and the export does not say who may call it. A flow "
                    "made before sign-in options existed, or set to Anyone, runs for whoever has the URL. Check the "
                    "trigger's 'Who can trigger the flow' setting." % name[:60])))
        if kind != "action":
            continue
        api = connector(node, refs)
        op = operation(node)
        if rule.check == "powerplatform_secret_history":
            if api == "shared_keyvault" and op.lower().startswith("getsecret") and not _secured(node, "outputs"):
                out.append(_at(sf, rule, name, message=(
                    "The Key Vault action '%s' reads a secret without Secure outputs, so the secret is shown in the "
                    "flow's run history to anyone with access to it." % name[:60])))
            elif typ.lower() == "http" and not _secured(node, "inputs") and (
                    isinstance(inputs.get("authentication"), dict) or
                    any(str(k).lower() in ("authorization", "x-api-key", "api-key", "apikey", "ocp-apim-subscription-key")
                        for k in (inputs.get("headers") or {}) if isinstance(inputs.get("headers"), dict))):
                out.append(_at(sf, rule, name, severity="minor", confidence="medium", message=(
                    "The HTTP action '%s' sends a credential without Secure inputs, so it is shown in the flow's run "
                    "history to anyone with access to it." % name[:60])))
        if rule.check == "powerplatform_consumer" and api in CONSUMER:
            out.append(_at(sf, rule, name, message=(
                "The action '%s' uses the %s connector, which can connect a personal account. Work data the flow "
                "handles can leave the organisation through it; the export cannot show whose account it is. Check "
                "your data policy classifies it." % (name[:60], CONSUMER[api]))))
        if rule.check == "powerplatform_ai_personal":
            uri = inputs.get("uri") if isinstance(inputs.get("uri"), str) else ""
            ai = api in AI_CONNECTORS or op.lower().startswith("aibuilderpredict") or \
                (typ.lower() == "http" and bool(_AI_HOST.match(uri)))
            if not ai:
                continue
            sent = json.dumps({k: v for k, v in inputs.items() if k not in ("host", "authentication")})[:200000]
            # a field counts unless it is read from a step named for redaction; a word in a prompt is not a redaction
            fields = sorted({m.group(0) for m in _PERSONAL.finditer(sent)
                             if not _redacted_source(sent[max(0, m.start() - 300):m.start()])})
            if fields:
                out.append(_at(sf, rule, name, message=(
                    "The action '%s' sends personal data (%s) to an AI service with no visible redaction. Check the "
                    "service is approved for this data and that the minimum is sent." % (
                        name[:60], ", ".join(f.strip("[]' ") for f in fields[:4])))))
    return out
